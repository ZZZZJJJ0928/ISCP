package iscprelayreference

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/queue"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
)

const receiveIOTimeout = 5 * time.Second

// Ping/Pong bounds silent connection loss independently of message delivery.
const receivePingInterval = 20 * time.Second

// The slot survives replacement until every attached receive loop has left.
// delivery serializes claim/write/commit/release. Swapping owner first fences
// the old loop; closing its socket and context interrupts an in-flight operation.
type receiveSlot struct {
	delivery sync.Mutex
	owner    atomic.Pointer[receiveConnection]
	users    int // guarded by Server.receiveMu
	closed   chan struct{}
}

type receiveConnection struct {
	conn   *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	wake   chan struct{}
	pongs  chan string
	done   chan struct{}
}

func (c *receiveConnection) stop() { c.cancel(); _ = c.conn.Close() }

func receiveKey(domain, device string) string { return domain + "\x00" + device }

func (s *Server) attachReceiver(key string, c *receiveConnection) *receiveSlot {
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if s.receiveClosed {
		return nil
	}
	slot := s.receivers[key]
	if slot == nil {
		slot = &receiveSlot{closed: make(chan struct{})}
		s.receivers[key] = slot
	}
	slot.users++
	if old := slot.owner.Swap(c); old != nil {
		old.stop()
	}
	return slot
}

func (s *Server) detachReceiver(key string, slot *receiveSlot, c *receiveConnection) {
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	slot.owner.CompareAndSwap(c, nil)
	slot.users--
	if slot.users == 0 {
		delete(s.receivers, key)
		close(slot.closed)
	}
}

func (s *Server) wakeReceiver(domain, device string) {
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if slot := s.receivers[receiveKey(domain, device)]; slot != nil {
		if c := slot.owner.Load(); c != nil {
			select {
			case c.wake <- struct{}{}:
			default:
			}
		}
	}
}

func (s *Server) stopReceiver(domain, device string) {
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if slot := s.receivers[receiveKey(domain, device)]; slot != nil {
		if c := slot.owner.Load(); c != nil {
			c.stop()
		}
	}
}

// Close stops upgraded WebSockets, which http.Server.Shutdown does not own.
// It is idempotent and rejects receive loops that finish authentication later.
func (s *Server) Close() {
	s.receiveMu.Lock()
	s.receiveClosed = true
	var slots []*receiveSlot
	for _, slot := range s.receivers {
		slots = append(slots, slot)
		if c := slot.owner.Load(); c != nil {
			c.stop()
		}
	}
	s.receiveMu.Unlock()
	for _, slot := range slots {
		<-slot.closed
	}
}

func (s *Server) receiveAllowed(slot *receiveSlot, c *receiveConnection, device string) bool {
	if c.ctx.Err() != nil || slot.owner.Load() != c {
		return false
	}
	s.mu.RLock()
	_, revoked := s.revoked[device]
	s.mu.RUnlock()
	return !revoked
}

func (s *Server) receiveStream(ctx context.Context, ws *websocket.Conn, id identity.DeviceIdentity) {
	ctx, cancel := context.WithCancel(ctx)
	c := &receiveConnection{conn: ws, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), pongs: make(chan string, 1), done: make(chan struct{})}
	key := receiveKey(id.DomainID, id.DeviceID)
	slot := s.attachReceiver(key, c)
	if slot == nil {
		c.stop()
		return
	}
	defer s.detachReceiver(key, slot, c)
	defer c.stop()
	// Wait for a replaced writer to release its claim before advertising ready.
	slot.delivery.Lock()
	allowed := s.receiveAllowed(slot, c, id.DeviceID)
	slot.delivery.Unlock()
	if !allowed {
		return
	}
	_ = ws.SetReadDeadline(time.Time{})
	_ = ws.SetWriteDeadline(time.Now().Add(receiveIOTimeout))
	if ws.WriteJSON(map[string]string{"state": "ready"}) != nil {
		return
	}
	ws.SetPongHandler(func(value string) error {
		select {
		case c.pongs <- value:
		default:
		}
		return nil
	})
	go func() {
		defer close(c.done)
		defer c.stop()
		// Only control frames follow authentication on a receive-only socket.
		_, _, _ = ws.ReadMessage()
	}()
	defer func() { c.stop(); <-c.done }()
	livenessDone := make(chan struct{})
	go func() {
		defer close(livenessDone)
		c.watchLiveness()
	}()
	defer func() { c.stop(); <-livenessDone }()
	fallback := time.NewTicker(time.Second)
	defer fallback.Stop()
	for {
		if !s.receiveAllowed(slot, c, id.DeviceID) {
			return
		}
		count, err := s.deliverNext(slot, c, id)
		if err != nil {
			return
		}
		if count == 0 {
			select {
			case <-ctx.Done():
				return
			case <-c.wake:
			case <-fallback.C:
			}
		}
	}
}

func (c *receiveConnection) watchLiveness() {
	defer c.stop()
	ticker := time.NewTicker(receivePingInterval)
	defer ticker.Stop()
	for {
		// The first probe starts immediately, but delivery never waits on Pong.
		if c.ping() != nil {
			return
		}
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *receiveConnection) ping() error {
	value := randomToken()
	if err := c.conn.WriteControl(websocket.PingMessage, []byte(value), time.Now().Add(receiveIOTimeout)); err != nil {
		return err
	}
	timer := time.NewTimer(receiveIOTimeout)
	defer timer.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return c.ctx.Err()
		case <-timer.C:
			return errors.New("receive liveness timeout")
		case pong := <-c.pongs:
			if pong == value {
				return nil
			}
		}
	}
}

func (s *Server) deliverNext(slot *receiveSlot, c *receiveConnection, id identity.DeviceIdentity) (int, error) {
	slot.delivery.Lock()
	defer slot.delivery.Unlock()
	if !s.receiveAllowed(slot, c, id.DeviceID) {
		return 0, context.Canceled
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	ctx, cancel := context.WithTimeout(c.ctx, receiveIOTimeout)
	defer cancel()
	claim, err := s.claimOne(ctx, id, now)
	if err != nil || claim == nil {
		return 0, err
	}
	defer claim.finish(false)
	msg := claim.message
	// The claim transaction is still open. A replacement cannot claim until
	// this critical section ends; rollback never releases a successor's claim.
	if !s.receiveAllowed(slot, c, id.DeviceID) {
		return 0, context.Canceled
	}
	_ = c.conn.SetWriteDeadline(time.Now().Add(receiveIOTimeout))
	err = c.conn.WriteJSON(map[string]any{"state": "message", "message_id": msg.MessageID, "envelope": json.RawMessage(msg.Envelope)})
	if err != nil {
		return 0, err
	}
	// Match reference delivery semantics: accepted by this connection. Final
	// business delivery is still governed by the existing durable result ACK.
	if err := claim.finish(true); err != nil {
		return 0, err
	}
	return 1, nil
}

type receiveClaim struct {
	server  *Server
	message queue.Message
	tx      pgx.Tx
	once    sync.Once
	err     error
}

func (s *Server) claimOne(ctx context.Context, id identity.DeviceIdentity, now time.Time) (*receiveClaim, error) {
	if s.repo == nil {
		s.queueMu.Lock()
		defer s.queueMu.Unlock()
		messages := s.queue.DequeueFor(id.DomainID, id.DeviceID, now, 1)
		if len(messages) == 0 {
			return nil, nil
		}
		s.reservedBytes += len(messages[0].Envelope)
		return &receiveClaim{server: s, message: messages[0]}, nil
	}
	// A single claim retains database priority/queued_at selection order;
	// UPDATE RETURNING does not guarantee ordering for a multi-row claim.
	// Keep the claim and delivery mark in one bounded transaction. Failed
	// reads/writes and process death roll it back instead of stranding a lease.
	tx, err := s.cfg.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	claim := &receiveClaim{server: s, tx: tx}
	repo := repository.NewRelayRepository(tx)
	messages, err := repo.ClaimPendingMessagesFor(ctx, repository.DomainID(id.DomainID), id.DeviceID, now, time.Minute, 1)
	if err != nil || len(messages) == 0 {
		_ = claim.finish(false)
		return nil, err
	}
	msg := messages[0]
	claim.message = queue.Message{DomainID: string(msg.DomainID), MessageID: msg.MessageID, SenderDeviceID: msg.SenderDeviceID, RecipientDeviceID: msg.RecipientDeviceID, Envelope: msg.EnvelopeRaw, Priority: msg.Priority, QueuedAt: msg.QueuedAt, ExpiresAt: msg.ExpiresAt}
	return claim, nil
}

func (c *receiveClaim) finish(delivered bool) error {
	c.once.Do(func() { c.err = c.finishOnce(delivered) })
	return c.err
}

func (c *receiveClaim) finishOnce(delivered bool) error {
	s, msg := c.server, c.message
	if c.tx == nil {
		s.queueMu.Lock()
		defer s.queueMu.Unlock()
		s.reservedBytes -= len(msg.Envelope)
		if !delivered && time.Now().Before(msg.ExpiresAt) && !s.queue.Enqueue(msg, time.Now().UTC()) {
			return errors.New("restore receive claim")
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), receiveIOTimeout)
	defer cancel()
	defer c.tx.Rollback(ctx)
	if !delivered {
		return c.tx.Rollback(ctx)
	}
	repo := repository.NewRelayRepository(c.tx)
	if err := repo.MarkMessageDelivered(ctx, repository.DomainID(msg.DomainID), msg.MessageID, time.Now().UTC()); err != nil {
		return err
	}
	return c.tx.Commit(ctx)
}

func (s *Server) enqueueMemory(msg queue.Message, now time.Time) bool {
	s.queueMu.Lock()
	defer s.queueMu.Unlock()
	if s.reservedBytes == 0 {
		return s.queue.Enqueue(msg, now)
	}
	// Claimed bytes still count until commit/release, so a failed write can
	// always restore its message even while other senders enqueue concurrently.
	s.queue.SnapshotMetadata(now) // Remove expired bytes before checking capacity.
	if s.queue.UsedBytes()+s.reservedBytes+len(msg.Envelope) > relayMaxQueuedBytes {
		return false
	}
	return s.queue.Enqueue(msg, now)
}
