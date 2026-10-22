package iscprelayreference

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/authority"
	"github.com/Infinimesh-ai/ISCP/pkg/server/repository"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
)

type duplexWrite struct {
	frame duplex.Frame
	data  bool
	done  chan error
}
type duplexConnection struct {
	s                                             *Server
	ws                                            *websocket.Conn
	ctx                                           context.Context
	cancel                                        context.CancelFunc
	id                                            identity.DeviceIdentity
	connection, generation, epoch, history, token string
	mu                                            sync.Mutex
	expires                                       time.Time
	credentialGeneration, revision                string
	challenge                                     duplex.Frame
	challengeUsed                                 bool
	lastRequest                                   uint64
	reauthID                                      string
	writes                                        chan duplexWrite
	controlWrites                                 chan duplexWrite
	changed                                       chan struct{}
	done                                          sync.WaitGroup
	queueMu                                       sync.Mutex
	pendingBytes                                  int
	submitTail                                    chan struct{}
	keys                                          map[string]chan struct{}
	// deliveryWake is signalled when an admission names this device, so the
	// delivery loop runs at once instead of waiting for its idle tick.
	deliveryWake chan struct{}
}

const (
	// duplexDeliveryIdle bounds the wait for messages no in-process admission
	// signalled (other Relay processes, lease expiry, restarts).
	duplexDeliveryIdle = 100 * time.Millisecond
	// duplexDeliveryBatch bounds one drain so a busy recipient cannot starve
	// the connection's expiry and cancellation checks.
	duplexDeliveryBatch = 64
)

// wakeDelivery nudges the recipient's connection on this Relay, if any.
func (s *Server) wakeDelivery(domain, device string) {
	s.duplexMu.Lock()
	owner := s.duplexOwners[receiveKey(domain, device)]
	s.duplexMu.Unlock()
	if owner == nil || owner.deliveryWake == nil {
		return
	}
	select {
	case owner.deliveryWake <- struct{}{}:
	default:
	}
}

func (s *Server) retiredTransport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": "transport_upgrade_required", "protocol": duplex.Protocol, "path": duplex.Path})
}
func (s *Server) duplexConnect(w http.ResponseWriter, r *http.Request) {
	s.duplexMu.Lock()
	if s.duplexClosed {
		s.duplexMu.Unlock()
		http.Error(w, "maintenance", 503)
		return
	}
	s.duplexWG.Add(1)
	s.duplexMu.Unlock()
	defer s.duplexWG.Done()

	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	valid := false
	for _, p := range websocket.Subprotocols(r) {
		if p == duplex.Protocol {
			valid = true
		}
	}
	if !valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(426)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "transport_upgrade_required"})
		return
	}
	if s.cfg.DB == nil {
		http.Error(w, "persistent duplex authority unavailable", 503)
		return
	}
	var epoch, history string
	var enabled bool
	if e := s.cfg.DB.QueryRow(r.Context(), `SELECT w.writer_epoch::text,w.writes_enabled,a.history_id FROM iscp_relay.writer_scopes w JOIN iscp_relay.domain_authority a ON a.scope_id=w.scope_id WHERE w.scope_id=$1 AND a.domain_id=$2`, s.cfg.RelayID, s.cfg.DomainID).Scan(&epoch, &enabled, &history); e != nil || !enabled || epoch != s.writerEpoch || len(history) != 43 {
		http.Error(w, "duplex maintenance", 503)
		return
	}
	up := s.upgrader
	up.Subprotocols = []string{duplex.Protocol}
	up.EnableCompression = false
	ws, e := up.Upgrade(w, r, nil)
	if e != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	c := &duplexConnection{s: s, ws: ws, ctx: ctx, cancel: cancel, connection: duplex.RandomID(), generation: "0", epoch: epoch, history: history, writes: make(chan duplexWrite, 64), controlWrites: make(chan duplexWrite, 16), changed: make(chan struct{}, 1), keys: map[string]chan struct{}{}, deliveryWake: make(chan struct{}, 1)}
	s.duplexMu.Lock()
	if s.duplexClosed {
		s.duplexMu.Unlock()
		cancel()
		ws.Close()
		return
	}
	if s.duplexAll == nil {
		s.duplexAll = map[*duplexConnection]struct{}{}
	}
	s.duplexAll[c] = struct{}{}
	s.duplexMu.Unlock()
	defer func() {
		cancel()
		ws.Close()
		c.done.Wait()
		s.duplexMu.Lock()
		delete(s.duplexAll, c)
		if s.duplexOwners[receiveKey(c.id.DomainID, c.id.DeviceID)] == c {
			delete(s.duplexOwners, receiveKey(c.id.DomainID, c.id.DeviceID))
		}
		s.duplexMu.Unlock()
	}()
	ws.SetReadLimit(duplex.MaxFrameBytes)
	_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
	c.challenge = c.newChallenge("challenge", "")
	if e = c.direct(c.challenge); e != nil {
		return
	}
	kind, raw, e := ws.ReadMessage()
	if e != nil {
		return
	}
	f, e := duplex.Decode(raw)
	if e != nil || kind != websocket.TextMessage || f.Kind != "authenticate" || f.ConnectionID != c.connection || f.RequestID != "1" {
		return
	}
	c.lastRequest = 1
	if e = c.authenticate(f, true); e != nil {
		_ = c.direct(c.frame("closing", "authentication_failed"))
		return
	}
	ready := c.frame("ready", "")
	ready.RequestID = f.RequestID
	ready.DomainID = c.id.DomainID
	ready.DeviceID = c.id.DeviceID
	ready.HistoryID = history
	limits := duplex.DefaultLimits()
	ready.Limits = &limits
	ready.AuthorityExpiresAt = duplex.Timestamp(c.expiry())
	if e = c.direct(ready); e != nil {
		return
	}
	s.duplexMu.Lock()
	if s.duplexOwners == nil {
		s.duplexOwners = map[string]*duplexConnection{}
	}
	key := receiveKey(c.id.DomainID, c.id.DeviceID)
	old := s.duplexOwners[key]
	s.duplexOwners[key] = c
	s.duplexMu.Unlock()
	if old != nil {
		old.cancel()
		old.ws.Close()
	}
	ws.SetPongHandler(func(string) error { return ws.SetReadDeadline(time.Now().Add(60 * time.Second)) })
	_ = ws.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.done.Add(3)
	go func() { defer c.done.Done(); c.writer() }()
	go func() { defer c.done.Done(); c.delivery() }()
	go func() { defer c.done.Done(); c.liveness() }()
	for ctx.Err() == nil {
		kind, raw, e := ws.ReadMessage()
		if e != nil {
			return
		}
		if kind != websocket.TextMessage {
			c.close("protocol_error", 1002)
			return
		}
		f, e := duplex.Decode(raw)
		if e != nil {
			c.close("protocol_error", 1002)
			return
		}
		if f.ConnectionID != c.connection || f.OwnerGeneration != c.generation {
			c.close("protocol_error", 1002)
			return
		}
		n, e := strconv.ParseUint(f.RequestID, 10, 64)
		if e != nil {
			c.close("protocol_error", 1002)
			return
		}
		reuse := f.Kind == "reauthenticate" && f.RequestID == c.reauthID
		if !reuse && n <= c.lastRequest {
			c.close("protocol_error", 1002)
			return
		}
		if !reuse {
			c.lastRequest = n
		}
		switch f.Kind {
		case "reauth.request":
			if c.reauthID != "" {
				c.close("protocol_error", 1002)
				return
			}
			c.reauthID = f.RequestID
			c.challenge = c.newChallenge("reauth.challenge", f.RequestID)
			c.challengeUsed = false
			if c.send(c.challenge, false) != nil {
				return
			}
		case "reauthenticate":
			if !reuse || c.authenticate(f, false) != nil {
				c.close("authentication_failed", 1008)
				return
			}
			reply := c.frame("reauthenticated", "")
			reply.RequestID = f.RequestID
			reply.AuthorityExpiresAt = duplex.Timestamp(c.expiry())
			c.reauthID = ""
			select {
			case c.changed <- struct{}{}:
			default:
			}
			if c.send(reply, false) != nil {
				return
			}
		case "submit", "submit.query":
			if !c.enqueue(f, len(raw)) {
				c.close("resource_exhausted", 1011)
				return
			}
		default:
			c.close("protocol_error", 1002)
			return
		}
	}
}
func (c *duplexConnection) frame(kind, code string) duplex.Frame {
	return duplex.Frame{V: 1, Kind: kind, ConnectionID: c.connection, OwnerGeneration: c.generation, Code: code}
}
func (c *duplexConnection) newChallenge(kind, request string) duplex.Frame {
	l := duplex.DefaultLimits()
	f := c.frame(kind, "")
	f.RequestID = request
	f.ChallengeID = duplex.RandomID()
	f.Challenge = duplex.RandomID()
	f.ExpiresAt = duplex.Timestamp(time.Now().Add(10 * time.Second))
	if kind == "challenge" {
		f.OwnerGeneration = ""
		f.RelayID = c.s.cfg.RelayID
		f.DomainID = c.s.cfg.DomainID
		f.HistoryID = c.history
		f.Limits = &l
	}
	return f
}
func (c *duplexConnection) expiry() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.expires }
func (c *duplexConnection) direct(f duplex.Frame) error {
	raw, e := duplex.Encode(f)
	if e != nil {
		return e
	}
	return c.ws.WriteMessage(websocket.TextMessage, raw)
}
func (c *duplexConnection) close(code string, closeCode int) {
	_ = c.send(c.frame("closing", code), false)
	_ = c.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(closeCode, code), time.Now().Add(time.Second))
	c.cancel()
	c.ws.Close()
}
func (c *duplexConnection) send(f duplex.Frame, data bool) (result error) {
	// A timeout must fence the actual socket before the caller releases its
	// authority transaction; a queued frame may never outlive that guard.
	defer func() {
		if result != nil {
			c.cancel()
			_ = c.ws.Close()
		}
	}()

	w := duplexWrite{f, data, make(chan error, 1)}
	queue := c.controlWrites
	if data {
		queue = c.writes
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case queue <- w:
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-timer.C:
		return errors.New("writer queue timeout")
	}
	select {
	case e := <-w.done:
		return e
	case <-c.ctx.Done():
		return c.ctx.Err()
	case <-timer.C:
		return errors.New("writer timeout")
	}
}
func (c *duplexConnection) writer() {
	defer c.cancel()
	var pending *duplexWrite
	write := func(w duplexWrite) bool {
		_ = c.ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
		e := c.direct(w.frame)
		w.done <- e
		if e != nil {
			c.ws.Close()
			return false
		}
		return true
	}
	for {
		if pending != nil && time.Now().Before(c.expiry()) {
			if !write(*pending) {
				return
			}
			pending = nil
			continue
		}
		var data <-chan duplexWrite
		if pending == nil {
			data = c.writes
		}
		select {
		case <-c.ctx.Done():
			return
		case w := <-c.controlWrites:
			if !write(w) {
				return
			}
		case <-c.changed:
		case w := <-data:
			if !time.Now().Before(c.expiry()) {
				pending = &w
				continue
			}
			if !write(w) {
				return
			}
		}
	}
}

func (c *duplexConnection) liveness() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	nextPing := time.Now()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-t.C:
			if now.After(c.expiry().Add(10 * time.Second)) {
				c.close("auth_required", 1008)
				return
			}
			if !now.Before(nextPing) {
				if c.ws.WriteControl(websocket.PingMessage, []byte("duplex"), now.Add(5*time.Second)) != nil {
					c.cancel()
					c.ws.Close()
					return
				}
				nextPing = now.Add(20 * time.Second)
			}
		}
	}
}
func (c *duplexConnection) authenticate(f duplex.Frame, initial bool) error {
	if f.Proof == nil || c.challengeUsed || f.ChallengeID != c.challenge.ChallengeID || !time.Now().Before(duplex.Time(c.challenge.ExpiresAt)) {
		return errors.New("challenge_expired")
	}
	p := *f.Proof
	if p.DomainID != c.s.cfg.DomainID || (!initial && (p.DeviceID != c.id.DeviceID || p.DomainID != c.id.DomainID)) {
		return errors.New("identity mismatch")
	}
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()
	tx, e := c.s.cfg.DB.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	snap, e := authority.Lock(ctx, tx, authority.Request{ScopeID: c.s.cfg.RelayID, DomainID: p.DomainID, ExpectedWriterEpoch: c.epoch, Devices: []authority.DeviceLock{{ID: p.DeviceID}}, Owners: []authority.DeviceLock{{ID: p.DeviceID, Exclusive: true}}})
	if e != nil {
		return e
	}
	repo := repository.NewRelayRepository(tx)
	d, e := repo.GetDevice(ctx, repository.DomainID(p.DomainID), p.DeviceID)
	if e != nil || d.Status != "active" {
		return errors.New("revoked")
	}
	var id identity.DeviceIdentity
	if json.Unmarshal(d.IdentityRaw, &id) != nil {
		return errors.New("invalid identity")
	}
	cred, e := repo.GetAccessByHash(ctx, repository.DomainID(p.DomainID), crypto.SHA256([]byte(f.AccessToken)), time.Now())
	if e != nil || cred.DeviceID != p.DeviceID {
		return errors.New("auth_required")
	}
	purpose := "authenticate"
	gen := "0"
	if !initial {
		purpose = "reauthenticate"
		gen = c.generation
		if snap.Owners[p.DeviceID].Generation != gen || snap.Owners[p.DeviceID].ConnectionID != c.connection {
			return errors.New("replaced")
		}
	}
	challenge := c.challenge
	l := duplex.DefaultLimits()
	challenge.Limits = &l
	challenge.RelayID = c.s.cfg.RelayID
	challenge.HistoryID = c.history
	expected, e := duplex.AuthChallenge(challenge, purpose, f.RequestID, gen, f.AccessToken, id)
	if e != nil {
		return e
	}
	now := time.Now()
	if p.IssuedAt.After(now.Add(30 * time.Second)) {
		return errors.New("proof future")
	}
	if e = identity.VerifyProof(c.s.provider, id, p, c.s.cfg.RelayID, expected, now, 60*time.Second); e != nil {
		return e
	}
	used, e := repo.UseProofNonce(ctx, repository.DomainID(p.DomainID), p.DeviceID, p.Audience, p.Nonce, p.IssuedAt.Add(60*time.Second), now)
	if e != nil || !used {
		return errors.New("proof replay")
	}
	state := snap.Devices[p.DeviceID]
	var tokenGeneration *string
	if e = tx.QueryRow(ctx, `SELECT credential_generation::text FROM iscp_relay.access_tokens WHERE domain_id=$1 AND device_id=$2 AND token_hash=$3`, p.DomainID, p.DeviceID, crypto.SHA256([]byte(f.AccessToken))).Scan(&tokenGeneration); e != nil || tokenGeneration == nil || *tokenGeneration != state.CredentialGeneration {
		return errors.New("auth_required")
	}

	if !initial {
		c.mu.Lock()
		same := state.AuthorizationRevision == c.revision
		c.mu.Unlock()
		if !same {
			return errors.New("scope changed")
		}
	} else {
		gen, e = duplex.Next(snap.Owners[p.DeviceID].Generation)
		if e != nil {
			return e
		}
	}
	_, e = tx.Exec(ctx, `UPDATE iscp_relay.connection_owners SET owner_generation=$4,connection_id=$5,authority_expires_at=$6,credential_generation=$7,authorization_revision=$8 WHERE scope_id=$1 AND domain_id=$2 AND device_id=$3`, c.s.cfg.RelayID, p.DomainID, p.DeviceID, gen, c.connection, cred.ExpiresAt, state.CredentialGeneration, state.AuthorizationRevision)
	if e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	c.challengeUsed = true
	if initial {
		c.id = id
		c.generation = gen
	}
	c.mu.Lock()
	c.token = f.AccessToken
	c.expires = cred.ExpiresAt
	c.credentialGeneration = state.CredentialGeneration
	c.revision = state.AuthorizationRevision
	c.mu.Unlock()
	return nil
}
func (c *duplexConnection) enqueue(f duplex.Frame, size int) bool {
	c.queueMu.Lock()
	if c.pendingBytes+size > 8*duplex.MaxFrameBytes {
		c.queueMu.Unlock()
		return false
	}
	before := c.keys[f.MessageID]
	var beforeSubmit chan struct{}
	if f.Kind == "submit" {
		beforeSubmit = c.submitTail
	}
	after := make(chan struct{})
	c.keys[f.MessageID] = after
	if f.Kind == "submit" {
		c.submitTail = after
	}
	c.pendingBytes += size
	c.queueMu.Unlock()
	c.done.Add(1)
	go func() {
		defer c.done.Done()
		defer func() {
			close(after)
			c.queueMu.Lock()
			c.pendingBytes -= size
			if c.keys[f.MessageID] == after {
				delete(c.keys, f.MessageID)
			}
			c.queueMu.Unlock()
		}()
		if beforeSubmit != nil {
			select {
			case <-beforeSubmit:
			case <-c.ctx.Done():
				return
			}
		}
		if before != nil {
			select {
			case <-before:
			case <-c.ctx.Done():
				return
			}
		}
		c.process(f)
	}()
	return true
}
func (c *duplexConnection) locked(ctx context.Context, tx pgx.Tx, key string, history bool) (authority.Snapshot, error) {
	snap, e := authority.Lock(ctx, tx, authority.Request{ScopeID: c.s.cfg.RelayID, DomainID: c.id.DomainID, ExpectedWriterEpoch: c.epoch, Devices: []authority.DeviceLock{{ID: c.id.DeviceID}}, Owners: []authority.DeviceLock{{ID: c.id.DeviceID}}, Keys: []authority.Key{{Namespace: "message", ID: key}}, RequireContinuousHistory: history})
	if e != nil {
		return snap, e
	}
	o := snap.Owners[c.id.DeviceID]
	if o.Generation != c.generation || o.ConnectionID != c.connection {
		return snap, errors.New("replaced")
	}
	c.mu.Lock()
	token := c.token
	revision, generation := c.revision, c.credentialGeneration
	c.mu.Unlock()
	state := snap.Devices[c.id.DeviceID]
	if state.AuthorizationRevision != revision || o.AuthorizationRevision != revision {
		return snap, errors.New("authority_changed")
	}
	if state.CredentialGeneration != generation || o.CredentialGeneration != generation {
		return snap, errors.New("auth_required")
	}
	cred, e := repository.NewRelayRepository(tx).GetAccessByHash(ctx, repository.DomainID(c.id.DomainID), crypto.SHA256([]byte(token)), time.Now())
	if e != nil || cred.DeviceID != c.id.DeviceID || !time.Now().Before(o.ExpiresAt) {
		return snap, errors.New("auth_required")
	}
	return snap, nil
}
func (c *duplexConnection) process(f duplex.Frame) {
	sub := duplex.Submission{MessageID: f.MessageID, EnvelopeDigest: f.EnvelopeDigest, HistoryID: f.HistoryID, NotAfter: f.NotAfter, Envelope: f.Envelope}
	reply := c.frame("submit.status", "")
	reply.RequestID = f.RequestID
	reply.MessageID = f.MessageID
	reply.EnvelopeDigest = f.EnvelopeDigest
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()
	tx, e := c.s.cfg.DB.Begin(ctx)
	if e != nil {
		reply.State = "unknown"
		reply.Reason = "barrier_timeout"
		_ = c.send(reply, true)
		return
	}
	defer tx.Rollback(context.Background())
	snap, e := c.locked(ctx, tx, f.MessageID, false)
	result := repository.AdmissionResult{}
	if e != nil {
		if errors.Is(e, authority.ErrRevoked) {
			c.close("revoked", 1008)
			return
		}
		if e.Error() == "authority_changed" {
			c.close("authentication_failed", 1008)
			return
		}
		if e.Error() == "replaced" {
			c.close("replaced", 1008)
			return
		}
		if e.Error() == "auth_required" {
			result.Code = "auth_required"
		} else {
			result.State = "unknown"
			result.Reason = "barrier_timeout"
		}
		e = nil
	} else if snap.HistoryState != "continuous" || snap.HistoryID != f.HistoryID {
		if f.Kind == "submit" {
			result.Code = "history_unavailable"
		} else {
			result.State = "unknown"
			result.Reason = "history_unavailable"
		}
	} else if f.Kind == "submit" {
		result, e = repository.AdmitEnvelope(ctx, tx, c.s.cfg.RelayID, c.id.DomainID, c.id.DeviceID, c.s.cfg.RelayID, sub, c.s.signer, time.Now())
	} else {
		result, e = repository.ReconcileAdmission(ctx, tx, c.id.DomainID, c.id.DeviceID, sub, time.Now())
	}
	if e != nil && result.Code == "" {

		if rollback := tx.Rollback(context.Background()); rollback == nil {
			result = repository.AdmissionResult{Code: "storage_unavailable"}
		} else {
			result = repository.AdmissionResult{State: "unknown", Reason: "commit_unknown"}
		}
	} else if result.Code == "" {
		c.s.duplexMu.Lock()
		commit := c.s.admissionCommit
		c.s.duplexMu.Unlock()
		if commit == nil {
			commit = func(ctx context.Context, tx pgx.Tx) error { return tx.Commit(ctx) }
		}
		if e = commit(ctx, tx); e != nil {
			result = repository.AdmissionResult{State: "unknown", Reason: "commit_unknown"}
		}
	}
	if result.Code != "" {
		reply.Kind = "rejected"
		reply.Code = result.Code
	} else if f.Kind == "submit" && result.Receipt != nil {
		reply.Kind = "accepted"
		reply.Receipt = result.Receipt
		c.s.wakeDelivery(c.id.DomainID, result.Receipt.RecipientDeviceID)
	} else {
		reply.State = result.State
		reply.Reason = result.Reason
		reply.Receipt = result.Receipt
	}
	_ = tx.Rollback(context.Background())
	if reply.Code == "auth_required" {
		_ = c.send(reply, false)
		return
	}
	// Reacquire current disclosure authority after commit. Rotation/revocation
	// and takeover cannot pass this shared lock while a receipt is written.
	disclosure, err := c.s.cfg.DB.Begin(ctx)
	if err != nil {
		return
	}
	defer disclosure.Rollback(context.Background())
	if _, err = c.locked(ctx, disclosure, f.MessageID, false); err != nil {
		return
	}
	_ = c.send(reply, true)
}
func (c *duplexConnection) delivery() {
	idle := duplexDeliveryIdle
	if c.s.deliveryIdle > 0 {
		idle = c.s.deliveryIdle
	}
	ticker := time.NewTicker(idle)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		case <-c.deliveryWake:
		}
		// Drain what is pending, one committed delivery at a time, then wait.
		for drained := 0; drained < duplexDeliveryBatch && c.ctx.Err() == nil && time.Now().Before(c.expiry()); drained++ {
			delivered, e := c.deliverOne()
			if e != nil && c.ctx.Err() == nil {
				if e.Error() == "auth_required" {
					break
				}
				if e.Error() == "authority_changed" {
					c.close("authentication_failed", 1008)
					return
				}
				if errors.Is(e, authority.ErrRevoked) {
					c.close("revoked", 1008)
					return
				}
				c.cancel()
				c.ws.Close()
				return
			}
			if e != nil || !delivered {
				break
			}
		}
	}
}

// deliverOne reports whether a message was delivered and committed.
func (c *duplexConnection) deliverOne() (bool, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()
	tx, e := c.s.cfg.DB.Begin(ctx)
	if e != nil {
		return false, e
	}
	defer tx.Rollback(context.Background())
	_, e = c.locked(ctx, tx, "delivery:"+c.id.DeviceID, false)
	if e != nil {
		return false, e
	}
	repo := repository.NewRelayRepository(tx)
	messages, e := repo.ClaimDuplexPendingMessage(ctx, repository.DomainID(c.id.DomainID), c.id.DeviceID, time.Now(), time.Minute)
	if e != nil || len(messages) == 0 {
		return false, e
	}
	m := messages[0]
	f := c.frame("delivery", "")
	f.MessageID = m.MessageID
	f.Envelope = json.RawMessage(m.EnvelopeRaw)
	f.EnvelopeDigest, e = duplex.Digest(f.Envelope)
	if e != nil {
		return false, e
	}
	if e = c.send(f, true); e != nil {
		return false, e
	}
	if e = repo.MarkMessageDelivered(ctx, repository.DomainID(c.id.DomainID), m.MessageID, time.Now()); e != nil {
		return false, e
	}
	if e = tx.Commit(ctx); e != nil {
		return false, e
	}
	return true, nil
}
