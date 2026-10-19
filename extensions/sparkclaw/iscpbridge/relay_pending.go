package iscpbridge

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	crypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
)

// RelaySubmissionStatus is safe for helper IPC: ciphertext and tokens stay in
// the encrypted local journal. A transport receipt is not a business receipt.
type RelaySubmissionStatus struct {
	MessageID      string             `json:"message_id"`
	EnvelopeDigest string             `json:"envelope_digest"`
	HistoryID      string             `json:"history_id"`
	NotAfter       string             `json:"not_after"`
	SessionID      string             `json:"session_id"`
	State          string             `json:"state"`
	Receipt        *AcceptanceReceipt `json:"receipt,omitempty"`
}
type relayPendingRecord struct {
	Order      uint64
	Submission RelaySubmission
	State      string
	Receipt    *AcceptanceReceipt
	Uncertain  bool
	Consumed   bool
}
type relayPendingState struct {
	NextOrder                   uint64
	DomainID, DeviceID, RelayID string
	Records                     map[string]relayPendingRecord
}
type relayJournal struct {
	mu            sync.Mutex
	path          string
	key           []byte
	state         relayPendingState
	sessionUsable func(string) bool
}

const relayJournalLimit = 16 << 20

func (c *RelayClient) initRelayJournal() error {
	c.socketMu.Lock()
	defer c.socketMu.Unlock()
	if c.journal != nil {
		return nil
	}
	b := c.Enrollment()
	j := &relayJournal{state: relayPendingState{DomainID: b.DomainID, DeviceID: b.DeviceID, RelayID: b.RelayID, Records: map[string]relayPendingRecord{}}}
	if c.enrollmentPath != "" {
		j.path = c.enrollmentPath + ".duplex.pending.v1"
		var err error
		j.key, err = c.provider.HKDF(c.device.Private.BytesForDevStore(), nil, []byte("iscp/relay-pending/v1\x00"+c.device.Identity.PublicKey.KID), 32)
		if err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(j.path), 0700); err != nil {
			return err
		}
		unlock, err := j.lockAndReload()
		if err != nil {
			return err
		}
		defer unlock()
		changed := false
		for key, r := range j.state.Records {
			if r.State == "pending" {
				r.State = "unknown"
				r.Uncertain = true
				j.state.Records[key] = r
				changed = true
			}
		}
		if changed {
			if err = j.persist(); err != nil {
				return err
			}
		}

	}
	j.sessionUsable = c.sessionUsable
	c.journal = j
	return nil
}

// Every checkpoint merges against the current disk snapshot under an OS lock;
// a stale helper cannot replace a newer helper's pending keys or outcomes.
func (j *relayJournal) lockAndReload() (func(), error) {
	if j.path == "" {
		return func() {}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	unlock, err := lockCredentialFile(ctx, j.path+".lock")
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return unlock, nil
	}
	if err != nil {
		unlock()
		return nil, err
	}
	if len(raw) > 2*relayJournalLimit {
		unlock()
		return nil, errors.New("Relay journal exceeds limit")
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(string(raw))
	if err != nil || len(sealed) < 12 {
		unlock()
		return nil, errors.New("invalid Relay journal")
	}
	plain, err := crypto.NewProvider().Open(j.key, sealed[:12], sealed[12:], []byte(j.path))
	if err != nil {
		unlock()
		return nil, errors.New("Relay journal authentication failed")
	}
	var state relayPendingState
	if strictUnmarshal(plain, &state) != nil || state.DomainID != j.state.DomainID || state.DeviceID != j.state.DeviceID || state.RelayID != j.state.RelayID || state.Records == nil {
		unlock()
		return nil, errors.New("Relay journal binding mismatch")
	}
	j.state = state
	return unlock, nil
}
func (j *relayJournal) persist() error {
	raw, err := json.Marshal(j.state)
	if err != nil {
		return err
	}
	if len(raw) > relayJournalLimit {
		return errors.New("Relay pending journal exhausted")
	}
	if j.path == "" {
		return nil
	}
	nonce := crypto.RandomBytes(12)
	ct, err := crypto.NewProvider().Seal(j.key, nonce, raw, []byte(j.path))
	if err != nil {
		return err
	}
	if err = writeSecretFile(j.path, []byte(crypto.Base64URL(append(nonce, ct...)))); err != nil {
		return err
	}
	return syncCredentialDirectory(filepath.Dir(j.path))
}
func (c *RelayClient) journalBeforeWrite(sub RelaySubmission, uncertain bool) error {
	if c.journal == nil {
		return errors.New("Relay journal not initialized")
	}
	j := c.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	unlock, err := j.lockAndReload()
	if err != nil {
		return err
	}
	defer unlock()
	old, exists := j.state.Records[sub.MessageID]
	if exists && (old.State == "accepted" || old.State == "expired") {
		return errors.New("original Relay admission already resolved")
	}
	if exists && (old.Submission.EnvelopeDigest != sub.EnvelopeDigest || old.Submission.NotAfter != sub.NotAfter || old.Submission.HistoryID != sub.HistoryID) {
		return errors.New("local Relay message key conflict")
	}
	// Keep unresolved evidence for the entire query window. Resolved observations
	// are bounded independently and cannot evict an unresolved original key.
	if !exists && len(j.state.Records) >= 4096 {
		var oldest string
		var deadline time.Time
		for key, r := range j.state.Records {
			if !r.Consumed || r.State == "unknown" || r.State == "pending" ||
				(r.Uncertain && time.Now().Before(duplex.Time(r.Submission.NotAfter).Add(duplex.QueryRecoverySeconds*time.Second))) {
				continue
			}
			t := duplex.Time(r.Submission.NotAfter)
			if oldest == "" || t.Before(deadline) {
				oldest, deadline = key, t
			}
		}
		if oldest == "" {
			return errors.New("Relay pending journal exhausted")
		}
		delete(j.state.Records, oldest)
	}
	order := old.Order
	if !exists {
		if j.state.NextOrder == ^uint64(0) {
			return errors.New("Relay journal order exhausted")
		}
		j.state.NextOrder++
		order = j.state.NextOrder
	}
	r := relayPendingRecord{Order: order, Submission: sub, State: "pending", Uncertain: old.Uncertain || uncertain}
	r.Submission.Envelope = append(json.RawMessage(nil), sub.Envelope...)
	j.state.Records[sub.MessageID] = r
	if err := j.persist(); err != nil {
		if exists {
			j.state.Records[sub.MessageID] = old
		} else {
			delete(j.state.Records, sub.MessageID)
		}
		return err
	}
	return nil
}
func (c *RelayClient) markRelayUnknown(sub RelaySubmission) {
	if c.journal == nil {
		return
	}
	j := c.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	unlock, err := j.lockAndReload()
	if err != nil {
		return
	}
	defer unlock()
	r, ok := j.state.Records[sub.MessageID]
	if !ok {
		return
	}
	if r.State != "accepted" && r.State != "expired" {
		r.State = "unknown"
	}
	r.Uncertain = true
	j.state.Records[sub.MessageID] = r
	_ = j.persist()
}
func (c *RelayClient) resolveRelaySubmission(sub RelaySubmission, state string, receipt *AcceptanceReceipt) {
	if c.journal == nil {
		return
	}
	j := c.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	unlock, err := j.lockAndReload()
	if err != nil {
		return
	}
	defer unlock()
	r, ok := j.state.Records[sub.MessageID]
	if !ok {
		return
	}
	if r.Submission.EnvelopeDigest != sub.EnvelopeDigest || r.Submission.HistoryID != sub.HistoryID {
		return
	}
	if (r.State == "accepted" || r.State == "expired") && (state == "unknown" || state == "absent" || state == "rejected") {
		return
	}
	if state == "unknown" {
		r.Uncertain = true
		r.State = "unknown"
	} else {
		r.State = state
		r.Receipt = receipt
		if state != "absent" {
			r.Submission.Envelope = nil
		}
	}
	j.state.Records[sub.MessageID] = r
	_ = j.persist()
}
func (c *RelayClient) SubmissionStatus(messageID string) (RelaySubmissionStatus, bool) {
	c.socketMu.Lock()
	j := c.journal
	c.socketMu.Unlock()
	if j == nil {
		return RelaySubmissionStatus{}, false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	unlock, err := j.lockAndReload()
	if err != nil {
		return RelaySubmissionStatus{}, false
	}
	defer unlock()
	r, ok := j.state.Records[messageID]
	if !ok {
		return RelaySubmissionStatus{}, false
	}
	v := r.Submission
	return RelaySubmissionStatus{MessageID: v.MessageID, EnvelopeDigest: v.EnvelopeDigest, HistoryID: v.HistoryID, NotAfter: v.NotAfter, SessionID: v.SessionID, State: r.State, Receipt: r.Receipt}, true
}

// SetSessionUsable attaches the E2E owner's current-session fence. A new process
// or replacement session may query an original key, but cannot replay its bytes.
func (c *RelayClient) SetSessionUsable(check func(string) bool) {
	c.socketMu.Lock()
	defer c.socketMu.Unlock()
	c.sessionUsable = check
	if c.journal != nil {
		c.journal.mu.Lock()
		c.journal.sessionUsable = check
		c.journal.mu.Unlock()
	}
}
func (s *relaySocket) recoverPending() {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		s.recoverPendingOnce()
		select {
		case <-s.ctx.Done():
			return
		case <-timer.C:
		}
	}
}
func (s *relaySocket) recoverPendingOnce() {
	j := s.owner.journal
	j.mu.Lock()
	unlock, err := j.lockAndReload()
	if err != nil {
		j.mu.Unlock()
		return
	}
	var pending []relayPendingRecord
	for _, r := range j.state.Records {
		if r.State != "accepted" && r.Submission.HistoryID == s.ready.HistoryID && time.Now().Before(duplex.Time(r.Submission.NotAfter).Add(duplex.QueryRecoverySeconds*time.Second)) {
			pending = append(pending, r)
		}
	}
	check := j.sessionUsable
	unlock()
	j.mu.Unlock()
	sort.Slice(pending, func(i, k int) bool { return pending[i].Order < pending[k].Order })
	blocked := map[string]bool{}
	for _, record := range pending {
		sub := record.Submission
		if blocked[sub.SessionID] {
			continue
		}
		// An unadmitted predecessor is part of the same encrypted sequence. Never
		// send a later original ciphertext until this predecessor is accepted.
		blocked[sub.SessionID] = true
		if record.State != "unknown" && record.State != "absent" {
			continue
		}
		if s.ctx.Err() != nil {
			return
		}
		future, err := s.enqueue(sub, true)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
		receipt, waitErr := future.Wait(ctx)
		err = waitErr
		cancel()
		if err == nil && receipt != nil && time.Now().Before(duplex.Time(receipt.ExpiresAt)) {
			blocked[sub.SessionID] = false
			continue
		}
		var absent *AbsentSubmission
		if !errors.As(err, &absent) || record.Order == 0 || check == nil || !time.Now().Before(duplex.Time(sub.NotAfter)) || !check(sub.SessionID) {
			continue
		}
		// Resubmission is the same immutable tuple. The writer rechecks the session
		// fence immediately before committing this attempt to the socket.
		retry, err := s.enqueueWithSession(sub, false, check)
		if err != nil {
			continue
		}
		ctx, cancel = context.WithTimeout(s.ctx, 5*time.Second)
		receipt, err = retry.Wait(ctx)
		cancel()
		if err == nil && receipt != nil {
			blocked[sub.SessionID] = false
		}
	}
}

// acknowledgeRelayResult runs only after Wait selected a completed result.
// Before this acknowledgement, even a known accepted record cannot be evicted:
// a canceled waiter may still expose its original tuple as Unknown.
func (c *RelayClient) acknowledgeRelayResult(sub RelaySubmission, uncertain bool) {
	if c.journal == nil {
		return
	}
	j := c.journal
	j.mu.Lock()
	defer j.mu.Unlock()
	unlock, err := j.lockAndReload()
	if err != nil {
		return
	}
	defer unlock()
	r, ok := j.state.Records[sub.MessageID]
	if !ok || r.Submission.EnvelopeDigest != sub.EnvelopeDigest || r.State == "unknown" || r.State == "pending" {
		return
	}
	r.Uncertain = r.Uncertain || uncertain
	if !r.Uncertain {
		delete(j.state.Records, sub.MessageID)
	} else {
		r.Consumed = true
		j.state.Records[sub.MessageID] = r
	}
	_ = j.persist()
}
