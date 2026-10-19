package iscpbridge

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRelayJournalPersistsOriginalUnknownAndHidesCiphertext(t *testing.T) {
	p := crypto.NewProvider()
	id, _ := identity.NewDevice(p, "domain", "sender", time.Now())
	path := filepath.Join(t.TempDir(), "enrollment.json")
	makeClient := func() *RelayClient {
		return &RelayClient{provider: p, device: id, enrollmentPath: path, enrollment: EnrollmentBundle{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
	}
	c := makeClient()
	if e := c.initRelayJournal(); e != nil {
		t.Fatal(e)
	}
	sub := RelaySubmission{MessageID: "original", EnvelopeDigest: duplex.RandomID(), HistoryID: duplex.RandomID(), NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "original-session", Envelope: json.RawMessage(`{"ciphertext":"private-wire-payload"}`)}
	if e := c.journalBeforeWrite(sub, false); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(path + ".duplex.pending.v1")
	if e != nil || strings.Contains(string(raw), "private-wire-payload") {
		t.Fatal("journal leaked plaintext", e)
	}
	restarted := makeClient()
	if e = restarted.initRelayJournal(); e != nil {
		t.Fatal(e)
	}
	state, ok := restarted.SubmissionStatus("original")
	if !ok || state.State != "unknown" || state.SessionID != sub.SessionID || state.NotAfter != sub.NotAfter || state.HistoryID != sub.HistoryID {
		t.Fatal(state)
	}
	serialized, _ := json.Marshal(state)
	if strings.Contains(string(serialized), "ciphertext") {
		t.Fatal("IPC metadata includes ciphertext")
	}
	conflict := sub
	conflict.NotAfter = duplex.Timestamp(time.Now().Add(2 * time.Minute))
	if restarted.journalBeforeWrite(conflict, false) == nil {
		t.Fatal("same key changed deadline")
	}
	restarted.resolveRelaySubmission(sub, "absent", nil)
	state, ok = restarted.SubmissionStatus(sub.MessageID)
	if !ok || state.State != "absent" {
		t.Fatal(state)
	}
}
func TestReceiptCancellationRetainsTypedOriginalLineage(t *testing.T) {
	sub := RelaySubmission{MessageID: "id", EnvelopeDigest: duplex.RandomID(), HistoryID: duplex.RandomID(), NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "session", Envelope: json.RawMessage(`{}`)}
	f := &ReceiptFuture{Submission: sub, done: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, e := f.Wait(ctx)
	var u *UnknownAcceptance
	if !errors.As(e, &u) || u.Submission.SessionID != "session" || !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestRelayJournalStaleProcessCannotLoseNewerKeys(t *testing.T) {
	p := crypto.NewProvider()
	id, _ := identity.NewDevice(p, "domain", "sender", time.Now())
	path := filepath.Join(t.TempDir(), "enrollment.json")
	makeClient := func() *RelayClient {
		c := &RelayClient{provider: p, device: id, enrollmentPath: path, enrollment: EnrollmentBundle{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
		if err := c.initRelayJournal(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	first, second := makeClient(), makeClient()
	a := RelaySubmission{MessageID: "a", EnvelopeDigest: duplex.RandomID(), HistoryID: duplex.RandomID(), NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "s", Envelope: json.RawMessage(`{}`)}
	b := a
	b.MessageID = "b"
	if err := first.journalBeforeWrite(a, true); err != nil {
		t.Fatal(err)
	}
	if err := second.journalBeforeWrite(b, true); err != nil {
		t.Fatal(err)
	}
	first.resolveRelaySubmission(a, "accepted", &AcceptanceReceipt{MessageID: "a"})
	second.markRelayUnknown(a)
	restored := makeClient()
	status, ok := restored.SubmissionStatus("a")
	if !ok || status.State != "accepted" {
		t.Fatal(status)
	}
	if _, ok = restored.SubmissionStatus("b"); !ok {
		t.Fatal("stale writer lost another process key")
	}
}

func TestRelayJournalCancellationBetweenCheckpointAndFutureCompletion(t *testing.T) {
	p := crypto.NewProvider()
	id, _ := identity.NewDevice(p, "domain", "sender", time.Now())
	path := filepath.Join(t.TempDir(), "enrollment.json")
	makeClient := func() *RelayClient {
		c := &RelayClient{provider: p, device: id, enrollmentPath: path, enrollment: EnrollmentBundle{DomainID: "domain", DeviceID: "sender", RelayID: "relay"}}
		if err := c.initRelayJournal(); err != nil {
			t.Fatal(err)
		}
		return c
	}
	c := makeClient()
	sub := RelaySubmission{MessageID: "accepted-before-finish", EnvelopeDigest: duplex.RandomID(), HistoryID: duplex.RandomID(), NotAfter: duplex.Timestamp(time.Now().Add(time.Minute)), SessionID: "original-session", Envelope: json.RawMessage(`{"ciphertext":"original"}`)}
	if err := c.journalBeforeWrite(sub, false); err != nil {
		t.Fatal(err)
	}
	receipt := &AcceptanceReceipt{MessageID: sub.MessageID}
	f := &ReceiptFuture{owner: c, Submission: sub, done: make(chan struct{})}
	// Pause the reader exactly after the terminal checkpoint, before finish.
	c.resolveRelaySubmission(sub, "accepted", receipt)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := f.Wait(ctx)
	var unknown *UnknownAcceptance
	if !errors.As(err, &unknown) {
		t.Fatalf("expected uncertain waiter, got %v", err)
	}
	restored := makeClient()
	status, ok := restored.SubmissionStatus(sub.MessageID)
	if !ok || status.State != "accepted" || status.HistoryID != sub.HistoryID || status.NotAfter != sub.NotAfter || status.SessionID != sub.SessionID {
		t.Fatal("lost original terminal checkpoint", status)
	}
	f.finish(receipt, nil)
	// A simultaneous canceled context and completed future returns known truth.
	for i := 0; i < 100; i++ {
		if got, err := f.Wait(ctx); err != nil || got != receipt {
			t.Fatal("completed result became unknown", err)
		}
	}
}
