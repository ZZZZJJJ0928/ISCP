package iscpcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

// Backend rechecks current authority and performs admission/CAS/disposition in
// its own durable transaction. Actor comes only from verified fresh proof.
// A supplied credential must be verified by Execute; an invalid token is never
// converted to an absent token. Empty credentials use standing authorization.
type Backend interface {
	ResolveActor(context.Context, string, string) (identity.DeviceIdentity, error)
	Execute(context.Context, Request, identity.DeviceIdentity, string) (Outcome, error)
}
type Failure struct {
	Code     string
	Revision *Counter
}

func (e *Failure) Error() string { return "control: " + e.Code }

type challengeEntry struct {
	challenge      Challenge
	domain, device string
}
type Handler struct {
	Audience   string
	Signer     identity.Device
	Backend    Backend
	Now        func() time.Time
	mu         sync.Mutex
	challenges map[string]challengeEntry
}

func NewHandler(audience string, signer identity.Device, backend Backend) *Handler {
	return &Handler{Audience: audience, Signer: signer, Backend: backend, Now: time.Now, challenges: make(map[string]challengeEntry)}
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.RawPath != "" {
		h.failure(w, "invalid_request", nil, nil)
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 {
		h.failure(w, "invalid_request", nil, nil)
		return
	}
	if r.URL.Path == ChallengePath {
		h.challenge(w, r, raw)
		return
	}
	action := strings.TrimPrefix(r.URL.Path, OperationPath)
	if action == r.URL.Path || !(action == "submit" || action == "recover" || action == "lookup" || action == "ack") {
		h.failure(w, "protocol_incompatible", nil, nil)
		return
	}
	var req Request
	if Decode(raw, "request_"+action, &req) != nil || req.Action != action || req.Validate() != nil {
		h.failure(w, "invalid_request", nil, nil)
		return
	}
	// Removing before verification makes every challenge a one-use authentication
	// capability. Process restart forgets all challenges and therefore fails closed.
	h.mu.Lock()
	entry, ok := h.challenges[req.Authentication.ChallengeID]
	delete(h.challenges, req.Authentication.ChallengeID)
	h.mu.Unlock()
	now := h.Now().UTC()
	if !ok || !now.Before(entry.challenge.ExpiresAt) {
		h.failure(w, "challenge_expired", &req, nil)
		return
	}
	if entry.domain != req.Key.DomainID || entry.device != req.Key.DeviceID {
		h.failure(w, "authentication_failed", &req, nil)
		return
	}
	actor, e := h.Backend.ResolveActor(r.Context(), req.Key.DomainID, req.Key.DeviceID)
	if e != nil {
		h.failure(w, "authentication_failed", &req, nil)
		return
	}
	token := ""
	if v := r.Header.Get("Authorization"); v != "" {
		if !strings.HasPrefix(v, "Bearer ") || len(v) > 4103 || strings.ContainsAny(v, "\r\n") {
			h.failure(w, "authentication_failed", &req, nil)
			return
		}
		token = strings.TrimPrefix(v, "Bearer ")
		if token == "" {
			h.failure(w, "authentication_failed", &req, nil)
			return
		}
	}
	if VerifyAuthentication(req, entry.challenge, actor, r.Method, r.URL.Path, h.Audience, token, now) != nil {
		h.failure(w, "authentication_failed", &req, nil)
		return
	}
	outcome, e := h.Backend.Execute(r.Context(), req, actor, token)
	if e != nil {
		var f *Failure
		if errors.As(e, &f) {
			h.failure(w, f.Code, &req, f.Revision)
		} else {
			h.failure(w, "authorization_unavailable", &req, nil)
		}
		return
	}
	switch {
	case outcome.Result != nil:
		if outcome.Result.Payload.Key != req.Key || outcome.Result.Payload.SemanticDigest != req.SemanticDigest {
			h.failure(w, "invalid_request", &req, nil)
			return
		}
		sealed, e := Seal(*outcome.Result, req)
		if e != nil {
			h.failure(w, "invalid_request", &req, nil)
			return
		}
		h.write(w, sealed)
	case outcome.Disposition != nil:
		h.write(w, outcome.Disposition)
	case outcome.Status != nil:
		h.write(w, outcome.Status)
	default:
		h.failure(w, "authorization_unavailable", &req, nil)
	}
}
func (h *Handler) challenge(w http.ResponseWriter, r *http.Request, raw []byte) {
	var q ChallengeRequest
	if Decode(raw, "challenge_request", &q) != nil || q.Audience != h.Audience {
		h.failure(w, "invalid_request", nil, nil)
		return
	}
	if _, e := h.Backend.ResolveActor(r.Context(), q.DomainID, q.DeviceID); e != nil {
		h.failure(w, "authentication_failed", nil, nil)
		return
	}
	now := h.Now().UTC().Truncate(time.Second)
	ch := Challenge{Type: "iscp.control.challenge.v2", Protocol: Protocol, Audience: h.Audience, ChallengeID: RandomID(), Challenge: RandomID(), Purpose: q.Purpose, ServerTime: now, ExpiresAt: now.Add(10 * time.Second)}
	h.mu.Lock()
	for k, v := range h.challenges {
		if !now.Before(v.challenge.ExpiresAt) {
			delete(h.challenges, k)
		}
	}
	if len(h.challenges) >= 4096 {
		h.mu.Unlock()
		h.failure(w, "resource_exhausted", nil, nil)
		return
	}
	h.challenges[ch.ChallengeID] = challengeEntry{ch, q.DomainID, q.DeviceID}
	h.mu.Unlock()
	h.write(w, ch)
}
func (h *Handler) failure(w http.ResponseWriter, code string, r *Request, revision *Counter) {
	e, err := NewError(code, h.Audience, r, revision, h.Now(), h.Signer)
	if err != nil {
		http.Error(w, "control unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusBadRequest)
	h.write(w, e)
}
func (h *Handler) write(w http.ResponseWriter, v any) { _ = json.NewEncoder(w).Encode(v) }

// Client's HTTP transport must already pin the original HTTPS authority. It never
// follows redirects or falls back to WSS. Fresh wraps/proofs are per attempt;
// callers persist Intent, Result and Disposition, never this transient request.
type Client struct {
	Origin, Audience string
	Device           identity.Device
	Signer           identity.DeviceIdentity
	HTTP             *http.Client
	Now              func() time.Time
}

func NewClient(origin, audience string, device identity.Device, signer identity.DeviceIdentity, httpClient *http.Client) (*Client, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !(u.Path == "" || u.Path == "/") || httpClient == nil {
		return nil, ErrInvalid
	}
	copyClient := *httpClient
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrAuthentication }
	return &Client{strings.TrimRight(origin, "/"), audience, device, signer, &copyClient, time.Now}, nil
}
func (c *Client) Attempt(ctx context.Context, r Request, credential string) (Outcome, error) {
	var zero Outcome
	q := ChallengeRequest{Type: "iscp.control.challenge.request.v2", Protocol: Protocol, Audience: c.Audience, DomainID: c.Device.Identity.DomainID, DeviceID: c.Device.Identity.DeviceID, Purpose: r.Action}
	raw, e := c.post(ctx, ChallengePath, q, "")
	if e != nil {
		return zero, e
	}
	if e = c.wireError(raw, nil); e != nil {
		return zero, e
	}
	var ch Challenge
	if Decode(raw, "challenge", &ch) != nil || ch.Audience != c.Audience || ch.Purpose != r.Action || ch.ExpiresAt.Sub(ch.ServerTime) != 10*time.Second {
		return zero, ErrAuthentication
	}
	r.Type = "iscp.operation.request.v2"
	r.Protocol = Protocol
	r.AttemptID = "attempt-" + RandomID()
	var private []byte
	if r.Action != "ack" {
		var d Delivery
		d, private, e = NewDelivery()
		if e != nil {
			return zero, e
		}
		r.Delivery = &d
	}
	if e = Authenticate(&r, ch, c.Device, credential, c.Now()); e != nil {
		return zero, e
	}
	raw, e = c.post(ctx, OperationPath+r.Action, r, credential)
	if e != nil {
		return zero, e
	}
	if e = c.wireError(raw, &r); e != nil {
		return zero, e
	}
	var header struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return zero, ErrInvalid
	}
	switch header.Type {
	case "iscp.operation.sealed-result.v2":
		var wire SealedResult
		if e = Decode(raw, "sealed_result", &wire); e != nil {
			return zero, e
		}
		result, e := Open(wire, r, private, c.Signer)
		if e != nil {
			return zero, e
		}
		return Outcome{Result: &result}, nil
	case "iscp.operation.status.v2":
		var s Status
		if e = Decode(raw, "status", &s); e != nil {
			return zero, e
		}
		if s.AttemptID != r.AttemptID || s.Key != r.Key || s.SemanticDigest != r.SemanticDigest {
			return zero, ErrAuthentication
		}
		if e = Verify(s.Type, s, s.Signature, c.Signer); e != nil {
			return zero, e
		}
		return Outcome{Status: &s}, nil
	case "iscp.operation.disposition.v2":
		var d Disposition
		if e = Decode(raw, "disposition_receipt", &d); e != nil {
			return zero, e
		}
		if r.Ack == nil || d.Key != r.Key || d.SemanticDigest != r.SemanticDigest || !equal(*r.Ack, d.Ack) {
			return zero, ErrAuthentication
		}
		if e = d.Verify(c.Signer); e != nil {
			return zero, e
		}
		return Outcome{Disposition: &d}, nil
	default:
		return zero, ErrInvalid
	}
}
func (c *Client) wireError(raw []byte, r *Request) error {
	var header struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &header) != nil {
		return ErrInvalid
	}
	if header.Type != "iscp.operation.error.v2" {
		return nil
	}
	var e Error
	if Decode(raw, "error", &e) != nil || e.Audience != c.Audience || Verify(e.Type, e, e.Signature, c.Signer) != nil {
		return ErrAuthentication
	}
	if r != nil && (e.AttemptID == nil || *e.AttemptID != r.AttemptID || e.Key == nil || *e.Key != r.Key) {
		return ErrAuthentication
	}
	return &e
}
func (c *Client) post(ctx context.Context, path string, v any, token string) ([]byte, error) {
	body, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	r, e := http.NewRequestWithContext(ctx, "POST", c.Origin+path, bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	response, e := c.HTTP.Do(r)
	if e != nil {
		return nil, errors.Join(ErrUnknown, e)
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 {
		return nil, ErrUnknown
	}
	if response.StatusCode != http.StatusOK {
		var kind struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(raw, &kind) != nil || kind.Type != "iscp.operation.error.v2" {
			return nil, ErrUnknown
		}
	}
	return raw, nil
}
func equal(a, b any) bool {
	aa, e := canonicalBytes(a)
	bb, f := canonicalBytes(b)
	return e == nil && f == nil && bytes.Equal(aa, bb)
}
