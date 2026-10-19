package iscpcontrol

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type routedChallenge struct {
	handler http.Handler
	expires time.Time
}
type Router struct {
	targets    map[string]http.Handler
	mu         sync.Mutex
	challenges map[string]routedChallenge
}

// NewRouter binds a fresh upstream challenge to its configured audience. Lookup
// and ACK need no unsigned routing header; restart invalidates the mapping.
func NewRouter(targets map[string]http.Handler) (*Router, error) {
	if len(targets) == 0 || len(targets) > 32 {
		return nil, ErrInvalid
	}
	copyTargets := map[string]http.Handler{}
	for id, h := range targets {
		if id == "" || h == nil {
			return nil, ErrInvalid
		}
		copyTargets[id] = h
	}
	return &Router{targets: copyTargets, challenges: map[string]routedChallenge{}}, nil
}
func (r *Router) ServeHTTP(w http.ResponseWriter, q *http.Request) {
	if q.Method != "POST" || q.URL.RawQuery != "" || q.URL.RawPath != "" {
		http.NotFound(w, q)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(q.Body, MaxBody+1))
	if err != nil || len(raw) > MaxBody {
		http.Error(w, "invalid control request", 400)
		return
	}
	q.Body = io.NopCloser(bytes.NewReader(raw))
	if q.URL.Path == ChallengePath {
		var request ChallengeRequest
		if Decode(raw, "challenge_request", &request) != nil {
			http.Error(w, "invalid control request", 400)
			return
		}
		target := r.targets[request.Audience]
		if target == nil {
			http.Error(w, "control unavailable", 503)
			return
		}
		captured := &challengeResponse{header: make(http.Header)}
		target.ServeHTTP(captured, q)
		if captured.status == 200 || captured.status == 0 {
			var challenge Challenge
			if Decode(captured.body.Bytes(), "challenge", &challenge) != nil || challenge.Audience != request.Audience || challenge.Purpose != request.Purpose {
				http.Error(w, "control unavailable", 503)
				return
			}
			r.mu.Lock()
			now := time.Now()
			for id, entry := range r.challenges {
				if !now.Before(entry.expires) {
					delete(r.challenges, id)
				}
			}
			_, exists := r.challenges[challenge.ChallengeID]
			if exists || len(r.challenges) >= 4096 {
				r.mu.Unlock()
				http.Error(w, "control unavailable", 503)
				return
			}
			r.challenges[challenge.ChallengeID] = routedChallenge{target, challenge.ExpiresAt}
			r.mu.Unlock()
		}
		for key, values := range captured.header {
			w.Header()[key] = values
		}
		status := captured.status
		if status == 0 {
			status = 200
		}
		w.WriteHeader(status)
		_, _ = w.Write(captured.body.Bytes())
		return
	}
	action := strings.TrimPrefix(q.URL.Path, OperationPath)
	if action == q.URL.Path {
		http.NotFound(w, q)
		return
	}
	var request Request
	if Decode(raw, "request_"+action, &request) != nil {
		http.Error(w, "invalid control request", 400)
		return
	}
	r.mu.Lock()
	route, ok := r.challenges[request.Authentication.ChallengeID]
	delete(r.challenges, request.Authentication.ChallengeID)
	r.mu.Unlock()
	if !ok || !time.Now().Before(route.expires) {
		http.Error(w, "control challenge unavailable", 503)
		return
	}
	// Direct forwarding keeps the origin's local disclosure write within its
	// authority guard. No operation response is buffered by this router.
	route.handler.ServeHTTP(w, q)
}

type challengeResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *challengeResponse) Header() http.Header    { return w.header }
func (w *challengeResponse) WriteHeader(status int) { w.status = status }
func (w *challengeResponse) Write(raw []byte) (int, error) {
	if w.body.Len()+len(raw) > MaxBody {
		return 0, ErrInvalid
	}
	return w.body.Write(raw)
}
func (w *challengeResponse) Flush() {}
