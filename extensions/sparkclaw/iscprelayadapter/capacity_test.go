package iscprelayadapter

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdapterKeepsDeadlineWithoutFixedRateOrInflightQuota(t *testing.T) {
	a := &Adapter{}
	h := a.bounded(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > 20*time.Second {
			t.Error("adapter lost bounded request context")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	for i := 0; i < 650; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
		if w.Code != http.StatusNoContent {
			t.Fatalf("artificial quota at request %d: %d", i, w.Code)
		}
	}
	const count = 80
	entered := make(chan struct{}, count)
	release := make(chan struct{})
	defer close(release)
	finished := make(chan int, count)
	h = a.bounded(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		select {
		case <-release:
		case <-r.Context().Done():
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	for i := 0; i < count; i++ {
		go func() {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/", nil))
			finished <- w.Code
		}()
	}
	for i := 0; i < count; i++ {
		select {
		case <-entered:
		case status := <-finished:
			t.Fatalf("adapter rejected a cancellable operation: %d", status)
		case <-time.After(3 * time.Second):
			t.Fatal("adapter admission stalled")
		}
	}
}
