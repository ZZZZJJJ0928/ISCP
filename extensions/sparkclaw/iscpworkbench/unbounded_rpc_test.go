package iscpworkbench

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNewNegotiationFallsBackToExactOldOfferWithoutReplayingFailures(t *testing.T) {
	var ids []string
	response, err := requestRPCNegotiation(context.Background(), func(ctx context.Context, r Request) (Response, error) {
		ids = append(ids, r.ID)
		if len(ids) <= 2 {
			if !bytes.Contains(r.Body, []byte(`"unbounded_rpc":true`)) {
				t.Fatal("new RPC policy was not offered")
			}
			return Response{Status: 400}, nil
		}
		const original = `{"transport_negotiation":{"profiles":["sparkclaw.workbench.transport.v2","sparkclaw.workbench.transport.v1"]}}`
		if string(r.Body) != original {
			t.Fatalf("old offer changed: %s", r.Body)
		}
		return Response{Status: 200, Body: json.RawMessage(`{"legacy":true}`)}, nil
	}, []string{ProfileV2, Profile})
	if err != nil || response.Status != 200 || len(ids) != 3 || ids[0] == ids[1] || ids[1] == ids[2] {
		t.Fatalf("compatibility read failed: %+v %v", response, err)
	}
	for _, status := range []int{401, 403, 429, 503} {
		calls := 0
		_, _ = requestRPCNegotiation(context.Background(), func(context.Context, Request) (Response, error) { calls++; return Response{Status: status}, nil }, []string{ProfileV2, Profile})
		if calls != 1 {
			t.Fatalf("remote failure replayed: %d", status)
		}
	}
	calls := 0
	_, err = requestRPCNegotiation(context.Background(), func(context.Context, Request) (Response, error) {
		calls++
		return Response{}, errors.New("sent response lost")
	}, []string{ProfileV2, Profile})
	if err == nil || calls != 1 {
		t.Fatal("ambiguous negotiation replayed")
	}
}

func TestUnboundedRPCNegotiationAndConcurrentShutdown(t *testing.T) {
	for _, profile := range []string{Profile, ProfileV2} {
		t.Run(profile, func(t *testing.T) {
			const count = 80
			entered := make(chan struct{}, count)
			i, r, _ := profileEndpoints(t, profile == ProfileV2, profile == ProfileV2, func(ctx context.Context, request Request) Response {
				entered <- struct{}{}
				<-ctx.Done()
				return Response{Status: 500}
			})
			caps, ok := i.Negotiated()
			if !ok || caps.Profile != profile || caps.Limits.Concurrent != 0 {
				t.Fatalf("RPC policy not negotiated: %+v", caps)
			}
			results := make(chan error, count)
			operation := OperationIdentity
			if profile == ProfileV2 {
				operation = OperationCapabilitiesGet
			}
			for j := 0; j < count; j++ {
				go func() {
					_, err := i.Call(context.Background(), Request{Type: RequestType, Profile: profile, ID: newUUID(), Operation: operation, Body: json.RawMessage(`{}`)})
					results <- err
				}()
			}
			for j := 0; j < count; j++ {
				select {
				case <-entered:
				case err := <-results:
					t.Fatalf("call was rejected before admission: %v", err)
				case <-time.After(3 * time.Second):
					t.Fatal("parallel request blocked by quota")
				}
			}
			_ = r.Close()
			_ = i.Close()
			for j := 0; j < count; j++ {
				select {
				case err := <-results:
					if err == nil {
						t.Fatal("closed pending call succeeded")
					}
				case <-time.After(3 * time.Second):
					t.Fatal("pending call leaked")
				}
			}
		})
	}
}

func TestOldNegotiationOfferRetainsLegacyContract(t *testing.T) {
	i, r, _ := v2Endpoints(t, true)
	body := json.RawMessage(`{"transport_negotiation":{"profiles":["sparkclaw.workbench.transport.v2","sparkclaw.workbench.transport.v1"]}}`)
	response, err := i.Call(context.Background(), Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	var reply negotiationReply
	if json.Unmarshal(response.Body, &reply) != nil || reply.Negotiation == nil || reply.Negotiation.Limits.Concurrent != MaxConcurrent {
		t.Fatalf("old helper contract changed: %s", response.Body)
	}
	caps, ok := r.Negotiated()
	if !ok || caps.Limits.Concurrent != MaxConcurrent {
		t.Fatal("old client policy was not retained")
	}
}

func TestUnboundedRPCResultsAreNotDuplicated(t *testing.T) {
	const count = 40
	var mu sync.Mutex
	seen := map[string]int{}
	i, _, _ := profileEndpoints(t, true, true, func(ctx context.Context, r Request) Response {
		mu.Lock()
		seen[r.ID]++
		mu.Unlock()
		return Response{Status: 200, Body: r.Body}
	})
	var wg sync.WaitGroup
	for j := 0; j < count; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := json.RawMessage(`{"original":true}`)
			r, err := i.Call(context.Background(), Request{Type: RequestType, Profile: ProfileV2, ID: newUUID(), Operation: OperationCapabilitiesGet, Body: body})
			if err != nil || r.Status != 200 || string(r.Body) != string(body) {
				t.Errorf("original result changed: %+v %v", r, err)
			}
		}()
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != count {
		t.Fatalf("original requests missing: %d", len(seen))
	}
	for _, n := range seen {
		if n != 1 {
			t.Fatal("request replayed")
		}
	}
}
