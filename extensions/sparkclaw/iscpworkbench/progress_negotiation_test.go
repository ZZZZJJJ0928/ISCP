package iscpworkbench

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"
)

func TestProgressNegotiationExactNewAndLegacyMatrices(t *testing.T) {
	for _, mode := range []string{"local-test", "node-managed"} {
		for _, progress := range []bool{false, true} {
			ops := withoutStream(OperationsV2ForMode(mode))
			if !progress {
				ops = withoutProgress(ops)
			}
			caps := TransportCapabilities{SchemaVersion: 2, Profile: ProfileV2, SessionID: "session", Revision: "2", AuthorizationRevision: 1, ExpiresAt: time.Now().Add(time.Minute), Operations: ops, Limits: TransportLimits{MaxRequestBytes, MaxResponseBytes, MaxBodyBytes, 0, 8192, 2}}
			if err := validateNegotiation(caps, "session", mode); err != nil {
				t.Fatalf("%s progress=%v: %v", mode, progress, err)
			}
			bad := caps
			bad.Operations = append(slices.Clone(ops), "unregistered")
			if validateNegotiation(bad, "session", mode) == nil {
				t.Fatal("unknown operation accepted")
			}
			bad = caps
			bad.Operations = slices.Clone(ops[1:])
			if validateNegotiation(bad, "session", mode) == nil {
				t.Fatal("missing mandatory operation accepted")
			}
			if !progress {
				bad = caps
				bad.QualifiedOperations = []string{OperationExecutionProgress}
				if validateNegotiation(bad, "session", mode) == nil {
					t.Fatal("unadvertised qualification accepted")
				}
			}
		}
	}
}

func TestProgressNegotiationPreservesOldUnboundedAndBoundedOffers(t *testing.T) {
	for _, generation := range []string{"progress", "unbounded", "bounded"} {
		t.Run(generation, func(t *testing.T) {
			calls := 0
			seen := map[string]bool{}
			response, err := requestRPCNegotiation(t.Context(), func(ctx context.Context, r Request) (Response, error) {
				calls++
				if r.Operation != OperationIdentity || seen[r.ID] {
					t.Fatal("replayed business operation or RPC ID")
				}
				seen[r.ID] = true
				var offer negotiationOffer
				if json.Unmarshal(r.Body, &offer) != nil {
					t.Fatal("bad offer")
				}
				if generation != "progress" && offer.Negotiation.ExecutionProgress {
					return Response{Status: 400}, nil
				}
				if generation == "bounded" && offer.Negotiation.UnboundedRPC {
					return Response{Status: 400}, nil
				}
				if generation == "unbounded" && !offer.Negotiation.UnboundedRPC {
					t.Fatal("fallback lost old unbounded capability")
				}
				if generation == "progress" && !offer.Negotiation.ExecutionProgress {
					t.Fatal("new feature not offered")
				}
				return Response{Status: 200}, nil
			}, []string{ProfileV2, Profile})
			want := map[string]int{"progress": 1, "unbounded": 2, "bounded": 3}[generation]
			if err != nil || response.Status != 200 || calls != want {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestProgressNegotiationOnlyAdvertisesRequestedExtension(t *testing.T) {
	for _, offer := range []struct{ progress, unbounded bool }{{true, true}, {false, true}, {false, false}} {
		t.Run(map[bool]string{true: "progress", false: "legacy"}[offer.progress]+map[bool]string{true: "unbounded", false: "bounded"}[offer.unbounded], func(t *testing.T) {
			i, _, _ := v2Endpoints(t, true)
			var request negotiationOffer
			request.Negotiation.Profiles = []string{ProfileV2, Profile}
			request.Negotiation.ExecutionProgress = offer.progress
			request.Negotiation.UnboundedRPC = offer.unbounded
			body, _ := json.Marshal(request)
			response, err := i.Call(t.Context(), Request{Type: RequestType, Profile: Profile, ID: newUUID(), Operation: OperationIdentity, Body: body})
			var reply negotiationReply
			if err != nil || json.Unmarshal(response.Body, &reply) != nil || reply.Negotiation == nil {
				t.Fatal("negotiation failed", err)
			}
			caps := reply.Negotiation
			if slices.Contains(caps.Operations, OperationExecutionProgress) != offer.progress {
				t.Fatal("extension advertised without opt-in")
			}
			if offer.unbounded != (caps.Limits.Concurrent == 0) {
				t.Fatal("changed independent concurrency contract")
			}
			if !offer.progress && !slices.Equal(caps.Operations, withoutStream(withoutProgress(OperationsV2()))) {
				t.Fatal("original exact list changed")
			}
		})
	}
}
