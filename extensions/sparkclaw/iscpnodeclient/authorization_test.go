package iscpnodeclient

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/trust"
)

type authorityGate struct {
	base         http.RoundTripper
	mu           sync.Mutex
	requests     []n.LifecycleRequest
	first        chan struct{}
	release      chan struct{}
	canceled     chan struct{}
	closeRelease sync.Once
	ignoreCancel bool
	status       int
}

func gateAuthority(t *testing.T, cl *Client) *authorityGate {
	t.Helper()
	g := &authorityGate{base: cl.http.Transport, first: make(chan struct{}), release: make(chan struct{}), canceled: make(chan struct{})}
	cl.http.Transport = g
	t.Cleanup(g.unblock)
	return g
}
func (g *authorityGate) unblock() { g.closeRelease.Do(func() { close(g.release) }) }
func (g *authorityGate) RoundTrip(req *http.Request) (*http.Response, error) {
	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	req.Body = io.NopCloser(bytes.NewReader(raw))
	var x n.Exchange
	var r n.LifecycleRequest
	check := n.StrictDecode(raw, &x) == nil && (x.Step == "renew" || x.Step == "recover") && n.StrictDecode(x.Frame, &r) == nil
	index := 0
	if check {
		g.mu.Lock()
		g.requests = append(g.requests, r)
		if r.Kind == "check" {
			for _, prior := range g.requests {
				if prior.Kind == "check" {
					index++
				}
			}
		}
		g.mu.Unlock()
	}
	var response *http.Response
	if index == 1 && g.status != 0 {
		response = &http.Response{StatusCode: g.status, Header: make(http.Header), Body: io.NopCloser(bytes.NewBufferString("{}")), Request: req}
	} else {
		response, err = g.base.RoundTrip(req)
	}
	if index != 1 || err != nil {
		return response, err
	}
	close(g.first) // The authority response is already available, but not delivered.
	if g.ignoreCancel {
		<-g.release // Exercise a stale active reply arriving after a mutation fence.
	} else {
		select {
		case <-g.release:
		case <-req.Context().Done():
			close(g.canceled)
			response.Body.Close()
			return nil, req.Context().Err()
		}
	}
	return response, nil
}
func (g *authorityGate) checks() []n.LifecycleRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []n.LifecycleRequest
	for _, r := range g.requests {
		if r.Kind == "check" {
			out = append(out, r)
		}
	}
	return out
}
func (g *authorityGate) wait(t *testing.T) {
	t.Helper()
	select {
	case <-g.first:
	case <-time.After(3 * time.Second):
		t.Fatal("fresh authority roundtrip did not start")
	}
}

type policyAnswer struct {
	policy iscpauth.Policy
	err    error
}

func checkAsync(cl *Client, ctx context.Context) <-chan policyAnswer {
	done := make(chan policyAnswer, 1)
	go func() { p, err := cl.AuthorizationPolicy(ctx); done <- policyAnswer{p, err} }()
	return done
}
func receivePolicy(t *testing.T, done <-chan policyAnswer) policyAnswer {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("authority waiter did not finish")
		return policyAnswer{}
	}
}
func waitAuthority(t *testing.T, cl *Client, predicate func(*Client) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cl.authorityMu.Lock()
		ok := predicate(cl)
		cl.authorityMu.Unlock()
		if ok {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("authority coordination condition was not reached")
}
func authorityFixture(t *testing.T, backend string) (*Client, *n.Issuer, trust.Grant) {
	t.Helper()
	var store n.Store = n.NewMemoryStore()
	if backend == "postgres" {
		dsn := os.Getenv("SC_ISCP_NODE_TEST_DSN")
		if dsn == "" {
			t.Skip("isolated PostgreSQL fixture not configured")
		}
		var err error
		store, err = n.NewPostgresStore(context.Background(), dsn, c.RandomBytes(32))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(store.Close)
	}
	cl, issuer, _, _, _ := setupClientStore(t, time.Minute, store, "authority-fixture-"+c.Base64URL(c.RandomBytes(24)))
	result, err := cl.Enroll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return cl, issuer, result.Grant
}

func TestFreshAuthorityCoalescesOnlyOverlappingCallsAndClonesScopes(t *testing.T) {
	for _, backend := range []string{"file", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			cl, _, grant := authorityFixture(t, backend)
			g := gateAuthority(t, cl)
			var done []<-chan policyAnswer
			for range 12 {
				done = append(done, checkAsync(cl, context.Background()))
			}
			g.wait(t)
			waitAuthority(t, cl, func(cl *Client) bool { return cl.authorityFlight != nil && cl.authorityFlight.waiters == 12 })
			if len(g.checks()) != 1 {
				t.Fatal("overlapping calls issued separate authority requests")
			}
			g.unblock()
			for _, d := range done {
				answer := receivePolicy(t, d)
				if answer.err != nil || answer.policy.Revision != 1 || !answer.policy.Allows("settings.read") {
					t.Fatal(answer)
				}
				answer.policy.Scopes[0] = "files.write"
			}
			cfg := cl.StoredConfig()
			cfg.Scopes[0] = "files.write"
			if cl.StoredConfig().Scopes[0] != "settings.read" {
				t.Fatal("configuration scope alias escaped")
			}
			if _, err := cl.AuthorizationPolicy(context.Background()); err != nil {
				t.Fatal(err)
			}
			again, err := NewStored(cl.StoredConfig(), cl.device, cl.directory, grant)
			if err != nil {
				t.Fatal(err)
			}
			again.http.Transport = g
			if _, err = again.AuthorizationPolicy(context.Background()); err != nil {
				t.Fatal("same-key encrypted-file restart", err)
			}
			checks := g.checks()
			if len(checks) != 3 || checks[0].OperationID == checks[1].OperationID || checks[1].OperationID == checks[2].OperationID || checks[0].Proof.Nonce == checks[1].Proof.Nonce {
				t.Fatal("completed response was cached or proof/operation reused")
			}
		})
	}
}

func TestAuthorityWaiterCancellationDoesNotOwnTheSharedRequest(t *testing.T) {
	cl, _, _ := authorityFixture(t, "file")
	g := gateAuthority(t, cl)
	ctx, cancel := context.WithCancel(context.Background())
	leader := checkAsync(cl, ctx)
	g.wait(t)
	follower := checkAsync(cl, context.Background())
	waitAuthority(t, cl, func(cl *Client) bool { return cl.authorityFlight != nil && cl.authorityFlight.waiters == 2 })
	cancel()
	if answer := receivePolicy(t, leader); !errors.Is(answer.err, context.Canceled) {
		t.Fatal("canceled leader", answer.err)
	}
	select {
	case <-g.canceled:
		t.Fatal("one canceled waiter canceled the other waiter's fresh check")
	default:
	}
	g.unblock()
	if answer := receivePolicy(t, follower); answer.err != nil || !answer.policy.Allows("settings.read") {
		t.Fatal("remaining waiter", answer)
	}
	if len(g.checks()) != 1 {
		t.Fatal("remaining waiter repeated the request")
	}
	// With no remaining waiter the pure read is canceled, and the next call
	// creates a new request instead of retaining an orphaned result/error.
	cl2, _, _ := authorityFixture(t, "file")
	g2 := gateAuthority(t, cl2)
	ctx2, cancel2 := context.WithCancel(context.Background())
	only := checkAsync(cl2, ctx2)
	g2.wait(t)
	cancel2()
	if answer := receivePolicy(t, only); !errors.Is(answer.err, context.Canceled) {
		t.Fatal(answer.err)
	}
	select {
	case <-g2.canceled:
	case <-time.After(time.Second):
		t.Fatal("orphaned request was not canceled")
	}
	if _, err := cl2.AuthorizationPolicy(context.Background()); err != nil || len(g2.checks()) != 2 {
		t.Fatal("fresh call reused canceled flight", err)
	}
}

func TestAuthorityFailuresAreSharedOnlyInFlightAndNotChangedToRevocation(t *testing.T) {
	for _, status := range []int{503, 403} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			cl, issuer, _ := authorityFixture(t, "file")
			g := gateAuthority(t, cl)
			g.status = status
			one := checkAsync(cl, context.Background())
			g.wait(t)
			two := checkAsync(cl, context.Background())
			waitAuthority(t, cl, func(cl *Client) bool { return cl.authorityFlight != nil && cl.authorityFlight.waiters == 2 })
			g.unblock()
			want := n.ErrUnavailable
			if status == 403 {
				want = n.ErrDenied
			}
			for _, d := range []<-chan policyAnswer{one, two} {
				if answer := receivePolicy(t, d); !errors.Is(answer.err, want) || errors.Is(answer.err, iscpbridge.ErrAuthorizationRevoked) {
					t.Fatal("authority failure changed classification", answer.err)
				}
			}
			if _, err := cl.AuthorizationPolicy(context.Background()); err != nil || len(g.checks()) != 2 {
				t.Fatal("authority failure cached", err)
			}
			if err := issuer.Revoke(context.Background(), cl.cfg.InvitationID, "owner-revoke-after-failure", 1); err != nil {
				t.Fatal(err)
			}
			if _, err := cl.AuthorizationPolicy(context.Background()); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) || len(g.checks()) != 3 {
				t.Fatal("fresh signed revoke was hidden", err)
			}
		})
	}
}

func TestLateActiveAuthorityCannotCrossGrantOrDeletionMutation(t *testing.T) {
	for _, backend := range []string{"file", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			for _, action := range []string{"renew", "accept-grant", "commit-renewal", "recover", "resolve-pending", "installation", "reenroll", "delete"} {
				t.Run(action, func(t *testing.T) {
					cl, _, grant := authorityFixture(t, backend)
					var fresh trust.Grant
					if action == "accept-grant" || action == "commit-renewal" || action == "resolve-pending" {
						var err error
						fresh, err = cl.Renew(context.Background(), grant)
						if err != nil {
							t.Fatal(err)
						}
						if action == "commit-renewal" {
							if err = cl.AcceptGrant(fresh); err != nil {
								t.Fatal(err)
							}
						}
					}
					g := gateAuthority(t, cl)
					g.ignoreCancel = true
					waiting := checkAsync(cl, context.Background())
					g.wait(t)
					mutation := make(chan error, 1)
					go func() {
						var err error
						switch action {
						case "renew":
							_, err = cl.Renew(context.Background(), grant)
						case "accept-grant":
							err = cl.AcceptGrant(fresh)
						case "commit-renewal":
							err = cl.CommitRenewal()
						case "recover":
							_, err = cl.RecoverTransport(context.Background())
						case "resolve-pending":
							_, err = cl.ResolvePendingLifecycle(context.Background())
						case "installation":
							err = cl.SetInstallationID("original-native-installation-uuid")
						case "reenroll":
							_, err = cl.Enroll(context.Background())
						case "delete":
							_, err = cl.DeleteAuthorization(context.Background(), "self-delete-fenced-operation", 1)
						}
						mutation <- err
					}()
					waitAuthority(t, cl, func(cl *Client) bool { return cl.authorityMutations == 1 })
					select {
					case answer := <-waiting:
						t.Fatal("old response crossed the mutation barrier", answer)
					default:
					}
					g.unblock()
					if err := <-mutation; err != nil {
						t.Fatal(err)
					}
					answer := receivePolicy(t, waiting)
					if action == "delete" {
						if !errors.Is(answer.err, iscpbridge.ErrAuthorizationRevoked) {
							t.Fatal("late active result revived deleted authority", answer)
						}
						return
					}
					checks := g.checks()
					if answer.err != nil || len(checks) != 2 || checks[0].OperationID == checks[1].OperationID {
						t.Fatal("mutation did not force a fresh check", answer.err, len(checks))
					}
					if action == "accept-grant" && checks[1].PreviousGrantID != fresh.GrantID {
						t.Fatal("fresh check used the previous Grant lineage")
					}
					if action == "renew" || action == "recover" || action == "resolve-pending" {
						kind, err := cl.PendingLifecycleKind()
						want := "recover"
						if action == "resolve-pending" || action == "renew" {
							want = "renew"
						}
						if err != nil || kind != want {
							t.Fatal("check changed pending mutation kind", kind, err)
						}
					}
				})
			}
		})
	}
}

func TestFreshAuthorityRejectsChangedSignedScopesWithoutMemoizingDenial(t *testing.T) {
	store := n.NewMemoryStore()
	cl, _, _, _, _ := setupClientStore(t, time.Minute, store, "signed-scope-operation")
	if _, err := cl.Enroll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(context.Background(), cl.cfg.InvitationID, func(s *n.State) error {
		s.Credential.Scopes = []string{"files.write"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	g := gateAuthority(t, cl)
	one := checkAsync(cl, context.Background())
	g.wait(t)
	two := checkAsync(cl, context.Background())
	waitAuthority(t, cl, func(cl *Client) bool { return cl.authorityFlight != nil && cl.authorityFlight.waiters == 2 })
	g.unblock()
	for _, d := range []<-chan policyAnswer{one, two} {
		if answer := receivePolicy(t, d); !errors.Is(answer.err, n.ErrDenied) || errors.Is(answer.err, iscpbridge.ErrAuthorizationRevoked) {
			t.Fatal("signed scope mismatch was accepted/converted", answer)
		}
	}
	if err := store.Update(context.Background(), cl.cfg.InvitationID, func(s *n.State) error {
		s.Credential.Scopes = []string{"settings.read"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if p, err := cl.AuthorizationPolicy(context.Background()); err != nil || !p.Allows("settings.read") || len(g.checks()) != 2 {
		t.Fatal("signed scope denial memoized", p, err)
	}
}

func TestFreshSignedRevocationFencesAlreadyPublishedActiveWaiter(t *testing.T) {
	for _, backend := range []string{"file", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			cl, issuer, _ := authorityFixture(t, backend)
			g := gateAuthority(t, cl)
			active := checkAsync(cl, context.Background())
			g.wait(t)
			// Deterministically pause a second subscriber immediately before
			// its final return decision, rather than relying on scheduler luck.
			cl.authorityMu.Lock()
			old := cl.authorityFlight
			old.waiters++
			cl.authorityMu.Unlock()
			g.unblock()
			if p := receivePolicy(t, active); p.err != nil || p.policy.State != iscpauth.Active {
				t.Fatal(p)
			}
			if err := issuer.Revoke(context.Background(), cl.cfg.InvitationID, "external-owner-revoke", 1); err != nil {
				t.Fatal(err)
			}
			if _, err := cl.AuthorizationPolicy(context.Background()); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
				t.Fatal("fresh signed revoke missing", err)
			}
			cl.authorityMu.Lock()
			policy, err, retry := cl.consumeAuthorizationFlightLocked(context.Background(), old)
			cl.authorityMu.Unlock()
			if !retry || err != nil || policy.State == iscpauth.Active {
				t.Fatal("published active waiter crossed known revocation", policy, err, retry)
			}
			if _, err = cl.AuthorizationPolicy(context.Background()); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
				t.Fatal("rescheduled old waiter regained authority", err)
			}
			if len(g.checks()) != 2 {
				t.Fatal("known signed revoke generated an unnecessary network retry")
			}
		})
	}
}

func TestIdenticalValidatedGrantPollDoesNotStarveFreshCheckPastTenSeconds(t *testing.T) {
	cl, _, grant := authorityFixture(t, "file")
	g := gateAuthority(t, cl)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	checking := checkAsync(cl, ctx)
	g.wait(t)
	cl.authorityMu.Lock()
	before := cl.authorityGeneration
	cl.authorityMu.Unlock()
	// Simulate the runtime's ten-second Current/AcceptGrant poll while an
	// already authenticated fresh status response is still in flight.
	time.Sleep(10 * time.Second)
	polls := make(chan error, 2)
	go func() { polls <- cl.AcceptGrant(grant) }()
	go func() { polls <- cl.AcceptGrant(cloneGrant(grant)) }()
	time.Sleep(100 * time.Millisecond)
	cl.authorityMu.Lock()
	unchanged := cl.authorityGeneration == before && cl.authorityMutations == 0 && cl.authorityFlight != nil
	cl.authorityMu.Unlock()
	if !unchanged {
		t.Fatal("identical validated Grant began an authority mutation")
	}
	select {
	case <-g.canceled:
		t.Fatal("ordinary Grant poll canceled the fresh check")
	default:
	}
	g.unblock()
	if p := receivePolicy(t, checking); p.err != nil || !p.policy.Allows("settings.read") {
		t.Fatal("fresh check lost its original 30-second budget", p)
	}
	for range 2 {
		if err := <-polls; err != nil {
			t.Fatal("identical Grant poll", err)
		}
	}
	cl.authorityMu.Lock()
	unchanged = cl.authorityGeneration == before && cl.authorityMutations == 0
	cl.authorityMu.Unlock()
	if !unchanged || len(g.checks()) != 1 {
		t.Fatal("no-op poll restarted the status cohort")
	}
	if _, err := cl.AuthorizationPolicy(context.Background()); err != nil || len(g.checks()) != 2 {
		t.Fatal("same Grant was used as an authority cache", err)
	}
}

func TestIdenticalGrantNoopStillVerifiesBindingExpirySignatureAndOwnsSlices(t *testing.T) {
	cl, issuer, grant := authorityFixture(t, "file")
	if err := cl.AcceptGrant(grant); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*trust.Grant){
		func(g *trust.Grant) { g.Audience = "another-responder" },
		func(g *trust.Grant) { g.SubjectDeviceID = "another-device" },
		func(g *trust.Grant) { g.RevocationEpoch++ },
		func(g *trust.Grant) { g.ExpiresAt = time.Now().Add(-time.Second) },
		func(g *trust.Grant) { g.Signature.Value = "invalid-signature" },
		func(g *trust.Grant) { g.Permissions[0] = "expanded-permission" },
	} {
		bad := cloneGrant(grant)
		change(&bad)
		if err := cl.AcceptGrant(bad); err == nil {
			t.Fatal("altered Grant accepted by no-op path")
		}
	}
	grant.Permissions[0] = "caller-mutated-permission"
	grant.RelayConstraints[0] = "caller-mutated-relay"
	current, err := cl.Current(context.Background())
	if err != nil || cl.verifyGrant(current) != nil {
		t.Fatal("caller slice mutation changed the accepted Grant", err)
	}
	if err = issuer.Revoke(context.Background(), cl.cfg.InvitationID, "revoke-noop-poll", 1); err != nil {
		t.Fatal(err)
	}
	if _, err = cl.AuthorizationPolicy(context.Background()); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
		t.Fatal(err)
	}
	if err = cl.AcceptGrant(current); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
		t.Fatal("identical Grant revived known signed revocation", err)
	}
}

func TestAuthorityWaiterDeadlineAndQueuedMutationCancellation(t *testing.T) {
	cl, _, _ := authorityFixture(t, "file")
	g := gateAuthority(t, cl)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	leader := checkAsync(cl, ctx)
	g.wait(t)
	follower := checkAsync(cl, context.Background())
	waitAuthority(t, cl, func(cl *Client) bool { return cl.authorityFlight != nil && cl.authorityFlight.waiters == 2 })
	if answer := receivePolicy(t, leader); !errors.Is(answer.err, context.DeadlineExceeded) {
		t.Fatal("waiter did not keep its original deadline", answer.err)
	}
	select {
	case <-g.canceled:
		t.Fatal("a waiter deadline shortened the shared request's budget")
	default:
	}
	g.unblock()
	if answer := receivePolicy(t, follower); answer.err != nil {
		t.Fatal("remaining waiter", answer.err)
	}
	// A caller waiting for a mutation can leave without starting any fresh
	// check, changing the mutation, or later dispatching an orphaned request.
	end := cl.beginAuthorityMutation()
	ctx2, cancel2 := context.WithCancel(context.Background())
	waiting := checkAsync(cl, ctx2)
	cancel2()
	if answer := receivePolicy(t, waiting); !errors.Is(answer.err, context.Canceled) {
		t.Fatal("queued caller did not cancel", answer.err)
	}
	end()
	if _, err := cl.AuthorizationPolicy(context.Background()); err != nil || len(g.checks()) != 2 {
		t.Fatal("canceled queued caller dispatched later", err, len(g.checks()))
	}
}

func TestFreshAuthorityFlightsNeverMixPeersOnOneIssuer(t *testing.T) {
	for _, backend := range []string{"file", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			one, issuer, _ := authorityFixture(t, backend)
			encoded, err := issuer.CreateInvitation(context.Background(), "Second SparkX", time.Minute, []string{"files.read"}, "peer-two-"+c.Base64URL(c.RandomBytes(24)))
			if err != nil {
				t.Fatal(err)
			}
			two, err := New(encoded, testDevice(t, "second-desktop-peer"), privateTestDir(t))
			if err != nil {
				t.Fatal(err)
			}
			if _, err = two.Enroll(context.Background()); err != nil {
				t.Fatal(err)
			}
			g1, g2 := gateAuthority(t, one), gateAuthority(t, two)
			first, second := checkAsync(one, context.Background()), checkAsync(two, context.Background())
			g1.wait(t)
			g2.wait(t)
			if g1.checks()[0].Identity.DeviceID == g2.checks()[0].Identity.DeviceID || g1.checks()[0].InvitationID == g2.checks()[0].InvitationID {
				t.Fatal("peer identity/binding shared")
			}
			g2.unblock()
			if p := receivePolicy(t, second); p.err != nil || !p.policy.Allows("files.read") || p.policy.Allows("settings.read") {
				t.Fatal("second peer inherited first peer authority", p)
			}
			if err = issuer.Revoke(context.Background(), one.cfg.InvitationID, "revoke-first-peer", 1); err != nil {
				t.Fatal(err)
			}
			g1.unblock()
			if p := receivePolicy(t, first); p.err != nil || !p.policy.Allows("settings.read") || p.policy.Allows("files.read") {
				t.Fatal("first overlapping check changed scope", p)
			}
			// A subsequent call must observe the revoke; the earlier overlapping
			// check legitimately linearized before it, without a TTL cache.
			if _, err = one.AuthorizationPolicy(context.Background()); !errors.Is(err, iscpbridge.ErrAuthorizationRevoked) {
				t.Fatal("revoke hidden by completed result", err)
			}
			if _, err = two.AuthorizationPolicy(context.Background()); err != nil {
				t.Fatal("other peer reset by revocation", err)
			}
		})
	}
}
