package iscpcontrol

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

type routeRestartTransport struct {
	http.RoundTripper
	restart func()
	once    atomic.Bool
}

func (r *routeRestartTransport) RoundTrip(q *http.Request) (*http.Response, error) {
	response, err := r.RoundTripper.RoundTrip(q)
	if err == nil && q.URL.Path == ChallengePath && r.once.CompareAndSwap(false, true) {
		r.restart()
	}
	return response, err
}
func TestFiveAudienceRouterUsesChallengeBindingAndFailsClosedAfterRestart(t *testing.T) {
	device, _ := identity.NewDevice(c.NewProvider(), "domain-test", "device-test", time.Now().UTC())
	targets := map[string]http.Handler{}
	backends := []*testBackend{}
	signers := []identity.Device{}
	for i := 1; i <= 5; i++ {
		signer, _ := identity.NewDevice(c.NewProvider(), "domain-test", fmt.Sprintf("work%d-issuer", i), time.Now().UTC())
		backend := &testBackend{actor: device.Identity, signer: signer}
		targets[signer.Identity.DeviceID] = NewHandler(signer.Identity.DeviceID, signer, backend)
		backends = append(backends, backend)
		signers = append(signers, signer)
	}
	var current atomic.Pointer[Router]
	router, err := NewRouter(targets)
	if err != nil {
		t.Fatal(err)
	}
	current.Store(router)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) { current.Load().ServeHTTP(w, q) }))
	defer server.Close()
	var intent Intent
	if err = Decode(fixture(t)["intent"], "intent", &intent); err != nil {
		t.Fatal(err)
	}
	for i, signer := range signers {
		intent.OperationID = fmt.Sprintf("route-operation-%d", i)
		intent.Target.ServiceID = signer.Identity.DeviceID
		digest, _ := Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
		client, err := NewClient(server.URL, signer.Identity.DeviceID, device, signer.Identity, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		request := Request{Action: "recover", Key: Key{device.Identity.DomainID, device.Identity.DeviceID, intent.Namespace, intent.OperationID}, SemanticDigest: digest, Intent: &intent}
		if _, err = client.Attempt(context.Background(), request, ""); err != nil {
			t.Fatal(err)
		}
		if backends[i].executions != 1 {
			t.Fatal("wrong audience routing")
		}
	}
	signer := signers[0]
	h := server.Client()
	h.Transport = &routeRestartTransport{RoundTripper: h.Transport, restart: func() { next, _ := NewRouter(targets); current.Store(next) }}
	client, _ := NewClient(server.URL, signer.Identity.DeviceID, device, signer.Identity, h)
	intent.OperationID = "after-router-restart"
	intent.Target.ServiceID = signer.Identity.DeviceID
	digest, _ := Digest("ISCP-OPERATION-INTENT-V2\x00", intent)
	request := Request{Action: "recover", Key: Key{device.Identity.DomainID, device.Identity.DeviceID, intent.Namespace, intent.OperationID}, SemanticDigest: digest, Intent: &intent}
	if _, err = client.Attempt(context.Background(), request, ""); err == nil {
		t.Fatal("lost challenge mapping guessed an authority")
	}
	if backends[0].executions != 1 {
		t.Fatal("restart admitted an unbound operation")
	}
}
