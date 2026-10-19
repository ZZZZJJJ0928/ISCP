package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpworkbench"
	c "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

type helperManagement struct {
	mu     sync.Mutex
	active map[string]bool
}

func (m *helperManagement) Identity(context.Context) (n.Binding, error) {
	return n.Binding{DeploymentID: "deployment", OwnerID: "owner"}, nil
}
func (m *helperManagement) Client(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[id], nil
}
func (m *helperManagement) CreateClient(_ context.Context, _ string, key string) (string, error) {
	id := n.StableClientID("owner", key)
	m.mu.Lock()
	m.active[id] = true
	m.mu.Unlock()
	return id, nil
}
func (m *helperManagement) RevokeManagedClient(_ context.Context, id string) error {
	m.mu.Lock()
	m.active[id] = false
	m.mu.Unlock()
	return nil
}

type helperRegistration struct {
	mu         sync.Mutex
	prepared   map[string]n.RegistrationPreparation
	receipts   map[string]n.RegistrationReceipt
	commits    int
	recoveries int
}

func (r *helperRegistration) Prepare(_ context.Context, p n.RegistrationPreparation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prepared[p.OperationID] = p
	return nil
}
func (r *helperRegistration) Commit(_ context.Context, p n.RegistrationCommit) (n.RegistrationReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.receipts[p.OperationID]; ok {
		return old, nil
	}
	prep := r.prepared[p.OperationID]
	r.commits++
	receipt, e := helperReceipt(prep.OperationID, prep.BindingDigest, prep.ReceiptWrapPublicKey, prep.Identity, time.Second)
	r.receipts[p.OperationID] = receipt
	return receipt, e
}
func (r *helperRegistration) Status(_ context.Context, op, digest string) (n.RegistrationReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v, ok := r.receipts[op]
	if !ok || v.BindingDigest != digest {
		return v, n.ErrDenied
	}
	return v, nil
}
func (r *helperRegistration) Revoke(context.Context, string, string, uint64) error { return nil }
func (r *helperRegistration) Recover(_ context.Context, p n.RegistrationRecovery) (n.RegistrationReceipt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recoveries++
	return helperReceipt(p.OperationID, p.BindingDigest, p.ReceiptWrapPublicKey, p.Identity, time.Hour)
}
func helperReceipt(op, digest, wrap string, id identity.DeviceIdentity, ttl time.Duration) (n.RegistrationReceipt, error) {
	now := time.Now().UTC()
	return n.SealRegistrationReceipt(n.RegistrationReceipt{OperationID: op, BindingDigest: digest, IssuedAt: now}, wrap, id, n.RelayCredentials{Access: iscpbridge.RelayCredential{DomainID: id.DomainID, DeviceID: id.DeviceID, Token: "synthetic-access-private", ExpiresAt: now.Add(ttl)}, Refresh: iscpbridge.RelayCredential{DomainID: id.DomainID, DeviceID: id.DeviceID, Token: "synthetic-refresh-private", ExpiresAt: now.Add(ttl)}})
}

func TestHelperNodeEnrollmentReplayExpiredResultAndPrivateActivation(t *testing.T) {
	device := func(id string) identity.Device {
		d, e := identity.NewDevice(c.NewProvider(), "domain", id, time.Now().UTC())
		if e != nil {
			t.Fatal(e)
		}
		return d
	}
	signer, inviter, responder, relay := device("issuer"), device("inviter"), device("responder"), device("relay-signer")
	var issuer *n.Issuer
	var controlHandler http.Handler
	drop := true
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v2/control/") {
			controlHandler.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/.well-known/iscp/relay" {
			now := time.Now().UTC()
			d := descriptor.RelayDescriptor{Type: "iscp.relay.descriptor.v2", DomainID: "domain", RelayID: "relay", BaseURL: server.URL, WebSocketURL: "wss" + strings.TrimPrefix(server.URL, "https") + "/v2/relay/duplex", SigningKeys: []descriptor.PublicKey{{KTY: "Ed25519", Use: "descriptor-signature", KID: relay.Identity.PublicKey.KID, Public: relay.Identity.PublicKey.Public}}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
			signed, _ := descriptor.Sign(c.NewProvider(), relay, d.Type, d, now)
			_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
			return
		}
		if r.URL.Path == "/v2/relay/duplex" {
			w.WriteHeader(503)
			return
		}
		if r.URL.Path != n.ExchangePath {
			t.Error("helper left its TEST1 application origin", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var x n.Exchange
		if n.StrictDecode(raw, &x) != nil {
			w.WriteHeader(400)
			return
		}
		out, e := issuer.Exchange(r.Context(), x)
		if e != nil {
			status := 503
			if errors.Is(e, n.ErrDenied) {
				status = 403
			}
			w.WriteHeader(status)
			return
		}
		if drop && x.Step == "redeem" {
			drop = false
			w.WriteHeader(503)
			return
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer server.Close()
	management := &helperManagement{active: map[string]bool{}}
	registration := &helperRegistration{prepared: map[string]n.RegistrationPreparation{}, receipts: map[string]n.RegistrationReceipt{}}
	controlRelay := &helperControlRelay{signer: relay, actor: device("issuer-service-actor"), registration: registration, records: map[string]*control.Record{}, generations: map[string]uint64{}}
	var err error
	issuerConfig := n.Config{EnableControlV2: true, ControlRelay: controlRelay, Template: n.Credential{Origin: server.URL, TLSCertificatePEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})), DomainID: "domain", RelayID: "relay", RelaySignerIdentity: relay.Identity, IssuerIdentity: signer.Identity, InvitationSignerIdentity: inviter.Identity, IssuerRoute: "work2-node", ResponderIdentity: responder.Identity, DeploymentID: "deployment", OwnerID: "owner"}, Issuer: signer, InvitationSigner: inviter, GrantTTL: time.Second}
	issuerStore := n.NewMemoryStore()
	issuer, err = n.New(issuerConfig, issuerStore, management, registration)
	if err != nil {
		t.Fatal(err)
	}
	// Only the retained enrollment seed has a one-second Grant. Recovery
	// exercises normal installation latency with a fresh Grant, rather than
	// racing the control wire's whole-second timestamp boundary on every ACK.
	// Both issuer instances share the exact state, identity and authorities.
	controlConfig := issuerConfig
	controlConfig.GrantTTL = time.Minute
	controlIssuer, err := n.New(controlConfig, issuerStore, management, registration)
	if err != nil {
		t.Fatal(err)
	}
	controlHandler = controlIssuer.ControlHandler()
	encoded, err := issuer.CreateInvitation(context.Background(), "SparkX", 15*time.Minute, []string{"workbench.read"}, "create-native-helper")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	installation := newHelperUUID()
	var stdout bytes.Buffer
	if err = enrollNode(context.Background(), strings.NewReader(encoded+"\n"), &stdout, dir, "file", "", installation); err == nil || stdout.Len() != 0 {
		t.Fatal("lost enrollment response activated a profile")
	}
	identityPath := filepath.Join(dir, "identity", iscpbridge.IdentityFileName)
	before, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	// Both signed seed Grant and transport credentials expire before retry.
	// The helper authenticates its original result, renews/recoveries through
	// TEST1, then emits a fresh profile without creating another device/Client.
	time.Sleep(1200 * time.Millisecond)
	if err = enrollNode(context.Background(), strings.NewReader(encoded+"\n"), &stdout, dir, "file", "", installation); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(identityPath)
	if string(before) != string(after) {
		t.Fatal("replay regenerated native identity")
	}
	var frame struct {
		IPCVersion  int                      `json:"ipc_version"`
		Type        string                   `json:"type"`
		ProfilePath string                   `json:"profile_path"`
		Descriptor  nodeConnectionDescriptor `json:"descriptor"`
	}
	if json.Unmarshal(stdout.Bytes(), &frame) != nil || frame.IPCVersion != 1 || frame.Type != "enrollment" || frame.Descriptor.SchemaVersion != 4 || frame.Descriptor.TestMode || frame.Descriptor.RelayURL != server.URL {
		t.Fatal("public enrollment frame differs")
	}
	if strings.Contains(stdout.String(), encoded) || strings.Contains(stdout.String(), "synthetic-access-private") || strings.Contains(stdout.String(), "synthetic-refresh-private") || strings.Contains(stdout.String(), "bootstrap_secret") {
		t.Fatal("private material crossed helper stdout")
	}
	profileRaw, _ := os.ReadFile(frame.ProfilePath)
	var wrapper struct {
		HelperConfig string `json:"helper_config"`
	}
	_ = json.Unmarshal(profileRaw, &wrapper)
	cfg, err := iscpworkbench.LoadConfig(wrapper.HelperConfig)
	if err != nil || cfg.ExpectedInstallationID != installation {
		t.Fatal("fresh native profile invalid", err)
	}
	registration.mu.Lock()
	if registration.commits != 1 || registration.recoveries != 1 {
		t.Error("replay duplicated enrollment or skipped cold recovery", registration.commits, registration.recoveries)
	}
	registration.mu.Unlock()
	stdout.Reset()
	if err = enrollNode(context.Background(), strings.NewReader(encoded+"\n"), &stdout, dir, "file", "", newHelperUUID()); err == nil || stdout.Len() != 0 {
		t.Fatal("another installation resumed owned enrollment")
	}
	// A running helper must recover transport after an outage too, without a
	// process restart. Construct while the original one-second credentials are
	// valid, then let both expiries pass before starting its receive loop.
	secondEncoded, e := issuer.CreateInvitation(context.Background(), "Second SparkX", 15*time.Minute, []string{"workbench.read"}, "create-live-runtime")
	if e != nil {
		t.Fatal(e)
	}
	secondDir := t.TempDir()
	_ = os.Chmod(secondDir, 0700)
	var secondOutput bytes.Buffer
	if e = enrollNode(context.Background(), strings.NewReader(secondEncoded+"\n"), &secondOutput, secondDir, "file", "", newHelperUUID()); e != nil {
		t.Fatal(e)
	}
	liveCfg, e := iscpworkbench.LoadConfig(filepath.Join(secondDir, "workbench.json"))
	if e != nil {
		t.Fatal(e)
	}
	endpoint, e := iscpworkbench.NewEndpoint(liveCfg, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	time.Sleep(1200 * time.Millisecond)
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = endpoint.Run(runCtx) }()
	deadline := time.Now().Add(5 * time.Second)
	recovered := false
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(liveCfg.EnrollmentFile)
		var b iscpbridge.EnrollmentBundle
		if json.Unmarshal(raw, &b) == nil && time.Until(b.Refresh.ExpiresAt) > time.Minute {
			recovered = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	_ = endpoint.Close()
	<-done
	if !recovered {
		t.Fatal("live helper required process restart after transport expiry")
	}
	registration.mu.Lock()
	if registration.commits != 2 || registration.recoveries != 2 {
		t.Error("live recovery recreated enrollment or skipped original lifecycle", registration.commits, registration.recoveries)
	}
	registration.mu.Unlock()

}
