package iscpbridge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/gorilla/websocket"
)

func TestCredentialOnlyRelayRefreshPreservesCloudTrust(t *testing.T) {
	now := time.Now().UTC()
	provider := iscpcrypto.NewProvider()
	device, err := identity.NewDevice(provider, "domain", "device", now)
	if err != nil {
		t.Fatal(err)
	}
	cloud, err := identity.NewDevice(provider, "cloud", "cloud-root", now)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != relayRefreshPath {
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access": RelayCredential{DomainID: "domain", DeviceID: "device", Token: "rotated-access", ExpiresAt: now.Add(time.Hour)}, "refresh": RelayCredential{DomainID: "domain", DeviceID: "device", Token: "rotated-refresh", ExpiresAt: now.Add(2 * time.Hour)}})
	}))
	defer server.Close()
	bundle := EnrollmentBundle{Type: EnrollmentBundleType, DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "wss://relay.invalid", TrustRootIdentity: cloud.Identity, Access: RelayCredential{DomainID: "domain", DeviceID: "device", Token: "access", ExpiresAt: now.Add(-time.Second)}, Refresh: RelayCredential{DomainID: "domain", DeviceID: "device", Token: "refresh", ExpiresAt: now.Add(time.Hour)}, IssuedAt: now, ExpiresAt: now.Add(2 * time.Hour)}
	path := filepath.Join(t.TempDir(), "enrollment.json")
	client, err := NewRelayCredentialClient(ProfileProduction, path, bundle, device, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.client = server.Client()
	if err := client.ensureAccess(context.Background()); err != nil {
		t.Fatal(err)
	}
	rotated := client.Enrollment()
	if rotated.Access.Token != "rotated-access" || rotated.TrustRootIdentity.PublicKey.KID != cloud.Identity.PublicKey.KID || len(rotated.Peers) != 0 {
		t.Fatal("refresh altered cloud trust or inserted application grants")
	}
	if rotated.Validate(now) == nil {
		t.Fatal("legacy Bridge validation unexpectedly accepted credential-only bundle")
	}
	if rotated.ValidateCredentials(now) != nil {
		t.Fatal("credential-only rotated bundle rejected")
	}
	var saved EnrollmentBundle
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal(raw, &saved) != nil || saved.Access.Token != "rotated-access" || !saved.ExpiresAt.Equal(bundle.ExpiresAt) || !reflect.DeepEqual(saved.TrustRootIdentity, bundle.TrustRootIdentity) {
		t.Fatal("credential rotation was not persisted")
	}
}

func TestRelayReceiveProofAndReadinessDeadline(t *testing.T) {
	provider := iscpcrypto.NewProvider()
	now := time.Now().UTC()
	device, err := identity.NewDevice(provider, "domain", "device", now)
	if err != nil {
		t.Fatal(err)
	}
	cloud, err := identity.NewDevice(provider, "cloud", "root", now)
	if err != nil {
		t.Fatal(err)
	}
	for _, stall := range []bool{false, true} {
		t.Run(map[bool]string{false: "signed_proof_then_ready", true: "challenge_read_timeout"}[stall], func(t *testing.T) {
			var proofVerified atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				upgrader := websocket.Upgrader{}
				connection, err := upgrader.Upgrade(w, r, nil)
				if err != nil {
					t.Error(err)
					return
				}
				defer connection.Close()
				if stall {
					_, _, _ = connection.ReadMessage()
					return
				}
				if err := connection.WriteJSON(relayMessage{State: "challenge", Challenge: "fresh-challenge"}); err != nil {
					t.Error(err)
					return
				}
				var proof identity.DeviceProof
				if err := connection.ReadJSON(&proof); err != nil {
					t.Error(err)
					return
				}
				if err := identity.VerifyProof(provider, device.Identity, proof, "relay", "fresh-challenge", time.Now().UTC(), time.Minute); err != nil {
					t.Error(err)
					return
				}
				proofVerified.Store(true)
				_ = connection.WriteJSON(relayMessage{State: "ready"})
				_ = connection.WriteJSON(relayMessage{State: "message", Envelope: json.RawMessage(`{"test":true}`)})
				_, _, _ = connection.ReadMessage()
			}))
			defer server.Close()
			localSigner := cloud.Identity
			localSigner.DomainID = "domain"
			bundle := EnrollmentBundle{Type: EnrollmentBundleType, Mode: BundleModeWorkbenchLocalLab, RelaySignerIdentity: &localSigner, DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "ws" + strings.TrimPrefix(server.URL, "http") + "/v2/relay/connect", Access: RelayCredential{DomainID: "domain", DeviceID: "device", Token: "access", ExpiresAt: now.Add(time.Hour)}, Refresh: RelayCredential{DomainID: "domain", DeviceID: "device", Token: "refresh", ExpiresAt: now.Add(time.Hour)}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
			client, err := NewRelayCredentialClient(ProfileLocalLab, filepath.Join(t.TempDir(), "enrollment.json"), bundle, device, 100*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			var ready atomic.Bool
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = client.runSocketOnce(ctx, func(context.Context, json.RawMessage) error { cancel(); return ctx.Err() }, func() { ready.Store(true) })
			if stall && (err == nil || ready.Load()) {
				t.Fatal("stalled authentication became ready")
			}
			if !stall && (!errors.Is(err, context.Canceled) || !ready.Load() || !proofVerified.Load()) {
				t.Fatalf("proof/ready failed: %v", err)
			}
		})
	}
}
