package iscpbridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestLocalRelayEnrollmentRefreshPersistsAcrossOriginalExpiry(t *testing.T) {
	for _, recoverExpired := range []bool{false, true} {
		t.Run(map[bool]string{false: "automatic_before_expiry", true: "explicit_existing_recovery"}[recoverExpired], func(t *testing.T) {
			now := time.Now().UTC()
			provider := iscpcrypto.NewProvider()
			signer, err := identity.NewDevice(provider, "domain", "signer", now)
			if err != nil {
				t.Fatal(err)
			}
			device, err := identity.NewDevice(provider, "domain", "device", now)
			if err != nil {
				t.Fatal(err)
			}
			refreshes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/iscp/relay":
					desc := descriptor.RelayDescriptor{Type: "iscp.relay.descriptor.v2", RelayID: "relay", DomainID: "domain", BaseURL: "http://iscp-relay:8080", WebSocketURL: "ws://iscp-relay:8080/v2/relay/connect", SigningKeys: []descriptor.PublicKey{{KTY: "Ed25519", Use: "descriptor-signature", KID: signer.Identity.PublicKey.KID, Public: signer.Identity.PublicKey.Public}}, IssuedAt: now, ExpiresAt: now.Add(48 * time.Hour)}
					signed, err := descriptor.Sign(provider, signer, desc.Type, desc, now)
					if err != nil {
						t.Error(err)
						w.WriteHeader(500)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
				case relayRefreshPath:
					var body map[string]string
					if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["refresh"] != "existing-refresh" {
						t.Error("existing credential not used")
						w.WriteHeader(403)
						return
					}
					refreshes++
					_ = json.NewEncoder(w).Encode(map[string]any{"access": RelayCredential{DomainID: "domain", DeviceID: "device", Token: "next-access", ExpiresAt: now.Add(15 * time.Minute)}, "refresh": RelayCredential{DomainID: "domain", DeviceID: "device", Token: "next-refresh", ExpiresAt: now.Add(24 * time.Hour)}})
				default:
					t.Errorf("unexpected endpoint %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			bundle := EnrollmentBundle{Type: EnrollmentBundleType, Mode: BundleModeWorkbenchLocalLab, DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "ws://iscp-relay:8080/v2/relay/connect", RelaySignerIdentity: &signer.Identity, IssuedAt: now.Add(-24 * time.Hour), ExpiresAt: now.Add(30 * time.Second), Access: RelayCredential{DomainID: "domain", DeviceID: "device", Token: "existing-access", ExpiresAt: now.Add(5 * time.Minute)}, Refresh: RelayCredential{DomainID: "domain", DeviceID: "device", Token: "existing-refresh", ExpiresAt: now.Add(time.Hour)}}
			if recoverExpired {
				bundle.ExpiresAt = now.Add(-time.Hour)
			}
			path := filepath.Join(t.TempDir(), "enrollment.json")
			if err := SaveEnrollment(path, bundle); err != nil {
				t.Fatal(err)
			}
			if recoverExpired {
				if _, err := NewRelayCredentialClient(ProfileLocalLab, path, bundle, device, time.Second); err == nil {
					t.Fatal("ordinary startup bypassed expired envelope")
				}
				if _, err := RefreshLocalRelayEnrollment(t.Context(), path, bundle, device); err != nil {
					t.Fatal(err)
				}
			} else {
				client, err := NewRelayCredentialClient(ProfileLocalLab, path, bundle, device, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				if err := client.ensureAccess(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var saved EnrollmentBundle
			if json.Unmarshal(raw, &saved) != nil {
				t.Fatal("invalid persisted enrollment")
			}
			if refreshes != 1 || !saved.ExpiresAt.Equal(now.Add(24*time.Hour)) || saved.Refresh.Token != "next-refresh" || saved.Access.Token != "next-access" || !reflect.DeepEqual(saved.RelaySignerIdentity, bundle.RelaySignerIdentity) || saved.DomainID != bundle.DomainID || saved.DeviceID != bundle.DeviceID || saved.RelayID != bundle.RelayID || !saved.IssuedAt.Equal(bundle.IssuedAt) {
				t.Fatal("renewal did not preserve pinned identity/bounded expiry")
			}
			if _, err := NewRelayCredentialClient(ProfileLocalLab, path, saved, device, time.Second); err != nil {
				t.Fatal("restart requires new pairing", err)
			}
			if err := saved.ValidateCredentials(bundle.ExpiresAt.Add(time.Second)); err != nil {
				t.Fatal("renewed envelope does not survive old expiry", err)
			}
		})
	}
}

func TestLocalRelayEnrollmentRecoveryCannotInventValidity(t *testing.T) {
	for _, failure := range []string{"changed-signer", "expired-discovery", "tampered-signature", "expired-refresh", "foreign-device", "refresh-rejected", "foreign-response"} {
		t.Run(failure, func(t *testing.T) {
			now := time.Now().UTC()
			provider := iscpcrypto.NewProvider()
			signer, _ := identity.NewDevice(provider, "domain", "signer", now)
			device, _ := identity.NewDevice(provider, "domain", "device", now)
			advertised := signer
			if failure == "changed-signer" {
				advertised, _ = identity.NewDevice(provider, "domain", "signer", now)
			}
			refreshes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/iscp/relay":
					expires := now.Add(time.Hour)
					issued := now
					if failure == "expired-discovery" {
						expires = now.Add(-time.Minute)
						issued = now.Add(-time.Hour)
					}
					desc := descriptor.RelayDescriptor{Type: "iscp.relay.descriptor.v2", RelayID: "relay", DomainID: "domain", BaseURL: "http://iscp-relay:8080", WebSocketURL: "ws://iscp-relay:8080/v2/relay/connect", SigningKeys: []descriptor.PublicKey{{KTY: "Ed25519", Use: "descriptor-signature", KID: advertised.Identity.PublicKey.KID, Public: advertised.Identity.PublicKey.Public}}, IssuedAt: issued, ExpiresAt: expires}
					signed, _ := descriptor.Sign(provider, advertised, desc.Type, desc, issued)
					if failure == "tampered-signature" {
						signed.Signature.Value = "invalid"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
				case relayRefreshPath:
					refreshes++
					if failure == "refresh-rejected" {
						w.WriteHeader(403)
						return
					}
					credential := RelayCredential{DomainID: "domain", DeviceID: "device", Token: "rotated", ExpiresAt: now.Add(time.Hour)}
					if failure == "foreign-response" {
						credential.DeviceID = "foreign"
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"access": credential, "refresh": credential})
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			bundle := EnrollmentBundle{Type: EnrollmentBundleType, Mode: BundleModeWorkbenchLocalLab, DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "ws://iscp-relay:8080/v2/relay/connect", RelaySignerIdentity: &signer.Identity, IssuedAt: now.Add(-24 * time.Hour), ExpiresAt: now.Add(-time.Hour), Access: RelayCredential{DomainID: "domain", DeviceID: "device", Token: "access", ExpiresAt: now.Add(-time.Minute)}, Refresh: RelayCredential{DomainID: "domain", DeviceID: "device", Token: "refresh", ExpiresAt: now.Add(time.Hour)}}
			if failure == "expired-refresh" {
				bundle.Refresh.ExpiresAt = now.Add(-time.Minute)
			}
			if failure == "foreign-device" {
				device, _ = identity.NewDevice(provider, "domain", "foreign", now)
			}
			path := filepath.Join(t.TempDir(), "enrollment.json")
			if err := SaveEnrollment(path, bundle); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			if _, err := RefreshLocalRelayEnrollment(context.Background(), path, bundle, device); err == nil {
				t.Fatal("unverified material renewed validity")
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("rejected recovery modified enrollment")
			}
			if failure != "refresh-rejected" && failure != "foreign-response" && refreshes != 0 {
				t.Fatal("invalid pin/material reached credential refresh")
			}
		})
	}
}
