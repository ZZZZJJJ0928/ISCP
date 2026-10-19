package iscpworkbench

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestRuntimeStartupRecoversExpiredLocalEnrollment(t *testing.T) {
	for _, variant := range []string{RoleInitiator, RoleResponder, "expired-refresh", "changed-signer", "rejected-refresh"} {
		t.Run(variant, func(t *testing.T) {
			desktop, gateway := testMaterials(t)
			m, role := desktop, RoleInitiator
			if variant == RoleResponder {
				m, role = gateway, RoleResponder
			}
			path := writeFixtureConfig(t, m, role)
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now().UTC()
			provider := iscpcrypto.NewProvider()
			signer, err := identity.NewDevice(provider, m.enrollment.DomainID, "relay-signer", now)
			if err != nil {
				t.Fatal(err)
			}
			advertised := signer
			if variant == "changed-signer" {
				advertised, err = identity.NewDevice(provider, m.enrollment.DomainID, "relay-signer", now)
				if err != nil {
					t.Fatal(err)
				}
			}
			var discoveries, refreshes atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/iscp/relay":
					discoveries.Add(1)
					desc := descriptor.RelayDescriptor{Type: "iscp.relay.descriptor.v2", RelayID: m.enrollment.RelayID, DomainID: m.enrollment.DomainID, BaseURL: "http://iscp-relay:8080", WebSocketURL: "ws://iscp-relay:8080/v2/relay/duplex", SigningKeys: []descriptor.PublicKey{{KTY: "Ed25519", Use: "descriptor-signature", KID: advertised.Identity.PublicKey.KID, Public: advertised.Identity.PublicKey.Public}}, IssuedAt: now, ExpiresAt: now.Add(24 * time.Hour)}
					signed, signErr := descriptor.Sign(provider, advertised, desc.Type, desc, now)
					if signErr != nil {
						t.Error(signErr)
						w.WriteHeader(500)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"descriptor": signed})
				case "/v2/relay/devices/refresh-access":
					refreshes.Add(1)
					var body map[string]string
					if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || body["refresh"] != m.enrollment.Refresh.Token {
						t.Error("startup did not use the existing refresh credential")
						w.WriteHeader(403)
						return
					}
					if variant == "rejected-refresh" {
						w.WriteHeader(401)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"access": iscpbridge.RelayCredential{DomainID: m.enrollment.DomainID, DeviceID: m.enrollment.DeviceID, Token: "next-access", ExpiresAt: now.Add(15 * time.Minute)}, "refresh": iscpbridge.RelayCredential{DomainID: m.enrollment.DomainID, DeviceID: m.enrollment.DeviceID, Token: "next-refresh", ExpiresAt: now.Add(12 * time.Hour)}})
				default:
					t.Error("startup attempted an enrollment or authorization operation")
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			cfg.RelayProfile = iscpbridge.ProfileLocalLab
			cfg.GrantRenewal = &GrantRenewalConfig{URL: "http://127.0.0.1:1", PendingFile: filepath.Join(cfg.IdentityDirectory, "pending.json"), PollIntervalSeconds: 1, AuthorizationLifetime: "until_revoked"}
			m.enrollment.Mode = iscpbridge.BundleModeWorkbenchLocalLab
			m.enrollment.RelaySignerIdentity = &signer.Identity
			m.enrollment.RelayBaseURL = server.URL
			m.enrollment.RelayWebSocketURL = "ws://iscp-relay:8080/v2/relay/duplex"
			m.enrollment.IssuedAt = now.Add(-2 * time.Hour)
			m.enrollment.ExpiresAt = now.Add(-time.Hour)
			if variant == "expired-refresh" {
				m.enrollment.Refresh.ExpiresAt = now.Add(-time.Minute)
			}
			raw, _ := json.Marshal(cfg)
			if err = os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err = iscpbridge.SaveEnrollment(cfg.EnrollmentFile, m.enrollment); err != nil {
				t.Fatal(err)
			}
			protected := map[string]string{}
			for _, file := range []string{cfg.GrantFile, cfg.PeerIdentityFile, cfg.IssuerIdentityFile, filepath.Join(cfg.IdentityDirectory, iscpbridge.IdentityFileName), filepath.Join(cfg.IdentityDirectory, iscpbridge.IdentityKeyFileName)} {
				data, readErr := os.ReadFile(file)
				if readErr != nil {
					t.Fatal(readErr)
				}
				protected[file] = string(data)
			}
			before, _ := os.ReadFile(cfg.EnrollmentFile)
			if _, err = LoadConfig(path); err == nil || discoveries.Load() != 0 || refreshes.Load() != 0 {
				t.Fatal("strict check admitted expired enrollment or performed network writes")
			}
			loaded, err := LoadRuntimeConfig(context.Background(), path)
			if variant == RoleInitiator || variant == RoleResponder {
				if err != nil || loaded.Role != role || discoveries.Load() != 1 || refreshes.Load() != 1 {
					t.Fatalf("normal startup did not recover the same device: discovery=%d refresh=%d err=%v", discoveries.Load(), refreshes.Load(), err)
				}
				if _, err = LoadConfig(path); err != nil {
					t.Fatal("persisted recovery fails ordinary strict reload", err)
				}
				var saved iscpbridge.EnrollmentBundle
				if err = readJSONFile(cfg.EnrollmentFile, &saved, true); err != nil || saved.DeviceID != m.enrollment.DeviceID || saved.RelaySignerIdentity.PublicKey != signer.Identity.PublicKey || !saved.ExpiresAt.Equal(now.Add(12*time.Hour)) {
					t.Fatal("startup changed identity or fabricated validity", err)
				}
			} else {
				after, _ := os.ReadFile(cfg.EnrollmentFile)
				if err == nil || string(before) != string(after) {
					t.Fatal("unverified recovery must fail without changing enrollment")
				}
				if variant != "rejected-refresh" && refreshes.Load() != 0 {
					t.Fatal("invalid recovery reached credential refresh")
				}
			}
			for file, expected := range protected {
				actual, _ := os.ReadFile(file)
				if string(actual) != expected {
					t.Fatal("startup recovery changed a protected identity or Grant")
				}
			}
		})
	}
}
