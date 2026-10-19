package iscpbridge

import (
	"testing"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/descriptor"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

func TestLocalRelayURLsExplicitAndConfined(t *testing.T) {
	valid := [][2]string{{"http://127.0.0.1:1234", "ws://127.0.0.1:1234/v2/relay/duplex"}, {"http://[::1]:1234", "ws://[::1]:1234/v2/relay/duplex"}, {"http://iscp-relay:8080", "ws://iscp-relay:8080/v2/relay/duplex"}, {"http://localhost:1234", "ws://localhost:1234/v2/relay/duplex"}}
	for _, pair := range valid {
		if err := ValidateWorkbenchRelayURLs(ProfileLocalLab, pair[0], pair[1]); err != nil {
			t.Fatal(err)
		}
		if ValidateWorkbenchRelayURLs(ProfileProduction, pair[0], pair[1]) == nil {
			t.Fatal("production TLS was weakened")
		}
	}
	invalid := [][2]string{{"http://192.168.1.10:1234", "ws://192.168.1.10:1234/v2/relay/duplex"}, {"http://example.com", "ws://example.com/v2/relay/duplex"}, {"http://127.0.0.1.evil", "ws://127.0.0.1.evil/v2/relay/duplex"}, {"http://user:secret@127.0.0.1", "ws://127.0.0.1/v2/relay/duplex"}, {"http://iscp-relay.example.com", "ws://iscp-relay.example.com/v2/relay/duplex"}, {"http://127.0.0.1/path", "ws://127.0.0.1/v2/relay/duplex"}, {"http://127.0.0.1", "ws://127.0.0.1/arbitrary"}}
	for _, pair := range invalid {
		if ValidateWorkbenchRelayURLs(ProfileLocalLab, pair[0], pair[1]) == nil {
			t.Fatalf("unauthorized local URL accepted: %v", pair)
		}
	}
}

func TestNodeManagedRelayUsesOneIPOrigin(t *testing.T) {
	if err := ValidateNodeRelayURLs("https://210.16.177.239", "wss://210.16.177.239/v2/relay/duplex"); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"https://210.16.177.239", "wss://210.16.177.239:24443/v2/relay/duplex"}, {"https://210.16.177.239", "wss://10.20.0.23/v2/relay/duplex"}, {"https://relay.example.com", "wss://relay.example.com/v2/relay/duplex"}, {"https://210.16.177.239/path", "wss://210.16.177.239/v2/relay/duplex"}, {"https://210.16.177.239", "wss://210.16.177.239/other"}, {"https://210.16.177.239", "wss://210.16.177.239/v2/relay/duplex?token=secret"}} {
		if ValidateNodeRelayURLs(pair[0], pair[1]) == nil {
			t.Fatal("node credential introduced another origin/path", pair)
		}
	}
}

func TestLocalRelaySignatureDomainAndSignerPin(t *testing.T) {
	provider := iscpcrypto.NewProvider()
	now := time.Now().UTC()
	signer, err := identity.NewDevice(provider, "domain", "relay-signer", now)
	if err != nil {
		t.Fatal(err)
	}
	desc := descriptor.RelayDescriptor{Type: "iscp.relay.descriptor.v2", RelayID: "relay", DomainID: "domain", BaseURL: "http://iscp-relay:8080", WebSocketURL: "ws://iscp-relay:8080/v2/relay/duplex", SigningKeys: []descriptor.PublicKey{{KTY: "Ed25519", Use: "descriptor-signature", KID: signer.Identity.PublicKey.KID, Public: signer.Identity.PublicKey.Public}}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}
	signed, err := descriptor.Sign(provider, signer, desc.Type, desc, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyLocalRelayDescriptor(signed, "relay", "domain", &signer.Identity, now); err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []struct{ relay, domain string }{{"other", "domain"}, {"relay", "other"}} {
		if _, _, err := verifyLocalRelayDescriptor(signed, wrong.relay, wrong.domain, &signer.Identity, now); err == nil {
			t.Fatal("wrong Relay/Domain accepted")
		}
	}
	foreign, err := identity.NewDevice(provider, "domain", "relay-signer", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := verifyLocalRelayDescriptor(signed, "relay", "domain", &foreign.Identity, now); err == nil {
		t.Fatal("wrong signer pin accepted")
	}
	signed.Signature.Value = iscpcrypto.Base64URL(make([]byte, 64))
	if _, _, err := verifyLocalRelayDescriptor(signed, "relay", "domain", &signer.Identity, now); err == nil {
		t.Fatal("bad local descriptor signature accepted")
	}
}
