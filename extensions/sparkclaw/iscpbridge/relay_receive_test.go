package iscpbridge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/gorilla/websocket"
)

func TestRelayIdlePingTrafficExtendsLivenessDeadline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		go func() { _, _, _ = connection.ReadMessage() }()
		// No application data for four receive-deadline periods. Standard
		// control frames alone must keep a healthy idle connection alive.
		for i := 0; i < 20; i++ {
			if err := connection.WriteControl(websocket.PingMessage, []byte("idle-probe"), time.Now().Add(time.Second)); err != nil {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		_ = connection.WriteJSON(relayMessage{State: "message", Envelope: json.RawMessage(`{"after_idle":true}`)})
	}))
	defer server.Close()
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := installRelayReceiveLiveness(connection, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	var message relayMessage
	if err := connection.ReadJSON(&message); err != nil || message.State != "message" {
		t.Fatalf("healthy idle receiver expired: %+v %v", message, err)
	}
}

func TestRelaySilentConnectionStillTimesOut(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		_, _, _ = connection.ReadMessage()
	}))
	defer server.Close()
	connection, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := installRelayReceiveLiveness(connection, 50*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.ReadMessage(); err == nil {
		t.Fatal("silent connection retained indefinitely")
	}
}

func TestRelayRejectsDrainWithoutReconnectingOrCooldown(t *testing.T) {
	var connections, ready atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		defer connection.Close()
		connections.Add(1)
		_ = connection.WriteJSON(relayMessage{State: "challenge", Challenge: "continuous-receive-test"})
		var proof identity.DeviceProof
		if connection.ReadJSON(&proof) != nil {
			return
		}
		_ = connection.WriteJSON(relayMessage{State: "ready"})
		_ = connection.WriteJSON(relayMessage{State: "drained"})
	}))
	defer server.Close()
	now := time.Now().UTC()
	device, err := identity.NewDevice(iscpcrypto.NewProvider(), "domain", "device", now)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewRelayClient(ProfileLocalLab, "", EnrollmentBundle{DomainID: "domain", DeviceID: "device", RelayID: "relay", RelayBaseURL: server.URL, RelayWebSocketURL: "ws" + strings.TrimPrefix(server.URL, "http"), Access: RelayCredential{ExpiresAt: now.Add(time.Hour)}, Refresh: RelayCredential{ExpiresAt: now.Add(time.Hour)}, ExpiresAt: now.Add(time.Hour)}, device, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	client.credentialOnly = true
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	started := time.Now()
	err = client.RunOnceReady(ctx, func(context.Context, json.RawMessage) error { return nil }, func() { ready.Add(1) })
	if err == nil || !strings.Contains(err.Error(), "matched Relay update required") || connections.Load() != 1 || ready.Load() != 1 {
		t.Fatalf("drain silently polled: %v, connections=%d, ready=%d", err, connections.Load(), ready.Load())
	}
	if time.Since(started) >= 500*time.Millisecond {
		t.Fatal("unexpected fixed receive cooldown")
	}
}
