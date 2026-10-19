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

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
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

func TestRelayRejectsRetiredDrainFrame(t *testing.T) {
	client, _ := newDuplexClientFixture(t, false, func(ws *websocket.Conn, _ duplex.Frame) { _ = ws.WriteJSON(relayMessage{State: "drained"}) })
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var ready atomic.Int32
	err := client.RunOnceReady(ctx, nil, func() { ready.Add(1) })
	if err == nil || ready.Load() != 1 {
		t.Fatal("retired frame accepted", err)
	}
}
