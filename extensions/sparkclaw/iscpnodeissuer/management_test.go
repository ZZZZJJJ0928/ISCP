package iscpnodeissuer

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGatewayManagementReconcilesStableClientAfterLostTokenReceipt(t *testing.T) {
	dir, e := os.MkdirTemp(os.TempDir(), "node-m-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "gateway.sock")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	owner, key, name := "owner", "original-issued-operation", "SparkX"
	id := StableClientID(owner, key)
	persisted := false
	calls := 0
	token := strings.Repeat("synthetic", 5)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/api/workbench/identity":
			_ = json.NewEncoder(w).Encode(Binding{"deployment", owner, "management-client"})
		case r.Method == "GET" && r.URL.Path == "/api/clients":
			clients := []managedClient{}
			if persisted {
				clients = append(clients, managedClient{ID: id, OwnerID: owner, Name: name})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"clients": clients})
		case r.Method == "POST" && r.URL.Path == "/api/clients":
			calls++
			if r.Header.Get("Idempotency-Key") != key {
				t.Error("operation changed")
			}
			persisted = true
			w.WriteHeader(409)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "CLIENT_CREDENTIAL_UNRECOVERABLE", "client_id": id})
		default:
			w.WriteHeader(404)
		}
	})}
	go server.Serve(listener)
	defer server.Close()
	m, e := NewGatewayManagement(socket, token, Binding{DeploymentID: "deployment", OwnerID: owner})
	if e != nil {
		t.Fatal(e)
	}
	created, e := m.CreateClient(context.Background(), name, key)
	if e != nil || created != id {
		t.Fatal(created, e)
	}
	again, e := m.CreateClient(context.Background(), name, key)
	if e != nil || again != id || calls != 1 {
		t.Fatal("Client recreated", e, calls)
	}
	if _, e = m.CreateClient(context.Background(), "different name", key); e == nil {
		t.Fatal("metadata continuity not checked")
	}
}
