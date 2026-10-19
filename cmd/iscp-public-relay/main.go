// iscp-public-relay keeps the pinned reference transport and adds a local-only
// managed transaction socket. TLS is terminated by the existing TEST1 ingress.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	ctl "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodecontrol"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscprelayadapter"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	ref "github.com/Infinimesh-ai/ISCP/pkg/server/relay"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	if e := run(); e != nil {
		slog.Error("public Relay stopped", "reason", "startup_or_runtime_failed")
		os.Exit(1)
	}
}
func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	dsn := os.Getenv("ISCP_DATABASE_URL")
	if dsn == "" {
		return errors.New("persistent database required")
	}
	startup, stop := context.WithTimeout(ctx, 30*time.Second)
	defer stop()
	pool, e := pgxpool.New(startup, dsn)
	if e != nil {
		return e
	}
	defer pool.Close()
	migrations, e := postgres.EmbeddedMigrations()
	if e != nil {
		return e
	}
	if e = postgres.ApplyMigrations(startup, pool, migrations); e != nil {
		return e
	}
	if e = ref.PrepareDatabase(startup, pool); e != nil {
		return e
	}
	cfg := ref.Config{SignerFile: os.Getenv("ISCP_SIGNER_FILE"), DomainID: env("ISCP_DOMAIN_ID", "infinimesh-public"), RelayID: env("ISCP_RELAY_ID", "relay-210-16-177-239"), BaseURL: env("ISCP_RELAY_BASE_URL", "https://210.16.177.239"), WebSocketURL: env("ISCP_RELAY_WS_URL", "wss://210.16.177.239/v2/relay/connect"), ProfileGate: config.DefaultGate(config.ProfileProduction), DB: pool, AdminToken: os.Getenv("ISCP_ADMIN_TOKEN"), AllowedOrigins: strings.Split(os.Getenv("ISCP_ALLOWED_ORIGINS"), ",")}
	var managed ref.ManagedAdapter
	var nodes []iscprelayadapter.ScopedNode
	var manager *iscprelayadapter.Manager
	if p := os.Getenv("ISCP_NODE_AUTHORITY_FILE"); p != "" {
		b, e := ctl.ReadPrivateBytes(p)
		var fields map[string]json.RawMessage
		if e != nil || iscpnodeissuer.StrictDecode(b, &fields) != nil {
			return errors.New("invalid node authority file")
		}
		version := 0
		if raw, ok := fields["schema_version"]; ok && json.Unmarshal(raw, &version) != nil {
			return errors.New("invalid authority version")
		}
		if version == 2 {
			var nc iscprelayadapter.MultiConfig
			if iscpnodeissuer.StrictDecode(b, &nc) != nil || nc.DomainID != cfg.DomainID || nc.RelayID != cfg.RelayID {
				return errors.New("invalid authority scope")
			}
			manager, e = iscprelayadapter.NewManager(startup, pool, nc)
			if e != nil {
				return e
			}
			managed = manager
			nodes = manager.Nodes()
		} else {
			var nc iscprelayadapter.Config
			if iscpnodeissuer.StrictDecode(b, &nc) != nil || nc.DomainID != cfg.DomainID || nc.RelayID != cfg.RelayID {
				return errors.New("invalid authority scope")
			}
			a, e := iscprelayadapter.New(startup, pool, nc)
			if e != nil {
				return e
			}
			managed = a
			nodes = []iscprelayadapter.ScopedNode{{ManagedSocket: os.Getenv("ISCP_MANAGED_SOCKET"), Adapter: a}}
			cfg.TicketIssuer = &nc.InvitationSigner
		}
		cfg.Managed = managed
	}
	relay, e := ref.New(cfg)
	if e != nil {
		return e
	}
	defer relay.Close()
	for _, node := range nodes {
		node.Adapter.Invalidate = relay.InvalidateDevice
		node.Adapter.MarkRevoked = relay.MarkRevoked
	}
	public := server(env("ISCP_RELAY_ADDR", "127.0.0.1:55117"), relay.Handler())
	var private []*http.Server
	var listeners []net.Listener
	// Bind every private authority before exposing public traffic. One failed
	// socket never silently drops a node or leaves a partial public deployment.
	for _, node := range nodes {
		listener, e := ctl.ListenPrivateUnix(node.ManagedSocket)
		if e != nil {
			return e
		}
		defer listener.Close()
		defer os.Remove(node.ManagedSocket)
		if e = os.Chmod(node.ManagedSocket, 0o660); e != nil {
			return e
		}
		listeners = append(listeners, listener)
		private = append(private, server("", node.Adapter.Handler()))
	}
	errs := make(chan error, len(private)+1)
	go func() { errs <- public.ListenAndServe() }()
	for i, p := range private {
		go func() { errs <- p.Serve(listeners[i]) }()
	}
	slog.Info("public Relay ready", "managed", managed != nil, "profile", "production")
	select {
	case <-ctx.Done():
	case e = <-errs:
		cancel()
	}
	shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	relay.Close()
	_ = public.Shutdown(shutdown)
	for _, p := range private {
		_ = p.Shutdown(shutdown)
	}
	if e != nil && !errors.Is(e, http.ErrServerClosed) {
		return e
	}
	return nil
}
func server(addr string, h http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 << 10}
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
