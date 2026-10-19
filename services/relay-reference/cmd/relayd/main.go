package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/config"
	iscplog "github.com/Infinimesh-ai/ISCP/pkg/iscp/logging"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	relay "github.com/Infinimesh-ai/ISCP/pkg/server/relay"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{ReplaceAttr: iscplog.ReplaceAttr}))
	ctx := context.Background()
	db, err := openDatabase(ctx, logger)
	if err != nil {
		logger.Error("relay database init failed", "error", err)
		os.Exit(1)
	}
	if db != nil {
		defer db.Close()
	}
	cfg := relay.Config{
		SignerFile:     os.Getenv("ISCP_RELAY_SIGNER_FILE"),
		DomainID:       env("ISCP_DOMAIN_ID", "local"),
		RelayID:        env("ISCP_RELAY_ID", "relay-local"),
		BaseURL:        env("ISCP_RELAY_BASE_URL", "http://localhost:8080"),
		WebSocketURL:   env("ISCP_RELAY_WS_URL", "ws://localhost:8080/v2/relay/connect"),
		ProfileGate:    config.DefaultGate(config.LoadProfileFromEnv(config.ProfileLocalLab)),
		DB:             db,
		AdminToken:     os.Getenv("ISCP_ADMIN_TOKEN"),
		AllowedOrigins: splitCSV(os.Getenv("ISCP_ALLOWED_ORIGINS")),
	}
	srv, err := relay.New(cfg)
	if err != nil {
		logger.Error("relay init failed", "error", err)
		os.Exit(1)
	}
	defer srv.Close()
	addr := env("ISCP_RELAY_ADDR", ":8080")
	logger.Info("relay starting", "addr", addr)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	if err := httpServer.ListenAndServe(); err != nil {
		logger.Error("relay stopped", "error", err)
		os.Exit(1)
	}
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if item := strings.TrimSpace(part); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func openDatabase(ctx context.Context, logger *slog.Logger) (*pgxpool.Pool, error) {
	dsn := os.Getenv("ISCP_DATABASE_URL")
	if dsn == "" {
		logger.Info("relay database disabled; using in-memory state")
		return nil, nil
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	migrations, err := postgres.EmbeddedMigrations()
	if err != nil {
		pool.Close()
		return nil, err
	}
	if err := postgres.ApplyMigrations(ctx, pool, migrations); err != nil {
		pool.Close()
		return nil, err
	}
	if err := relay.PrepareDatabase(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	logger.Info("relay database ready")
	return pool, nil
}
