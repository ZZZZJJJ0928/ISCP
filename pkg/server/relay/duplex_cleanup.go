package iscprelayreference

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/Infinimesh-ai/ISCP/pkg/server/cleanup"
)

const (
	payloadCleanupInterval = 15 * time.Second
	payloadCleanupBudget   = 5 * time.Second
	payloadCleanupBatches  = 8
)

type payloadCleanupMetrics struct {
	runs, batches, deleted, errors atomic.Uint64
	lastSuccess                    atomic.Int64
}

func (m *payloadCleanupMetrics) write(w io.Writer) {
	for _, metric := range []struct {
		name, kind, help string
		value            uint64
	}{
		{"runs_total", "counter", "Payload cleanup passes started", m.runs.Load()},
		{"batches_total", "counter", "Payload cleanup batches committed", m.batches.Load()},
		{"deleted_total", "counter", "Delivered or expired payload rows removed", m.deleted.Load()},
		{"errors_total", "counter", "Payload cleanup passes that failed", m.errors.Load()},
		{"last_success_unixtime", "gauge", "Unix time of the latest committed cleanup batch", uint64(m.lastSuccess.Load())},
	} {
		name := "iscp_relay_payload_cleanup_" + metric.name
		_, _ = fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %d\n", name, metric.help, name, metric.kind, name, metric.value)
	}
}

// Each batch commits separately: a later deadline cannot erase earlier progress.
// A full pass is bounded in both rows and wall time, including lock acquisition.
func (s *Server) cleanupPayloads(ctx context.Context) {
	s.payloadCleanup.runs.Add(1)
	call, done := context.WithTimeout(ctx, payloadCleanupBudget)
	defer done()
	now := time.Now().UTC()
	for i := 0; i < payloadCleanupBatches; i++ {
		result, err := cleanup.PruneDuplexRelayMessages(call, s.cfg.DB, s.cfg.RelayID, s.cfg.DomainID, s.writerEpoch, now, false)
		if err != nil {
			if ctx.Err() == nil {
				s.payloadCleanup.errors.Add(1)
				// Database errors may contain data values. Keep the retry visible
				// without logging envelopes, credentials or query arguments.
				slog.Warn("Relay payload cleanup failed", "retry_seconds", int(payloadCleanupInterval/time.Second))
			}
			return
		}
		s.payloadCleanup.batches.Add(1)
		s.payloadCleanup.deleted.Add(uint64(result.Deleted))
		s.payloadCleanup.lastSuccess.Store(time.Now().Unix())
		if result.Deleted < cleanup.DuplexBatchSize {
			return
		}
	}
}

func (s *Server) startDuplexCleanup() {
	if s.cfg.DB == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.maintenanceCancel = cancel
	s.duplexWG.Add(1)
	go func() {
		defer s.duplexWG.Done()
		s.cleanupPayloads(ctx)
		tick := time.NewTicker(payloadCleanupInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				s.cleanupPayloads(ctx)
			}
		}
	}()
}
