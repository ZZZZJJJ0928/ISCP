package iscprelayreference

import (
	"context"
	"github.com/Infinimesh-ai/ISCP/pkg/server/cleanup"
	"time"
)

func (s *Server) startDuplexCleanup() {
	if s.cfg.DB == nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.maintenanceCancel = cancel
	s.duplexWG.Add(1)
	go func() {
		defer s.duplexWG.Done()
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-tick.C:
				call, done := context.WithTimeout(ctx, 5*time.Second)
				_, _ = cleanup.ExpiredDuplexRelayMessages(call, s.cfg.DB, s.cfg.RelayID, s.cfg.DomainID, s.writerEpoch, now, false)
				done()
			}
		}
	}()
}
