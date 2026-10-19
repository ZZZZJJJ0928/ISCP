package iscprelayreference

import (
	"github.com/Infinimesh-ai/ISCP/pkg/server/httpx"
	"net/http"
)

func (s *Server) serviceRecover(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Managed == nil {
		http.NotFound(w, r)
		return
	}
	raw, err := s.cfg.Managed.ServiceRecover(r)
	if err != nil {
		httpx.WriteError(w, managedStatus(err), err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(raw)
}

// MarkRevoked also closes live receive loops after durable revocation.
func (s *Server) MarkRevoked(deviceID string) {
	s.InvalidateDevice(deviceID)
	s.mu.Lock()
	s.revoked[deviceID] = struct{}{}
	s.mu.Unlock()
	s.stopReceiver(s.cfg.DomainID, deviceID)
}

func managedStatus(err error) int {
	if v, ok := err.(interface{ StatusCode() int }); ok {
		return v.StatusCode()
	}
	return http.StatusServiceUnavailable
}

// InvalidateDevice discards credential/identity caches only after the durable
// transaction commits. The next request checks the repository's current state.
func (s *Server) InvalidateDevice(deviceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.access {
		if c.DeviceID == deviceID {
			delete(s.access, k)
		}
	}
	for k, c := range s.refresh {
		if c.DeviceID == deviceID {
			delete(s.refresh, k)
		}
	}
	delete(s.devices, deviceID)
}
