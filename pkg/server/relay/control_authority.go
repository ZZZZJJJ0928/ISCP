package iscprelayreference

import "github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"

// ControlAuthority shares the Relay signer and this process's fixed writer
// epoch with the in-process control service. An epoch change fences this
// process; neither control requests nor new sockets can adopt the new epoch.
func (s *Server) ControlAuthority() (identity.Device, string) {
	return s.signer, s.writerEpoch
}
