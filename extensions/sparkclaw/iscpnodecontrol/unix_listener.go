package iscpnodecontrol

import (
	"errors"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// ListenPrivateUnix removes only a dead same-owner socket inode. An active
// process, ordinary file or replacement inode is preserved and startup fails.
func ListenPrivateUnix(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, n.ErrInvalid
	}
	st, e := os.Lstat(path)
	if e == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return nil, n.ErrConflict
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) {
			return nil, n.ErrDenied
		}
		conn, probe := net.Dial("unix", path)
		if probe == nil {
			conn.Close()
			return nil, n.ErrConflict
		}
		if !errors.Is(probe, syscall.ECONNREFUSED) && !errors.Is(probe, syscall.ENOENT) {
			return nil, n.ErrUnavailable
		}
		again, e := os.Lstat(path)
		if e != nil || !os.SameFile(st, again) {
			return nil, n.ErrConflict
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	l, e := net.Listen("unix", path)
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(path, 0600); e != nil {
		l.Close()
		return nil, e
	}
	return l, nil
}
