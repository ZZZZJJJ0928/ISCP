package iscpnodecontrol

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"

	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
)

var issuerRoutePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)

const MaxForwarderNodes = 16

type ForwarderNodeConfig struct {
	IssuerRoute    string `json:"issuer_route"`
	PeerConfigFile string `json:"peer_config_file"`
	RelaySocket    string `json:"relay_socket"`
}
type ForwarderConfig struct {
	SchemaVersion  int                   `json:"schema_version"`
	Bind           string                `json:"bind"`
	IssuerRoute    string                `json:"issuer_route,omitempty"`
	PeerConfigFile string                `json:"peer_config_file,omitempty"`
	RelaySocket    string                `json:"relay_socket,omitempty"`
	Nodes          []ForwarderNodeConfig `json:"nodes,omitempty"`
}

func (c ForwarderConfig) Validate() error {
	host, _, e := net.SplitHostPort(c.Bind)
	if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return n.ErrInvalid
	}
	var nodes []ForwarderNodeConfig
	switch c.SchemaVersion {
	case 1:
		if len(c.Nodes) != 0 {
			return n.ErrInvalid
		}
		nodes = []ForwarderNodeConfig{{c.IssuerRoute, c.PeerConfigFile, c.RelaySocket}}
	case 2:
		if c.IssuerRoute != "" || c.PeerConfigFile != "" || c.RelaySocket != "" || len(c.Nodes) == 0 || len(c.Nodes) > MaxForwarderNodes {
			return n.ErrInvalid
		}
		nodes = c.Nodes
	default:
		return n.ErrInvalid
	}
	routes, peers, sockets := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, v := range nodes {
		if !issuerRoutePattern.MatchString(v.IssuerRoute) || routes[v.IssuerRoute] || !filepath.IsAbs(v.PeerConfigFile) || filepath.Clean(v.PeerConfigFile) != v.PeerConfigFile || peers[v.PeerConfigFile] || !filepath.IsAbs(v.RelaySocket) || filepath.Clean(v.RelaySocket) != v.RelaySocket || sockets[v.RelaySocket] {
			return n.ErrInvalid
		}
		routes[v.IssuerRoute] = true
		peers[v.PeerConfigFile] = true
		sockets[v.RelaySocket] = true
	}
	return nil
}
func (c ForwarderConfig) NodeConfigs() []ForwarderNodeConfig {
	if c.SchemaVersion == 1 {
		return []ForwarderNodeConfig{{c.IssuerRoute, c.PeerConfigFile, c.RelaySocket}}
	}
	return append([]ForwarderNodeConfig(nil), c.Nodes...)
}

// Exact public routing does not confer authority. The selected node's unchanged
// handler validates the signed control identity or encrypted issuer exchange.
func NewForwarderRouter(forwarders []*Forwarder) (http.Handler, error) {
	if len(forwarders) == 0 || len(forwarders) > MaxForwarderNodes {
		return nil, n.ErrInvalid
	}
	routes := map[string]http.Handler{}
	for _, f := range forwarders {
		if f == nil || !issuerRoutePattern.MatchString(f.Route) || routes[f.Route] != nil {
			return nil, n.ErrInvalid
		}
		routes[f.Route] = f.Handler()
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.Path != n.ExchangePath && r.URL.Path != ControlGrantPath {
			http.NotFound(w, r)
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, n.MaxFrameBytes))
		if e != nil {
			writeError(w, 400, "invalid")
			return
		}
		route := ""
		if r.URL.Path == n.ExchangePath {
			var req n.Exchange
			if n.StrictDecode(raw, &req) != nil || req.Validate() != nil {
				writeError(w, 400, "invalid")
				return
			}
			route = req.IssuerRoute
		} else {
			var req ControlGrantUpdate
			if n.StrictDecode(raw, &req) != nil || req.Version != 1 || !issuerRoutePattern.MatchString(req.IssuerRoute) {
				writeError(w, 400, "invalid")
				return
			}
			route = req.IssuerRoute
		}
		h := routes[route]
		if h == nil {
			writeError(w, 403, "denied")
			return
		}
		r = r.Clone(r.Context())
		r.Body = io.NopCloser(bytes.NewReader(raw))
		h.ServeHTTP(w, r)
	}), nil
}

func ValidatePeerSet(peers []*Peer) error {
	devices, keys := map[string]int{}, map[string]int{}
	for i, p := range peers {
		if p == nil || p.cfg.Initiator {
			return n.ErrInvalid
		}
		for _, id := range []identity.DeviceIdentity{p.cfg.Device.Identity, p.cfg.Peer, p.cfg.Issuer} {
			if owner, ok := devices[id.DeviceID]; ok && owner != i {
				return n.ErrInvalid
			}
			if owner, ok := keys[id.PublicKey.Public]; ok && owner != i {
				return n.ErrInvalid
			}
			devices[id.DeviceID] = i
			keys[id.PublicKey.Public] = i
		}
	}
	return nil
}
