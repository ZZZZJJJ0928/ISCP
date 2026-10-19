package iscpbridge

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// ValidateWorkbenchRelayURLs preserves production TLS and confines explicit
// reference local-lab connections to loopback or the isolated Docker alias.
func ValidateWorkbenchRelayURLs(profile, baseURL, websocketURL string) error {
	if profile == "" {
		profile = ProfileProduction
	}
	if profile == ProfileProduction {
		if err := validateRelayURLs(ProfileProduction, baseURL, websocketURL); err != nil {
			return err
		}
		for _, raw := range []string{baseURL, websocketURL} {
			u, _ := url.Parse(raw)
			if u.Fragment != "" {
				return errors.New("workbench Relay URLs must not contain fragments")
			}
		}
		return nil
	}
	if profile != ProfileLocalLab {
		return errors.New("unsupported workbench Relay profile")
	}
	for i, raw := range []string{baseURL, websocketURL} {
		u, err := url.Parse(raw)
		expected := "http"
		if i == 1 {
			expected = "ws"
		}
		if err != nil || u.Scheme != expected || u.User != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
			return errors.New("local-lab Relay requires plain local HTTP/ws URLs without credentials")
		}
		host := strings.ToLower(u.Hostname())
		ip := net.ParseIP(host)
		if host != "localhost" && host != "iscp-relay" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("local-lab Relay host must be loopback or iscp-relay")
		}
		if (i == 0 && strings.Trim(u.Path, "/") != "") || (i == 1 && u.Path != "/v2/relay/duplex") {
			return errors.New("local-lab Relay endpoint path is invalid")
		}
	}
	return nil
}

// ValidateNodeRelayURLs freezes the single IP origin selected for this
// deployment. A signed bundle still cannot redirect WSS or control traffic to
// another host/port, accept URL credentials, or introduce a second ingress.
func ValidateNodeRelayURLs(baseURL, websocketURL string) error {
	base, err := url.Parse(baseURL)
	if err != nil {
		return errors.New("invalid node Relay origin")
	}
	ws, err := url.Parse(websocketURL)
	if err != nil {
		return errors.New("invalid node Relay WSS endpoint")
	}
	if base.Scheme != "https" || ws.Scheme != "wss" || net.ParseIP(base.Hostname()) == nil || base.Host != ws.Host || base.User != nil || ws.User != nil || base.Path != "" || ws.Path != "/v2/relay/duplex" || base.RawQuery != "" || ws.RawQuery != "" || base.Fragment != "" || ws.Fragment != "" || base.Opaque != "" || ws.Opaque != "" || baseURL != base.String() || websocketURL != ws.String() {
		return errors.New("node-managed Relay requires one canonical IP HTTPS/WSS origin")
	}
	return nil
}
