package iscpnodecontrol

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	control "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpcontrol"
	n "github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpnodeissuer"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"io"
	"net/http"
	"strings"
	"time"
)

func PinnedControlHTTP(origin, certificate string) (*http.Client, error) {
	if n.ValidateOrigin(origin, certificate, time.Now().UTC(), true) != nil {
		return nil, n.ErrInvalid
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(certificate)) {
		return nil, n.ErrInvalid
	}
	return &http.Client{Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, ResponseHeaderTimeout: 15 * time.Second, MaxIdleConnsPerHost: 4}, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return n.ErrDenied }}, nil
}

type HTTPControlRelay struct{ client *control.Client }

func NewHTTPControlRelay(origin, certificate, relayID string, actor identity.Device, relaySigner identity.DeviceIdentity) (*HTTPControlRelay, error) {
	h, err := PinnedControlHTTP(origin, certificate)
	if err != nil {
		return nil, err
	}
	client, err := control.NewClient(origin, relayID, actor, relaySigner, h)
	if err != nil {
		return nil, err
	}
	return &HTTPControlRelay{client}, nil
}
func (r *HTTPControlRelay) Actor() identity.DeviceIdentity { return r.client.Device.Identity }
func (r *HTTPControlRelay) Attempt(ctx context.Context, q control.Request, token string) (control.Outcome, error) {
	return r.client.Attempt(ctx, q, token)
}
func (r *HTTPControlRelay) Authority(ctx context.Context, subject control.Subject, target control.Target) (n.ControlAuthority, error) {
	return r.client.Authority(ctx, subject, target)
}

// NewHTTPSControlTarget forwards only the fixed control paths to a configured,
// pinned HTTPS service. It never derives an origin from request content.
func NewHTTPSControlTarget(origin, certificate string) (http.Handler, error) {
	client, err := PinnedControlHTTP(origin, certificate)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.RawQuery != "" || !(r.URL.Path == control.ChallengePath || strings.HasPrefix(r.URL.Path, control.OperationPath)) {
			http.NotFound(w, r)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, control.MaxBody+1))
		if err != nil || len(raw) > control.MaxBody {
			http.Error(w, "invalid control request", 400)
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), "POST", strings.TrimRight(origin, "/")+r.URL.Path, bytes.NewReader(raw))
		if err != nil {
			http.Error(w, "control unavailable", 503)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		if token := r.Header.Get("Authorization"); token != "" {
			req.Header.Set("Authorization", token)
		}
		response, err := client.Do(req)
		if err != nil {
			http.Error(w, "control unavailable", 503)
			return
		}
		defer response.Body.Close()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(response.Body, control.MaxBody+1))
	}), nil
}
