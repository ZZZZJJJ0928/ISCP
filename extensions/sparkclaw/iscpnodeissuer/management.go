package iscpnodeissuer

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"time"
)

type GatewayManagement struct {
	http     *http.Client
	token    string
	expected Binding
}

func NewGatewayManagement(socket, token string, binding Binding) (*GatewayManagement, error) {
	if !filepath.IsAbs(socket) || len(token) < 32 || binding.OwnerID == "" || binding.DeploymentID == "" {
		return nil, ErrInvalid
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrDenied }}
	return &GatewayManagement{client, token, binding}, nil
}
func (m *GatewayManagement) call(ctx context.Context, method, path, key string, in, out any) (int, error) {
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	req, e := http.NewRequestWithContext(ctx, method, "http://local"+path, bytes.NewReader(body))
	if e != nil {
		return 0, ErrInvalid
	}
	req.Header.Set("Authorization", "Bearer "+m.token)
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	res, e := m.http.Do(req)
	if e != nil {
		return 0, ErrUnknownOutcome
	}
	defer res.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if e != nil {
		return res.StatusCode, ErrUnavailable
	}
	if out != nil && json.Unmarshal(raw, out) != nil {
		return res.StatusCode, ErrUnavailable
	}
	return res.StatusCode, nil
}
func (m *GatewayManagement) Identity(ctx context.Context) (Binding, error) {
	var out struct {
		DeploymentID string `json:"deployment_id"`
		OwnerID      string `json:"owner_id"`
		ClientID     string `json:"client_id"`
	}
	status, e := m.call(ctx, "GET", "/api/workbench/identity", "", nil, &out)
	if e != nil || status != 200 {
		return Binding{}, ErrUnavailable
	}
	b := Binding{out.DeploymentID, out.OwnerID, out.ClientID}
	if b.DeploymentID != m.expected.DeploymentID || b.OwnerID != m.expected.OwnerID {
		return Binding{}, ErrDenied
	}
	return b, nil
}

type managedClient struct {
	ID        string     `json:"id"`
	OwnerID   string     `json:"owner_id"`
	ActorID   string     `json:"actor_id"`
	Name      string     `json:"name"`
	RevokedAt *time.Time `json:"revoked_at"`
}

func (m *GatewayManagement) clients(ctx context.Context) ([]managedClient, error) {
	var out struct {
		Clients []managedClient `json:"clients"`
	}
	status, e := m.call(ctx, "GET", "/api/clients", "", nil, &out)
	if e != nil || status != 200 {
		return nil, ErrUnavailable
	}
	return out.Clients, nil
}
func (m *GatewayManagement) Client(ctx context.Context, id string) (bool, error) {
	rows, e := m.clients(ctx)
	if e != nil {
		return false, e
	}
	for _, v := range rows {
		if v.ID == id {
			return v.OwnerID == m.expected.OwnerID && v.RevokedAt == nil, nil
		}
	}
	return false, nil
}
func (m *GatewayManagement) CreateClient(ctx context.Context, name, key string) (string, error) {
	id := StableClientID(m.expected.OwnerID, key)
	rows, e := m.clients(ctx)
	if e != nil {
		return "", e
	}
	for _, v := range rows {
		if v.ID == id {
			if v.OwnerID != m.expected.OwnerID || v.Name != name || v.RevokedAt != nil {
				return "", ErrConflict
			}
			return id, nil
		}
	}
	var out struct {
		Client   managedClient `json:"client"`
		Code     string        `json:"code"`
		ClientID string        `json:"client_id"`
	}
	status, e := m.call(ctx, "POST", "/api/clients", key, map[string]string{"client_name": name}, &out)
	// Any unknown outcome is reconciled against the same deterministic ID. The
	// one-time token can expire, but it is not used by the ISCP client.
	if e != nil || status != 200 && status != 201 {
		rows, re := m.clients(ctx)
		if re != nil {
			return "", ErrUnknownOutcome
		}
		for _, v := range rows {
			if v.ID == id && v.OwnerID == m.expected.OwnerID && v.Name == name && v.RevokedAt == nil {
				return id, nil
			}
		}
		return "", ErrUnknownOutcome
	}
	if out.Client.ID != id || out.Client.OwnerID != m.expected.OwnerID || out.Client.Name != name || out.Client.RevokedAt != nil {
		return "", ErrDenied
	}
	return id, nil
}
func (m *GatewayManagement) RevokeManagedClient(ctx context.Context, id string) error {
	ok, e := m.Client(ctx, id)
	if e != nil {
		return e
	}
	if !ok {
		return nil
	}
	status, e := m.call(ctx, "POST", "/api/clients/"+url.PathEscape(id)+"/revoke", "", map[string]any{}, nil)
	if e != nil {
		return ErrUnknownOutcome
	}
	if status != 200 {
		return ErrUnavailable
	}
	return nil
}
