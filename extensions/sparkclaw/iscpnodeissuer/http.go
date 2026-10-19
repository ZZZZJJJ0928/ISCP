package iscpnodeissuer

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type DeviceRecord struct {
	ClientID           string `json:"client_id"`
	InvitationID       string `json:"invitation_id"`
	Name               string `json:"name"`
	State              string `json:"state"`
	Revision           uint64 `json:"revision"`
	RevocationComplete bool   `json:"revocation_complete"`
}

func (i *Issuer) DeviceRecords(ctx context.Context) ([]DeviceRecord, error) {
	rows, e := i.store.List(ctx)
	if e != nil {
		return nil, e
	}
	out := []DeviceRecord{}
	for _, v := range rows {
		out = append(out, DeviceRecord{v.Credential.ClientID, v.Credential.InvitationID, v.ClientName, v.State, v.Revision, v.RelayRevoked})
	}
	return out, nil
}

// ManagementHandler is mounted only on the issuer's private Unix socket.
func (i *Issuer) ManagementHandler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || len(token) < 32 || len(got) != len(token) || subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			w.WriteHeader(401)
			return
		}
		if r.URL.RawQuery != "" {
			w.WriteHeader(400)
			return
		}
		if r.Method == "GET" && r.URL.Path == "/v1/devices" {
			out, e := i.DeviceRecords(r.Context())
			if e != nil {
				w.WriteHeader(503)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"schema_version": 1, "deployment_id": i.cfg.Template.DeploymentID, "devices": out})
			return
		}
		raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxFrameBytes))
		if e != nil {
			w.WriteHeader(400)
			return
		}
		if r.Method == "POST" && r.URL.Path == "/v1/invitations" {
			var req struct {
				ClientName       string   `json:"client_name"`
				OperationID      string   `json:"operation_id"`
				IdempotencyKey   string   `json:"idempotency_key,omitempty"`
				TTLSeconds       int      `json:"ttl_seconds,omitempty"`
				Scopes           []string `json:"scopes,omitempty"`
				OwnerID          string   `json:"owner_id"`
				DeploymentID     string   `json:"deployment_id"`
				ExistingClientID string   `json:"existing_client_id,omitempty"`
			}
			if StrictDecode(raw, &req) != nil {
				w.WriteHeader(400)
				return
			}
			if req.OwnerID != i.cfg.Template.OwnerID || req.DeploymentID != i.cfg.Template.DeploymentID || len(i.cfg.ApprovedScopes) == 0 {
				w.WriteHeader(403)
				return
			}
			if len(req.Scopes) > 0 && Digest(req.Scopes) != Digest(i.cfg.ApprovedScopes) {
				w.WriteHeader(403)
				return
			}
			key := req.OperationID
			if key == "" {
				key = req.IdempotencyKey
			}
			if req.TTLSeconds == 0 {
				req.TTLSeconds = 900
			}
			var encoded string
			var e error
			if req.ExistingClientID != "" {
				encoded, e = i.CreateMigrationInvitation(r.Context(), req.ClientName, time.Duration(req.TTLSeconds)*time.Second, i.cfg.ApprovedScopes, key, req.ExistingClientID)
			} else {
				encoded, e = i.CreateInvitation(r.Context(), req.ClientName, time.Duration(req.TTLSeconds)*time.Second, i.cfg.ApprovedScopes, key)
			}
			if e != nil {
				writeManagementError(w, e)
				return
			}
			credential, e := ParseCredential(encoded, i.Now(), false)
			if e != nil {
				writeManagementError(w, e)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"credential": encoded, "client_id": credential.ClientID, "invitation_id": credential.InvitationID, "revision": 1, "state": "issued"})
			return
		}
		if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/devices/") && strings.HasSuffix(r.URL.Path, "/revoke") {
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/devices/"), "/revoke")
			var req struct {
				OperationID      string `json:"operation_id"`
				Revision         uint64 `json:"revision,omitempty"`
				ExpectedRevision uint64 `json:"expected_revision,omitempty"`
			}
			if !identifier.MatchString(id) || StrictDecode(raw, &req) != nil {
				w.WriteHeader(400)
				return
			}
			revision := req.ExpectedRevision
			if revision == 0 {
				revision = req.Revision
			}
			rows, e := i.store.List(r.Context())
			if e != nil {
				writeManagementError(w, e)
				return
			}
			invitation := ""
			for _, s := range rows {
				if s.Credential.ClientID == id || s.Credential.InvitationID == id {
					invitation = s.Credential.InvitationID
					break
				}
			}
			if invitation == "" {
				w.WriteHeader(404)
				return
			}
			e = i.Revoke(r.Context(), invitation, req.OperationID, revision)
			if e != nil {
				writeManagementError(w, e)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"state": "revoked", "revision": revision + 1, "revocation_complete": true})
			return
		}
		http.NotFound(w, r)
	})
}
func writeManagementError(w http.ResponseWriter, e error) {
	status := 503
	if errors.Is(e, ErrDenied) {
		status = 403
	} else if errors.Is(e, ErrInvalid) {
		status = 400
	} else if errors.Is(e, ErrConflict) {
		status = 409
	} else if errors.Is(e, ErrExpired) {
		status = 410
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(WireError{Version: 1, Code: http.StatusText(status)})
}
