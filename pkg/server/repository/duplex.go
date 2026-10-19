package repository

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/duplex"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/envelope"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/Infinimesh-ai/ISCP/pkg/server/postgres"
	"github.com/jackc/pgx/v5"
	"time"
)

type AdmissionResult struct {
	State, Reason, Code string
	Receipt             *duplex.Receipt
}

// ReconcileAdmission requires the caller's common authority+message-key lock.
// It never changes a record, expiry, priority or delivered state.
func ReconcileAdmission(ctx context.Context, tx pgx.Tx, domain, sender string, sub duplex.Submission, now time.Time) (AdmissionResult, error) {
	var raw []byte
	var foundSender, digest, history string
	var deadline, expires time.Time
	e := tx.QueryRow(ctx, `SELECT sender_device_id,envelope_digest,history_id,not_after,expires_at,receipt_raw FROM iscp_relay.admissions WHERE domain_id=$1 AND message_id=$2`, domain, sub.MessageID).Scan(&foundSender, &digest, &history, &deadline, &expires, &raw)
	if e == nil {
		if foundSender != sender || digest != sub.EnvelopeDigest || !deadline.Equal(duplex.Time(sub.NotAfter)) {
			return AdmissionResult{Code: "message_conflict"}, nil
		}
		if history != sub.HistoryID {
			return AdmissionResult{State: "unknown", Reason: "history_unavailable"}, nil
		}
		var r duplex.Receipt
		if json.Unmarshal(raw, &r) != nil {
			return AdmissionResult{}, errors.New("corrupt immutable receipt")
		}
		state := "accepted"
		if !now.Before(expires) {
			state = "expired"
		}
		return AdmissionResult{State: state, Receipt: &r}, nil
	}
	if e != pgx.ErrNoRows {
		return AdmissionResult{}, e
	}
	var legacy bool
	e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM iscp_relay.legacy_admission_keys WHERE domain_id=$1 AND message_id=$2 UNION ALL SELECT 1 FROM iscp_relay.messages WHERE domain_id=$1 AND message_id=$2 UNION ALL SELECT 1 FROM iscp_relay.delivery_receipts WHERE domain_id=$1 AND message_id=$2)`, domain, sub.MessageID).Scan(&legacy)
	if e != nil {
		return AdmissionResult{}, e
	}
	if legacy {
		return AdmissionResult{State: "unknown", Reason: "legacy_record"}, nil
	}
	return AdmissionResult{State: "absent"}, nil
}

// AdmitEnvelope inserts message+original signed acceptance in the caller's
// transaction. The caller emits accepted only after Commit succeeds.
func AdmitEnvelope(ctx context.Context, tx pgx.Tx, scope, domain, sender, relay string, sub duplex.Submission, signer identity.Device, now time.Time) (AdmissionResult, error) {
	result, e := ReconcileAdmission(ctx, tx, domain, sender, sub, now)
	if e != nil || result.State != "absent" {
		return result, e
	}
	var env envelope.SecureEnvelope
	if e = json.Unmarshal(sub.Envelope, &env); e != nil {
		return AdmissionResult{Code: "envelope_invalid"}, nil
	}
	if env.DomainID != domain || env.SenderDeviceID != sender || env.Route.RelayID != relay {
		return AdmissionResult{Code: "sender_mismatch"}, nil
	}
	deadline := duplex.Time(sub.NotAfter)
	if !now.Before(deadline) || deadline.After(now.Add(time.Duration(env.Route.TTLSeconds)*time.Second)) {
		return AdmissionResult{Code: "deadline_expired"}, nil
	}
	expires := now.Add(time.Duration(env.Route.TTLSeconds) * time.Second)
	if deadline.Before(expires) {
		expires = deadline
	}
	now = now.UTC().Truncate(time.Second)
	expires = expires.UTC().Truncate(time.Second)
	r, e := duplex.SignReceipt(crypto.NewProvider(), signer, duplex.Receipt{ReceiptID: crypto.Base64URL(crypto.RandomBytes(16)), RelayID: relay, DomainID: domain, HistoryID: sub.HistoryID, MessageID: sub.MessageID, SenderDeviceID: sender, RecipientDeviceID: env.RecipientDeviceID, EnvelopeDigest: sub.EnvelopeDigest, NotAfter: sub.NotAfter, AcceptedAt: duplex.Timestamp(now), ExpiresAt: duplex.Timestamp(expires)})
	if e != nil {
		return AdmissionResult{}, e
	}
	raw, _ := json.Marshal(r)
	canon, e := canonical.Marshal(raw)
	if e != nil {
		return AdmissionResult{}, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO iscp_relay.admissions(domain_id,message_id,scope_id,history_id,sender_device_id,recipient_device_id,envelope_digest,not_after,accepted_at,expires_at,receipt_raw,receipt_canonical) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, domain, sub.MessageID, scope, sub.HistoryID, sender, env.RecipientDeviceID, sub.EnvelopeDigest, deadline, now, expires, raw, canon); e != nil {
		return AdmissionResult{}, e
	}
	id, e := postgres.NewUUIDv7Like(now)
	if e != nil {
		return AdmissionResult{}, e
	}
	route, _ := json.Marshal(env.Route)
	encoded, e := canonical.Marshal(sub.Envelope)
	if e != nil {
		return AdmissionResult{}, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO iscp_relay.messages(id,domain_id,message_id,sender_device_id,recipient_device_id,session_id,payload_type,route_metadata,envelope_raw,envelope_canonical,priority,queued_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, postgres.UUIDString(id), domain, sub.MessageID, sender, env.RecipientDeviceID, env.SessionID, env.PayloadType, route, sub.Envelope, encoded, env.Route.Priority, now, expires)
	if e != nil {
		return AdmissionResult{}, e
	}
	return AdmissionResult{State: "accepted", Receipt: &r}, nil
}
