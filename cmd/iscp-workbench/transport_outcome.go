package main

import (
	"encoding/json"
	"errors"
	"regexp"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpworkbench"
)

var relayMessageID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$`)

func relaySubmissionFrame(endpoint caller, frame callFrame) map[string]any {
	out := map[string]any{"ipc_version": ipcVersion, "type": "relay_submission_status", "id": frame.ID, "message_id": frame.MessageID, "found": false}
	if source, ok := endpoint.(interface {
		RelaySubmissionStatus(string) (iscpbridge.RelaySubmissionStatus, bool)
	}); ok {
		if status, found := source.RelaySubmissionStatus(frame.MessageID); found {
			out["found"], out["submission"] = true, status
		}
	}
	return out
}

// Local pipe metadata binds an uncertain Relay admission to the original RPC.
// It never exports ciphertext, proof, token or a replacement operation ID.
func transportOutcome(response *iscpworkbench.Response, err error) {
	var unknown *iscpbridge.UnknownAcceptance
	if !errors.As(err, &unknown) {
		return
	}
	s := unknown.Submission
	response.Status = 503
	response.Error = "ISCP transport outcome is unknown"
	response.Retryable = false
	if response.Profile == iscpworkbench.ProfileV2 {
		response.Code = iscpworkbench.ErrorOutcomeUnknown
	}
	response.Body, _ = json.Marshal(map[string]any{
		"error": response.Error, "code": "transport_outcome_unknown", "retryable": false,
		"relay_submission": map[string]string{"message_id": s.MessageID, "envelope_digest": s.EnvelopeDigest, "not_after": s.NotAfter, "history_id": s.HistoryID, "session_id": s.SessionID},
	})
}
