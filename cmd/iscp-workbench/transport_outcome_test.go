package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpbridge"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpworkbench"
)

type submissionCaller struct{ pipeCaller }

func (*submissionCaller) RelaySubmissionStatus(id string) (iscpbridge.RelaySubmissionStatus, bool) {
	return iscpbridge.RelaySubmissionStatus{MessageID: id, SessionID: "original-session", State: "absent"}, true
}

func TestPrivateSubmissionLookupRetainsTransportAbsenceWithoutBusinessCall(t *testing.T) {
	input := `{"ipc_version":1,"type":"relay_submission_status","id":"query","message_id":"original-message"}` + "\n"
	endpoint := &submissionCaller{}
	var output bytes.Buffer
	if err := serve(context.Background(), strings.NewReader(input), &ipcWriter{writer: &output}, endpoint); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Found      bool                             `json:"found"`
		Submission iscpbridge.RelaySubmissionStatus `json:"submission"`
	}
	if json.Unmarshal(output.Bytes(), &result) != nil || !result.Found || result.Submission.State != "absent" || result.Submission.MessageID != "original-message" || len(endpoint.body) != 0 {
		t.Fatal("status lookup invoked business or lost original tuple", output.String())
	}
	for _, invalid := range []string{strings.Replace(input, "original-message", "../secret", 1), strings.Replace(input, `"message_id"`, `"token"`, 1), strings.Replace(input, `"message_id":`, `"operation_id":"new-effect","message_id":`, 1)} {
		if _, err := decodeCall([]byte(invalid)); err == nil {
			t.Fatal("invalid private query accepted")
		}
	}
}

func TestUnknownAdmissionRetainsOnlyOriginalMetadataOnPrivatePipe(t *testing.T) {
	sub := iscpbridge.RelaySubmission{MessageID: "original-message", EnvelopeDigest: "original-digest", HistoryID: "original-history", NotAfter: "2026-10-19T13:00:00Z", SessionID: "original-session", Envelope: json.RawMessage(`{"ciphertext":"private-ciphertext"}`)}
	for _, profile := range []string{iscpworkbench.Profile, iscpworkbench.ProfileV2} {
		response := iscpworkbench.Response{Type: iscpworkbench.ResponseType, Profile: profile, ID: "00000000-0000-4000-8000-000000000001"}
		transportOutcome(&response, fmt.Errorf("send original: %w", &iscpbridge.UnknownAcceptance{Submission: sub}))
		if response.Validate() != nil || response.Status != 503 || response.Retryable {
			t.Fatal("invalid unknown response", response)
		}
		var body struct {
			Code       string            `json:"code"`
			Submission map[string]string `json:"relay_submission"`
		}
		if json.Unmarshal(response.Body, &body) != nil || body.Code != "transport_outcome_unknown" || len(body.Submission) != 5 || body.Submission["message_id"] != sub.MessageID || body.Submission["not_after"] != sub.NotAfter || strings.Contains(string(response.Body), "ciphertext") {
			t.Fatal("original tuple lost or private material leaked", string(response.Body))
		}
	}
}
