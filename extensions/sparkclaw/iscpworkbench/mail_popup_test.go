package iscpworkbench

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMailPopupPresentationBatchBoundDoesNotBroadenOtherParameters(t *testing.T) {
	ids := make([]string, 100)
	for i := range ids {
		ids[i] = strings.Repeat("a", 64)
	}
	raw, _ := json.Marshal(ids)
	request := Request{Type: RequestType, Profile: ProfileV2, ID: newUUID(), Operation: OperationMailPresentationsGet, Params: map[string]string{"target_kind": "mail", "language": "zh", "target_ids": string(raw)}}
	if err := request.Validate(); err != nil {
		t.Fatal("original popup 100-item batch rejected", err)
	}
	request.Params["target_ids"] = strings.Repeat("x", (32<<10)+1)
	if request.Validate() == nil {
		t.Fatal("unbounded presentation parameter accepted")
	}
	request.Operation = OperationMailConversationsList
	request.Params = map[string]string{"q": strings.Repeat("x", 1025)}
	if request.Validate() == nil {
		t.Fatal("presentation batch broadened scalar query limit")
	}
	request.Params = map[string]string{"target_ids": string(raw)}
	if request.Validate() == nil {
		t.Fatal("presentation batch escaped its exact operation")
	}
}
