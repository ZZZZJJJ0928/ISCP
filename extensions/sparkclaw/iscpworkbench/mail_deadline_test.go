package iscpworkbench

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestMailRPCBudgetsAllowBoundedUploadsAndPreserveCancellation(t *testing.T) {
	initiator, _, _ := profileEndpoints(t, true, true, func(ctx context.Context, request Request) Response {
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Error("missing operation deadline")
		}
		remaining := time.Until(deadline)
		want := 30 * time.Second
		if request.Operation == OperationMailDraftsSave || request.Operation == OperationMailDraftsSend || request.Operation == OperationMailDraftsReconcile || request.Operation == OperationMailSend || request.Operation == OperationMailProvidersCheck || request.Operation == OperationMailProvidersLogin || request.Operation == OperationMailIntakeUpdate || request.Operation == OperationMailRepliesPolish || request.Operation == OperationMailSourceCleanup || request.Operation == OperationMailConversationsDelete {
			want = 180 * time.Second
		}
		if remaining > want || remaining < want-time.Second {
			t.Errorf("%s handler budget %v, expected %v", request.Operation, remaining, want)
		}
		if string(request.Body) == `{"wait_for_cancel":true}` {
			<-ctx.Done()
		}
		return Response{Status: 200, Body: json.RawMessage(`{}`)}
	})
	for _, op := range []string{OperationMailDraftsSave, OperationMailDraftsSend, OperationMailDraftsReconcile, OperationMailSend, OperationMailProvidersCheck, OperationMailProvidersLogin, OperationMailIntakeUpdate, OperationMailRepliesPolish, OperationMailSourceCleanup, OperationMailConversationsDelete, OperationMailDraftsList, OperationTransferChunk, OperationSettingsOwnerGet} {
		r := Request{Type: RequestType, Profile: ProfileV2, ID: newUUID(), Operation: op, OperationID: newUUID(), Body: json.RawMessage(`{}`)}
		response, err := initiator.Call(t.Context(), r)
		if err != nil || response.Status != 200 {
			t.Fatalf("%s call %+v %v", op, response, err)
		}
	}
	for _, op := range []string{OperationMailDraftsSend, OperationMailDraftsReconcile} {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		start := time.Now()
		_, err := initiator.Call(ctx, Request{Type: RequestType, Profile: ProfileV2, ID: newUUID(), Operation: op, OperationID: newUUID(), Body: json.RawMessage(`{"wait_for_cancel":true}`)})
		cancel()
		if err == nil || time.Since(start) > time.Second {
			t.Fatal("mail budget ignored earlier caller cancellation", op, err)
		}
	}
}
