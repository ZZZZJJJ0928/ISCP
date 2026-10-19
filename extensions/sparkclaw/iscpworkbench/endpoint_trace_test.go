package iscpworkbench

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Infinimesh-ai/ISCP/internal/latencytrace"
)

func TestPrivateLatencyTraceCorrelatesEncryptedRPC(t *testing.T) {
	if os.Getenv("SPARKCLAW_TRACE_TEST_CHILD") != "1" {
		directory := filepath.Join(t.TempDir(), "private-trace")
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestPrivateLatencyTraceCorrelatesEncryptedRPC$", "-test.timeout=15s")
		cmd.Env = append(os.Environ(), "SPARKCLAW_TRACE_TEST_CHILD=1", latencytrace.Environment+"="+directory)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("trace integration failed: %v\n%s", err, output)
		}
		return
	}
	initiator, _, _, _ := testEndpoints(t, func(context.Context, Request) Response {
		return Response{Status: 200, Body: json.RawMessage(`{"private":"never traced"}`)}
	})
	rpcID, requestID := newUUID(), newUUID()
	response, err := initiator.Call(t.Context(), Request{Type: RequestType, Profile: Profile, ID: rpcID, Operation: OperationLookup, RequestID: requestID})
	if err != nil || response.Status != 200 {
		t.Fatal("trace changed encrypted call result", err)
	}
	want := map[string]bool{"rpc.call.start": false, "rpc.call": false, "rpc.send_authorization": false, "rpc.request_received": false, "rpc.request_authorization": false, "rpc.handler": false, "rpc.encrypted_received": false, "rpc.response_authorization": false, "rpc.delivered": false}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		files, err := filepath.Glob(filepath.Join(os.Getenv(latencytrace.Environment), "*.ndjson"))
		if err != nil || len(files) != 1 {
			time.Sleep(time.Millisecond)
			continue
		}
		raw, err := os.ReadFile(files[0])
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "never traced") || strings.Contains(string(raw), "fixture-access") {
			t.Fatal("trace leaked business data")
		}
		for _, line := range strings.Split(string(raw), "\n") {
			var row struct {
				Stage     string `json:"stage"`
				RPCID     string `json:"rpc_id"`
				RequestID string `json:"request_id"`
				Operation string `json:"operation"`
			}
			if json.Unmarshal([]byte(line), &row) != nil || row.RPCID != rpcID {
				continue
			}
			if row.RequestID != requestID || row.Operation != OperationLookup {
				t.Fatal("trace lost original execution correlation")
			}
			if _, tracked := want[row.Stage]; tracked {
				want[row.Stage] = true
			}
		}
		complete := true
		for _, found := range want {
			complete = complete && found
		}
		if complete {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("missing correlated stages", want)
}
