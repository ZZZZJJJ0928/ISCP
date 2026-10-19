package latencytrace

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrivateDestinationAndExclusivePerProcessFiles(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	public := filepath.Join(root, "public")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(public, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{"", "relative", public, link, filepath.Join(root, "missing")} {
		if r := newRecorder(directory); r != nil {
			close(r.queue)
			<-r.done
			t.Fatalf("accepted unsafe diagnostic destination %q", directory)
		}
	}
	first, second := newRecorder(private), newRecorder(private)
	if first == nil || second == nil {
		t.Fatal("private diagnostic destination unavailable")
	}
	if first.file.Name() == second.file.Name() {
		t.Fatal("process files were reused")
	}
	for _, r := range []*recorder{first, second} {
		info, err := r.file.Stat()
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("trace file is not private", err)
		}
		close(r.queue)
		<-r.done
	}
}

func TestFixedSchemaDoesNotRecordUntrustedFieldsOrErrorText(t *testing.T) {
	fields := clean(Fields{Role: "https://private.example", RPCID: "Bearer secret-token", RequestID: `{"prompt":"private"}`, Operation: "https://secret.example/credential"})
	if fields != (Fields{}) {
		t.Fatal("untrusted metadata survived", fields)
	}
	if status(errors.New("private provider detail")) != "error" {
		t.Fatal("error classification failed")
	}
	if status(context.Canceled) != "canceled" || status(context.DeadlineExceeded) != "deadline" {
		t.Fatal("context classification failed")
	}
	r := newRecorder(privateTestDirectory(t))
	if r == nil {
		t.Fatal("private recorder unavailable")
	}
	start := time.Now()
	end := start.Add(1500 * time.Microsecond)
	value := event{SchemaVersion: 1, Time: end.UTC(), Stage: "rpc.call", Fields: clean(Fields{Role: "initiator", RPCID: "11111111-1111-4111-8111-111111111111", RequestID: "22222222-2222-4222-8222-222222222222", Operation: "execution.lookup"}), DurationMS: float64(end.Sub(start)) / float64(time.Millisecond), Status: status(errors.New("secret error"))}
	r.emit(value)
	close(r.queue)
	<-r.done
	raw, err := os.ReadFile(r.file.Name())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret") {
		t.Fatal("private error text was recorded")
	}
	var result map[string]any
	if json.Unmarshal(raw, &result) != nil || result["duration_ms"] != 1.5 || result["request_id"] != value.RequestID {
		t.Fatal("invalid timing evidence", string(raw))
	}
	want := map[string]bool{"schema_version": true, "time": true, "stage": true, "role": true, "rpc_id": true, "request_id": true, "operation": true, "duration_ms": true, "status": true, "count": true}
	for field := range result {
		if !want[field] {
			t.Fatal("unexpected trace field", field)
		}
	}
}

func TestTracePressureAndStorageFailureNeverBlockProducer(t *testing.T) {
	r := &recorder{queue: make(chan event, 1)}
	r.emit(event{})
	done := make(chan struct{})
	go func() {
		for range 10000 {
			r.emit(event{})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("full trace queue blocked producer")
	}
	if r.dropped.Load() != 10000 {
		t.Fatal("dropped timing evidence not counted")
	}
	r = newRecorder(privateTestDirectory(t))
	if r == nil {
		t.Fatal("private recorder unavailable")
	}
	_ = r.file.Close()
	for range 2048 {
		r.emit(event{Stage: "rpc.call"})
	}
	close(r.queue)
	select {
	case <-r.done:
	case <-time.After(time.Second):
		t.Fatal("failed trace file blocked writer")
	}
}

func TestDisabledTracingPreservesContextAndDoesNotReadClock(t *testing.T) {
	// The normal unit suite has no opt-in. Enabled-process integration is in
	// iscpworkbench's isolated child so the immutable process setting stays true.
	if os.Getenv(Environment) != "" {
		t.Skip("explicit trace environment supplied")
	}
	ctx := context.Background()
	if Enabled() || !Clock().IsZero() || WithFields(ctx, Fields{Role: "initiator"}) != ctx {
		t.Fatal("disabled tracing changed runtime context")
	}
	Record(ctx, "rpc.call", time.Time{}, errors.New("private"), 0)
}

func privateTestDirectory(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private-trace")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}
