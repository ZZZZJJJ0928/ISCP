// Package latencytrace provides optional private, best-effort timing evidence.
// It never records payloads, endpoints, credentials or error messages. Set
// SPARKCLAW_PRIVATE_LATENCY_TRACE_DIR to an existing absolute 0700 directory
// before starting the process; invalid configuration simply disables tracing.
package latencytrace

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const Environment = "SPARKCLAW_PRIVATE_LATENCY_TRACE_DIR"

type Fields struct {
	Role      string `json:"role,omitempty"`
	RPCID     string `json:"rpc_id,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Operation string `json:"operation,omitempty"`
}

type event struct {
	SchemaVersion int       `json:"schema_version"`
	Time          time.Time `json:"time"`
	Stage         string    `json:"stage"`
	Fields
	DurationMS float64 `json:"duration_ms"`
	Status     string  `json:"status"`
	Count      uint64  `json:"count,omitempty"`
}

type recorder struct {
	file    *os.File
	queue   chan event
	done    chan struct{}
	dropped atomic.Uint64
}

var processRecorder = sync.OnceValue(func() *recorder { return newRecorder(os.Getenv(Environment)) })
var uuid = regexp.MustCompile(`(?i)^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
var operationName = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,5}$`)

func newRecorder(directory string) *recorder {
	if !filepath.IsAbs(directory) {
		return nil
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil
	}
	// CreateTemp uses O_EXCL and 0600, so an existing name/symlink is never
	// opened. One unique file belongs to this process for its entire lifetime.
	file, err := os.CreateTemp(directory, "go-"+strconv.Itoa(os.Getpid())+"-"+time.Now().UTC().Format("20060102T150405.000000000")+"-*.ndjson")
	if err != nil {
		return nil
	}
	r := &recorder{file: file, queue: make(chan event, 1024), done: make(chan struct{})}
	go r.write()
	return r
}

func (r *recorder) write() {
	defer close(r.done)
	defer r.file.Close()
	encoder := json.NewEncoder(r.file)
	bytes := int64(0)
	failed := false
	for value := range r.queue {
		if failed {
			continue
		}
		if dropped := r.dropped.Swap(0); dropped != 0 {
			if encoder.Encode(event{SchemaVersion: 1, Time: time.Now().UTC(), Stage: "trace.dropped", Status: "incomplete", Count: dropped}) != nil {
				failed = true
				continue
			}
		}
		// A bounded private diagnostic cannot fill the business data disk.
		if bytes >= 64<<20 {
			_ = encoder.Encode(event{SchemaVersion: 1, Time: time.Now().UTC(), Stage: "trace.limit", Status: "incomplete"})
			failed = true
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil {
			continue
		}
		raw = append(raw, '\n')
		n, err := r.file.Write(raw)
		bytes += int64(n)
		failed = err != nil
	}
}

func (r *recorder) emit(value event) {
	select {
	case r.queue <- value:
	default:
		r.dropped.Add(1)
	}
}

func Enabled() bool { return processRecorder() != nil }

type contextKey struct{}

// WithFields accepts only correlation metadata already validated by its caller.
// UUID and operation-name filtering provides a second boundary against logging
// arbitrary input. An empty value inherits the corresponding parent field.
func WithFields(ctx context.Context, fields Fields) context.Context {
	if !Enabled() {
		return ctx
	}
	prior, _ := ctx.Value(contextKey{}).(Fields)
	fields = clean(fields)
	if fields.Role != "" {
		prior.Role = fields.Role
	}
	if fields.RPCID != "" {
		prior.RPCID = fields.RPCID
	}
	if fields.RequestID != "" {
		prior.RequestID = fields.RequestID
	}
	if fields.Operation != "" {
		prior.Operation = fields.Operation
	}
	return context.WithValue(ctx, contextKey{}, prior)
}

func clean(fields Fields) Fields {
	if fields.Role != "initiator" && fields.Role != "responder" && fields.Role != "gateway" && fields.Role != "relay" {
		fields.Role = ""
	}
	if !uuid.MatchString(fields.RPCID) {
		fields.RPCID = ""
	}
	if !uuid.MatchString(fields.RequestID) {
		fields.RequestID = ""
	}
	if len(fields.Operation) > 96 || !operationName.MatchString(fields.Operation) {
		fields.Operation = ""
	}
	return fields
}

// Clock returns a monotonic timestamp only when tracing is enabled.
func Clock() time.Time {
	if !Enabled() {
		return time.Time{}
	}
	return time.Now()
}

func status(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	default:
		return "error"
	}
}

// Record uses time.Since's monotonic clock for a span. For instantaneous events
// pass a zero start; At can retain the original arrival time after correlation.
func Record(ctx context.Context, stage string, start time.Time, err error, count uint64) {
	r := processRecorder()
	if r == nil {
		return
	}
	now := time.Now()
	value := event{SchemaVersion: 1, Time: now.UTC(), Stage: stage, Status: status(err), Count: count}
	value.Fields, _ = ctx.Value(contextKey{}).(Fields)
	if !start.IsZero() {
		value.DurationMS = float64(now.Sub(start)) / float64(time.Millisecond)
	}
	r.emit(value)
}

func At(ctx context.Context, stage string, when time.Time) {
	r := processRecorder()
	if r == nil || when.IsZero() {
		return
	}
	value := event{SchemaVersion: 1, Time: when.UTC(), Stage: stage, Status: "ok"}
	value.Fields, _ = ctx.Value(contextKey{}).(Fields)
	r.emit(value)
}
