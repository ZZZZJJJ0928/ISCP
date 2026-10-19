// iscp-workbench is a private-pipe SDK helper. It never opens a listening
// socket and accepts only the fixed workbench operation registry.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpauth"
	"github.com/Infinimesh-ai/ISCP/extensions/sparkclaw/iscpworkbench"
)

const ipcVersion = 1

type callFrame struct {
	MessageID        string                 `json:"message_id,omitempty"`
	OperationID      string                 `json:"operation_id,omitempty"`
	ExpectedRevision uint64                 `json:"expected_revision,omitempty"`
	IPCVersion       int                    `json:"ipc_version"`
	Type             string                 `json:"type"`
	ID               string                 `json:"id,omitempty"`
	Request          iscpworkbench.Request  `json:"request,omitempty"`
	Response         iscpworkbench.Response `json:"response,omitempty"`
	BodyBase64       string                 `json:"body_base64,omitempty"`
}

type ipcWriter struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *ipcWriter) send(value any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return json.NewEncoder(w.writer).Encode(value)
}

func main() {
	enroll := flag.Bool("enroll-node", false, "enroll a node-managed device using one private stdin credential")
	directory := flag.String("directory", "", "private pending enrollment directory")
	keyBackend := flag.String("key-backend", "keyring", "native device key backend")
	keyringService := flag.String("keyring-service", "", "native keyring service")
	installationID := flag.String("installation-id", "", "existing ClientStore installation UUID")
	configPath := flag.String("config", "", "private workbench configuration")
	controlOnly := flag.Bool("control-only", false, "serve proof-bound authorization deletion and receipt control without Relay")
	check := flag.Bool("check", false, "validate private profile without contacting Relay")
	upgradeControl := flag.Bool("upgrade-node-control-v2", false, "explicitly activate the maintained control history for an existing node profile")
	activationEvidence := flag.String("activation-evidence-sha256", "", "accepted activation evidence digest for explicit control maintenance")
	flag.Parse()
	if *upgradeControl {
		if *configPath == "" || *activationEvidence == "" || *enroll || *controlOnly || *check || flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "control upgrade requires -config and -activation-evidence-sha256 without enrollment or runtime modes")
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := iscpworkbench.UpgradeNodeControlV2(ctx, *configPath, *activationEvidence); err != nil {
			fmt.Fprintln(os.Stderr, "control history upgrade failed:", err)
			os.Exit(1)
		}
		return
	}
	if *activationEvidence != "" {
		fmt.Fprintln(os.Stderr, "activation evidence requires -upgrade-node-control-v2")
		os.Exit(2)
	}
	if *enroll {
		if *configPath != "" || *controlOnly || *check || flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "enrollment flags conflict")
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		if err := enrollNode(ctx, os.Stdin, os.Stdout, *directory, *keyBackend, *keyringService, *installationID); err != nil {
			fmt.Fprintln(os.Stderr, "node enrollment failed:", err)
			os.Exit(1)
		}
		return
	}
	if *configPath == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: iscp-workbench -config <path> [-check]")
		os.Exit(2)
	}
	var cfg iscpworkbench.Config
	var err error
	if *controlOnly {
		cfg, err = iscpworkbench.LoadControlConfig(*configPath)
	} else if *check {
		cfg, err = iscpworkbench.LoadConfig(*configPath)
	} else {
		cfg, err = iscpworkbench.LoadRuntimeConfig(context.Background(), *configPath)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ISCP workbench profile validation failed:", err)
		os.Exit(1)
	}
	writer := &ipcWriter{writer: os.Stdout}
	if *controlOnly {
		control, err := iscpworkbench.NewAuthorizationControl(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "authorization control profile validation failed")
			os.Exit(1)
		}
		defer control.Close()
		if *check {
			_ = writer.send(map[string]any{"valid": true, "control_only": true, "identity": control.PublicIdentity()})
			return
		}
		_ = writer.send(map[string]any{"ipc_version": ipcVersion, "type": "hello", "control_only": true, "identity": control.PublicIdentity(), "operations": []string{}})
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		if err := serveFrames(ctx, os.Stdin, writer, control, nil, true); err != nil {
			fmt.Fprintln(os.Stderr, "authorization control helper stopped:", err)
			os.Exit(1)
		}
		return
	}
	publicIdentity, err := cfg.PublicIdentity()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ISCP workbench identity validation failed")
		os.Exit(1)
	}
	if *check {
		_ = writer.send(map[string]any{"valid": true, "schema_version": cfg.SchemaVersion, "mode": cfg.Mode, "role": cfg.Role, "profile": iscpworkbench.Profile, "identity": publicIdentity, "operations": iscpworkbench.Operations(), "max_request_bytes": iscpworkbench.MaxRequestBytes, "max_response_bytes": iscpworkbench.MaxResponseBytes})
		return
	}
	if cfg.Role != iscpworkbench.RoleInitiator {
		fmt.Fprintln(os.Stderr, "ISCP workbench helper requires desktop initiator role")
		os.Exit(1)
	}
	bridge := newReverseBridge(writer)
	endpoint, err := iscpworkbench.NewEndpoint(cfg, bridge.handle, func(state string) {
		_ = writer.send(map[string]any{"ipc_version": ipcVersion, "type": "state", "state": state})
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ISCP workbench initialization failed:", err)
		os.Exit(1)
	}
	endpoint.SetCapabilitiesHandler(func(c iscpworkbench.TransportCapabilities) {
		_ = writer.send(map[string]any{"ipc_version": ipcVersion, "type": "admission", "profile": c.Profile, "session_id": c.SessionID, "authorization_revision": c.AuthorizationRevision, "expires_at": c.ExpiresAt, "concurrent": c.Limits.Concurrent})
		if c.Profile == iscpworkbench.ProfileV2 {
			_ = writer.send(map[string]any{"ipc_version": ipcVersion, "type": "capabilities", "capabilities": c})
		}
	})
	defer endpoint.Close()
	if err := writer.send(map[string]any{"ipc_version": ipcVersion, "type": "hello", "stream_schema_version": 1, "identity": publicIdentity, "operations": iscpworkbench.Operations(), "max_request_bytes": iscpworkbench.MaxRequestBytes, "max_response_bytes": iscpworkbench.MaxResponseBytes}); err != nil {
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := serveWithReverse(ctx, os.Stdin, writer, endpoint, bridge); err != nil {
		fmt.Fprintln(os.Stderr, "ISCP workbench helper stopped:", err)
		os.Exit(1)
	}
}

type caller interface {
	DeleteAuthorization(context.Context, string, uint64) (iscpauth.DeletionReceipt, error)
	AuthorizationDeletionReceipt(context.Context, string, uint64) (iscpauth.DeletionReceipt, error)
	Run(context.Context) error
	Call(context.Context, iscpworkbench.Request) (iscpworkbench.Response, error)
	StreamCall(context.Context, iscpworkbench.Request, func(json.RawMessage) error) (iscpworkbench.Response, error)
	StreamAuthorityRemaining(string) (time.Duration, error)
	Close() error
}

func serve(ctx context.Context, input io.Reader, writer *ipcWriter, endpoint caller) error {
	return serveWithReverse(ctx, input, writer, endpoint, nil)
}
func serveWithReverse(ctx context.Context, input io.Reader, writer *ipcWriter, endpoint caller, bridge *reverseBridge) error {
	return serveFrames(ctx, input, writer, endpoint, bridge, false)
}
func serveFrames(ctx context.Context, input io.Reader, writer *ipcWriter, endpoint caller, bridge *reverseBridge, controlOnly bool) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	runDone := make(chan struct{})
	go func() { defer close(runDone); _ = endpoint.Run(ctx) }()
	defer func() { cancel(); _ = endpoint.Close(); <-runDone }()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 4096), 128<<10)
	lines := make(chan []byte)
	readErr := make(chan error, 1)
	go func() {
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...)
			select {
			case lines <- line:
			case <-ctx.Done():
				return
			}
		}
		readErr <- scanner.Err()
		close(lines)
	}()
	var calls sync.WaitGroup
	defer func() { cancel(); calls.Wait() }()
	controls := make(chan struct{}, 1)
	streams := newPipeStreams()
	defer streams.close()
	for {
		select {
		case <-ctx.Done():
			return nil
		case line, ok := <-lines:
			if !ok {
				cancel()
				return <-readErr
			}
			frame, err := decodeCall(line)
			if err != nil {
				return err
			}
			if controlOnly && frame.Type != "authorization_delete" && frame.Type != "authorization_delete_receipt" && frame.Type != "shutdown" {
				return errors.New("authorization control mode rejects business frames")
			}
			if frame.Type == "authorization_delete" || frame.Type == "authorization_delete_receipt" {
				select {
				case controls <- struct{}{}:
				default:
					_ = writer.send(map[string]any{"ipc_version": ipcVersion, "type": "authorization_receipt", "id": frame.ID, "error": "authorization control busy", "retryable": true})
					continue
				}
				calls.Add(1)
				go func(frame callFrame) {
					defer calls.Done()
					defer func() { <-controls }()
					var r iscpauth.DeletionReceipt
					var err error
					if frame.Type == "authorization_delete" {
						r, err = endpoint.DeleteAuthorization(ctx, frame.OperationID, frame.ExpectedRevision)
					} else {
						r, err = endpoint.AuthorizationDeletionReceipt(ctx, frame.OperationID, frame.ExpectedRevision)
					}
					out := map[string]any{"ipc_version": ipcVersion, "type": "authorization_receipt", "id": frame.ID}
					if err != nil {
						out["error"] = "authorization control unavailable"
					} else {
						out["receipt"] = r
					}
					_ = writer.send(out)
				}(frame)
				continue
			}
			if frame.Type == "stream_cancel" {
				streams.cancel(frame.ID)
				continue
			}
			if frame.Type == "relay_submission_status" {
				calls.Add(1)
				go func(frame callFrame) {
					defer calls.Done()
					_ = writer.send(relaySubmissionFrame(endpoint, frame))
				}(frame)
				continue
			}
			if frame.Type == "stream_call" {
				streamStarted := time.Now()
				streamCtx, done, err := streams.open(ctx, frame.ID)
				if err != nil {
					return err
				}
				calls.Add(1)
				go func(frame callFrame) {
					defer calls.Done()
					defer done()
					response, err := endpoint.StreamCall(streamCtx, frame.Request, func(event json.RawMessage) error {
						sampledElapsed := time.Since(streamStarted)
						remaining, err := endpoint.StreamAuthorityRemaining(frame.Request.ID)
						if err != nil {
							return err
						}
						// Electron anchors this relative monotonic deadline before it
						// sends the call. Pipe queuing cannot renew old event authority.
						return writer.send(map[string]any{"ipc_version": ipcVersion, "type": "stream_event", "id": frame.ID, "event": event, "authority_valid_for_ms": remaining.Milliseconds(), "authority_deadline_ms": (sampledElapsed + remaining).Milliseconds()})
					})
					if err != nil {
						response = iscpworkbench.Response{Type: iscpworkbench.ResponseType, Profile: frame.Request.Profile, ID: frame.Request.ID, Status: 503, Error: "ISCP stream unavailable", Code: iscpworkbench.ErrorCapabilityUnavailable, Retryable: true}
						if errors.Is(err, iscpworkbench.ErrStreamAuthorityExpired) {
							response.Status = 403
							response.Code = iscpworkbench.ErrorGrantExpired
						}
						transportOutcome(&response, err)
					}
					_ = writeResponse(writer, frame.ID, response)
				}(frame)
				continue
			}
			if frame.Type == "reverse_response" {
				if bridge == nil {
					return errors.New("unexpected reverse response")
				}
				bridge.accept(frame.ID, frame.Response)
				continue
			}
			if frame.Type == "shutdown" {
				cancel()
				return nil
			}
			calls.Add(1)
			go func(frame callFrame) {
				defer calls.Done()
				response, err := endpoint.Call(ctx, frame.Request)
				if err != nil {
					response = iscpworkbench.Response{Type: iscpworkbench.ResponseType, Profile: frame.Request.Profile, ID: frame.Request.ID, Status: 503, Error: "ISCP workbench call failed"}
					var transportError *iscpworkbench.TransportError
					if errors.As(err, &transportError) && frame.Request.Profile == iscpworkbench.ProfileV2 {
						response.Status = transportError.Status
						response.Code = transportError.Code
						response.Retryable = transportError.Retryable
					}
					transportOutcome(&response, err)
				}
				_ = writeResponse(writer, frame.ID, response)
			}(frame)
		}
	}
}

func writeResponse(writer *ipcWriter, id string, response iscpworkbench.Response) error {
	return writer.send(map[string]any{"ipc_version": ipcVersion, "type": "response", "id": id, "response": response})
}

func decodeCall(line []byte) (callFrame, error) {
	var frame callFrame
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil {
		return frame, errors.New("invalid private IPC frame")
	}
	if decoder.Decode(new(any)) != io.EOF || frame.IPCVersion != ipcVersion {
		return frame, errors.New("unsupported private IPC version or trailing data")
	}
	if frame.Type == "shutdown" {
		return frame, nil
	}
	if frame.Type == "relay_submission_status" {
		if frame.ID == "" || len(frame.ID) > 200 || !relayMessageID.MatchString(frame.MessageID) || frame.Request.Type != "" || frame.BodyBase64 != "" || frame.OperationID != "" || frame.ExpectedRevision != 0 {
			return frame, errors.New("invalid Relay submission status frame")
		}
		return frame, nil
	}
	if frame.Type == "authorization_delete" || frame.Type == "authorization_delete_receipt" {
		if frame.ID == "" || len(frame.ID) > 200 || frame.OperationID == "" || len(frame.OperationID) > 128 || frame.ExpectedRevision == 0 {
			return frame, errors.New("invalid authorization control frame")
		}
		return frame, nil
	}
	if frame.Type == "reverse_response" {
		if frame.ID == "" || len(frame.ID) > 200 || frame.Response.Validate() != nil {
			return frame, errors.New("invalid reverse response")
		}
		return frame, nil
	}
	if frame.Type == "stream_cancel" && frame.ID != "" && len(frame.ID) <= 200 {
		return frame, nil
	}
	if (frame.Type != "call" && frame.Type != "stream_call") || frame.ID == "" || len(frame.ID) > 200 {
		return frame, errors.New("invalid private IPC call")
	}
	if frame.BodyBase64 != "" {
		if len(frame.Request.Body) != 0 {
			return frame, errors.New("IPC call supplies two bodies")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(frame.BodyBase64)
		if err != nil || len(raw) > iscpworkbench.MaxRequestBytes || !json.Valid(raw) {
			return frame, errors.New("invalid private IPC encoded body")
		}
		frame.Request.Body = json.RawMessage(raw)
	}
	if frame.Type == "stream_call" && (frame.Request.Operation != iscpworkbench.OperationExecutionProgressStream || frame.ID != frame.Request.ID) {
		return frame, errors.New("invalid IPC stream call")
	}
	if frame.Type == "call" && frame.Request.Operation == iscpworkbench.OperationExecutionProgressStream {
		return frame, errors.New("stream operation requires stream_call")
	}
	if err := frame.Request.Validate(); err != nil {
		return frame, errors.New("invalid private IPC workbench request")
	}
	return frame, nil
}
