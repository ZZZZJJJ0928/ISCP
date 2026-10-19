package iscpbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Infinimesh-ai/ISCP/internal/latencytrace"
	iscpcrypto "github.com/Infinimesh-ai/ISCP/pkg/iscp/crypto"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/identity"
	"github.com/gorilla/websocket"
)

const (
	relayEnvelopePath = "/v2/relay/envelopes"
	relayRefreshPath  = "/v2/relay/devices/refresh-access"
	relayMaxBody      = 4 << 20
	accessProofHeader = "X-ISCP-Access-Proof"
)

type RelayClient struct {
	provider           iscpcrypto.Provider
	device             identity.Device
	enrollmentPath     string
	profile            string
	timeout            time.Duration
	client             *http.Client
	credentialOnly     bool
	credentialProvider CredentialProvider

	mu         sync.RWMutex
	enrollment EnrollmentBundle
}

type relayMessage struct {
	State     string          `json:"state"`
	Challenge string          `json:"challenge,omitempty"`
	MessageID string          `json:"message_id,omitempty"`
	Envelope  json.RawMessage `json:"envelope,omitempty"`
	Error     string          `json:"error,omitempty"`
}

func (c *RelayClient) Submit(ctx context.Context, value any) (resultErr error) {
	started := latencytrace.Clock()
	defer func() { latencytrace.Record(ctx, "relay.submit", started, resultErr, 0) }()
	if err := c.ensureAccess(ctx); err != nil {
		return err
	}
	if err := c.submit(ctx, value); err != nil {
		var relayErr *relayHTTPError
		if errors.As(err, &relayErr) && relayErr.status == http.StatusUnauthorized {
			if refreshErr := c.refresh(ctx); refreshErr == nil {
				return c.submit(ctx, value)
			}
		}
		return err
	}
	return nil
}

func (c *RelayClient) submit(ctx context.Context, value any) (resultErr error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode Relay envelope: %w", err)
	}
	if len(raw) > relayMaxBody {
		return errors.New("Relay envelope is too large")
	}
	bundle := c.Enrollment()
	endpoint := strings.TrimRight(bundle.RelayBaseURL, "/") + relayEnvelopePath
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return errors.New("create Relay envelope request")
	}
	request.Header.Set("Authorization", "Bearer "+bundle.Access.Token)
	request.Header.Set("Content-Type", "application/json")
	proof, err := c.accessProof(bundle.Access.Token, http.MethodPost, relayEnvelopePath, bundle.RelayID)
	if err != nil {
		return err
	}
	request.Header.Set(accessProofHeader, proof)
	started := latencytrace.Clock()
	defer func() { latencytrace.Record(ctx, "relay.post", started, resultErr, 0) }()
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("submit Relay envelope: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, relayMaxBody))
	if response.StatusCode != http.StatusAccepted {
		return &relayHTTPError{status: response.StatusCode}
	}
	return nil
}

func (c *RelayClient) RunOnce(ctx context.Context, handle func(context.Context, json.RawMessage) error) error {
	return c.RunOnceReady(ctx, handle, nil)
}

// RunOnceReady reports the authenticated receive connection before reading
// messages. Session initiators must wait for this point before sending Hello.
func (c *RelayClient) RunOnceReady(ctx context.Context, handle func(context.Context, json.RawMessage) error, onReady func()) error {
	return c.runSocketOnce(ctx, handle, onReady)
}

func (c *RelayClient) runSocketOnce(ctx context.Context, handle func(context.Context, json.RawMessage) error, onReady func()) (resultErr error) {
	started := latencytrace.Clock()
	var received uint64
	defer func() { latencytrace.Record(ctx, "relay.socket", started, resultErr, received) }()
	if err := c.ensureAccess(ctx); err != nil {
		return err
	}
	bundle := c.Enrollment()
	dialer := websocket.Dialer{HandshakeTimeout: c.timeout, Proxy: http.ProxyFromEnvironment}
	if c.credentialOnly && c.profile == ProfileLocalLab {
		dialer.Proxy = nil
	} else if bundle.Mode == BundleModeWorkbenchNodeManaged {
		tlsConfig, err := VerifiedTLSConfig(bundle.TLSCertificatePEM)
		if err != nil {
			return err
		}
		dialer.TLSClientConfig, dialer.Proxy = tlsConfig, nil
	}
	connection, response, err := dialer.DialContext(ctx, bundle.RelayWebSocketURL, nil)
	if err != nil {
		if response != nil {
			return &relayHTTPError{status: response.StatusCode}
		}
		return fmt.Errorf("connect Relay: %w", err)
	}
	defer connection.Close()
	connection.SetReadLimit(relayMaxBody)
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()
	// Authentication reads and writes must not outlive the dial timeout when
	// a reachable Relay stalls before sending challenge or authenticated ready.
	if err := connection.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return errors.New("set Relay authentication read deadline")
	}
	if err := connection.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return errors.New("set Relay authentication write deadline")
	}

	var challenge relayMessage
	if err := connection.ReadJSON(&challenge); err != nil {
		return fmt.Errorf("read Relay challenge: %w", err)
	}
	if challenge.State != "challenge" || strings.TrimSpace(challenge.Challenge) == "" {
		return errors.New("Relay returned an invalid connection challenge")
	}
	proof, err := c.device.CreateProof(c.provider, bundle.RelayID, challenge.Challenge, randomNonce(), time.Now().UTC())
	if err != nil {
		return errors.New("create Relay connection proof")
	}
	if err := connection.WriteJSON(proof); err != nil {
		return fmt.Errorf("send Relay connection proof: %w", err)
	}

	var ready relayMessage
	if err := connection.ReadJSON(&ready); err != nil {
		return fmt.Errorf("read Relay connection state: %w", err)
	}
	if ready.State == "closed" {
		return errors.New("Relay rejected or revoked the enrolled device")
	}
	if ready.State != "ready" {
		return errors.New("Relay did not enter ready state")
	}
	latencytrace.Record(ctx, "relay.authentication", started, nil, 0)
	if err := installRelayReceiveLiveness(connection, 2*time.Minute); err != nil {
		return err
	}
	if onReady != nil {
		onReady()
	}
	for {
		if err := connection.SetReadDeadline(time.Now().Add(2 * time.Minute)); err != nil {
			return errors.New("set Relay receive liveness deadline")
		}
		var message relayMessage
		if err := connection.ReadJSON(&message); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read Relay message: %w", err)
		}
		switch message.State {
		case "message":
			received++
			if len(message.Envelope) == 0 {
				return errors.New("Relay delivered an empty envelope")
			}
			if err := handle(ctx, message.Envelope); err != nil {
				return err
			}
		case "drained":
			return errors.New("Relay drained a continuous receive connection; matched Relay update required")
		case "closed":
			return errors.New("Relay closed the connection")
		default:
			return errors.New("Relay returned an unknown connection state")
		}
	}
}

// Ping traffic extends the receive deadline even when no application messages
// arrive. Gorilla invokes the handler on the reader goroutine; it may send a
// control Pong concurrently with the ordinary writer.
func installRelayReceiveLiveness(connection *websocket.Conn, timeout time.Duration) error {
	pong := connection.PingHandler()
	connection.SetPingHandler(func(value string) error {
		if err := connection.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		return pong(value)
	})
	return connection.SetReadDeadline(time.Now().Add(timeout))
}

type relayHTTPError struct {
	status int
}

func (e *relayHTTPError) Error() string {
	return fmt.Sprintf("Relay returned HTTP status %d", e.status)
}

func validateRelayURLs(profile, baseURL, websocketURL string) error {
	base, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil || base.Hostname() == "" || (base.Scheme != "https" && base.Scheme != "http") {
		return errors.New("Relay base URL is invalid")
	}
	websocketEndpoint, err := url.Parse(strings.TrimSpace(websocketURL))
	if err != nil || websocketEndpoint.Hostname() == "" || (websocketEndpoint.Scheme != "wss" && websocketEndpoint.Scheme != "ws") {
		return errors.New("Relay WebSocket URL is invalid")
	}
	if profile == ProfileProduction && (base.Scheme != "https" || websocketEndpoint.Scheme != "wss") {
		return errors.New("production Bridge requires HTTPS and WSS Relay URLs")
	}
	if base.User != nil || websocketEndpoint.User != nil {
		return errors.New("Relay URLs must not contain credentials")
	}
	return nil
}

func randomNonce() string {
	return newWireID("nonce")
}
