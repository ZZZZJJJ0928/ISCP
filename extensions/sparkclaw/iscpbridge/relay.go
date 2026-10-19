package iscpbridge

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

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

	journal         *relayJournal
	sessionUsable   func(string) bool
	socketMu        sync.Mutex
	socket          *relaySocket
	running         bool
	connectionEpoch ConnectionEpoch
	mu              sync.RWMutex
	enrollment      EnrollmentBundle
}

type relayMessage struct {
	State     string          `json:"state"`
	Challenge string          `json:"challenge,omitempty"`
	MessageID string          `json:"message_id,omitempty"`
	Envelope  json.RawMessage `json:"envelope,omitempty"`
	Error     string          `json:"error,omitempty"`
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
