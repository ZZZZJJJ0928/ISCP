package iscpbridge

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Transport helpers retained from SparkClaw service.go without its business adapter.
func strictUnmarshal(raw []byte, dst any) error {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func newWireID(prefix string) string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UTC().UnixNano())
	}
	return prefix + "-" + hex.EncodeToString(raw)
}

// The existing enrollment advertises these SparkClaw profile identifiers.
const (
	manifestPayloadType     = "agent.capability.v1"
	sparkclawBridgeProtocol = "sparkclaw.bridge.v1"
)
