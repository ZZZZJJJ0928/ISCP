package iscpbridge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBridgeConfigAllowsNoGatewayTokenFile(t *testing.T) {
	config := Config{
		Profile: ProfileLocalLab, IdentityDirectory: "/identity",
		IdentityKeyBackend: IdentityKeyBackendFile, EnrollmentFile: "/enrollment",
		Gateway: GatewayConfig{BaseURL: "http://127.0.0.1:18789"},
	}
	if err := config.normalizeAndValidate(); err != nil {
		t.Fatalf("no-auth loopback config was rejected: %v", err)
	}
	if token, err := config.LoadGatewayToken(); err != nil || token != "" {
		t.Fatalf("optional Gateway token = %q, %v", token, err)
	}
}

func TestPublishedSchemaContainsAllRequestTypes(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	schemaPath := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "../protocol/iscp-bridge.v1.schema.json"))
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) {
		t.Fatal("published Bridge schema is not valid JSON")
	}
	for requestType := range supportedRequestTypes {
		if !strings.Contains(string(raw), `"`+requestType+`"`) {
			t.Fatalf("published Bridge schema is missing %q", requestType)
		}
	}
}

func TestProductionConfigRejectsFileIdentityKey(t *testing.T) {
	config := Config{
		Profile: ProfileProduction, IdentityDirectory: "/identity", IdentityKeyBackend: IdentityKeyBackendFile,
		EnrollmentFile: "/enrollment", Gateway: GatewayConfig{TokenFile: "/token"},
	}
	if err := config.normalizeAndValidate(); err == nil {
		t.Fatal("production config accepted file identity key backend")
	}
}
