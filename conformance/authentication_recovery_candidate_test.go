package conformance

// These tests verify a freeze candidate's independently generated vectors and
// schema. They intentionally do not claim service recovery or database safety.
import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func recoveryFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("fixtures/operation-recovery.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err = json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func recoveryObject(value any) map[string]any { return value.(map[string]any) }
func recoveryCanonical(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	out, err := canonical.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func recoveryDigest(t *testing.T, prefix string, value any) string {
	t.Helper()
	sum := sha256.Sum256(append([]byte(prefix), recoveryCanonical(t, value)...))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func recoveryBytes(t *testing.T, value any) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.Strict().DecodeString(value.(string))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func recoveryHex(t *testing.T, value any) []byte {
	t.Helper()
	b, err := hex.DecodeString(value.(string))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func recoveryCopy(value any) map[string]any {
	raw, _ := json.Marshal(value)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}
func recoveryMutate(object map[string]any, mutation map[string]any) {
	path := mutation["path"].([]any)
	for _, key := range path[:len(path)-1] {
		object = recoveryObject(object[key.(string)])
	}
	object[path[len(path)-1].(string)] = mutation["value"]
}
func recoveryVerify(t *testing.T, object map[string]any, public []byte) bool {
	t.Helper()
	raw, _ := json.Marshal(object)
	input, err := canonical.SignatureInput(object["type"].(string), raw)
	if err != nil {
		return false
	}
	signature := recoveryObject(object["signature"])
	return ed25519.Verify(ed25519.PublicKey(public), input, recoveryBytes(t, signature["value"]))
}

func TestAuthenticationRecoveryCandidateCanonicalVectors(t *testing.T) {
	f := recoveryFixture(t)
	for _, pair := range [][2]string{{"intent", "intent_canonical"}, {"authentication_context", "authentication_context_canonical"}} {
		if string(recoveryCanonical(t, f[pair[0]])) != f[pair[1]] {
			t.Fatalf("%s canonical bytes differ", pair[0])
		}
	}
	if got := recoveryDigest(t, "ISCP-OPERATION-INTENT-V2\x00", f["intent"]); got != f["semantic_digest"] {
		t.Fatalf("intent digest %s", got)
	}
	request := recoveryCopy(f["request"])
	delete(request, "authentication")
	context := recoveryObject(f["authentication_context"])
	if got := recoveryDigest(t, "ISCP-CONTROL-REQUEST-V2\x00", request); got != context["request_digest"] {
		t.Fatal("request digest differs")
	}
	raw, _ := json.Marshal(context)
	input, err := canonical.SignatureInput("iscp.control.authentication.v2", raw)
	if err != nil || !bytes.Equal(input, recoveryHex(t, f["authentication_signature_input_hex"])) {
		t.Fatal("authentication signing bytes differ")
	}
	keys := recoveryObject(f["test_keys"])
	proof := recoveryObject(recoveryObject(f["request"])["authentication"])
	signature := recoveryBytes(t, recoveryObject(proof["signature"])["value"])
	if !ed25519.Verify(recoveryBytes(t, keys["device_public_key"]), input, signature) {
		t.Fatal("device proof does not verify")
	}
	for _, item := range f["negative_binding"].([]any) {
		m := recoveryObject(item)
		t.Run(m["name"].(string), func(t *testing.T) {
			changed := recoveryCopy(context)
			recoveryMutate(changed, m)
			raw, _ := json.Marshal(changed)
			input, err := canonical.SignatureInput("iscp.control.authentication.v2", raw)
			if err == nil && ed25519.Verify(recoveryBytes(t, keys["device_public_key"]), input, signature) {
				t.Fatal("altered context accepted")
			}
		})
	}
	for _, path := range [][]string{{"intent", "payload"}, {"delivery", "recipient_public_key"}, {"attempt_id"}, {"semantic_digest"}} {
		changed := recoveryCopy(request)
		target := changed
		for _, key := range path[:len(path)-1] {
			target = recoveryObject(target[key])
		}
		if len(path) > 1 && path[1] == "payload" {
			target[path[1]] = map[string]any{"requested_scopes": []string{"admin"}}
		} else {
			target[path[len(path)-1]] = "changed"
		}
		if recoveryDigest(t, "ISCP-CONTROL-REQUEST-V2\x00", changed) == context["request_digest"] {
			t.Fatalf("request binding omitted %v", path)
		}
	}
	result := recoveryObject(f["result"])
	if string(recoveryCanonical(t, result["payload"])) != f["result_payload_canonical"] || recoveryDigest(t, "ISCP-OPERATION-RESULT-V2\x00", result["payload"]) != f["result_digest"] {
		t.Fatal("result canonical digest differs")
	}
	for _, name := range []string{"result", "disposition", "status_record"} {
		if !recoveryVerify(t, recoveryObject(f[name]), recoveryBytes(t, keys["issuer_public_key"])) {
			t.Fatalf("invalid signed %s", name)
		}
		changed := recoveryCopy(f[name])
		changed["type"] = "iscp.wrong-purpose.v2"
		if recoveryVerify(t, changed, recoveryBytes(t, keys["issuer_public_key"])) {
			t.Fatal("signature accepted under wrong object type")
		}
	}
	disposition := recoveryCopy(f["disposition"])
	delete(disposition, "signature")
	delete(disposition, "accepted_at")
	delete(disposition, "disposition_digest")
	if recoveryDigest(t, "ISCP-OPERATION-DISPOSITION-V2\x00", disposition) != recoveryObject(f["disposition"])["disposition_digest"] {
		t.Fatal("disposition digest differs")
	}
	child := recoveryObject(f["child"])
	if string(recoveryCanonical(t, child["context"])) != child["canonical"] || "child-"+recoveryDigest(t, "ISCP-CHILD-OPERATION-V2\x00", child["context"]) != child["operation_id"] {
		t.Fatal("child key differs")
	}
}

func TestAuthenticationRecoveryCandidateResealsSameImmutableResult(t *testing.T) {
	f := recoveryFixture(t)
	for _, raw := range f["deliveries"].([]any) {
		v := recoveryObject(raw)
		wire := recoveryObject(v["wire"])
		context := recoveryObject(v["context"])
		if string(recoveryCanonical(t, context)) != v["context_canonical"] {
			t.Fatal("delivery context differs")
		}
		client, err := ecdh.X25519().NewPrivateKey(recoveryHex(t, v["client_seed_hex"]))
		if err != nil {
			t.Fatal(err)
		}
		server, err := ecdh.X25519().NewPublicKey(recoveryBytes(t, wire["server_public_key"]))
		if err != nil {
			t.Fatal(err)
		}
		secret, err := client.ECDH(server)
		if err != nil {
			t.Fatal(err)
		}
		canon := recoveryCanonical(t, context)
		salt := sha256.Sum256(append([]byte("ISCP-CONTROL-RESULT-SALT-V2\x00"), canon...))
		if !bytes.Equal(salt[:], recoveryHex(t, v["salt_hex"])) {
			t.Fatal("salt differs")
		}
		key := make([]byte, 32)
		if _, err = io.ReadFull(hkdf.New(sha256.New, secret, salt[:], append([]byte("ISCP-CONTROL-RESULT-KEY-V2\x00"), canon...)), key); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(key, recoveryHex(t, v["key_hex"])) {
			t.Fatal("derived key differs")
		}
		aad := append([]byte("ISCP-CONTROL-RESULT-AAD-V2\x00"), canon...)
		if !bytes.Equal(aad, recoveryHex(t, v["aad_hex"])) {
			t.Fatal("delivery AAD differs")
		}
		aead, err := chacha20poly1305.New(key)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext := recoveryBytes(t, wire["ciphertext"])
		nonce := recoveryBytes(t, wire["nonce"])
		plain, err := aead.Open(nil, nonce, ciphertext, aad)
		if err != nil || !bytes.Equal(plain, recoveryCanonical(t, f["result"])) {
			t.Fatal("resealed result is not the identical immutable result")
		}
		for _, field := range []string{"recipient_public_key", "result_digest", "delivery_id", "semantic_digest"} {
			changed := recoveryCopy(context)
			changed[field] = "changed"
			wrongAAD := append([]byte("ISCP-CONTROL-RESULT-AAD-V2\x00"), recoveryCanonical(t, changed)...)
			if _, err = aead.Open(nil, nonce, ciphertext, wrongAAD); err == nil {
				t.Fatalf("changed %s decrypted", field)
			}
		}
	}
}

// Candidate parsing supplements current canonical.ParseStrict, whose UTF-8,
// surrogate and trailing-token fixes are owned by the duplex line. This helper
// is test-only and cannot be mistaken for a production verifier.
func recoveryStrict(raw []byte) error {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return fmt.Errorf("invalid UTF-8/JSON")
	}
	inString := false
	for i := 0; i < len(raw); i++ {
		if raw[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || raw[i] != '\\' {
			continue
		}
		i++
		if raw[i] != 'u' {
			continue
		}
		var code uint32
		_, err := fmt.Sscanf(string(raw[i+1:i+5]), "%04x", &code)
		if err != nil {
			return err
		}
		i += 4
		if code >= 0xd800 && code <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return fmt.Errorf("lone high surrogate")
			}
			var low uint32
			_, err = fmt.Sscanf(string(raw[i+3:i+7]), "%04x", &low)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return fmt.Errorf("invalid surrogate pair")
			}
			i += 6
		} else if code >= 0xdc00 && code <= 0xdfff {
			return fmt.Errorf("lone low surrogate")
		}
	}
	_, err := canonical.ParseStrict(raw)
	return err
}

func TestAuthenticationRecoveryCandidateRejectsMalformedInputs(t *testing.T) {
	f := recoveryFixture(t)
	for _, item := range f["negative_raw"].([]any) {
		v := recoveryObject(item)
		t.Run(v["name"].(string), func(t *testing.T) {
			raw := []byte(fmt.Sprint(v["raw"]))
			if v["raw_hex"] != nil {
				raw = recoveryHex(t, v["raw_hex"])
			}
			if recoveryStrict(raw) == nil {
				t.Fatal("malformed input accepted")
			}
		})
	}
	for _, raw := range []string{`{"value":"\ud83d\ude00"}`, `{"value":"\\ud800"}`, `{"value":"汉字<>&"}`} {
		if err := recoveryStrict([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
}

// Small test-only evaluator for the exact schema vocabulary used by this
// candidate. AJV 2020 validation is additionally run when preparing the assets;
// this evaluator keeps Go CI independent of a shared JavaScript installation.
func recoverySchema(value any, schema, root map[string]any) error {
	if ref, ok := schema["$ref"].(string); ok {
		return recoverySchema(value, recoveryObject(recoveryObject(root["$defs"])[strings.TrimPrefix(ref, "#/$defs/")]), root)
	}
	if choices, ok := schema["oneOf"].([]any); ok {
		matches := 0
		for _, choice := range choices {
			if recoverySchema(value, recoveryObject(choice), root) == nil {
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("oneOf matches %d", matches)
		}
		return nil
	}
	if constant, ok := schema["const"]; ok && !reflect.DeepEqual(value, constant) {
		return fmt.Errorf("const mismatch")
	}
	if choices, ok := schema["enum"].([]any); ok {
		found := false
		for _, choice := range choices {
			found = found || reflect.DeepEqual(value, choice)
		}
		if !found {
			return fmt.Errorf("enum mismatch")
		}
	}
	switch schema["type"] {
	case "object":
		obj, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("not object")
		}
		properties, _ := schema["properties"].(map[string]any)
		if required, ok := schema["required"].([]any); ok {
			for _, key := range required {
				if _, ok := obj[key.(string)]; !ok {
					return fmt.Errorf("missing %s", key)
				}
			}
		}
		for key, v := range obj {
			if child, ok := properties[key]; ok {
				if err := recoverySchema(v, recoveryObject(child), root); err != nil {
					return fmt.Errorf("%s: %w", key, err)
				}
			} else if schema["additionalProperties"] == false {
				return fmt.Errorf("unknown %s", key)
			}
		}
	case "string":
		s, ok := value.(string)
		if !ok {
			return fmt.Errorf("not string")
		}
		if n, ok := schema["minLength"].(float64); ok && utf8.RuneCountInString(s) < int(n) {
			return fmt.Errorf("too short")
		}
		if n, ok := schema["maxLength"].(float64); ok && utf8.RuneCountInString(s) > int(n) {
			return fmt.Errorf("too long")
		}
		if pattern, ok := schema["pattern"].(string); ok && !regexp.MustCompile(pattern).MatchString(s) {
			return fmt.Errorf("pattern mismatch")
		}
	case "array":
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("not array")
		}
		if n, ok := schema["minItems"].(float64); ok && len(items) < int(n) {
			return fmt.Errorf("too few items")
		}
		if n, ok := schema["maxItems"].(float64); ok && len(items) > int(n) {
			return fmt.Errorf("too many items")
		}
		seen := map[string]bool{}
		for _, v := range items {
			if err := recoverySchema(v, recoveryObject(schema["items"]), root); err != nil {
				return err
			}
			raw, _ := json.Marshal(v)
			if schema["uniqueItems"] == true && seen[string(raw)] {
				return fmt.Errorf("duplicate item")
			}
			seen[string(raw)] = true
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("not boolean")
		}
	case "null":
		if value != nil {
			return fmt.Errorf("not null")
		}
	case "integer":
		value, ok := value.(float64)
		if !ok || value != float64(int64(value)) {
			return fmt.Errorf("not integer")
		}
		if minimum, ok := schema["minimum"].(float64); ok && value < minimum {
			return fmt.Errorf("below minimum")
		}
		if maximum, ok := schema["maximum"].(float64); ok && value > maximum {
			return fmt.Errorf("above maximum")
		}
	case nil:
	default:
		return fmt.Errorf("unsupported test schema keyword type %v", schema["type"])
	}
	return nil
}

func recoveryDelegatedAllowed(t *testing.T, value map[string]any) bool {
	t.Helper()
	actor := recoveryObject(value["authenticated_actor"])
	key := recoveryObject(value["key"])
	intent := recoveryObject(value["intent"])
	subject := recoveryObject(intent["subject_binding"])
	stored := recoveryObject(value["stored_authority"])
	preconditions := recoveryObject(intent["preconditions"])
	parent := recoveryObject(intent["parent"])
	parentKey := recoveryObject(parent["key"])
	if actor["domain_id"] != stored["domain_id"] || actor["device_id"] != stored["issuer_device_id"] || key["domain_id"] != actor["domain_id"] || key["device_id"] != actor["device_id"] || stored["service_active"] != true || stored["subject_active"] != true {
		return false
	}
	for _, field := range []string{"domain_id", "device_id", "binding_id"} {
		if subject[field] != stored[field] {
			return false
		}
	}
	for _, field := range []string{"authorization_revision", "resource_version", "credential_generation"} {
		if preconditions[field] != stored[field] {
			return false
		}
	}
	if parentKey["domain_id"] != subject["domain_id"] || parentKey["device_id"] != subject["device_id"] || parentKey["namespace"] != "control.credentials.v2" {
		return false
	}
	allowed := map[any]bool{}
	for _, scope := range stored["scopes"].([]any) {
		allowed[scope] = true
	}
	requested := recoveryObject(intent["payload"])["requested_scopes"].([]any)
	if !reflect.DeepEqual(requested, recoveryObject(intent["task_authorization"])["scopes"]) {
		return false
	}
	for _, scope := range requested {
		if !allowed[scope] {
			return false
		}
	}
	childContext := map[string]any{"parent_key": parentKey, "parent_semantic_digest": parent["semantic_digest"], "target_service_id": recoveryObject(intent["target"])["service_id"], "step": parent["step"], "child_index": parent["child_index"], "predecessor_disposition_digest": nil}
	childID := "child-" + recoveryDigest(t, "ISCP-CHILD-OPERATION-V2\x00", childContext)
	return key["operation_id"] == childID && intent["operation_id"] == childID
}

func TestAuthenticationRecoveryCandidateDelegatedChildAndSuccessor(t *testing.T) {
	f := recoveryFixture(t)
	if !recoveryDelegatedAllowed(t, recoveryObject(f["delegated_child"])) {
		t.Fatal("authorized child rejected")
	}
	for _, raw := range f["negative_delegation"].([]any) {
		m := recoveryObject(raw)
		t.Run(m["name"].(string), func(t *testing.T) {
			value := recoveryCopy(f["delegated_child"])
			recoveryMutate(value, m)
			if recoveryDelegatedAllowed(t, value) {
				t.Fatal("untrusted delegated authority accepted")
			}
		})
	}
	keys := recoveryObject(f["test_keys"])
	for _, name := range []string{"child_result", "child_disposition", "child_delegated_disposition"} {
		if !recoveryVerify(t, recoveryObject(f[name]), recoveryBytes(t, keys["relay_public_key"])) {
			t.Fatalf("%s signature", name)
		}
	}
	parentResult := recoveryObject(f["parent_recovery_result"])
	if !recoveryVerify(t, parentResult, recoveryBytes(t, keys["issuer_public_key"])) {
		t.Fatal("parent recovery signature")
	}
	parentPayload := recoveryObject(parentResult["payload"])
	childResult := recoveryObject(recoveryObject(parentPayload["body"])["relay_result"])
	if !recoveryVerify(t, childResult, recoveryBytes(t, keys["relay_public_key"])) || recoveryVerify(t, childResult, recoveryBytes(t, keys["issuer_public_key"])) {
		t.Fatal("embedded child must verify under original pinned Relay signer")
	}
	childPayload := recoveryObject(childResult["payload"])
	if parentPayload["credential_generation"] != "9" || childPayload["credential_generation"] != "22" {
		t.Fatal("independent issuer and Relay generation vectors collapsed")
	}
	delegatedAck := recoveryObject(recoveryObject(f["child_delegated_disposition"])["ack"])
	if delegatedAck["disposition"] != "delegated" || delegatedAck["parent_result_digest"] != parentResult["result_digest"] {
		t.Fatal("delegated child not bound to frozen parent result")
	}
	successor := recoveryObject(f["child_successor"])
	context := recoveryObject(successor["context"])
	if successor["requires_predecessor_closed"] != true || context["child_index"] != "1" || context["predecessor_disposition_digest"] != recoveryObject(f["child_disposition"])["disposition_digest"] {
		t.Fatal("successor lacks durable closure binding")
	}
	if got := "child-" + recoveryDigest(t, "ISCP-CHILD-OPERATION-V2\x00", context); got != successor["operation_id"] || got == recoveryObject(f["child"])["operation_id"] {
		t.Fatal("successor does not have a distinct deterministic child key")
	}
	// Dropping the closure or changing its disposition produces a different key;
	// callers cannot reuse the admitted successor for another predecessor.
	changed := recoveryCopy(context)
	changed["predecessor_disposition_digest"] = nil
	if "child-"+recoveryDigest(t, "ISCP-CHILD-OPERATION-V2\x00", changed) == successor["operation_id"] {
		t.Fatal("successor key omitted predecessor closure")
	}
}

func TestAuthenticationRecoveryCandidateSchemaAndNegativeVectors(t *testing.T) {
	f := recoveryFixture(t)
	raw, err := os.ReadFile("../schemas/candidates/operation-recovery.v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err = json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"intent", "challenge", "request", "authentication_context", "result", "disposition", "status_record", "child_result", "child_disposition", "child_delegated_disposition", "parent_recovery_intent", "parent_recovery_result"} {
		if err = recoverySchema(f[name], schema, schema); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	for _, item := range f["negative_status"].([]any) {
		m := recoveryObject(item)
		t.Run(m["name"].(string), func(t *testing.T) {
			value := recoveryCopy(f["status_record"])
			recoveryMutate(value, m)
			if recoverySchema(value, schema, schema) == nil {
				t.Fatal("contradictory status accepted")
			}
		})
	}
	for _, v := range f["deliveries"].([]any) {
		if err = recoverySchema(recoveryObject(v)["wire"], schema, schema); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range f["negative_schema"].([]any) {
		m := recoveryObject(item)
		t.Run(m["name"].(string), func(t *testing.T) {
			value := recoveryCopy(f["request"])
			recoveryMutate(value, m)
			if recoverySchema(value, schema, schema) == nil {
				t.Fatal("invalid request matched schema")
			}
		})
	}
	// Scope arrays are semantic sets in the control profile: sorted unique bytes
	// prevent spelling the same requested privilege with another semantic digest.
	scopes := recoveryObject(recoveryObject(f["intent"])["task_authorization"])["scopes"].([]any)
	values := make([]string, len(scopes))
	for i, v := range scopes {
		values[i] = v.(string)
	}
	if !sort.StringsAreSorted(values) {
		t.Fatal("control scopes must be sorted")
	}
}
