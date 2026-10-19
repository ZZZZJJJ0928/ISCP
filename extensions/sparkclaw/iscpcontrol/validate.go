package iscpcontrol

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// schemaJSON is the immutable accepted 0041 schema. It intentionally stays local
// so independently released clients and servers do not need a module migration.
//
//go:embed schema.json
var schemaJSON []byte
var frozenSchema = func() map[string]any {
	var v map[string]any
	if e := json.Unmarshal(schemaJSON, &v); e != nil {
		panic(e)
	}
	return v
}()

func object(v any) map[string]any { return v.(map[string]any) }

// Decode validates lexical JSON, the closed wire shape, and scalar semantics
// before populating a typed value. No caller-supplied schema is executed.
func Decode(raw []byte, definition string, out any) error {
	if len(raw) == 0 || len(raw) > MaxBody || !utf8.Valid(raw) || !json.Valid(raw) || !validUnicodeEscapes(raw) {
		return ErrInvalid
	}
	if _, e := canonical.ParseStrict(raw); e != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, e)
	}
	var value any
	if e := json.Unmarshal(raw, &value); e != nil {
		return ErrInvalid
	}
	def, ok := object(frozenSchema["$defs"])[definition].(map[string]any)
	if !ok {
		return ErrInvalid
	}
	if e := validateSchema(value, def, frozenSchema); e != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, e)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if e := dec.Decode(out); e != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, e)
	}
	return nil
}
func Validate(v any, definition string) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	var out any
	return Decode(b, definition, &out)
}
func (r Request) Validate() error {
	if e := Validate(r, "request_"+r.Action); e != nil {
		return e
	}
	if r.Intent != nil {
		if e := r.Intent.Validate(); e != nil {
			return e
		}
		if r.Intent.Namespace != r.Key.Namespace || r.Intent.OperationID != r.Key.OperationID {
			return ErrInvalid
		}
		d, e := Digest("ISCP-OPERATION-INTENT-V2\x00", r.Intent)
		if e != nil || d != r.SemanticDigest {
			return ErrInvalid
		}
		if r.Intent.Parent == nil && (r.Key.DomainID != r.Intent.SubjectBinding.DomainID || r.Key.DeviceID != r.Intent.SubjectBinding.DeviceID) {
			return ErrInvalid
		}
	}
	if r.Ack != nil && (r.Ack.Disposition == "delegated") != (r.Ack.ParentResultDigest != nil) {
		return ErrInvalid
	}
	return nil
}
func (v Intent) Validate() error {
	if e := Validate(v, "intent"); e != nil {
		return e
	}
	ns := CredentialNamespace
	if v.Kind == "relay.refresh" || v.Kind == "relay.recover" {
		ns = RelayNamespace
	}
	if v.Namespace != ns {
		return ErrInvalid
	}
	if !sort.StringsAreSorted(v.Payload.RequestedScopes) || !reflect.DeepEqual(v.Payload.RequestedScopes, v.TaskAuthorization.Scopes) || v.TaskAuthorization.AuthorizationRevision != v.Preconditions.AuthorizationRevision {
		return ErrInvalid
	}
	if v.Parent != nil && (v.Kind != "relay.recover" || v.Parent.Step != "relay.credentials.recover" || v.Parent.Key.Namespace != CredentialNamespace || v.Parent.Key.DomainID != v.SubjectBinding.DomainID || v.Parent.Key.DeviceID != v.SubjectBinding.DeviceID) {
		return ErrInvalid
	}
	if v.Parent != nil {
		initial := v.Parent.ChildIndex == "0"
		if initial != (v.Predecessor == nil) {
			return ErrInvalid
		}
		var prior *string
		if v.Predecessor != nil {
			prior = &v.Predecessor.DispositionDigest
		}
		id, err := ChildOperationID(v.Parent.Key, v.Parent.SemanticDigest, v.Target.ServiceID, v.Parent.ChildIndex, prior)
		if err != nil || id != v.OperationID {
			return ErrInvalid
		}
	}
	return nil
}
func validateSchema(value any, schema, root map[string]any) error {
	if ref, ok := schema["$ref"].(string); ok {
		return validateSchema(value, object(object(root["$defs"])[strings.TrimPrefix(ref, "#/$defs/")]), root)
	}
	if choices, ok := schema["oneOf"].([]any); ok {
		matches := 0
		for _, choice := range choices {
			if validateSchema(value, object(choice), root) == nil {
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
				if err := validateSchema(v, object(child), root); err != nil {
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
		pattern, _ := schema["pattern"].(string)
		if pattern == "^(0|[1-9][0-9]{0,19})$" {
			if _, e := strconv.ParseUint(s, 10, 64); e != nil {
				return fmt.Errorf("counter overflow")
			}
		}
		if strings.HasPrefix(pattern, "^[0-9]{4}-") {
			t, e := time.Parse("2006-01-02T15:04:05Z", s)
			if e != nil || t.UTC().Format("2006-01-02T15:04:05Z") != s {
				return fmt.Errorf("invalid UTC timestamp")
			}
		}
		if strings.HasPrefix(pattern, "^[A-Za-z0-9_-]{") || pattern == "^[A-Za-z0-9_-]+$" {
			b, e := base64.RawURLEncoding.Strict().DecodeString(s)
			if e != nil || base64.RawURLEncoding.EncodeToString(b) != s {
				return fmt.Errorf("noncanonical base64url")
			}
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
			if err := validateSchema(v, object(schema["items"]), root); err != nil {
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

// JSON syntax is checked before this scan. encoding/json otherwise silently
// replaces invalid UTF-16 surrogate escapes with U+FFFD, changing signed bytes.
func validUnicodeEscapes(input []byte) bool {
	for i := 0; i < len(input); i++ {
		if input[i] != '"' {
			continue
		}
		i++
		for ; i < len(input) && input[i] != '"'; i++ {
			if input[i] != '\\' {
				continue
			}
			i++
			if input[i] != 'u' {
				continue
			}
			n, _ := strconv.ParseUint(string(input[i+1:i+5]), 16, 16)
			i += 4
			if n >= 0xD800 && n <= 0xDBFF {
				if i+6 >= len(input) || input[i+1] != '\\' || input[i+2] != 'u' {
					return false
				}
				low, err := strconv.ParseUint(string(input[i+3:i+7]), 16, 16)
				if err != nil || low < 0xDC00 || low > 0xDFFF {
					return false
				}
				i += 6
			} else if n >= 0xDC00 && n <= 0xDFFF {
				return false
			}
		}
	}
	return true
}
