// Package duplex implements the accepted iscp.relay.duplex.v1 wire contract.
package duplex

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Infinimesh-ai/ISCP/pkg/iscp/canonical"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

//go:embed schemas/candidates/*.json schemas/json/*.json
var schemas embed.FS

func strictJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return nil, fmt.Errorf("invalid UTF-8 or JSON")
	}
	// encoding/json replaces lone UTF-16 surrogates; reject them before decoding.
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		i++
		for ; i < len(raw) && raw[i] != '"'; i++ {
			if raw[i] != '\\' {
				continue
			}
			i++
			if raw[i] != 'u' {
				continue
			}
			n, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			i += 4
			if n >= 0xD800 && n <= 0xDBFF {
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return nil, fmt.Errorf("unpaired high surrogate")
				}
				lo, e := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
				if e != nil || lo < 0xDC00 || lo > 0xDFFF {
					return nil, fmt.Errorf("unpaired high surrogate")
				}
				i += 6
			} else if n >= 0xDC00 && n <= 0xDFFF {
				return nil, fmt.Errorf("unpaired low surrogate")
			}
		}
	}
	v, e := canonical.ParseStrict(raw)
	if e != nil {
		return nil, e
	}
	var walk func(any, int) error
	walk = func(v any, d int) error {
		switch x := v.(type) {
		case map[string]any:
			if d > 16 {
				return fmt.Errorf("depth")
			}
			for _, z := range x {
				if e := walk(z, d+1); e != nil {
					return e
				}
			}
		case []any:
			if d > 16 {
				return fmt.Errorf("depth")
			}
			for _, z := range x {
				if e := walk(z, d+1); e != nil {
					return e
				}
			}
		case int64:
			if x < 0 || x > 9007199254740991 {
				return fmt.Errorf("unsafe integer")
			}
		}
		return nil
	}
	return v, walk(v, 1)
}

func loadSchema(path string) (map[string]any, error) {
	b, e := schemas.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var s map[string]any
	e = json.Unmarshal(b, &s)
	return s, e
}
func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

// Evaluate only the assertion vocabulary used by these checked-in schemas;
// unknown assertion keywords fail the test, rather than silently weakening it.
func validateSchema(v any, s, root map[string]any, path string) error {
	for k := range s {
		switch k {
		case "$schema", "$id", "$comment", "title", "description", "$defs", "$ref", "type", "const", "enum", "oneOf", "anyOf", "allOf", "properties", "required", "additionalProperties", "minimum", "maximum", "minLength", "maxLength", "pattern", "format", "contentEncoding":
		default:
			return fmt.Errorf("unsupported schema assertion %s", k)
		}
	}
	if r, ok := s["$ref"].(string); ok {
		parts := strings.SplitN(r, "#", 2)
		doc := root
		p := path
		if parts[0] != "" {
			p = filepath.Join(filepath.Dir(path), parts[0])
			var e error
			doc, e = loadSchema(p)
			if e != nil {
				return e
			}
		}
		var target any = doc
		if len(parts) == 2 && parts[1] != "" {
			for _, key := range strings.Split(strings.TrimPrefix(parts[1], "/"), "/") {
				target = target.(map[string]any)[key]
			}
		}
		if target == nil {
			return fmt.Errorf("missing ref %s", r)
		}
		if e := validateSchema(v, target.(map[string]any), doc, p); e != nil {
			return e
		}
	}
	for _, k := range []string{"allOf", "oneOf", "anyOf"} {
		if list, ok := s[k].([]any); ok {
			n := 0
			for _, x := range list {
				if validateSchema(v, x.(map[string]any), root, path) == nil {
					n++
				}
			}
			if k == "allOf" && n != len(list) || k == "oneOf" && n != 1 || k == "anyOf" && n == 0 {
				return fmt.Errorf("%s matched %d", k, n)
			}
		}
	}
	if c, ok := s["const"]; ok && !equalJSON(v, c) {
		return fmt.Errorf("const")
	}
	if list, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range list {
			found = found || equalJSON(v, x)
		}
		if !found {
			return fmt.Errorf("enum")
		}
	}
	if typ, ok := s["type"].(string); ok {
		valid := false
		switch typ {
		case "object":
			_, valid = v.(map[string]any)
		case "string":
			_, valid = v.(string)
		case "integer":
			_, valid = v.(int64)
		default:
			return fmt.Errorf("unsupported type %s", typ)
		}
		if !valid {
			return fmt.Errorf("type %s", typ)
		}
	}
	if m, ok := v.(map[string]any); ok {
		props, _ := s["properties"].(map[string]any)
		if req, ok := s["required"].([]any); ok {
			for _, k := range req {
				if _, exists := m[k.(string)]; !exists {
					return fmt.Errorf("required %s", k)
				}
			}
		}
		for k, x := range m {
			p, known := props[k]
			if !known {
				if s["additionalProperties"] == false {
					return fmt.Errorf("unknown %s", k)
				}
				continue
			}
			if e := validateSchema(x, p.(map[string]any), root, path); e != nil {
				return fmt.Errorf("%s: %w", k, e)
			}
		}
	}
	if n, ok := v.(int64); ok {
		if lo, ok := s["minimum"].(float64); ok && float64(n) < lo {
			return fmt.Errorf("minimum")
		}
		if hi, ok := s["maximum"].(float64); ok && float64(n) > hi {
			return fmt.Errorf("maximum")
		}
	}
	if x, ok := v.(string); ok {
		if lo, ok := s["minLength"].(float64); ok && utf8.RuneCountInString(x) < int(lo) {
			return fmt.Errorf("minLength")
		}
		if hi, ok := s["maxLength"].(float64); ok && len(x) > int(hi) {
			return fmt.Errorf("max UTF-8 bytes")
		}
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(x) {
			return fmt.Errorf("pattern")
		}
		if s["format"] == "date-time" {
			z, e := time.Parse("2006-01-02T15:04:05Z", x)
			if e != nil || z.Format("2006-01-02T15:04:05Z") != x {
				return fmt.Errorf("timestamp")
			}
		}
		if s["pattern"] == "^[1-9][0-9]{0,19}$" {
			if _, e := strconv.ParseUint(x, 10, 64); e != nil {
				return e
			}
		}
		if s["pattern"] == "^[A-Za-z0-9_-]+$" || s["contentEncoding"] == "base64url" {
			b, e := base64.RawURLEncoding.Strict().DecodeString(x)
			if e != nil || base64.RawURLEncoding.EncodeToString(b) != x {
				return fmt.Errorf("base64url")
			}
		}
	}
	return nil
}
func Validate(raw []byte) error {
	v, e := strictJSON(raw)
	if e != nil {
		return e
	}
	p := "schemas/candidates/relay.duplex.v1.json"
	s, e := loadSchema(p)
	if e != nil {
		return e
	}
	if e = validateSchema(v, s, s, p); e != nil {
		return e
	}
	m := v.(map[string]any)
	limit := 65536
	if m["kind"] == "submit" || m["kind"] == "delivery" {
		limit = 1114112
	}
	if len(raw) > limit {
		return fmt.Errorf("frame size")
	}
	if receipt, ok := m["receipt"].(map[string]any); ok {
		for _, key := range []string{"message_id", "envelope_digest"} {
			if receipt[key] != m[key] {
				return fmt.Errorf("receipt correlation: %s", key)
			}
		}
	}
	if env, ok := m["envelope"]; ok {
		var encoded map[string]json.RawMessage
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return err
		}
		b := encoded["envelope"]
		if len(b) > 1048576 {
			return fmt.Errorf("envelope size")
		}
		if env.(map[string]any)["message_id"] != m["message_id"] {
			return fmt.Errorf("message correlation")
		}
		c, e := canonical.Marshal(b)
		if e != nil {
			return e
		}
		digest := sha256.Sum256(c)
		if base64.RawURLEncoding.EncodeToString(digest[:]) != m["envelope_digest"] {
			return fmt.Errorf("envelope digest")
		}
	}
	return nil
}
