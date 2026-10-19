package canonical

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	iscperrors "github.com/Infinimesh-ai/ISCP/pkg/iscp/errors"
)

const signaturePrefix = "ISCP-V2-SIGNATURE\x00"

type Value any

func ParseStrict(input []byte) (Value, error) {
	if !utf8.Valid(input) || !json.Valid(input) || !validUnicodeEscapes(input) {
		return nil, iscperrors.New(iscperrors.CodeCanonicalInvalid, "invalid UTF-8, Unicode escape or JSON input")
	}
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.UseNumber()
	value, err := parseValue(dec)
	if err != nil {
		return nil, iscperrors.Wrap(iscperrors.CodeCanonicalInvalid, "invalid canonical json input", err)
	}
	if dec.More() {
		return nil, iscperrors.New(iscperrors.CodeCanonicalInvalid, "unexpected trailing json value")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, iscperrors.New(iscperrors.CodeCanonicalInvalid, "unexpected trailing json content")
	}
	return value, nil
}

func Marshal(input []byte) ([]byte, error) {
	value, err := ParseStrict(input)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := writeCanonical(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func MarshalValue(value Value) ([]byte, error) {
	var out bytes.Buffer
	if err := writeCanonical(&out, value); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func SignatureInput(objectType string, input []byte) ([]byte, error) {
	value, err := ParseStrict(input)
	if err != nil {
		return nil, err
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, iscperrors.New(iscperrors.CodeCanonicalInvalid, "signed object must be a json object")
	}
	delete(obj, "signature")
	canon, err := MarshalValue(obj)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(signaturePrefix)+len(objectType)+1+len(canon))
	out = append(out, signaturePrefix...)
	out = append(out, objectType...)
	out = append(out, 0)
	out = append(out, canon...)
	return out, nil
}

func RejectUnknownTopLevel(input []byte, allowed map[string]struct{}) error {
	value, err := ParseStrict(input)
	if err != nil {
		return err
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return iscperrors.New(iscperrors.CodeCanonicalInvalid, "top-level value must be an object")
	}
	for key := range obj {
		if _, ok := allowed[key]; !ok {
			return iscperrors.New(iscperrors.CodeCanonicalInvalid, "unknown top-level field: "+key)
		}
	}
	return nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, fmt.Errorf("object key is not string")
				}
				if _, exists := obj[key]; exists {
					return nil, fmt.Errorf("duplicate object field %q", key)
				}
				value, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = value
			}
			end, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if end != json.Delim('}') {
				return nil, fmt.Errorf("object not closed")
			}
			return obj, nil
		case '[':
			var arr []any
			for dec.More() {
				value, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, value)
			}
			end, err := dec.Token()
			if err != nil {
				return nil, err
			}
			if end != json.Delim(']') {
				return nil, fmt.Errorf("array not closed")
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("unexpected delimiter %q", t)
		}
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return nil, fmt.Errorf("float values are not allowed")
		}
		if len(s) > 1 && s[0] == '0' {
			return nil, fmt.Errorf("leading zero integer is not allowed")
		}
		if strings.HasPrefix(s, "-0") {
			return nil, fmt.Errorf("negative leading zero integer is not allowed")
		}
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return nil, err
		}
		return i, nil
	case string, bool, nil:
		return t, nil
	default:
		return nil, fmt.Errorf("unsupported token %T", tok)
	}
}

func writeCanonical(out *bytes.Buffer, value any) error {
	switch v := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if v {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		b, _ := json.Marshal(v)
		out.Write(b)
	case int64:
		out.WriteString(strconv.FormatInt(v, 10))
	case int:
		out.WriteString(strconv.Itoa(v))
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			keyBytes, _ := json.Marshal(k)
			out.Write(keyBytes)
			out.WriteByte(':')
			if err := writeCanonical(out, v[k]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	case []any:
		out.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonical(out, item); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	default:
		return iscperrors.New(iscperrors.CodeCanonicalInvalid, fmt.Sprintf("unsupported canonical type %T", value))
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
