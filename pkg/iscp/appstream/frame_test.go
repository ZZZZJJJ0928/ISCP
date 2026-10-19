package appstream

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestGenericConformanceFixtures(t *testing.T) {
	raw, err := os.ReadFile("../../../conformance/fixtures/application-stream.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	type fixture struct {
		Name  string
		Kind  string
		Value json.RawMessage
	}
	var fixtures struct {
		Positive []fixture
		Negative []fixture
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	validate := func(f fixture) error {
		switch f.Kind {
		case "frame":
			_, err := Decode(f.Value)
			return err
		case "control":
			_, err := DecodeControl(f.Value)
			return err
		case "completion":
			_, err := DecodeCompletion(f.Value)
			return err
		default:
			t.Fatalf("unknown fixture kind: %s", f.Kind)
			return nil
		}
	}
	for _, f := range fixtures.Positive {
		if err := validate(f); err != nil {
			t.Fatalf("positive %s: %v", f.Kind, err)
		}
	}
	for _, f := range fixtures.Negative {
		if err := validate(f); err == nil {
			t.Fatalf("accepted negative %s", f.Name)
		}
	}
}

func TestStrictFrameAdmission(t *testing.T) {
	valid := `{"type":"iscp.application.stream.v1","schema_version":1,"subscription_id":"11111111-1111-4111-8111-111111111111","stream_seq":1,"body":{"text":"你好😀"}}`
	if _, err := Decode([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"duplicate":        strings.Replace(valid, `"stream_seq":1`, `"stream_seq":1,"stream_seq":2`, 1),
		"nested duplicate": strings.Replace(valid, `"text":"你好😀"`, `"text":"a","text":"b"`, 1),
		"unknown":          strings.Replace(valid, `"body":`, `"extra":1,"body":`, 1),
		"zero":             strings.Replace(valid, `"stream_seq":1`, `"stream_seq":0`, 1),
		"fraction":         strings.Replace(valid, `"stream_seq":1`, `"stream_seq":1.2`, 1),
		"unsafe":           strings.Replace(valid, `"stream_seq":1`, `"stream_seq":9007199254740992`, 1),
		"surrogate":        strings.Replace(valid, `你好😀`, `\ud800`, 1),
		"utf8":             strings.Replace(valid, `你好😀`, string([]byte{0xff}), 1),
		"version":          strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1),
		"trailing":         valid + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(raw)); err == nil {
				t.Fatal("accepted invalid frame")
			}
		})
	}
	if DecodeStrict([]byte(`{"text":"\ud83d\ude00"}`), new(map[string]string)) != nil {
		t.Fatal("paired surrogate rejected")
	}
}
func TestControlsDoNotCarrySequence(t *testing.T) {
	raw := []byte(`{"type":"iscp.application.stream.control.v1","schema_version":1,"subscription_id":"11111111-1111-4111-8111-111111111111","action":"cancel","latest_open_at":"2026-10-18T10:00:00Z"}`)
	if _, err := DecodeControl(raw); err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	_ = json.Unmarshal(raw, &v)
	v["stream_seq"] = 1
	raw, _ = json.Marshal(v)
	if _, err := DecodeControl(raw); err == nil {
		t.Fatal("sequenced control accepted")
	}
}

func TestCompletionRequiresExplicitSequence(t *testing.T) {
	if _, err := DecodeCompletion([]byte(`{"schema_version":1,"last_stream_seq":0,"reason":"terminal"}`)); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{"schema_version":1,"reason":"terminal"}`,
		`{"schema_version":1,"last_stream_seq":null,"reason":"terminal"}`,
		`{"schema_version":1,"last_stream_seq":-1,"reason":"terminal"}`,
		`{"schema_version":1,"last_stream_seq":9007199254740992,"reason":"terminal"}`,
		`{"schema_version":1,"last_stream_seq":0,"reason":"done"}`,
	} {
		if _, err := DecodeCompletion([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid completion: %s", raw)
		}
	}
}
