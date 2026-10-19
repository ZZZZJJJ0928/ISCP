package canonical

import "testing"

func TestMarshalSortsKeys(t *testing.T) {
	got, err := Marshal([]byte(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":1,"b":2}` {
		t.Fatalf("unexpected canonical bytes: %s", got)
	}
}

func TestRejectDuplicate(t *testing.T) {
	if _, err := Marshal([]byte(`{"a":1,"a":2}`)); err == nil {
		t.Fatal("expected duplicate field rejection")
	}
}

func TestRejectFloat(t *testing.T) {
	if _, err := Marshal([]byte(`{"a":1.2}`)); err == nil {
		t.Fatal("expected float rejection")
	}
}

func TestSignatureInputRemovesSignature(t *testing.T) {
	got, err := SignatureInput("iscp.test.v2", []byte(`{"b":2,"signature":{"value":"x"},"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	want := "ISCP-V2-SIGNATURE\x00iscp.test.v2\x00" + `{"a":1,"b":2}`
	if string(got) != want {
		t.Fatalf("unexpected signature input: %q", got)
	}
}

func TestStrictRejectsLossyUnicodeAndTrailingGarbage(t *testing.T) {
	for _, raw := range [][]byte{[]byte("{\"x\":\"\xff\"}"), []byte(`{"x":"\ud800"}`), []byte(`{"x":"\udc00"}`), []byte(`{"x":"\ud800x\udc00"}`), []byte(`{"x":"\ud800\ud800"}`), []byte(`{"x":"\udc00\ud800"}`), []byte(`{} garbage`), []byte(`{} {`), []byte(`{} []`)} {
		if _, err := ParseStrict(raw); err == nil {
			t.Errorf("accepted lossy or trailing input %q", raw)
		}
	}
	for _, raw := range []string{`{"x":"\ud83d\ude00"}`, `{"x":"😀"}`, `{"x":"�"}`, `{"x":"\\ud800"}`, "{} \n\t"} {
		if _, err := ParseStrict([]byte(raw)); err != nil {
			t.Errorf("valid input %q: %v", raw, err)
		}
	}
}
