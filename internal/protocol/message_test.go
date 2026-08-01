package protocol

import (
	"encoding/json"
	"testing"
)

func TestClassifyRequest(t *testing.T) {
	m := &Message{JSONRPC: Version, ID: json.RawMessage(`1`), Method: "tools/call"}
	if !m.IsRequest() {
		t.Error("message with method and id should be a request")
	}
	if m.IsNotification() || m.IsResponse() {
		t.Error("a request must not classify as notification or response")
	}
}

func TestClassifyNotification(t *testing.T) {
	m := &Message{JSONRPC: Version, Method: "notifications/initialized"}
	if !m.IsNotification() {
		t.Error("message with method and no id should be a notification")
	}
	if m.IsRequest() {
		t.Error("a notification must not classify as a request")
	}
}

func TestClassifyResponse(t *testing.T) {
	m := &Message{JSONRPC: Version, ID: json.RawMessage(`1`), Result: json.RawMessage(`{}`)}
	if !m.IsResponse() {
		t.Error("message with id and no method should be a response")
	}
}

func TestNullIDIsNotAnID(t *testing.T) {
	// JSON-RPC permits a null id on error responses to unparseable requests.
	// Treating "null" as a real id would corrupt the correlation table, because
	// two unrelated failures would collide on the same key.
	m := &Message{JSONRPC: Version, ID: json.RawMessage(`null`), Method: "tools/call"}
	if m.HasID() {
		t.Error("null id must not count as having an id")
	}
	if !m.IsNotification() {
		t.Error("method with null id behaves as a notification for routing purposes")
	}
}

func TestIDKeyIsStableAcrossWhitespace(t *testing.T) {
	// Encoders differ in whitespace. If IDKey is whitespace-sensitive, a response
	// fails to correlate to its request and the call hangs forever.
	a := &Message{ID: json.RawMessage(` 42 `)}
	b := &Message{ID: json.RawMessage(`42`)}
	if a.IDKey() != b.IDKey() {
		t.Errorf("IDKey should ignore surrounding whitespace: %q vs %q", a.IDKey(), b.IDKey())
	}
}

func TestIDKeyDistinguishesStringAndNumber(t *testing.T) {
	// The JSON-RPC id "1" and 1 are different ids. Collapsing them would let one
	// response satisfy two requests.
	num := &Message{ID: json.RawMessage(`1`)}
	str := &Message{ID: json.RawMessage(`"1"`)}
	if num.IDKey() == str.IDKey() {
		t.Error("numeric and string ids must not share a key")
	}
}

func TestStringAndNumericIDsRoundTrip(t *testing.T) {
	for _, raw := range []string{`1`, `"abc"`, `-9007199254740993`} {
		var m Message
		in := `{"jsonrpc":"2.0","id":` + raw + `,"method":"ping"}`
		if err := json.Unmarshal([]byte(in), &m); err != nil {
			t.Fatalf("unmarshal %s: %v", in, err)
		}
		out, err := json.Marshal(&m)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var got map[string]any
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatalf("re-unmarshal: %v", err)
		}
		// RawMessage preserves the exact bytes, so a large integer id survives
		// without being mangled into a float64.
		if string(m.ID) != raw {
			t.Errorf("id %s was altered to %s", raw, m.ID)
		}
	}
}

func TestOmitEmptyKeepsMessagesMinimal(t *testing.T) {
	m := &Message{JSONRPC: Version, Method: "ping", ID: json.RawMessage(`1`)}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	if string(out) != want {
		t.Errorf("marshal = %s, want %s", out, want)
	}
}

func TestErrorImplementsError(t *testing.T) {
	var err error = &Error{Code: CodePolicyDenied, Message: "denied by policy"}
	if got := err.Error(); got == "" {
		t.Error("Error() must produce a non-empty string")
	}
}

func TestDenyResponseShape(t *testing.T) {
	m := DenyResponse(json.RawMessage(`7`), "deny-protected-branches", "branch is main")

	if m.JSONRPC != Version {
		t.Errorf("jsonrpc = %q, want %q", m.JSONRPC, Version)
	}
	if m.IDKey() != "7" {
		t.Errorf("id = %q, want 7", m.IDKey())
	}
	if m.Error == nil {
		t.Fatal("deny response must carry an error object")
	}
	if m.Error.Code != CodePolicyDenied {
		t.Errorf("code = %d, want %d", m.Error.Code, CodePolicyDenied)
	}
	// The rule name and reason must reach the model so it can adapt rather than
	// retry the same denied call in a loop.
	var data struct {
		Rule   string `json:"rule"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(m.Error.Data, &data); err != nil {
		t.Fatalf("error data is not the expected object: %v", err)
	}
	if data.Rule != "deny-protected-branches" || data.Reason != "branch is main" {
		t.Errorf("data = %+v, want rule and reason populated", data)
	}
}

func TestErrorResponseWithUnmarshalableDataOmitsData(t *testing.T) {
	// A marshal failure while constructing an error must not itself become an
	// error path. Omitting the data field degrades gracefully.
	m := ErrorResponse(json.RawMessage(`1`), CodeInternalError, "boom", make(chan int))
	if m.Error == nil {
		t.Fatal("expected an error object")
	}
	if len(m.Error.Data) != 0 {
		t.Errorf("Data should be empty when marshalling fails, got %s", m.Error.Data)
	}
}
