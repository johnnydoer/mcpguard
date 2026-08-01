package protocol

import (
	"encoding/json"
	"testing"
)

func TestParseToolsCall(t *testing.T) {
	m := &Message{
		JSONRPC: Version, ID: json.RawMessage(`1`), Method: MethodToolsCall,
		Params: json.RawMessage(`{"name":"read_file","arguments":{"path":"/srv/a"}}`),
	}
	p, err := ParseToolsCall(m)
	if err != nil {
		t.Fatalf("ParseToolsCall: %v", err)
	}
	if p.Name != "read_file" {
		t.Errorf("Name = %q, want read_file", p.Name)
	}
	if got := p.Arguments["path"]; got != "/srv/a" {
		t.Errorf("arguments[path] = %v, want /srv/a", got)
	}
}

func TestParseToolsCallWithNoArguments(t *testing.T) {
	// A zero-argument tool is legitimate. Arguments must be a usable empty map,
	// not nil, so matchers can check for absent keys without a nil guard.
	m := &Message{Method: MethodToolsCall, Params: json.RawMessage(`{"name":"list_all"}`)}
	p, err := ParseToolsCall(m)
	if err != nil {
		t.Fatalf("ParseToolsCall: %v", err)
	}
	if p.Arguments == nil {
		t.Error("Arguments must be non-nil even when absent from the payload")
	}
	if len(p.Arguments) != 0 {
		t.Errorf("Arguments = %v, want empty", p.Arguments)
	}
}

func TestParseToolsCallRejectsMissingName(t *testing.T) {
	// Without a tool name there is nothing to authorize. This must be an error
	// so the caller denies rather than evaluating against an empty name and
	// possibly matching a wildcard rule.
	m := &Message{Method: MethodToolsCall, Params: json.RawMessage(`{"arguments":{}}`)}
	if _, err := ParseToolsCall(m); err == nil {
		t.Fatal("expected an error when name is missing")
	}
}

func TestParseToolsCallRejectsMalformedParams(t *testing.T) {
	m := &Message{Method: MethodToolsCall, Params: json.RawMessage(`"not an object"`)}
	if _, err := ParseToolsCall(m); err == nil {
		t.Fatal("expected an error for non-object params")
	}
}

func TestParseToolsCallPreservesNestedStructure(t *testing.T) {
	// Argument matchers address nested values, so decoding must not flatten.
	m := &Message{Method: MethodToolsCall, Params: json.RawMessage(
		`{"name":"t","arguments":{"outer":{"inner":"v"},"list":[1,2]}}`)}
	p, err := ParseToolsCall(m)
	if err != nil {
		t.Fatal(err)
	}
	outer, ok := p.Arguments["outer"].(map[string]any)
	if !ok {
		t.Fatalf("outer decoded as %T, want map", p.Arguments["outer"])
	}
	if outer["inner"] != "v" {
		t.Errorf("outer.inner = %v, want v", outer["inner"])
	}
	if _, ok := p.Arguments["list"].([]any); !ok {
		t.Errorf("list decoded as %T, want slice", p.Arguments["list"])
	}
}

func TestParseResourcesRead(t *testing.T) {
	m := &Message{Method: MethodResourcesRead, Params: json.RawMessage(`{"uri":"file:///srv/a"}`)}
	p, err := ParseResourcesRead(m)
	if err != nil {
		t.Fatal(err)
	}
	if p.URI != "file:///srv/a" {
		t.Errorf("URI = %q", p.URI)
	}
}

func TestParseResourcesReadRejectsMissingURI(t *testing.T) {
	m := &Message{Method: MethodResourcesRead, Params: json.RawMessage(`{}`)}
	if _, err := ParseResourcesRead(m); err == nil {
		t.Fatal("expected an error when uri is missing")
	}
}

func TestFilterToolsListRemovesDeniedTools(t *testing.T) {
	in := json.RawMessage(`{"tools":[
		{"name":"read_file","description":"read"},
		{"name":"write_file","description":"write"},
		{"name":"delete_file","description":"delete"}]}`)

	out, err := FilterToolsList(in, func(name string) bool { return name == "read_file" })
	if err != nil {
		t.Fatal(err)
	}

	var got ToolsListResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Tools) != 1 || got.Tools[0].Name != "read_file" {
		t.Errorf("tools = %+v, want only read_file", got.Tools)
	}
}

func TestFilterToolsListKeepsSchemaBytesIntact(t *testing.T) {
	// The schema is what the model uses to construct calls. Re-marshalling it
	// through a typed struct would drop unknown fields and change behaviour, so
	// it is carried as RawMessage.
	in := json.RawMessage(`{"tools":[{"name":"t","inputSchema":{"type":"object","x-custom":1}}]}`)
	out, err := FilterToolsList(in, func(string) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(out) {
		t.Fatal("output is not valid JSON")
	}
	var got ToolsListResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if !containsAll(string(got.Tools[0].InputSchema), `"x-custom"`, `"type"`) {
		t.Errorf("schema lost fields: %s", got.Tools[0].InputSchema)
	}
}

func TestFilterToolsListEmptyResultIsEmptyArrayNotNull(t *testing.T) {
	// A null tools field breaks clients that iterate without a nil check, and
	// denying every tool is a legitimate configuration.
	in := json.RawMessage(`{"tools":[{"name":"a"}]}`)
	out, err := FilterToolsList(in, func(string) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if !containsAll(string(out), `"tools":[]`) {
		t.Errorf("out = %s, want an empty array", out)
	}
}

func TestFilterResourcesListRemovesDeniedURIs(t *testing.T) {
	in := json.RawMessage(`{"resources":[
		{"uri":"file:///srv/public/a"},
		{"uri":"file:///etc/shadow"}]}`)

	out, err := FilterResourcesList(in, func(uri string) bool {
		return uri == "file:///srv/public/a"
	})
	if err != nil {
		t.Fatal(err)
	}
	var got ResourcesListResult
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Resources) != 1 {
		t.Errorf("resources = %+v, want 1", got.Resources)
	}
}

func TestFilterRejectsMalformedResult(t *testing.T) {
	if _, err := FilterToolsList(json.RawMessage(`not json`), func(string) bool { return true }); err == nil {
		t.Error("expected an error for malformed tools/list result")
	}
	if _, err := FilterResourcesList(json.RawMessage(`not json`), func(string) bool { return true }); err == nil {
		t.Error("expected an error for malformed resources/list result")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
