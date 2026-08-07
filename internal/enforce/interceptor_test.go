package enforce

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/JohnnyDoer/mcpguard/internal/policy"
	"github.com/JohnnyDoer/mcpguard/internal/protocol"
	"github.com/JohnnyDoer/mcpguard/internal/transport/stdio"
)

// Compile-time assertion that *Interceptor satisfies the transport-agnostic
// stdio.Interceptor interface. Living in the test file (rather than the
// production file) avoids internal/enforce importing internal/transport/stdio
// for no reason other than this check.
var _ stdio.Interceptor = (*Interceptor)(nil)

var errAuditWriteForTest = errors.New("simulated audit write failure")

type fakeRecorder struct {
	events []Event
	err    error
}

func (f *fakeRecorder) Record(ev Event) error {
	f.events = append(f.events, ev)
	return f.err
}

func testEngine(t *testing.T, yaml string) *policy.Engine {
	t.Helper()
	cfg, err := policy.Load(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	e, err := policy.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

const enforceConfig = `
version: v1
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules:
  - name: allow-public
    servers: [fs]
    tools: [read_file]
    match:
      args:
        path: {type: string, canonicalize: path, prefix: /srv/public/}
    action: allow
  - name: deny-deletes
    servers: [fs]
    tools: [delete_file]
    action: deny
    message: "deletion is not permitted"
`

func newTestInterceptor(t *testing.T, rec Recorder) *Interceptor {
	t.Helper()
	i, err := New(Options{Server: "fs", Engine: testEngine(t, enforceConfig), Recorder: rec})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return i
}

func call(id, tool, args string) *protocol.Message {
	return &protocol.Message{
		JSONRPC: protocol.Version, ID: json.RawMessage(id), Method: protocol.MethodToolsCall,
		Params: json.RawMessage(`{"name":"` + tool + `","arguments":` + args + `}`),
	}
}

func TestInboundAllowsPermittedCall(t *testing.T) {
	rec := &fakeRecorder{}
	forward, reply := newTestInterceptor(t, rec).Inbound(
		call(`1`, "read_file", `{"path":"/srv/public/a"}`))

	if !forward || reply != nil {
		t.Fatalf("got (%v, %v), want (true, nil)", forward, reply)
	}
	if len(rec.events) != 1 || rec.events[0].Decision.Action != policy.ActionAllow {
		t.Errorf("events = %+v, want one allow", rec.events)
	}
}

func TestInboundDeniesAndDoesNotForward(t *testing.T) {
	rec := &fakeRecorder{}
	forward, reply := newTestInterceptor(t, rec).Inbound(
		call(`2`, "delete_file", `{"path":"/srv/public/a"}`))

	if forward {
		t.Error("a denied call must not reach the server")
	}
	if reply == nil || reply.Error == nil {
		t.Fatal("a denied call must produce an error reply to the agent")
	}
	if reply.Error.Code != protocol.CodePolicyDenied {
		t.Errorf("code = %d, want %d", reply.Error.Code, protocol.CodePolicyDenied)
	}
	if reply.IDKey() != "2" {
		t.Errorf("reply id = %q, want 2 — a mismatched id leaves the agent hanging", reply.IDKey())
	}
	if !strings.Contains(reply.Error.Message, "deny-deletes") {
		t.Errorf("message = %q, should name the rule", reply.Error.Message)
	}
}

func TestInboundDeniesMalformedToolsCall(t *testing.T) {
	// A tools/call that cannot be parsed cannot be authorized, so it must be
	// denied rather than forwarded and left to the server.
	rec := &fakeRecorder{}
	m := &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`3`),
		Method: protocol.MethodToolsCall, Params: json.RawMessage(`{"arguments":{}}`)}

	forward, reply := newTestInterceptor(t, rec).Inbound(m)
	if forward {
		t.Error("an unparseable tools/call must not be forwarded")
	}
	if reply == nil || reply.Error == nil {
		t.Fatal("expected an error reply")
	}
}

func TestInboundAuditModeForwardsDeniedCall(t *testing.T) {
	// Audit mode is the whole reason a policy can be rolled out safely: the
	// decision is recorded, but the call proceeds.
	cfg, err := policy.Load(strings.NewReader(strings.Replace(
		enforceConfig, "version: v1", "version: v1\nmode: audit", 1)))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rec := &fakeRecorder{}
	i, err := New(Options{Server: "fs", Engine: engine, Recorder: rec})
	if err != nil {
		t.Fatal(err)
	}

	forward, reply := i.Inbound(call(`4`, "delete_file", `{"path":"/srv/public/a"}`))
	if !forward {
		t.Error("audit mode must forward the call")
	}
	if reply != nil {
		t.Error("audit mode must not inject a denial")
	}
	if len(rec.events) != 1 || rec.events[0].Decision.Action != policy.ActionDeny {
		t.Errorf("audit mode must still record the deny it would have enforced: %+v", rec.events)
	}
	if rec.events[0].Mode != policy.ModeAudit {
		t.Errorf("Mode = %q, want audit so the log distinguishes it", rec.events[0].Mode)
	}
}

func TestInboundRecorderFailureDeniesWhenConfigured(t *testing.T) {
	// audit.on_error: deny. A call that cannot be recorded must not be
	// permitted, because permitting it unrecorded is worse than refusing it.
	rec := &fakeRecorder{err: errAuditWriteForTest}
	forward, reply := newTestInterceptor(t, rec).Inbound(
		call(`5`, "read_file", `{"path":"/srv/public/a"}`))

	if forward {
		t.Error("with on_error deny, an unrecordable call must not be forwarded")
	}
	if reply == nil || reply.Error == nil {
		t.Fatal("expected an error reply")
	}
}

func TestInboundForwardsNonInterceptedMethods(t *testing.T) {
	rec := &fakeRecorder{}
	i := newTestInterceptor(t, rec)

	for _, method := range []string{protocol.MethodInitialize, "ping", "notifications/initialized"} {
		m := &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`9`), Method: method}
		forward, reply := i.Inbound(m)
		if !forward || reply != nil {
			t.Errorf("%s: got (%v, %v), want (true, nil)", method, forward, reply)
		}
	}
	if len(rec.events) != 0 {
		t.Errorf("non-intercepted methods must not produce audit events, got %+v", rec.events)
	}
}

func TestOutboundPassesResponsesThroughByDefault(t *testing.T) {
	i := newTestInterceptor(t, &fakeRecorder{})
	m := &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`1`),
		Result: json.RawMessage(`{"ok":true}`)}

	if got := i.Outbound(m); got != m {
		t.Error("a response with no pending filter must pass through unchanged")
	}
}

func TestNewRejectsMissingDependencies(t *testing.T) {
	engine := testEngine(t, enforceConfig)
	if _, err := New(Options{Engine: engine, Recorder: &fakeRecorder{}}); err == nil {
		t.Error("Server is required")
	}
	if _, err := New(Options{Server: "fs", Recorder: &fakeRecorder{}}); err == nil {
		t.Error("Engine is required")
	}
	if _, err := New(Options{Server: "fs", Engine: engine}); err == nil {
		t.Error("Recorder is required — a proxy that cannot audit must not start")
	}
}

func TestOutboundFiltersToolsList(t *testing.T) {
	i := newTestInterceptor(t, &fakeRecorder{})

	// Inbound must run first so the interceptor knows this id was a tools/list.
	req := &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`10`),
		Method: protocol.MethodToolsList}
	if forward, _ := i.Inbound(req); !forward {
		t.Fatal("tools/list must be forwarded")
	}

	resp := &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`10`),
		Result: json.RawMessage(`{"tools":[{"name":"read_file"},{"name":"delete_file"},{"name":"other"}]}`)}

	out := i.Outbound(resp)
	var result protocol.ToolsListResult
	if err := json.Unmarshal(out.Result, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Tools) != 1 || result.Tools[0].Name != "read_file" {
		t.Errorf("tools = %+v; delete_file has a deny rule and 'other' falls to "+
			"default deny, so only read_file should remain", result.Tools)
	}
}

func TestOutboundDoesNotFilterUncorrelatedResponse(t *testing.T) {
	// A response whose id was never seen must pass through untouched rather than
	// being speculatively parsed as a tools/list result.
	i := newTestInterceptor(t, &fakeRecorder{})
	resp := &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`99`),
		Result: json.RawMessage(`{"tools":[{"name":"delete_file"}]}`)}

	if out := i.Outbound(resp); string(out.Result) != string(resp.Result) {
		t.Error("an uncorrelated response must not be filtered")
	}
}

func TestOutboundFiltersOnlyOncePerID(t *testing.T) {
	// The correlation entry must be consumed, or the table grows without bound
	// across a long session.
	i := newTestInterceptor(t, &fakeRecorder{})
	req := &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`11`),
		Method: protocol.MethodToolsList}
	i.Inbound(req)

	resp := func() *protocol.Message {
		return &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`11`),
			Result: json.RawMessage(`{"tools":[{"name":"delete_file"}]}`)}
	}
	first := i.Outbound(resp())
	second := i.Outbound(resp())

	if strings.Contains(string(first.Result), "delete_file") {
		t.Error("the first response should have been filtered")
	}
	if !strings.Contains(string(second.Result), "delete_file") {
		t.Error("the second response has no pending entry and must pass through")
	}
}

func TestOutboundPassesThroughErrorResponseUnfiltered(t *testing.T) {
	// An error response has no result to filter, and attempting to parse one
	// would turn a server error into a proxy error.
	i := newTestInterceptor(t, &fakeRecorder{})
	i.Inbound(&protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`12`),
		Method: protocol.MethodToolsList})

	resp := &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`12`),
		Error: &protocol.Error{Code: -32603, Message: "server exploded"}}

	out := i.Outbound(resp)
	if out.Error == nil || out.Error.Message != "server exploded" {
		t.Errorf("error response was altered: %+v", out)
	}
}

func TestOutboundFilterFailureDropsTheResponse(t *testing.T) {
	// If a tools/list result cannot be filtered, forwarding it unfiltered would
	// advertise denied tools. Replacing it with an error is the fail-closed
	// choice.
	i := newTestInterceptor(t, &fakeRecorder{})
	i.Inbound(&protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`13`),
		Method: protocol.MethodToolsList})

	resp := &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`13`),
		Result: json.RawMessage(`{"tools": "not an array"}`)}

	out := i.Outbound(resp)
	if out == nil {
		t.Fatal("expected an error response, not a dropped message")
	}
	if out.Error == nil {
		t.Errorf("an unfilterable tools/list must become an error, got %+v", out)
	}
}

func TestInboundPolicesResourcesRead(t *testing.T) {
	i, err := New(Options{Server: "fs", Recorder: &fakeRecorder{}, Engine: testEngine(t, `
version: v1
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules:
  - name: allow-public-resources
    servers: [fs]
    tools: ["file:///srv/public/*"]
    action: allow
`)})
	if err != nil {
		t.Fatal(err)
	}

	allowed := &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`20`),
		Method: protocol.MethodResourcesRead,
		Params: json.RawMessage(`{"uri":"file:///srv/public/a.txt"}`)}
	if forward, reply := i.Inbound(allowed); !forward || reply != nil {
		t.Errorf("permitted resource read: got (%v, %v), want (true, nil)", forward, reply)
	}

	denied := &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`21`),
		Method: protocol.MethodResourcesRead,
		Params: json.RawMessage(`{"uri":"file:///etc/shadow"}`)}
	forward, reply := i.Inbound(denied)
	if forward {
		t.Error("a resource read outside the allowed prefix must not be forwarded")
	}
	if reply == nil || reply.Error == nil {
		t.Fatal("expected a denial reply")
	}
}

func TestInboundDeniesMalformedResourcesRead(t *testing.T) {
	i := newTestInterceptor(t, &fakeRecorder{})
	m := &protocol.Message{JSONRPC: protocol.Version, ID: json.RawMessage(`22`),
		Method: protocol.MethodResourcesRead, Params: json.RawMessage(`{}`)}

	if forward, _ := i.Inbound(m); forward {
		t.Error("a resources/read with no uri cannot be authorized and must be denied")
	}
}
