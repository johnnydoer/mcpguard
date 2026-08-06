package policy

import (
	"strings"
	"testing"
)

func engineFrom(t *testing.T, yaml string) *Engine {
	t.Helper()
	cfg, err := Load(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

const twoRuleConfig = `
version: v1
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules:
  - name: deny-etc
    servers: [fs]
    tools: [read_file]
    match:
      args:
        path: {type: string, canonicalize: path, prefix: /etc/}
    action: deny
    message: "system files are off limits"
  - name: allow-srv
    servers: [fs]
    tools: [read_file]
    match:
      args:
        path: {type: string, canonicalize: path, prefix: /srv/}
    action: allow
`

func TestEvaluateFirstMatchWins(t *testing.T) {
	e := engineFrom(t, twoRuleConfig)

	d := e.Evaluate(Request{Server: "fs", Method: "tools/call", Tool: "read_file",
		Args: map[string]any{"path": "/srv/a"}})
	if d.Action != ActionAllow || d.Rule != "allow-srv" {
		t.Errorf("got %+v, want allow via allow-srv", d)
	}

	d = e.Evaluate(Request{Server: "fs", Method: "tools/call", Tool: "read_file",
		Args: map[string]any{"path": "/etc/shadow"}})
	if d.Action != ActionDeny || d.Rule != "deny-etc" {
		t.Errorf("got %+v, want deny via deny-etc", d)
	}
	if d.Message != "system files are off limits" {
		t.Errorf("Message = %q, want the rule's message", d.Message)
	}
}

func TestEvaluateFallsThroughToDefault(t *testing.T) {
	e := engineFrom(t, twoRuleConfig)
	d := e.Evaluate(Request{Server: "fs", Method: "tools/call", Tool: "read_file",
		Args: map[string]any{"path": "/home/x"}})

	if d.Action != ActionDeny {
		t.Errorf("Action = %q, want deny by default", d.Action)
	}
	if d.Rule != "" {
		t.Errorf("Rule = %q, want empty when no rule matched", d.Rule)
	}
	if d.Reason == "" {
		t.Error("a default-deny decision must still explain itself")
	}
}

func TestEvaluateUnknownToolFallsThroughToDefault(t *testing.T) {
	e := engineFrom(t, twoRuleConfig)
	d := e.Evaluate(Request{Server: "fs", Method: "tools/call", Tool: "delete_file",
		Args: map[string]any{}})
	if d.Action != ActionDeny || d.Rule != "" {
		t.Errorf("got %+v, want default deny", d)
	}
}

func TestEvaluateWrongServerDoesNotMatch(t *testing.T) {
	// Keeping servers: on rules means one config file works unchanged in gateway
	// mode later, but it must actually scope.
	e := engineFrom(t, twoRuleConfig)
	d := e.Evaluate(Request{Server: "other", Method: "tools/call", Tool: "read_file",
		Args: map[string]any{"path": "/srv/a"}})
	if d.Action != ActionDeny || d.Rule != "" {
		t.Errorf("got %+v, want default deny for a different server", d)
	}
}

func TestEvaluateOmittedServersListMatchesAllServers(t *testing.T) {
	e := engineFrom(t, `
version: v1
servers:
  - {name: a, transport: stdio, command: ["true"]}
  - {name: b, transport: stdio, command: ["true"]}
rules:
  - {name: global, tools: ["*"], action: allow}
`)
	for _, server := range []string{"a", "b"} {
		if d := e.Evaluate(Request{Server: server, Tool: "anything"}); d.Action != ActionAllow {
			t.Errorf("server %s: got %+v, want allow", server, d)
		}
	}
}

func TestEvaluateToolGlobs(t *testing.T) {
	e := engineFrom(t, `
version: v1
servers: [{name: gl, transport: stdio, command: ["true"]}]
rules:
  - {name: reads, servers: [gl], tools: ["get_*", "list_*"], action: allow}
`)
	for tool, want := range map[string]Action{
		"get_file":   ActionAllow,
		"list_repos": ActionAllow,
		"push_files": ActionDeny,
	} {
		if d := e.Evaluate(Request{Server: "gl", Tool: tool}); d.Action != want {
			t.Errorf("tool %s: Action = %q, want %q", tool, d.Action, want)
		}
	}
}

func TestEvaluateMatcherErrorBecomesDeny(t *testing.T) {
	// The central fail-closed guarantee. A type-confused argument produces an
	// error inside the matcher, and that must become a denial rather than
	// falling through to a later, broader rule.
	e := engineFrom(t, `
version: v1
defaults: {action: allow}
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules:
  - name: scoped
    servers: [fs]
    tools: [read_file]
    match:
      args:
        path: {type: string, prefix: /srv/}
    action: allow
  - name: catch-all
    servers: [fs]
    tools: ["*"]
    action: allow
`)
	d := e.Evaluate(Request{Server: "fs", Tool: "read_file",
		Args: map[string]any{"path": []any{"/srv/ok", "/etc/shadow"}}})

	if d.Action != ActionDeny {
		t.Fatalf("Action = %q, want deny — an evaluation error must not fall through "+
			"to the catch-all rule", d.Action)
	}
	if d.Rule != "scoped" {
		t.Errorf("Rule = %q, want the rule that errored", d.Rule)
	}
	if !strings.Contains(d.Reason, "type") {
		t.Errorf("Reason = %q, should explain the type mismatch", d.Reason)
	}
}

func TestEvaluateTraversalBecomesDeny(t *testing.T) {
	e := engineFrom(t, twoRuleConfig)
	d := e.Evaluate(Request{Server: "fs", Tool: "read_file",
		Args: map[string]any{"path": "/srv/data/../../etc/shadow"}})

	if d.Action != ActionDeny {
		t.Errorf("Action = %q, want deny for a traversal path", d.Action)
	}
}

func TestEvaluateAdditionalArgsDeniedByDefault(t *testing.T) {
	// A rule constraining path says nothing about follow_symlinks. Without this,
	// a rule is a partial statement about the call rather than an exhaustive one.
	e := engineFrom(t, `
version: v1
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules:
  - name: scoped
    servers: [fs]
    tools: [read_file]
    match:
      args:
        path: {type: string, prefix: /srv/}
    action: allow
`)
	d := e.Evaluate(Request{Server: "fs", Tool: "read_file",
		Args: map[string]any{"path": "/srv/a", "follow_symlinks": true}})

	if d.Action != ActionDeny {
		t.Errorf("Action = %q, want deny for an unnamed argument", d.Action)
	}
	if !strings.Contains(d.Reason, "follow_symlinks") {
		t.Errorf("Reason = %q, should name the offending argument", d.Reason)
	}
}

func TestEvaluatePerRuleAdditionalArgsOverride(t *testing.T) {
	e := engineFrom(t, `
version: v1
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules:
  - name: scoped
    servers: [fs]
    tools: [read_file]
    additional_args: allow
    match:
      args:
        path: {type: string, prefix: /srv/}
    action: allow
`)
	d := e.Evaluate(Request{Server: "fs", Tool: "read_file",
		Args: map[string]any{"path": "/srv/a", "follow_symlinks": true}})

	if d.Action != ActionAllow {
		t.Errorf("Action = %q, want allow when the rule opts into extra args", d.Action)
	}
}

func TestEvaluateRuleWithNoMatchBlockIgnoresArgs(t *testing.T) {
	// A rule with no match block constrains nothing, so additional_args cannot
	// apply — there is no named set to be additional to.
	e := engineFrom(t, `
version: v1
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules:
  - {name: any-write, servers: [fs], tools: [write_file], action: approve, message: "confirm"}
`)
	d := e.Evaluate(Request{Server: "fs", Tool: "write_file",
		Args: map[string]any{"path": "/srv/a", "content": "x", "mode": 420}})

	if d.Action != ActionApprove {
		t.Errorf("Action = %q, want approve", d.Action)
	}
}

func TestEvaluateApproveIsReturnedVerbatim(t *testing.T) {
	e := engineFrom(t, `
version: v1
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules:
  - {name: writes, servers: [fs], tools: [write_file], action: approve, message: "confirm write"}
`)
	d := e.Evaluate(Request{Server: "fs", Tool: "write_file"})
	if d.Action != ActionApprove || d.Rule != "writes" || d.Message != "confirm write" {
		t.Errorf("got %+v, want approve via writes", d)
	}
}

func TestToolVisibleIgnoresArgumentMatchers(t *testing.T) {
	// tools/list filtering asks "could this tool ever be permitted?", so a tool
	// whose rule constrains arguments must still be advertised. Hiding it would
	// remove a capability the agent legitimately has for some inputs.
	e := engineFrom(t, twoRuleConfig)
	if !e.ToolVisible("fs", "read_file") {
		t.Error("read_file should be visible: an allow rule matches it for some arguments")
	}
	if e.ToolVisible("fs", "delete_file") {
		t.Error("delete_file should be hidden: no rule matches and the default is deny")
	}
}

func TestToolVisibleHidesToolsWhoseFirstMatchIsDeny(t *testing.T) {
	e := engineFrom(t, `
version: v1
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules:
  - {name: no-deletes, servers: [fs], tools: [delete_file], action: deny}
  - {name: everything, servers: [fs], tools: ["*"], action: allow}
`)
	if e.ToolVisible("fs", "delete_file") {
		t.Error("delete_file should be hidden: its first matching rule denies")
	}
	if !e.ToolVisible("fs", "read_file") {
		t.Error("read_file should be visible via the catch-all allow")
	}
}

func TestToolVisibleTreatsApproveAsVisible(t *testing.T) {
	e := engineFrom(t, `
version: v1
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules:
  - {name: writes, servers: [fs], tools: [write_file], action: approve}
`)
	if !e.ToolVisible("fs", "write_file") {
		t.Error("an approve rule means the tool is usable, so it must be advertised")
	}
}

func TestNewRejectsNilConfig(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Error("New(nil) must fail rather than produce an engine that allows everything")
	}
}

func TestNewCompilesNestedMatchers(t *testing.T) {
	// Load already compiles, but New must not depend on having been given a
	// Config that came through Load — a caller could build one programmatically.
	cfg := &Config{
		Version: "v1", Mode: ModeEnforce,
		Defaults: Defaults{Action: ActionDeny, AdditionalArgs: ActionDeny},
		Audit:    AuditConfig{OnError: OnErrorDeny},
		Approval: ApprovalConfig{Timeout: DefaultApprovalTimeout, OnTimeout: ActionDeny},
		Servers:  []Server{{Name: "fs", Transport: "stdio", Command: []string{"true"}}},
		Rules: []Rule{{
			Name: "r", Servers: []string{"fs"}, Tools: []string{"t"}, Action: ActionAllow,
			Match: &Match{Args: map[string]Matcher{"x": {Regex: ptr(`^[a-z]+$`)}}},
		}},
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if d := e.Evaluate(Request{Server: "fs", Tool: "t", Args: map[string]any{"x": "abc"}}); d.Action != ActionAllow {
		t.Errorf("got %+v, want allow — the regex was not compiled", d)
	}
}

func TestNewRejectsBadRegexInProgrammaticConfig(t *testing.T) {
	cfg := &Config{
		Version: "v1", Mode: ModeEnforce,
		Defaults: Defaults{Action: ActionDeny, AdditionalArgs: ActionDeny},
		Audit:    AuditConfig{OnError: OnErrorDeny},
		Approval: ApprovalConfig{Timeout: DefaultApprovalTimeout, OnTimeout: ActionDeny},
		Servers:  []Server{{Name: "fs", Transport: "stdio", Command: []string{"true"}}},
		Rules: []Rule{{
			Name: "r", Servers: []string{"fs"}, Tools: []string{"t"}, Action: ActionAllow,
			Match: &Match{Args: map[string]Matcher{"x": {Regex: ptr("([bad")}}},
		}},
	}
	if _, err := New(cfg); err == nil {
		t.Error("New must reject an uncompilable regex")
	}
}
