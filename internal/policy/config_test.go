package policy

import (
	"strings"
	"testing"
	"time"
)

const minimalConfig = `
version: v1
mode: enforce
defaults:
  action: deny
  additional_args: deny
servers:
  - name: filesystem
    transport: stdio
    command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/srv/data"]
rules:
  - name: allow-public-reads
    servers: [filesystem]
    tools: [read_file]
    match:
      args:
        path:
          type: string
          canonicalize: path
          prefix: /srv/data/public/
    action: allow
`

func TestLoadMinimalConfig(t *testing.T) {
	cfg, err := Load(strings.NewReader(minimalConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Mode != ModeEnforce {
		t.Errorf("Mode = %q, want enforce", cfg.Mode)
	}
	if cfg.Defaults.Action != ActionDeny {
		t.Errorf("Defaults.Action = %q, want deny", cfg.Defaults.Action)
	}
	if len(cfg.Servers) != 1 || cfg.Servers[0].Name != "filesystem" {
		t.Fatalf("Servers = %+v", cfg.Servers)
	}
	if len(cfg.Rules) != 1 {
		t.Fatalf("Rules = %+v", cfg.Rules)
	}
	m, ok := cfg.Rules[0].Match.Args["path"]
	if !ok {
		t.Fatal("rule is missing the path matcher")
	}
	if m.Prefix == nil || *m.Prefix != "/srv/data/public/" {
		t.Errorf("prefix matcher = %+v", m.Prefix)
	}
}

func TestLoadDefaultsToDenyWhenDefaultsOmitted(t *testing.T) {
	// The most important default in the system. Omitting the defaults block must
	// never produce an allow-by-default policy.
	cfg, err := Load(strings.NewReader(`
version: v1
servers: [{name: s, transport: stdio, command: ["true"]}]
rules: []
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Defaults.Action != ActionDeny {
		t.Errorf("Defaults.Action = %q, want deny when omitted", cfg.Defaults.Action)
	}
	if cfg.Defaults.AdditionalArgs != ActionDeny {
		t.Errorf("Defaults.AdditionalArgs = %q, want deny when omitted", cfg.Defaults.AdditionalArgs)
	}
	if cfg.Mode != ModeEnforce {
		t.Errorf("Mode = %q, want enforce when omitted", cfg.Mode)
	}
	if cfg.Audit.OnError != OnErrorDeny {
		t.Errorf("Audit.OnError = %q, want deny when omitted", cfg.Audit.OnError)
	}
	if cfg.Approval.OnTimeout != ActionDeny {
		t.Errorf("Approval.OnTimeout = %q, want deny when omitted", cfg.Approval.OnTimeout)
	}
	if cfg.Approval.Timeout != 120*time.Second {
		t.Errorf("Approval.Timeout = %v, want 120s when omitted", cfg.Approval.Timeout)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	// A typo'd key must be an error, not silently ignored. "acton: allow" that
	// loads as a zero Action and then defaults to something is exactly the class
	// of bug this prevents.
	_, err := Load(strings.NewReader(`
version: v1
servers: [{name: s, transport: stdio, command: ["true"]}]
rules:
  - name: r
    tools: [t]
    acton: allow
`))
	if err == nil {
		t.Fatal("expected an error for an unknown field")
	}
	if !strings.Contains(err.Error(), "acton") {
		t.Errorf("error should name the unknown field, got %v", err)
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	_, err := Load(strings.NewReader(`
version: v99
servers: [{name: s, transport: stdio, command: ["true"]}]
rules: []
`))
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("err = %v, want a version error", err)
	}
}

func TestLoadRejectsInvalidAction(t *testing.T) {
	_, err := Load(strings.NewReader(`
version: v1
servers: [{name: s, transport: stdio, command: ["true"]}]
rules:
  - name: r
    tools: [t]
    action: maybe
`))
	if err == nil || !strings.Contains(err.Error(), "maybe") {
		t.Fatalf("err = %v, want an error naming the invalid action", err)
	}
}

func TestLoadRejectsDuplicateRuleNames(t *testing.T) {
	// Rule names appear in audit logs, deny messages, and test expectations.
	// Duplicates would make all three ambiguous.
	_, err := Load(strings.NewReader(`
version: v1
servers: [{name: s, transport: stdio, command: ["true"]}]
rules:
  - {name: dup, tools: [a], action: allow}
  - {name: dup, tools: [b], action: allow}
`))
	if err == nil || !strings.Contains(err.Error(), "dup") {
		t.Fatalf("err = %v, want a duplicate-name error", err)
	}
}

func TestLoadRejectsUnnamedRule(t *testing.T) {
	_, err := Load(strings.NewReader(`
version: v1
servers: [{name: s, transport: stdio, command: ["true"]}]
rules:
  - {tools: [a], action: allow}
`))
	if err == nil {
		t.Fatal("expected an error for a rule with no name")
	}
}

func TestLoadRejectsRuleReferencingUnknownServer(t *testing.T) {
	// A typo here silently disables the rule. With deny-by-default that fails
	// safe, but it fails silently, which is worse than failing loudly.
	_, err := Load(strings.NewReader(`
version: v1
servers: [{name: filesystem, transport: stdio, command: ["true"]}]
rules:
  - {name: r, servers: [filesytem], tools: [a], action: allow}
`))
	if err == nil || !strings.Contains(err.Error(), "filesytem") {
		t.Fatalf("err = %v, want an error naming the unknown server", err)
	}
}

func TestLoadRejectsRuleWithNoTools(t *testing.T) {
	// An empty tools list is ambiguous: it could mean "no tools" or "all tools".
	// Requiring ["*"] to mean all tools removes the ambiguity.
	_, err := Load(strings.NewReader(`
version: v1
servers: [{name: s, transport: stdio, command: ["true"]}]
rules:
  - {name: r, action: allow}
`))
	if err == nil || !strings.Contains(err.Error(), "tools") {
		t.Fatalf("err = %v, want an error about the missing tools list", err)
	}
}

func TestLoadRejectsStdioServerWithoutCommand(t *testing.T) {
	_, err := Load(strings.NewReader(`
version: v1
servers: [{name: s, transport: stdio}]
rules: []
`))
	if err == nil || !strings.Contains(err.Error(), "command") {
		t.Fatalf("err = %v, want an error about the missing command", err)
	}
}

func TestLoadRejectsHTTPServerWithoutURL(t *testing.T) {
	_, err := Load(strings.NewReader(`
version: v1
servers: [{name: s, transport: http}]
rules: []
`))
	if err == nil || !strings.Contains(err.Error(), "url") {
		t.Fatalf("err = %v, want an error about the missing url", err)
	}
}

func TestLoadRejectsDuplicateServerNames(t *testing.T) {
	_, err := Load(strings.NewReader(`
version: v1
servers:
  - {name: s, transport: stdio, command: ["true"]}
  - {name: s, transport: stdio, command: ["false"]}
rules: []
`))
	if err == nil || !strings.Contains(err.Error(), "s") {
		t.Fatalf("err = %v, want a duplicate-server error", err)
	}
}

func TestLoadRejectsInvalidRegexEarly(t *testing.T) {
	// A regex that fails to compile must be caught when the config loads, not on
	// the first call that reaches the rule. Discovering it at request time means
	// the failure surfaces in production.
	_, err := Load(strings.NewReader(`
version: v1
servers: [{name: s, transport: stdio, command: ["true"]}]
rules:
  - name: r
    tools: [t]
    action: allow
    match:
      args:
        x: {regex: "([unclosed"}
`))
	if err == nil || !strings.Contains(err.Error(), "regex") {
		t.Fatalf("err = %v, want a regex compilation error", err)
	}
}

func TestLoadParsesPerRuleAdditionalArgsOverride(t *testing.T) {
	cfg, err := Load(strings.NewReader(`
version: v1
servers: [{name: s, transport: stdio, command: ["true"]}]
rules:
  - name: r
    tools: [t]
    action: allow
    additional_args: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rules[0].AdditionalArgs == nil {
		t.Fatal("per-rule override was not parsed")
	}
	if *cfg.Rules[0].AdditionalArgs != ActionAllow {
		t.Errorf("override = %q, want allow", *cfg.Rules[0].AdditionalArgs)
	}
}

func TestConfigServerNamesHelper(t *testing.T) {
	cfg, err := Load(strings.NewReader(minimalConfig))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ServerNames(); len(got) != 1 || got[0] != "filesystem" {
		t.Errorf("ServerNames() = %v", got)
	}
}

func TestLoadApprovalTimeoutParsesDuration(t *testing.T) {
	cfg, err := Load(strings.NewReader(`
version: v1
approval: {channel: ntfy, url: "http://x", topic: t, timeout: 45s, on_timeout: deny}
servers: [{name: s, transport: stdio, command: ["true"]}]
rules: []
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Approval.Timeout != 45*time.Second {
		t.Errorf("Timeout = %v, want 45s", cfg.Approval.Timeout)
	}
}

func TestLoadRejectsApprovalTimeoutAllowOnTimeout(t *testing.T) {
	// on_timeout: allow means an unanswered high-risk call proceeds. That is
	// never a defensible configuration, so it is rejected rather than warned
	// about.
	_, err := Load(strings.NewReader(`
version: v1
approval: {channel: ntfy, url: "http://x", topic: t, on_timeout: allow}
servers: [{name: s, transport: stdio, command: ["true"]}]
rules: []
`))
	if err == nil || !strings.Contains(err.Error(), "on_timeout") {
		t.Fatalf("err = %v, want a rejection of on_timeout: allow", err)
	}
}
