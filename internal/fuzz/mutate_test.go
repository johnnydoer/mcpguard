package fuzz

import (
	"strings"
	"testing"

	"github.com/JohnnyDoer/mcpguard/internal/policy"
)

func TestMutateStringProducesTraversalVariants(t *testing.T) {
	got := MutateString("/srv/data/public/a.txt")
	joined := strings.Join(got, "\n")

	for _, want := range []string{"..", "%2e%2e", "\x00"} {
		if !strings.Contains(joined, want) {
			t.Errorf("mutations should include a variant containing %q", want)
		}
	}
	if len(got) < 8 {
		t.Errorf("only %d mutations; the strategy set is too thin to be meaningful", len(got))
	}
}

func TestMutateStringDoesNotIncludeTheOriginal(t *testing.T) {
	// A mutation identical to the input would report a false bypass: the original
	// is permitted by definition.
	const in = "/srv/data/public/a.txt"
	for _, m := range MutateString(in) {
		if m == in {
			t.Error("mutations must all differ from the input")
		}
	}
}

func TestMutateArgsCoversEveryStringArgument(t *testing.T) {
	got := MutateArgs(map[string]any{"path": "/srv/a", "mode": "r"})

	seen := map[string]bool{}
	for _, m := range got {
		seen[m.Arg] = true
	}
	if !seen["path"] || !seen["mode"] {
		t.Errorf("both string arguments should be mutated, saw %v", seen)
	}
}

func TestMutateArgsIncludesTypeSwaps(t *testing.T) {
	// The type-confusion bypass: {"path": ["/srv/ok", "/etc/shadow"]}.
	var foundArray bool
	for _, m := range MutateArgs(map[string]any{"path": "/srv/a"}) {
		if _, ok := m.Args["path"].([]any); ok {
			foundArray = true
		}
	}
	if !foundArray {
		t.Error("mutations must include an array-typed swap")
	}
}

func TestMutateArgsIncludesExtraArgumentInjection(t *testing.T) {
	// Tests the additional_args control specifically.
	var found bool
	for _, m := range MutateArgs(map[string]any{"path": "/srv/a"}) {
		if _, ok := m.Args["mcpguard_injected"]; ok {
			found = true
		}
	}
	if !found {
		t.Error("mutations must include an injected extra argument")
	}
}

func TestMutateArgsDoesNotMutateTheInput(t *testing.T) {
	args := map[string]any{"path": "/srv/a"}
	MutateArgs(args)
	if args["path"] != "/srv/a" {
		t.Errorf("input was mutated: %v", args)
	}
}

func TestFindBypassesReportsNothingForAStrictPolicy(t *testing.T) {
	e := engineFor(t, `
version: v1
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules:
  - name: allow-public
    servers: [fs]
    tools: [read_file]
    match:
      args:
        path: {type: string, canonicalize: path, prefix: /srv/data/public/}
    action: allow
`)
	pt := &policy.PolicyTest{Cases: []policy.Case{{
		Name: "public read", Server: "fs", Tool: "read_file",
		Args: map[string]any{"path": "/srv/data/public/a.txt"}, Expect: policy.ActionAllow,
	}}}

	if got := FindBypasses(e, pt); len(got) != 0 {
		t.Errorf("a strict policy should have no bypasses, found: %+v", got)
	}
}

func TestFindBypassesDetectsAMissingCanonicalizer(t *testing.T) {
	// The exact mistake this tool exists to catch: a prefix rule with no
	// canonicalize, which traversal walks straight through.
	e := engineFor(t, `
version: v1
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules:
  - name: unsafe-prefix
    servers: [fs]
    tools: [read_file]
    match:
      args:
        path: {type: string, prefix: /srv/data/public/}
    action: allow
`)
	pt := &policy.PolicyTest{Cases: []policy.Case{{
		Name: "public read", Server: "fs", Tool: "read_file",
		Args: map[string]any{"path": "/srv/data/public/a.txt"}, Expect: policy.ActionAllow,
	}}}

	got := FindBypasses(e, pt)
	if len(got) == 0 {
		t.Fatal("a prefix rule without canonicalize must be reported as a bypass")
	}
	if got[0].GotRule != "unsafe-prefix" {
		t.Errorf("GotRule = %q, want unsafe-prefix", got[0].GotRule)
	}
}

func TestFindBypassesIgnoresNonAllowCases(t *testing.T) {
	// Mutating an already-denied case proves nothing.
	e := engineFor(t, `
version: v1
servers: [{name: fs, transport: stdio, command: ["true"]}]
rules: []
`)
	pt := &policy.PolicyTest{Cases: []policy.Case{{
		Name: "denied", Server: "fs", Tool: "read_file",
		Args: map[string]any{"path": "/etc/shadow"}, Expect: policy.ActionDeny,
	}}}

	if got := FindBypasses(e, pt); len(got) != 0 {
		t.Errorf("deny cases must not be fuzzed, found: %+v", got)
	}
}

func TestFindBypassesDoesNotFlagWildcardToolGlobs(t *testing.T) {
	// Regression: tool mutations like get_pods/../../etc/shadow match a "get_*"
	// glob (GlobMatch treats * as matching /). Old canonicalTool applied canon.Path
	// to the mutated name, got an error, returned "", which matched nothing and was
	// reported as a bypass. The fix: non-path tool names are returned unchanged so
	// the canonical re-evaluation uses the same broad glob, not "".
	e := engineFor(t, `
version: v1
servers: [{name: k8s, transport: stdio, command: ["true"]}]
rules:
  - name: read-resources
    servers: [k8s]
    tools: ["get_*", "list_*"]
    action: allow
`)
	pt := &policy.PolicyTest{Cases: []policy.Case{{
		Name: "get pods", Server: "k8s", Tool: "get_pods",
		Args: map[string]any{"namespace": "default"}, Expect: policy.ActionAllow,
	}}}

	if got := FindBypasses(e, pt); len(got) != 0 {
		t.Errorf("wildcard tool policy should have no bypasses, found: %+v", got)
	}
}

func TestCanonicalStringArgsPreservesNonPathStrings(t *testing.T) {
	// Non-path strings must pass through unchanged so they do not affect
	// the policy re-evaluation decision.
	in := map[string]any{
		"namespace": "default",
		"path":      "/srv/data/public/a.txt",
		"bad":       "/srv/../etc/shadow",
		"count":     float64(3),
	}
	out := canonicalStringArgs(in)

	if out["namespace"] != "default" {
		t.Errorf("namespace = %q, want \"default\"", out["namespace"])
	}
	if out["path"] != "/srv/data/public/a.txt" {
		t.Errorf("path = %q, want clean absolute path", out["path"])
	}
	if out["bad"] != "" {
		t.Errorf("traversal path = %q, want \"\"", out["bad"])
	}
	if out["count"] != float64(3) {
		t.Errorf("count = %v, want 3", out["count"])
	}
}

func engineFor(t *testing.T, yaml string) *policy.Engine {
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
