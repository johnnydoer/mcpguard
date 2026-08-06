package policy

import (
	"strings"
	"testing"
)

const testEngineConfig = `
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
`

func TestLoadTestFile(t *testing.T) {
	pt, err := LoadTest(strings.NewReader(`
apiVersion: mcpguard.dev/v1
kind: PolicyTest
policy: ../mcpguard.yaml
cases:
  - name: public read is allowed
    server: fs
    tool: read_file
    args: {path: /srv/data/public/a.txt}
    expect: allow
    expect_rule: allow-public
`))
	if err != nil {
		t.Fatalf("LoadTest: %v", err)
	}
	if pt.Policy != "../mcpguard.yaml" || len(pt.Cases) != 1 {
		t.Fatalf("parsed %+v", pt)
	}
	if pt.Cases[0].ExpectRule == nil || *pt.Cases[0].ExpectRule != "allow-public" {
		t.Errorf("ExpectRule = %v, want allow-public", pt.Cases[0].ExpectRule)
	}
}

func TestLoadTestRejectsWrongKind(t *testing.T) {
	_, err := LoadTest(strings.NewReader(`
apiVersion: mcpguard.dev/v1
kind: Deployment
policy: p.yaml
cases: []
`))
	if err == nil || !strings.Contains(err.Error(), "Deployment") {
		t.Fatalf("err = %v, want a kind error", err)
	}
}

func TestLoadTestRejectsUnknownFields(t *testing.T) {
	_, err := LoadTest(strings.NewReader(`
apiVersion: mcpguard.dev/v1
kind: PolicyTest
policy: p.yaml
cases:
  - {name: n, tool: t, expct: allow}
`))
	if err == nil {
		t.Fatal("a typo'd field must fail rather than silently skip the assertion")
	}
}

func TestLoadTestRejectsCaseWithNoExpectation(t *testing.T) {
	_, err := LoadTest(strings.NewReader(`
apiVersion: mcpguard.dev/v1
kind: PolicyTest
policy: p.yaml
cases:
  - {name: n, tool: t}
`))
	if err == nil || !strings.Contains(err.Error(), "expect") {
		t.Fatalf("err = %v, want an error about the missing expect", err)
	}
}

func TestRunTestPassingCase(t *testing.T) {
	e := engineFrom(t, testEngineConfig)
	rule := "allow-public"
	report := RunTest(e, &PolicyTest{Cases: []Case{{
		Name: "ok", Server: "fs", Tool: "read_file",
		Args:   map[string]any{"path": "/srv/data/public/a.txt"},
		Expect: ActionAllow, ExpectRule: &rule,
	}}})

	if !report.OK() || report.Passed != 1 {
		t.Fatalf("report = %+v, want 1 pass", report)
	}
}

func TestRunTestDetectsWrongAction(t *testing.T) {
	e := engineFrom(t, testEngineConfig)
	report := RunTest(e, &PolicyTest{Cases: []Case{{
		Name: "should have been denied", Server: "fs", Tool: "read_file",
		Args: map[string]any{"path": "/etc/shadow"}, Expect: ActionAllow,
	}}})

	if report.OK() {
		t.Fatal("a wrong action must fail the report")
	}
	if !strings.Contains(report.Results[0].Detail, "action") {
		t.Errorf("Detail = %q, should mention the action mismatch", report.Results[0].Detail)
	}
}

func TestRunTestDetectsRightActionFromWrongRule(t *testing.T) {
	// The load-bearing assertion of the whole framework. A deny arriving from
	// default-deny instead of the rule under test is a latent bug the moment
	// someone adds a broader allow above it, and only expect_rule catches it.
	e := engineFrom(t, testEngineConfig)
	rule := "allow-public"
	report := RunTest(e, &PolicyTest{Cases: []Case{{
		Name: "passes for the wrong reason", Server: "fs", Tool: "read_file",
		Args:   map[string]any{"path": "/etc/shadow"},
		Expect: ActionDeny, ExpectRule: &rule,
	}}})

	if report.OK() {
		t.Fatal("expect_rule mismatch must fail even when the action is correct")
	}
	if !strings.Contains(report.Results[0].Detail, "rule") {
		t.Errorf("Detail = %q, should mention the rule mismatch", report.Results[0].Detail)
	}
}

func TestRunTestEmptyExpectRuleAssertsNoRuleMatched(t *testing.T) {
	// expect_rule: "" is a positive assertion that the decision came from the
	// defaults, distinct from omitting the field entirely.
	e := engineFrom(t, testEngineConfig)
	empty := ""
	report := RunTest(e, &PolicyTest{Cases: []Case{{
		Name: "falls through", Server: "fs", Tool: "read_file",
		Args:   map[string]any{"path": "/home/x"},
		Expect: ActionDeny, ExpectRule: &empty,
	}}})

	if !report.OK() {
		t.Fatalf("expected a pass, got %+v", report.Results[0])
	}
}

func TestRunTestOmittedExpectRuleSkipsRuleCheck(t *testing.T) {
	e := engineFrom(t, testEngineConfig)
	report := RunTest(e, &PolicyTest{Cases: []Case{{
		Name: "action only", Server: "fs", Tool: "read_file",
		Args: map[string]any{"path": "/home/x"}, Expect: ActionDeny,
	}}})

	if !report.OK() {
		t.Fatalf("omitting expect_rule should not assert anything about the rule: %+v",
			report.Results[0])
	}
}

func TestRunTestTraversalCase(t *testing.T) {
	e := engineFrom(t, testEngineConfig)
	report := RunTest(e, &PolicyTest{Cases: []Case{{
		Name: "traversal denied", Server: "fs", Tool: "read_file",
		Args:   map[string]any{"path": "/srv/data/public/../../etc/shadow"},
		Expect: ActionDeny,
	}}})

	if !report.OK() {
		t.Errorf("traversal must be denied: %+v", report.Results[0])
	}
}

func TestRunTestTypeConfusionCase(t *testing.T) {
	e := engineFrom(t, testEngineConfig)
	report := RunTest(e, &PolicyTest{Cases: []Case{{
		Name: "array path denied", Server: "fs", Tool: "read_file",
		Args:   map[string]any{"path": []any{"/srv/data/public/ok", "/etc/shadow"}},
		Expect: ActionDeny,
	}}})

	if !report.OK() {
		t.Errorf("a type-confused argument must be denied: %+v", report.Results[0])
	}
}

func TestRunTestCountsBothOutcomes(t *testing.T) {
	e := engineFrom(t, testEngineConfig)
	report := RunTest(e, &PolicyTest{Cases: []Case{
		{Name: "a", Server: "fs", Tool: "read_file",
			Args: map[string]any{"path": "/srv/data/public/x"}, Expect: ActionAllow},
		{Name: "b", Server: "fs", Tool: "read_file",
			Args: map[string]any{"path": "/srv/data/public/x"}, Expect: ActionDeny},
	}})

	if report.Passed != 1 || report.Failed != 1 {
		t.Errorf("Passed=%d Failed=%d, want 1 and 1", report.Passed, report.Failed)
	}
}
