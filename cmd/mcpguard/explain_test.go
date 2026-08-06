package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePolicy(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "mcpguard.yaml")
	content := `
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
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestExplainAllowedCall(t *testing.T) {
	var out, errOut bytes.Buffer
	code := dispatch([]string{"explain",
		"--policy", writePolicy(t), "--server", "fs", "--tool", "read_file",
		"--args", `{"path":"/srv/public/a.txt"}`}, &out, &errOut)

	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut.String())
	}
	s := out.String()
	for _, want := range []string{"allow", "allow-public"} {
		if !strings.Contains(s, want) {
			t.Errorf("output missing %q:\n%s", want, s)
		}
	}
}

func TestExplainDeniedCallExitsOne(t *testing.T) {
	// A non-zero exit lets explain be used as a shell assertion.
	var out, errOut bytes.Buffer
	code := dispatch([]string{"explain",
		"--policy", writePolicy(t), "--server", "fs", "--tool", "read_file",
		"--args", `{"path":"/etc/shadow"}`}, &out, &errOut)

	if code != 1 {
		t.Fatalf("exit = %d, want 1 for a denied call", code)
	}
	if !strings.Contains(out.String(), "deny") {
		t.Errorf("output should say deny:\n%s", out.String())
	}
}

func TestExplainShowsWhyNoRuleMatched(t *testing.T) {
	var out bytes.Buffer
	dispatch([]string{"explain",
		"--policy", writePolicy(t), "--server", "fs", "--tool", "unknown_tool"},
		&out, &bytes.Buffer{})

	if !strings.Contains(out.String(), "no rule matched") {
		t.Errorf("output should explain the fall-through:\n%s", out.String())
	}
}

func TestExplainRejectsMalformedArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	code := dispatch([]string{"explain",
		"--policy", writePolicy(t), "--server", "fs", "--tool", "read_file",
		"--args", `{not json}`}, &out, &errOut)

	if code != 2 {
		t.Fatalf("exit = %d, want 2 for malformed args", code)
	}
}

func TestExplainRequiresPolicyAndTool(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := dispatch([]string{"explain", "--tool", "t"}, &out, &errOut); code != 2 {
		t.Errorf("exit = %d, want 2 when --policy is missing", code)
	}
	if code := dispatch([]string{"explain", "--policy", writePolicy(t)}, &out, &errOut); code != 2 {
		t.Errorf("exit = %d, want 2 when --tool is missing", code)
	}
}

func TestExplainListsEvaluatedRules(t *testing.T) {
	// Showing which rules were considered and skipped is what makes explain
	// useful for debugging an ordering mistake.
	var out bytes.Buffer
	dispatch([]string{"explain",
		"--policy", writePolicy(t), "--server", "fs", "--tool", "read_file",
		"--args", `{"path":"/etc/shadow"}`}, &out, &bytes.Buffer{})

	if !strings.Contains(out.String(), "allow-public") {
		t.Errorf("output should mention the rule that was considered:\n%s", out.String())
	}
}
