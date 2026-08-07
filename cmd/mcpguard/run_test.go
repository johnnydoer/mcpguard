package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRunPolicy(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "mcpguard.yaml")
	content := `
version: v1
` + extra + `
audit:
  path: ` + filepath.Join(dir, "audit.jsonl") + `
servers:
  - name: fs
    transport: stdio
    command: ["/bin/cat"]
rules:
  - {name: allow-reads, servers: [fs], tools: [read_file], action: allow}
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunRequiresPolicyAndServer(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := dispatch([]string{"run"}, &out, &errOut); code != 2 {
		t.Errorf("exit = %d, want 2 with no flags", code)
	}
	if code := dispatch([]string{"run", "--policy", writeRunPolicy(t, "")}, &out, &errOut); code != 2 {
		t.Errorf("exit = %d, want 2 without --server", code)
	}
}

func TestRunRejectsUnknownServer(t *testing.T) {
	var out, errOut bytes.Buffer
	code := dispatch([]string{"run",
		"--policy", writeRunPolicy(t, ""), "--server", "nope"}, &out, &errOut)

	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "nope") {
		t.Errorf("stderr should name the unknown server: %s", errOut.String())
	}
}

func TestRunRejectsUnwritableAuditPath(t *testing.T) {
	// Startup must fail rather than run unaudited.
	dir := t.TempDir()
	path := filepath.Join(dir, "mcpguard.yaml")
	content := `
version: v1
audit: {path: /nonexistent-directory-xyz/audit.jsonl}
servers: [{name: fs, transport: stdio, command: ["/bin/cat"]}]
rules: []
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := dispatch([]string{"run", "--policy", path, "--server", "fs"}, &out, &errOut); code != 2 {
		t.Errorf("exit = %d, want 2 for an unwritable audit path", code)
	}
}

func TestRunPolicyOnlyValidatesWithoutStarting(t *testing.T) {
	// --policy-only makes the binary usable as a CI config check.
	var out, errOut bytes.Buffer
	code := dispatch([]string{"run",
		"--policy", writeRunPolicy(t, ""), "--server", "fs", "--policy-only"}, &out, &errOut)

	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(out.String(), "fs") {
		t.Errorf("output should confirm what it validated: %s", out.String())
	}
}

func TestRunAuditModeFlagOverridesConfig(t *testing.T) {
	// The override exists so audit mode can be turned on without editing a file
	// that may be under GitOps control.
	var out, errOut bytes.Buffer
	code := dispatch([]string{"run",
		"--policy", writeRunPolicy(t, "mode: enforce"), "--server", "fs",
		"--audit-mode", "--policy-only"}, &out, &errOut)

	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut.String())
	}
	if !strings.Contains(out.String(), "audit") {
		t.Errorf("output should report the effective mode: %s", out.String())
	}
}
