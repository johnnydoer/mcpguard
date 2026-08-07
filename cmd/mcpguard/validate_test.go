package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeValidatePolicy(t *testing.T, serverCommand, rules string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "mcpguard.yaml")
	content := `
version: v1
servers:
  - name: fs
    transport: stdio
    command: ` + serverCommand + `
rules:
` + rules
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildFakeValidate(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping test that builds a subprocess")
	}
	bin := filepath.Join(t.TempDir(), "fakeserver")
	if out, err := exec.CommandContext(context.Background(), "go", "build", "-o", bin, "../../testdata/fakeserver").
		CombinedOutput(); err != nil {
		t.Fatalf("building fakeserver: %v\n%s", err, out)
	}
	return bin
}

func TestValidateOfflineAcceptsAValidPolicy(t *testing.T) {
	path := writeValidatePolicy(t, `["/bin/true"]`,
		`  - {name: r, servers: [fs], tools: [read_file], action: allow}`)

	var out, errOut bytes.Buffer
	if code := dispatch([]string{"validate", "--policy", path, "--offline"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errOut.String())
	}
}

func TestValidateOfflineRejectsAnInvalidPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("version: v99\nservers: []\nrules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errOut bytes.Buffer
	if code := dispatch([]string{"validate", "--policy", path, "--offline"}, &out, &errOut); code == 0 {
		t.Error("an invalid policy must not validate")
	}
}

func TestValidateOfflineWarnsAboutAdditionalArgsOverrides(t *testing.T) {
	// additional_args: allow is a deliberate weakening. Reporting it stops the
	// overrides accumulating unnoticed.
	path := writeValidatePolicy(t, `["/bin/true"]`,
		`  - {name: loose, servers: [fs], tools: [t], action: allow, additional_args: allow}`)

	var out bytes.Buffer
	dispatch([]string{"validate", "--policy", path, "--offline"}, &out, &bytes.Buffer{})

	if !strings.Contains(out.String(), "loose") {
		t.Errorf("output should report the override:\n%s", out.String())
	}
}

func TestIntegrationValidateDetectsUnknownTool(t *testing.T) {
	// The drift case. The fakeserver advertises read_file, write_file, and
	// delete_file; a rule naming fs_read must be reported.
	path := writeValidatePolicy(t, `["`+buildFakeValidate(t)+`"]`,
		`  - {name: stale, servers: [fs], tools: [fs_read], action: allow}`)

	var out, errOut bytes.Buffer
	code := dispatch([]string{"validate", "--policy", path}, &out, &errOut)

	if code == 0 {
		t.Fatalf("validate should fail on a rule naming a nonexistent tool\n%s", out.String())
	}
	if !strings.Contains(out.String(), "fs_read") {
		t.Errorf("output should name the unmatched tool:\n%s", out.String())
	}
}

func TestIntegrationValidateAcceptsMatchingTools(t *testing.T) {
	path := writeValidatePolicy(t, `["`+buildFakeValidate(t)+`"]`,
		`  - {name: good, servers: [fs], tools: [read_file, "write_*"], action: allow}`)

	var out, errOut bytes.Buffer
	if code := dispatch([]string{"validate", "--policy", path}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d, want 0\n%s\n%s", code, out.String(), errOut.String())
	}
}

func TestIntegrationValidateReportsToolsWithNoRule(t *testing.T) {
	// The inverse drift: a server gained a tool no rule mentions. Deny-by-default
	// covers it, but the operator should know it appeared.
	path := writeValidatePolicy(t, `["`+buildFakeValidate(t)+`"]`,
		`  - {name: only-reads, servers: [fs], tools: [read_file], action: allow}`)

	var out bytes.Buffer
	dispatch([]string{"validate", "--policy", path}, &out, &bytes.Buffer{})

	if !strings.Contains(out.String(), "delete_file") {
		t.Errorf("output should mention the unreferenced tool:\n%s", out.String())
	}
}
