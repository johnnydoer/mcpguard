package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestDispatchNoArgsIsUsageError(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := dispatch(nil, &out, &errOut); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "usage: mcpguard") {
		t.Errorf("stderr missing usage text, got %q", errOut.String())
	}
}

func TestDispatchUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := dispatch([]string{"nope"}, &out, &errOut); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), `unknown command "nope"`) {
		t.Errorf("stderr should name the unknown command, got %q", errOut.String())
	}
}

func TestDispatchHelpExitsZero(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := dispatch([]string{"--help"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "commands:") {
		t.Errorf("help should list commands, got %q", out.String())
	}
}

func TestDispatchVersion(t *testing.T) {
	var out bytes.Buffer
	if code := dispatch([]string{"version"}, &out, io.Discard); code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if strings.TrimSpace(out.String()) != version {
		t.Errorf("version output = %q, want %q", out.String(), version)
	}
}

func TestDispatchRoutesToRegisteredCommand(t *testing.T) {
	register("__testcmd", func(args []string, _, _ io.Writer) int {
		if len(args) != 1 || args[0] != "--flag" {
			t.Errorf("subcommand got args %v, want [--flag]", args)
		}
		return 7
	})
	t.Cleanup(func() { delete(commands, "__testcmd") })

	if code := dispatch([]string{"__testcmd", "--flag"}, io.Discard, io.Discard); code != 7 {
		t.Fatalf("exit code = %d, want 7 (subcommand's return value)", code)
	}
}
