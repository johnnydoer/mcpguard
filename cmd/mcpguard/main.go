// Command mcpguard is a policy proxy for the Model Context Protocol.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is set at build time via -ldflags.
var version = "dev"

// subcommand is the contract every command file in this package implements.
// Returning an exit code rather than calling os.Exit keeps each command
// testable from a normal Go test.
type subcommand func(args []string, stdout, stderr io.Writer) int

// commands is populated by init() in run.go, test.go, validate.go, explain.go.
// A map rather than a switch so each command file owns its own registration and
// adding one touches exactly one file.
var commands = map[string]subcommand{}

func register(name string, fn subcommand) {
	if _, exists := commands[name]; exists {
		panic("duplicate subcommand registration: " + name)
	}
	commands[name] = fn
}

func usage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `mcpguard %s — policy proxy for the Model Context Protocol

usage: mcpguard <command> [flags]

commands:
  run        proxy an MCP server, applying policy to every call
  test       run policy tests offline, with no server or network
  validate   check a policy against a live server's advertised tools
  explain    show which rule matches a hypothetical call, and why

run "mcpguard <command> -h" for command flags.
`, version)
}

func dispatch(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "-h", "--help", "help":
		usage(stdout)
		return 0
	case "-v", "--version", "version":
		_, _ = fmt.Fprintln(stdout, version)
		return 0
	}
	cmd, ok := commands[args[0]]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
	return cmd(args[1:], stdout, stderr)
}

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdout, os.Stderr))
}
