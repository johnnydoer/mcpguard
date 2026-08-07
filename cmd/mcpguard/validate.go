package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/JohnnyDoer/mcpguard/internal/policy"
	"github.com/JohnnyDoer/mcpguard/internal/protocol"
	"github.com/JohnnyDoer/mcpguard/internal/transport/stdio"
)

func init() { register("validate", validateCmd) }

func validateCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "path to mcpguard.yaml (required)")
	serverName := fs.String("server", "", "validate only this server (default: all stdio servers)")
	offline := fs.Bool("offline", false, "check the policy without contacting any server")
	timeout := fs.Duration("timeout", 30*time.Second, "per-server tools/list timeout")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: mcpguard validate --policy <file> [--server <name>] "+
			"[--offline]\n\n"+
			"Checks the policy for validity and, unless --offline, compares every rule's\n"+
			"tool patterns against what each server actually advertises. Intended for CI.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" {
		fs.Usage()
		return 2
	}

	cfg, err := policy.LoadFile(*policyPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcpguard: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "policy %s parses and validates\n", *policyPath)

	problems := 0

	// Report deliberate weakenings so they cannot accumulate unnoticed.
	for _, rule := range cfg.Rules {
		if rule.AdditionalArgs != nil && *rule.AdditionalArgs == policy.ActionAllow {
			_, _ = fmt.Fprintf(stdout, "  NOTE  rule %q sets additional_args: allow, so it does not "+
				"constrain arguments it omits\n", rule.Name)
		}
	}

	if *offline {
		if problems > 0 {
			return 1
		}
		return 0
	}

	for _, server := range cfg.Servers {
		if *serverName != "" && server.Name != *serverName {
			continue
		}
		if server.Transport != "stdio" {
			_, _ = fmt.Fprintf(stdout, "  SKIP  server %q uses transport %q; live validation "+
				"supports stdio\n", server.Name, server.Transport)
			continue
		}

		tools, err := listTools(server, *timeout)
		if err != nil {
			_, _ = fmt.Fprintf(stdout, "  FAIL  server %q: %v\n", server.Name, err)
			problems++
			continue
		}
		_, _ = fmt.Fprintf(stdout, "  server %q advertises %d tool(s)\n", server.Name, len(tools))
		problems += compareToolsToRules(cfg, server.Name, tools, stdout)
	}

	if problems > 0 {
		_, _ = fmt.Fprintf(stdout, "\n%d problem(s) found\n", problems)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "\nno problems found\n")
	return 0
}

// compareToolsToRules reports drift in both directions.
func compareToolsToRules(cfg *policy.Config, server string, tools []string, stdout io.Writer) int {
	problems := 0

	// A rule pattern matching nothing is the dangerous direction: the rule looks
	// active but is dead, and the call it was meant to govern falls through.
	for _, rule := range cfg.Rules {
		if len(rule.Servers) > 0 && !containsString(rule.Servers, server) {
			continue
		}
		for _, pattern := range rule.Tools {
			if pattern == "*" {
				continue
			}
			matched := false
			for _, tool := range tools {
				if policy.GlobMatch(pattern, tool) {
					matched = true
					break
				}
			}
			if !matched {
				_, _ = fmt.Fprintf(stdout, "  FAIL  rule %q pattern %q matches no tool advertised "+
					"by %q; the rule is dead and calls it was meant to govern now fall "+
					"through to defaults.action\n", rule.Name, pattern, server)
				problems++
			}
		}
	}

	// The inverse is informational: deny-by-default covers a new tool, but the
	// operator should know it appeared.
	for _, tool := range tools {
		referenced := false
		for _, rule := range cfg.Rules {
			if len(rule.Servers) > 0 && !containsString(rule.Servers, server) {
				continue
			}
			for _, pattern := range rule.Tools {
				if policy.GlobMatch(pattern, tool) {
					referenced = true
					break
				}
			}
			if referenced {
				break
			}
		}
		if !referenced {
			_, _ = fmt.Fprintf(stdout, "  NOTE  tool %q on %q matches no rule; it falls through to "+
				"defaults.action=%s\n", tool, server, cfg.Defaults.Action)
		}
	}

	return problems
}

// listTools performs a minimal initialize and tools/list against a server.
//
// It reuses the real stdio proxy with a passthrough interceptor rather than
// hand-rolling a client, so validation exercises the same framing the proxy uses.
func listTools(server policy.Server, timeout time.Duration) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	requests := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",` +
			`"capabilities":{},"clientInfo":{"name":"mcpguard-validate","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	}, "\n") + "\n"

	var responses strings.Builder
	err := stdio.Run(ctx, stdio.Config{
		Command:     server.Command,
		Interceptor: stdio.PassthroughInterceptor{},
		AgentIn:     strings.NewReader(requests),
		AgentOut:    &responses,
		Stderr:      io.Discard,
	})
	// A non-zero child exit after we have the response we need is not a failure;
	// closing its stdin is how a well-behaved server is told to stop.
	if err != nil && responses.Len() == 0 {
		return nil, fmt.Errorf("could not talk to the server: %w", err)
	}

	dec := protocol.NewDecoder(strings.NewReader(responses.String()))
	for {
		m, decErr := dec.Decode()
		if decErr != nil {
			break
		}
		if m.IDKey() != "2" || len(m.Result) == 0 {
			continue
		}
		var result protocol.ToolsListResult
		if jsonErr := json.Unmarshal(m.Result, &result); jsonErr != nil {
			return nil, fmt.Errorf("tools/list result is malformed: %w", jsonErr)
		}
		names := make([]string, 0, len(result.Tools))
		for _, tool := range result.Tools {
			names = append(names, tool.Name)
		}
		return names, nil
	}
	return nil, fmt.Errorf("server did not answer tools/list")
}

func containsString(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
