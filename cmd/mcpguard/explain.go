package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/JohnnyDoer/mcpguard/internal/policy"
)

func init() { register("explain", explainCmd) }

func explainCmd(args []string, stdout, stderr io.Writer) int {
	flagSet := flag.NewFlagSet("explain", flag.ContinueOnError)
	flagSet.SetOutput(stderr)
	policyPath := flagSet.String("policy", "", "path to mcpguard.yaml (required)")
	server := flagSet.String("server", "", "server name the call targets")
	tool := flagSet.String("tool", "", "tool name or resource URI (required)")
	method := flagSet.String("method", "tools/call", "MCP method")
	argsJSON := flagSet.String("args", "{}", "call arguments as a JSON object")
	flagSet.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: mcpguard explain --policy <file> --tool <name> "+
			"[--server <name>] [--args '<json>']\n\n"+
			"Evaluates a hypothetical call and shows which rule decided it.\n"+
			"Exit code is 0 for allow, 1 for deny or approve, 2 for a usage error.\n\n")
		flagSet.PrintDefaults()
	}
	if err := flagSet.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" || *tool == "" {
		flagSet.Usage()
		return 2
	}

	var callArgs map[string]any
	if err := json.Unmarshal([]byte(*argsJSON), &callArgs); err != nil {
		_, _ = fmt.Fprintf(stderr, "mcpguard: --args is not a JSON object: %v\n", err)
		return 2
	}

	cfg, err := policy.LoadFile(*policyPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcpguard: %v\n", err)
		return 2
	}
	engine, err := policy.New(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcpguard: %v\n", err)
		return 2
	}

	req := policy.Request{Server: *server, Method: *method, Tool: *tool, Args: callArgs}
	decision := engine.Evaluate(req)

	_, _ = fmt.Fprintf(stdout, "call:     %s %s/%s\n", req.Method, req.Server, req.Tool)
	_, _ = fmt.Fprintf(stdout, "args:     %s\n", *argsJSON)
	_, _ = fmt.Fprintf(stdout, "\ndecision: %s\n", decision.Action)
	if decision.Rule != "" {
		_, _ = fmt.Fprintf(stdout, "rule:     %s\n", decision.Rule)
	} else {
		_, _ = fmt.Fprintf(stdout, "rule:     <none — defaults.action applied>\n")
	}
	_, _ = fmt.Fprintf(stdout, "reason:   %s\n", decision.Reason)
	if decision.Message != "" {
		_, _ = fmt.Fprintf(stdout, "message:  %s\n", decision.Message)
	}

	// Listing every rule and whether it targeted this call is what makes an
	// ordering mistake visible. Without it, "no rule matched" gives no clue
	// which rule was supposed to. RuleTargets is the engine's own exported
	// answer to "was this rule even a candidate?" — not a local
	// reimplementation — so this listing cannot drift from what Evaluate
	// actually did.
	_, _ = fmt.Fprintf(stdout, "\nrules considered, in order:\n")
	for _, rule := range cfg.Rules {
		targeted := engine.RuleTargets(rule, req.Server, req.Tool)
		marker := "  skipped (server/tool did not match)"
		switch {
		case rule.Name == decision.Rule:
			marker = "  MATCHED"
		case targeted:
			marker = "  targeted this tool, but its argument matchers did not match"
		}
		_, _ = fmt.Fprintf(stdout, "  %-32s%s\n", rule.Name, marker)
	}

	if decision.Action == policy.ActionAllow {
		return 0
	}
	return 1
}
