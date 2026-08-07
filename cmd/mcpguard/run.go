package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/JohnnyDoer/mcpguard/internal/audit"
	"github.com/JohnnyDoer/mcpguard/internal/enforce"
	"github.com/JohnnyDoer/mcpguard/internal/policy"
	"github.com/JohnnyDoer/mcpguard/internal/transport/stdio"
)

func init() { register("run", runCmd) }

func runCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	policyPath := fs.String("policy", "", "path to mcpguard.yaml (required)")
	serverName := fs.String("server", "", "which server in the policy to proxy (required)")
	auditMode := fs.Bool("audit-mode", false,
		"force audit mode: record decisions but enforce nothing, overriding the config")
	policyOnly := fs.Bool("policy-only", false,
		"validate the policy and exit without starting the proxy")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: mcpguard run --policy <file> --server <name> "+
			"[--audit-mode] [--policy-only]\n\n"+
			"Proxies the named server's stdio transport, applying policy to every call.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" || *serverName == "" {
		fs.Usage()
		return 2
	}

	cfg, err := policy.LoadFile(*policyPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcpguard: %v\n", err)
		return 2
	}

	server, ok := cfg.ServerByName(*serverName)
	if !ok {
		_, _ = fmt.Fprintf(stderr, "mcpguard: server %q is not defined in %s (known: %v)\n",
			*serverName, *policyPath, cfg.ServerNames())
		return 2
	}
	if server.Transport != "stdio" {
		_, _ = fmt.Fprintf(stderr, "mcpguard: server %q uses transport %q; run supports stdio "+
			"in this build\n", server.Name, server.Transport)
		return 2
	}

	if *auditMode {
		cfg.Mode = policy.ModeAudit
	}

	engine, err := policy.New(cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcpguard: %v\n", err)
		return 2
	}

	// Opened before the proxy starts so an unwritable path is a startup failure
	// rather than a session that runs unaudited.
	sessionID := audit.NewSessionID()
	logger, err := audit.Open(cfg.Audit, sessionID)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcpguard: %v\n", err)
		return 2
	}
	defer func() { _ = logger.Close() }()

	interceptor, err := enforce.New(enforce.Options{
		Server:   server.Name,
		Engine:   engine,
		Recorder: logger,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcpguard: %v\n", err)
		return 2
	}

	if *policyOnly {
		_, _ = fmt.Fprintf(stdout, "policy %s is valid\n", *policyPath)
		_, _ = fmt.Fprintf(stdout, "  server:  %s (%s)\n", server.Name, server.Transport)
		_, _ = fmt.Fprintf(stdout, "  mode:    %s\n", cfg.Mode)
		_, _ = fmt.Fprintf(stdout, "  rules:   %d\n", len(cfg.Rules))
		_, _ = fmt.Fprintf(stdout, "  default: %s\n", cfg.Defaults.Action)
		return 0
	}

	// Signals must reach the child, or Ctrl-C orphans the MCP server.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Diagnostics go to stderr because stdout is the MCP channel — a stray
	// line there corrupts the protocol.
	_, _ = fmt.Fprintf(stderr, "mcpguard: proxying %s in %s mode (session %s)\n",
		server.Name, cfg.Mode, sessionID)

	err = stdio.Run(ctx, stdio.Config{
		Command:     server.Command,
		Interceptor: interceptor,
		AgentIn:     os.Stdin,
		AgentOut:    os.Stdout,
		Stderr:      stderr,
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcpguard: %v\n", err)
		return 1
	}
	return 0
}
