package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/JohnnyDoer/mcpguard/internal/transport/stdio"
)

func init() { register("run", runCmd) }

func runCmd(args []string, _, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	command := fs.String("command", "", "the MCP server to spawn, space separated (required)")
	fs.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: mcpguard run --command \"<server> <args...>\"\n\n")
		fs.PrintDefaults()
		_, _ = fmt.Fprintf(stderr, "\nPolicy enforcement is added in a later phase; this build proxies transparently.\n")
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *command == "" {
		fs.Usage()
		return 2
	}

	// SIGINT and SIGTERM must reach the child, or a Ctrl-C leaves an orphaned
	// MCP server holding whatever resources it opened.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	err := stdio.Run(ctx, stdio.Config{
		Command:     strings.Fields(*command),
		Interceptor: stdio.PassthroughInterceptor{},
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
