# mcpguard

mcpguard is a policy proxy for MCP (Model Context Protocol) that enforces deterministic authorization on every tool call an AI agent makes. The agent is unmodified and cannot opt out — it does not know it is proxied.

## Quickstart

Install:

```bash
go install github.com/JohnnyDoer/mcpguard/cmd/mcpguard@latest
```

Create `mcpguard.yaml`:

```yaml
version: v1
servers:
  - name: filesystem
    transport: stdio
    command: [npx, -y, "@modelcontextprotocol/server-filesystem", /srv/public]
defaults:
  action: deny
rules:
  - name: allow-reads
    servers: [filesystem]
    tools: [read_file, list_directory]
    action: allow
```

Add to your Claude Code MCP config (`~/.claude.json` or `.mcp.json`):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcpguard",
      "args": ["run", "--policy", "/path/to/mcpguard.yaml", "--server", "filesystem"]
    }
  }
}
```

Ask Claude to read `/etc/shadow`. It gets a denial naming the rule it hit. Ask it to read a file under `/srv/public`. It works.

## What it does not protect against

- **Prompt injection.** If a poisoned document convinces the agent to call a tool
  it is permitted to call, mcpguard allows it — correctly, by design. Policy
  constrains what can be done, not why it was asked for. Detection was
  deliberately excluded: it is probabilistic, and a control that cannot be shown
  to work should not be claimed.
- **A malicious MCP server.** A server can lie in its results. Guarding that is a
  different tool.
- **Isolation.** This is authorization, not sandboxing. A permitted tool runs with
  whatever privilege the server holds.
- **Symlinks under a containerized server.** Canonicalization resolves symlinks
  against mcpguard's filesystem view. If the server runs in a different mount
  namespace, the two can disagree and the guarantee is weaker.
- **Anyone who can edit the policy.** The policy is the control. Protect it with
  the same care as the credentials the tools use.
- **Relative paths.** They resolve against the server's working directory, which
  mcpguard does not know, so they are denied rather than guessed at.

## How it works

mcpguard intercepts at the MCP protocol boundary:

| Message type | What mcpguard does |
|---|---|
| `tools/call` | Evaluates against policy; allow / deny / request approval |
| `tools/list` | Filters out tools the agent is not allowed to call |
| `resources/read` | Evaluates URI against policy |
| Everything else | Passes through unmodified |

Four decision outcomes:

- **Allow** — forwarded to the server
- **Deny** — error returned to the agent; server never sees the call
- **Approve** — held until a human answers via ntfy; then allow or deny
- **Filter** — removed from the list response; agent cannot discover or call

## Policy at a glance

```yaml
rules:
  - name: allow-reads            # appears in deny messages and audit logs
    servers: [filesystem]        # empty = all servers
    tools: [read_file, "list_*"] # globs, not regexes
    match:
      args:
        path:
          canonicalize: path
          prefix: /srv/public    # combined: canonicalize, then check prefix
    action: allow
```

Full reference: [docs/policy-reference.md](docs/policy-reference.md)

## Testing your policy

```bash
# Run policy tests
mcpguard test --policy mcpguard.yaml --tests policy-test.yaml

# Fuzz all examples
mcpguard test -fuzz examples/

# Validate against a live server
mcpguard validate --policy mcpguard.yaml --server filesystem

# Explain a decision
mcpguard explain --policy mcpguard.yaml --server filesystem \
  --tool read_file --args '{"path":"/srv/public/a.txt"}'
```

## Comparison

See [docs/prior-art.md](docs/prior-art.md) for a survey of related projects and what differentiates mcpguard.

## Status

**Implemented:**
- stdio and HTTP/SSE transports
- Policy engine: exact, prefix, regex, CIDR, glob, path canonicalization matchers
- Approval via ntfy with single-use call-bound nonces
- Audit log with redaction and unredacted hashing
- `tools/list` and `resources/list` filtering
- `mcpguard test`, `mcpguard test --fuzz`, `mcpguard validate`, `mcpguard explain`
- Prometheus metrics and Grafana dashboard

**Test coverage:** 218 tests, 77.1% overall, 89.1% internal/policy, 89.7% internal/canon

**Not implemented:**
- Windows (stdio process supervision differs materially; not supported)
- WebSocket transport
- Remote policy sources (HTTP, git)
- Approval channels other than ntfy

**Platform support:** Linux and macOS. Windows is not supported.
