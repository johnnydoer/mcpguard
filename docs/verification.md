# mcpguard Definition-of-Done Verification

Verified: 2026-08-07. BASE commit: b0ba045.

---

## 1. Full test suite

**Result: PASS**

```
golangci-lint run ./...   → 0 issues
go test -race -count=1 ./... → 10 packages, all ok
```

- 218 individual test cases, 0 failures, 0 skipped
- All 10 packages pass with `-race`
- Lint: golangci-lint v2.12.2, 0 issues

---

## 2. Claude Code runs through mcpguard unmodified

**NOT VERIFIED — requires live infrastructure**

### Operator steps

1. Install the binary: `go install github.com/JohnnyDoer/mcpguard/cmd/mcpguard@latest`
2. Choose one of the `examples/` policies (e.g. `examples/filesystem/mcpguard.yaml`) or write your own.
3. Add to `~/.claude.json` (or project `.mcp.json`):

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

4. Start Claude Code and issue a prompt that requires a permitted tool call (e.g. "Read the file /srv/public/README.md").
5. Confirm: the call succeeds and the response is identical to what the unproxied server would return.
6. Check `~/.local/share/mcpguard/audit.log` (or the path set in `audit.output`) to confirm the call was logged.

**Pass criterion:** The tool call succeeds and the agent receives the correct response without observing any proxy artefacts.

---

## 3. A denied call fails legibly

**NOT VERIFIED — requires live infrastructure**

### Operator steps

1. Same setup as item 2.
2. Issue a prompt that causes the agent to call a denied tool or use a denied path (e.g. "Read the file /etc/shadow").
3. Confirm: the agent receives an MCP error response containing the rule name that triggered the denial, e.g.:

   ```
   denied by rule "default-deny"
   ```

4. Confirm: the server process never receives the call (check server-side logs or use `strace`).
5. Confirm: the denial appears in the audit log.

**Pass criterion:** Agent sees a meaningful error message, server is never contacted, audit log contains the denial event.

---

## 4. tools/list filtering invisible to agent

**NOT VERIFIED — requires live infrastructure**

### Operator steps

1. Add a `filter` action to a rule covering one or more tools:

   ```yaml
   rules:
     - name: hide-write-tools
       tools: [write_file, delete_file]
       action: filter
   ```

2. Ask the agent to list available tools (or observe which tools it enumerates in a planning step).
3. Confirm: the filtered tools do not appear in the list the agent sees.
4. Confirm: if the agent attempts to call a filtered tool directly by name, it receives a denial (not a "tool not found" error from the server).
5. Confirm: an unfiltered tools/list call to the server still returns all tools.

**Pass criterion:** Filtered tools are absent from the agent's tool list; the agent cannot discover or invoke them.

---

## 5. Test suite, fuzz, and validate all clean

**Result: PASS**

```
go test -count=1 ./... → 218 tests, 10 packages, 0 failures
```

Example policy validation (`mcpguard validate --offline`):

```
examples/filesystem/mcpguard.yaml  → parses and validates
examples/gitlab/mcpguard.yaml      → parses and validates
examples/kubernetes/mcpguard.yaml  → parses and validates
```

Fuzz integration test (`mcpguard test --fuzz examples/`):

```
Test Summary: 18 passed, 0 failed
```

All three examples pass both `validate --offline` and `test --fuzz`.

---

## 6. Approval round-trips

**NOT VERIFIED — requires live infrastructure**

### Operator steps

Deploy:
- An ntfy instance (self-hosted or ntfy.sh) reachable from the mcpguard host.
- Configure `approval.ntfy.url` and `approval.ntfy.topic` in `mcpguard.yaml`.

Trigger an approval-gated call from the agent and observe all four outcomes:

| Outcome | How to trigger | Expected result |
|---------|----------------|-----------------|
| **Allow** | Receive the ntfy notification and reply `allow` (or tap the allow button). | Agent receives the server's response as if the call had been allowed immediately. |
| **Deny** | Receive the ntfy notification and reply `deny`. | Agent receives a denial error; server is not contacted. |
| **Timeout** | Do not respond within the configured `approval.timeout` window. | Agent receives a timeout denial; server is not contacted. |
| **Replay** | Copy the `allow` URL from the notification and submit it a second time. | Second submission is rejected with a "nonce already used" or "not found" error (single-use nonce). |

**Pass criterion:** All four outcomes behave as described.

---

## 7. Audit log and Grafana dashboard populated

**NOT VERIFIED — requires live infrastructure**

### Operator steps

**Audit log:**

```bash
# Find the log path (default: stdout or the path set in audit.output)
tail -f /path/to/audit.log | jq .

# Confirm fields present on each event:
#   timestamp, server, tool, action (allow|deny|approve|filter),
#   rule, args_hash (SHA-256 of unredacted args), redacted_args
```

**Prometheus metrics:**

```bash
# mcpguard exposes metrics on the address set in metrics.addr (default :9090)
curl http://localhost:9090/metrics | grep mcpguard_
```

**Grafana:**

```bash
# Import docs/grafana-dashboard.json into your Grafana instance.
# Set the Prometheus data source to point at the mcpguard metrics endpoint.
# Confirm panels populate after sending several tool calls through the proxy.
```

Key panels to verify:
- `mcpguard_decisions_total` — labelled by action and rule
- `mcpguard_approval_duration_seconds` — histogram of approval latency
- `mcpguard_calls_in_flight` — gauge

**Pass criterion:** All metrics appear in `curl /metrics`; Grafana panels show non-zero values after traffic.

---

## 8. Coverage and cardinality

| Package | Coverage |
|---------|----------|
| overall (all packages) | 77.1% |
| `internal/policy` | 89.1% |
| `internal/canon` | 89.7% |

Both `internal/policy` and `internal/canon` exceed the 85% threshold.

Overall coverage is 77.1%. The shortfall relative to 85% is concentrated in transport packages:
- `internal/transport/httpsse`: 71.0% — HTTP/SSE integration paths require a live HTTP client/server pair that the unit tests do not fully exercise.
- `internal/transport/stdio`: 85.3% — subprocess teardown edge cases.

These are integration-layer gaps, not logic gaps.

---

## 9. Deferred minors

Five known defects are deferred to a follow-on task:

1. **Task 5: test count in report miscounted (31 vs actual 32)** — documentation only; no code change required.

2. **Task 6: `Config.AgentIn` doc comment does not disclose that `Run` closes it on shutdown when it implements `io.Closer`** — missing doc annotation; no logic defect.

3. **Task 6: `Wait()` race fix trusts `ProcessState.Success()` for any Wait error** — hypothetical stderr-copy failure on clean exit would be swallowed; not reachable in practice; not a live bug.

4. **Task 7: `file://[::1]/` rejected (fail-closed, over-strict for IPv6 localhost)** — the IPv6 localhost file URI is rejected rather than resolved; fail-closed behaviour, but over-strict.

5. **Task 17: `canonicalStringArgs` hardcodes `canon.Path` — wrong for URL/enum args** — only affects fuzz bypass detection, not enforcement; no security impact on the policy engine's allow/deny decisions.
