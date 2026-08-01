# Prior Art: MCP Security Proxies

Survey date: 2026-08-01. Scope: publicly available projects that sit between an MCP
client/agent and one or more MCP servers and make an allow/deny decision on tool
calls (and, where applicable, resource reads), without requiring changes to the
agent or the server. Search terms used: `mcp proxy security`, `mcp gateway
policy`, `mcp tool authorization`, `mcp guardrails`, `mcp firewall`, `model
context protocol access control`, `mcp server allowlist`, `mcp interceptor`,
plus follow-up terms for argument-level policy, OPA/Rego integration, and named
projects turned up along the way (ToolHive, ContextForge, mcp-scan, etc.).
Facts below come from reading READMEs, docs, and the GitHub API — not from
marketing pages — except where marked "not documented," meaning the fact could
not be established from public material in the time available.

`Puliczek/awesome-mcp-security` was used as a secondary index to cross-check
coverage; it is a curated list, not an implementation, so it is not scored as a
competing project.

## Comparison table

| Project | Modifies agent/server? | Argument-level policy | Offline policy tests | `resources/read` policed | Fail-open / fail-closed | Human approval | Transports | Licence | Language | Last commit | Stars |
|---|---|---|---|---|---|---|---|---|---|---|---|
| [mcpwall](https://github.com/behrensd/mcpwall) | No | **Yes** — regex/`not_under` matchers on argument values | `mcpwall check` dry-run validator | No (tools/call only) | Open on malformed non-strict input; closed on bad regex at startup | No | stdio only | Apache-2.0 | TypeScript | 2026-07-13 | 4 |
| [mcp-firewall](https://github.com/evalops/mcp-firewall) (archived) | No | No — tool/resource/prompt/method name only | No | **Yes** — resource URI scheme/pattern rules | Closed in enforce mode; observe mode logs only | No | stdio, HTTP, SSE | MIT | Go | 2026-05-24 | 0 |
| [AgentFence](https://github.com/dgenio/agentfence) | No | **Yes** — path/repo/URL/shell patterns per tool | **Yes** — `agentfence policy test` with declarative fixtures | No (confirmed: gates `tools/call` only) | Closed by default (deny-by-default; `--no-interactive` defaults to deny) | **Yes** — `ask` decision, interactive TTY prompt | stdio (proxy), HTTP (proxy-http), SSE passthrough | Apache-2.0 | Go | 2026-07-23 | 3 |
| [mcp-context-forge](https://github.com/IBM/mcp-context-forge) (ContextForge) | No | Partial — via hand-written `tool_pre_invoke` plugins + Cedar/OPA PDP, not built-in declarative matchers | Not found | Unclear — resources are managed entities but authorization parity with tools is undocumented | Not documented | Not documented | stdio, HTTP, WebSocket, SSE | Apache-2.0 | Python | 2026-07-31 | 4,175 |
| [mcp-gateway](https://github.com/Kuadrant/mcp-gateway) (Kuadrant) | No, but requires Envoy/Istio/Keycloak | No — tool-name/method level via CEL on JWT claims | Not found | Not documented | Not documented | No | HTTP (streamable-http) | Apache-2.0 | Go | 2026-07-31 | 94 |
| [mcp-context-protector](https://github.com/trailofbits/mcp-context-protector) | No | Partial — compares tool schemas/descriptions for drift, not per-call argument rules | No | No (tools only) | Closed — blocks until a changed server config is approved | **Yes** — `--review-server`, `--review-quarantine` | stdio, HTTP, SSE | Apache-2.0 | Python | 2026-04-14 | 222 |
| [ToolHive](https://github.com/stacklok/toolhive) | No | Not documented in public docs | Not found | Not documented | Not documented | Not documented | stdio, HTTP/SSE via containerized proxy | Apache-2.0 | Go | 2026-08-01 | 1,985 |
| [agent-scan](https://github.com/snyk/agent-scan) (formerly Invariant Labs `mcp-scan`, acquired by Snyk) | No | No — scans tool descriptions/names, not call arguments | No | **Yes** — scans tools, prompts, and resources for description-level attacks | **Open** — declined servers are recorded, not blocked | **Yes** — consent prompt before starting a stdio server | stdio (primary) | Apache-2.0 | Python | 2026-07-28 | 2,847 |
| [mcp-sentinel](https://github.com/g-gerchow/mcp-sentinel) | Agent-side reference pattern, ambiguous | Not specified | No | No | Not specified | Not specified | Not specified | MIT | Python | 2026-01-26 | 5 |

"Not documented" / "Not found" means the public README, docs, and source
tree did not answer the question — treat as absence of evidence, not evidence
of absence, for the less-popular projects where documentation is thin.

## Per-project assessment

**mcpwall** is the closest single-feature match to `mcpguard`'s core loop and it
already exists today: `arguments._any_value.regex` and `arguments.path.not_under`
matchers give real argument-level policy, and `mcpwall check` is a working
offline dry-run validator, both shipped, both usable right now against Claude
Code, Cursor, and Windsurf. It does this with a fraction of the engineering
`mcpguard` is scoping — a single TypeScript proxy — which is a legitimate
efficiency advantage `mcpguard` cannot claim over it. What it does not do:
police `resources/read`, support human approval, or run over anything but
stdio, and its test command checks one input at a time rather than asserting
which rule fired.

**mcp-firewall** (evalops), despite being archived with zero stars, is the only
project surveyed that treats `resources`, `prompts`, and raw JSON-RPC `methods`
as first-class policy targets *today*, with a GUI for editing rules and
reviewing history — a policy-authoring UX `mcpguard` has no plan to build. Its
weakness is exactly `mcpguard`'s first differentiator: policy is name/pattern
matching on the tool, resource URI, or method identifier, not on argument
values, so `fs.read` cannot be scoped to a path prefix and `gitlab.push` cannot
be denied only when `branch == main`.

**AgentFence** is the strongest overall analog found and the one that most
threatens the case for building `mcpguard`. It is a single Go binary, Apache-2.0,
with real argument-level matchers (`repo` patterns for `github.create_issue`,
`paths` allow/deny for `filesystem.write`), a genuine offline test framework
(`agentfence policy test --policy … --tests … --output json` against
declarative fixtures), a fail-closed default, and first-class human-in-the-loop
approval via an `ask` decision that opens an interactive TTY prompt — four of
`mcpguard`'s seven intended differentiators, in some form, already shipped.
It beats `mcpguard`'s plan on schedule alone: it exists, mcpguard does not.
Where it falls short of the full design: it gates `tools/call` only — its own
README describes the proxy as policy enforcement on intercepted `tools/call`,
with no mention of `resources/read` — so the "most proxies ignore resource
reads" gap is still open here too. It has no `tools/list` filtering (a denied
tool is still visible to the agent, just refused at call time), no
mutation/fuzz testing of the policy itself (its `make fuzz` target fuzzes its
own parser, glob, and redaction *code*, which is a code-quality safeguard, not
a security property of the policy), and no nonce-bound out-of-band approval
(the TTY prompt is synchronous and local, not "have a human on another channel
approve this exact call once"). It is also ten weeks old with three stars —
adoption and hardening are effectively at day one, the same place `mcpguard`
would start from.

**mcp-context-forge (IBM ContextForge)** is the most credible reason to pause:
4,175 stars, Apache-2.0, an active team, and a real plugin architecture where a
`tool_pre_invoke` hook can inspect and mutate arguments before a call executes,
backed by a "Unified Policy Decision Point" that can delegate to Cedar or OPA.
For a team willing to write Python plugins or Rego/Cedar policies, it can
almost certainly express `mcpguard`'s argument-level rules — and it does so
inside a gateway that also handles federation, virtual servers, OIDC/OAuth,
and multi-protocol translation (REST/gRPC/A2A) that `mcpguard` will never
attempt. What it does not offer is `mcpguard`'s specific bet: a *declarative*,
no-code YAML policy format with built-in matchers and combinators, ready-made
offline test tooling that asserts which rule fired (not just the verdict), or
a documented fail-closed contract on plugin/PDP errors. Building the same
policy in ContextForge means writing and maintaining a plugin; `mcpguard`
means writing four lines of YAML.

**Kuadrant's mcp-gateway** does something `mcpguard` explicitly will not:
real enterprise identity integration — Keycloak group mappings, Istio/Envoy
policy attachment, OIDC — for teams that already run a service mesh. That is a
genuine, mature capability. Its authorization is scoped to which tools a role
may call (via CEL over JWT claims and a `tool:` prefix check), not what
arguments they may pass, and it requires adopting Envoy/Istio/Keycloak as
infrastructure, which is a much heavier deployment than a single static binary.

**mcp-context-protector (Trail of Bits)** solves a different, real problem
better than `mcpguard` ever will attempt to: it defends against a *malicious or
compromised MCP server* — trust-on-first-use pinning of tool descriptions and
server instructions, quarantining of tool responses, and scanning for prompt
injection payloads hidden in tool metadata. `mcpguard`'s threat model is a
compliant server and a policy over what the agent is allowed to do; Trail of
Bits' is a server that lies about what it does. Both are needed; they are not
substitutes for each other, and this project is a genuinely stronger answer to
its own threat model, with 222 stars and an active maintainer (Trail of Bits)
behind it.

**ToolHive (Stacklok)** wins on adoption and defense-in-depth: 1,985 stars,
Apache-2.0, and — unlike every proxy on this list — it runs each MCP server in
its own isolated container with no direct network or host access, which stops
a whole class of exfiltration and lateral-movement attacks that a
process-level policy proxy cannot touch no matter how good its argument
matching is. Its public documentation does not establish argument-level policy,
an offline test framework, or documented fail-open/closed semantics, so it was
not possible to confirm or rule out overlap with `mcpguard`'s core
differentiators from the docs alone — this is recorded as an open question,
not a claim that ToolHive lacks them.

**agent-scan (formerly Invariant Labs mcp-scan, now owned by Snyk)** is the
most adopted project in this survey by a wide margin for its category (2,847
stars) and it is the only one that treats `resources` and `prompts`, not just
tools, as first-class scan targets — but for a different failure mode than
`mcpguard`: prompt injection and tool-poisoning payloads hidden in tool
descriptions, not policy violations in the arguments of an otherwise-legitimate
call. It also fails open by design — a declined server is logged, not blocked
— which is the opposite of the control `mcpguard` is built to be, and its
human-in-the-loop step is a one-time consent gate at server startup, not a
per-call approval.

**mcp-sentinel** is explicitly a teaching reference for an RSA 2026 talk ("not
production-ready," "not a full framework or product") and does not beat
`mcpguard` on any concrete axis surveyed here except code-reading simplicity —
a single validation function is easier to audit than a full proxy. It is
included because the brief asks for honest treatment of partial matches, not
because it competes.

## Why build this anyway

No project surveyed combines all four of: argument-level policy, an offline
test framework, `resources/read` coverage, and documented fail-closed semantics
under a permissive licence with real adoption. The closest candidate,
**AgentFence**, has three of the four (argument-level policy, offline tests,
fail-closed default) but explicitly does not police `resources/read`, has no
`tools/list` filtering, no policy-mutation fuzzing, and no nonce-bound
out-of-band approval — and it is a ten-week-old, three-star personal project,
not an established codebase with the kind of adoption that would make
contributing upstream clearly better than building. The most-adopted general
gateway, **IBM mcp-context-forge**, can likely express argument-level rules
through custom plugins and a Cedar/OPA backend, but does not offer a
declarative, matcher-based YAML format or a policy test framework, and
building `mcpguard`'s policies inside it means writing and maintaining code,
not YAML — the opposite of `mcpguard`'s bet that policy authors should not
need to write a plugin to deny a path prefix.

Concretely, the gaps `mcpguard` fills that no single surveyed project closes
together are:

1. **Declarative argument-level policy with a full matcher/combinator set**
   (equals, prefix, in, regex, cidr, gt/lt, all/any/not) as the default,
   no-code experience — closest existing match (mcpwall, AgentFence) offers a
   narrower matcher set and no combinators.
2. **`resources/read` coverage as a first-class citizen**, not an
   afterthought — only mcp-firewall (archived, tool-name-level only) and
   agent-scan (description-scanning, not argument policy) attempt this at
   all; nothing surveyed does both resource coverage *and* argument-level
   policy.
3. **An offline test framework that asserts which rule produced a decision**,
   not just the allow/deny verdict — nothing surveyed does this; AgentFence's
   fixtures check the verdict only.
4. **A fuzzing mode that mutates permitted calls** to find policy bypasses
   (path traversal, percent-encoding, NUL bytes, type swaps, extra-argument
   injection) — nothing surveyed does this; the one project with a "fuzz"
   command (AgentFence) fuzzes its own parser code, not the policy's
   semantics.
5. **`tools/list` filtering** so a denied tool is never disclosed to the
   agent — not found in any surveyed project; all of them refuse at call
   time while still listing the tool.
6. **Nonce-bound, out-of-band human approval** tied to a hash of the exact
   call — the two projects with approval workflows (AgentFence,
   mcp-context-protector) use synchronous local prompts, not single-use
   tokens verifiable by a separate approver.

Decision: **proceed.** The survey found real, shipped, permissively-licensed
competitors — several of them closer in spirit than expected, especially
AgentFence and mcpwall — but none combines the full set of `mcpguard`'s
differentiators, and the two candidates with the broadest adoption
(mcp-context-forge, ToolHive) solve a materially different problem
(federation/virtualization/OIDC gateway, and container sandboxing,
respectively) rather than declarative argument-level policy with offline,
provenance-asserting tests. This is not a case of "an existing project
already covers the design" — it is a crowded space with no project yet
covering all of it. Priority order for the differentiators, given what this
survey found closest to prior art already: ship declarative argument-level
policy and the offline test framework first (items 1 and 3 — genuinely
novel among small/permissive projects), `resources/read` coverage second
(item 2 — the biggest one-line credibility gap versus mcpwall/AgentFence),
then fuzzing, `tools/list` filtering, and nonce-bound approval (items 4–6 —
novel against every project surveyed, including the well-funded ones, so
lower schedule risk of being scooped).
