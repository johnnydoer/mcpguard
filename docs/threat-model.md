# Threat Model

## What mcpguard defends

An AI agent that can call tools has the privilege of every tool it can reach.
mcpguard constrains that reach with deterministic policy applied at the protocol
boundary, without cooperation from the agent.

## Trust boundaries

| Component | Trusted? | Why |
|---|---|---|
| The agent | **No** | It is the thing being constrained, and it cannot opt out because it does not know it is proxied |
| The model driving the agent | **No** | May be steered by injected content in tool results |
| mcpguard | Yes | It is the policy decision and enforcement point |
| The policy file | Yes | Operator-authored, expected under version control |
| The MCP server | Partially | Trusted to execute correctly; not trusted to authorize |
| Tool results | **No** | May contain content designed to influence the agent |

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

## Deliberate strictness

Three choices reject input that a more permissive tool would accept. Each removes
a bypass class at a small cost in convenience:

- **Any path containing `..` is rejected outright**, not normalized. Normalizing
  correctly in the presence of symlinks is genuinely hard, because `filepath.Clean`
  and the kernel disagree about `/a/link/../b`, and the disagreement is
  exploitable.
- **A type-confused argument is a denial**, not a skipped rule. Skipping would
  fall through to a later, broader rule.
- **Arguments a matched rule does not name are denied** by default, so a rule is
  an exhaustive statement about a call rather than a partial one.

## Fail-closed inventory

| Failure | Result |
|---|---|
| Invalid policy at startup | refuse to start |
| Evaluation error | deny, attributed to the rule that errored |
| Unparseable request | deny |
| Unwritable audit log at startup | refuse to start |
| Unwritable audit log at runtime | apply `audit.on_error`, default deny |
| Approval channel unreachable | deny |
| Approval unanswered | deny |
| No approver configured but a rule requires approval | deny |
| List response cannot be filtered | replace with an error rather than forward unfiltered |
