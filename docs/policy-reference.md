# Policy Reference

## Top-level structure

A minimal complete policy:

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

### Fields

- **`version: v1`** — required; only `v1` is supported.
- **`servers`** — list of upstream MCP servers this proxy fronts. Each entry has:
  - `name` — short identifier referenced in rules and audit logs.
  - `transport` — `stdio` (subprocess) or `http` (HTTP/SSE remote server).
  - `command` — command and arguments for `stdio` servers (e.g. `[npx, -y, pkg]`).
  - `url` — base URL for `http` servers.
- **`rules`** — ordered list of authorization rules. Evaluated top to bottom; first
  match wins. A call that matches no rule is subject to `defaults.action`.
- **`defaults.action`** — `allow` or `deny` (default: `deny`). Applied when no rule
  matches. Omitting this is the same as `deny`.
- **`audit`** — configures the structured audit log:
  - `path` — file path for the JSONL audit log.
  - `mode` — `redact` (default) or `passthrough`. Redact replaces argument values
    with a stable hash; passthrough records them verbatim.
  - `on_error` — what to do when the log cannot be written at runtime: `deny`
    (default), `continue` (allow the call), or `halt` (terminate the proxy).
- **`approval`** — configures out-of-band human approval for `approve`-action rules:
  - `channel` — only `ntfy` is supported.
  - `url` — base URL of the ntfy server (e.g. `http://172.16.0.10:80`).
  - `topic` — ntfy topic name.
  - `timeout` — duration to wait for a human response (e.g. `5m`). Defaults to
    `120s`.
  - `on_timeout` — action when the timeout expires: `deny` or `approve`. Must not
    be `allow`; the policy validator rejects it.

---

## Rules

Each rule is one entry in the `rules` list.

- **`name`** — required; must be unique. Appears in audit log entries and in deny
  messages returned to the agent. Choose names that make a log entry
  self-explanatory.
- **`servers`** — list of server names this rule applies to. An empty list (or
  omitting the field) means the rule applies to all servers.
- **`tools`** — list of glob patterns matched against the tool name. `*` matches
  everything. `write_*` matches `write_file` and `write_dir`. Patterns are globs,
  not regexes — the only wildcard is `*`.
- **`action`** — required: `allow`, `deny`, or `approve`.
- **`match.args`** — map from argument name to a Matcher (see below). A call only
  matches the rule if every named argument satisfies its matcher. Arguments not
  named in `match.args` are subject to `additional_args`.
- **`additional_args`** — `allow` or `deny` (default: `deny`). Controls whether
  arguments not named in `match.args` are permitted. Omitting this inherits
  `defaults.additional_args`. Setting it to `allow` is a deliberate weakening of
  the rule; `mcpguard validate` reports it as a warning.

### Evaluation semantics

- Rules are evaluated in order; the first matching rule wins.
- Deny-by-default: a call that matches no rule receives `defaults.action` (which
  defaults to `deny`).
- `in` accepts globs (not regexes): `["read_*", "list_*"]` matches any tool whose
  name starts with `read_` or `list_`.
- Tool patterns are also globs: `write_*` matches `write_file` and `write_dir`.
- Relative paths in arguments are always rejected by the `canonicalize: path`
  matcher — they resolve against the server's working directory, which mcpguard
  does not know.
- `additional_args: allow` is a deliberate weakening. `mcpguard validate` reports
  any rule that sets it.

---

## Matchers

A matcher constrains one argument value. All fields are optional; combining
multiple operators in one matcher applies them as a conjunction (AND).

### Leaf operators

- **`equals: value`** — case-sensitive string equality.
  ```yaml
  match:
    args:
      action:
        equals: read
  ```

- **`prefix: /srv/public`** — the string must start with this value.
  ```yaml
  match:
    args:
      path:
        prefix: /srv/public
  ```

- **`regex: '^[a-z]+$'`** — full-match Go regular expression.
  ```yaml
  match:
    args:
      name:
        regex: '^[a-z][a-z0-9_-]{0,63}$'
  ```

- **`cidr: 10.0.0.0/8`** — IPv4 or IPv6 CIDR range. The argument must be a bare IP
  address string.
  ```yaml
  match:
    args:
      host:
        cidr: 10.0.0.0/8
  ```

- **`in: [a, b, "write_*"]`** — the value must match at least one entry; entries
  are globs.
  ```yaml
  match:
    args:
      namespace:
        in: [default, staging]
  ```

### Path canonicalization

**`canonicalize: path`** normalizes the argument to an absolute path, then rejects
it if it contains `..` or a NUL byte, or if it is relative. Combine with `prefix`
to enforce a directory boundary:

```yaml
match:
  args:
    path:
      canonicalize: path
      prefix: /srv/public/
```

This is the primary defense against path traversal. Without `canonicalize: path`,
a prefix check can be bypassed with `../`.

### Combinators

- **`all: [...]`** — all nested matchers must match (conjunction).
  ```yaml
  match:
    args:
      path:
        all:
          - canonicalize: path
            prefix: /srv/data/
          - not:
              suffix: .key
  ```

- **`not: {...}`** — the nested matcher must not match.
  ```yaml
  match:
    args:
      operation:
        not:
          in: [delete, drop, truncate]
  ```

---

## Examples

### 1. Read-only filesystem access

Allow reads inside `/srv/public`; require approval for writes; deny deletes.

```yaml
version: v1

servers:
  - name: filesystem
    transport: stdio
    command: [npx, -y, "@modelcontextprotocol/server-filesystem", /srv/public]

defaults:
  action: deny

approval:
  channel: ntfy
  url: http://172.16.0.10:80
  topic: mcpguard
  timeout: 5m
  on_timeout: deny

rules:
  - name: allow-reads
    servers: [filesystem]
    tools: [read_file, read_multiple_files, list_directory, directory_tree]
    match:
      args:
        path:
          canonicalize: path
          prefix: /srv/public/
    action: allow

  - name: approve-writes
    servers: [filesystem]
    tools: [write_file, edit_file, create_directory, move_file]
    action: approve

  - name: deny-deletes
    servers: [filesystem]
    tools: ["delete_*"]
    action: deny
```

### 2. Kubernetes read-only with approval for apply

Read operations are always allowed. Applying a manifest requires a human to
approve. Delete operations are denied outright.

```yaml
version: v1

servers:
  - name: kubernetes
    transport: stdio
    command: [npx, -y, "@modelcontextprotocol/server-kubernetes"]

defaults:
  action: deny

approval:
  channel: ntfy
  url: http://172.16.0.10:80
  topic: mcpguard
  timeout: 5m
  on_timeout: deny

rules:
  - name: read-resources
    servers: [kubernetes]
    tools: ["get_*", "list_*", "describe_*"]
    action: allow

  - name: apply-manifest
    servers: [kubernetes]
    tools: [apply_manifest]
    action: approve

  - name: deny-delete
    servers: [kubernetes]
    tools: ["delete_*"]
    action: deny
```

### 3. Approval-required high-privilege call

Require human approval before merging a merge request; allow read operations.

```yaml
version: v1

servers:
  - name: gitlab
    transport: stdio
    command: [npx, -y, "@modelcontextprotocol/server-gitlab"]

defaults:
  action: deny

approval:
  channel: ntfy
  url: http://172.16.0.10:80
  topic: mcpguard
  timeout: 5m
  on_timeout: deny

rules:
  - name: read-issues
    servers: [gitlab]
    tools: [list_issues, get_issue, list_merge_requests, get_merge_request]
    action: allow

  - name: merge-mr
    servers: [gitlab]
    tools: [merge_merge_request]
    action: approve
```
