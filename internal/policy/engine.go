package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Request is one authorization question.
//
// Tool carries the tool name for tools/call and the resource URI for
// resources/read, so both go through one evaluation path.
type Request struct {
	Server string
	Method string
	Tool   string
	Args   map[string]any
}

// Decision is the answer. Rule is empty when no rule matched and the default
// applied; Reason always explains the outcome, including for defaults, because
// an audit log entry with no explanation is not much use during an incident.
type Decision struct {
	Action  Action
	Rule    string
	Message string
	Reason  string
}

// Engine evaluates requests against a compiled policy.
//
// It holds no mutable state after construction, so a single Engine is safe for
// concurrent use by both transport directions.
type Engine struct {
	cfg *Config
}

// New compiles a config into an Engine.
//
// Matchers are compiled here as well as in Load, because a caller may construct
// a Config programmatically and must not end up with an engine whose regexes
// silently never match.
func New(cfg *Config) (*Engine, error) {
	if cfg == nil {
		return nil, errors.New("policy: config must not be nil")
	}
	for i := range cfg.Rules {
		if cfg.Rules[i].Match == nil {
			continue
		}
		for arg, m := range cfg.Rules[i].Match.Args {
			if err := m.compile(); err != nil {
				return nil, fmt.Errorf("policy: rule %q arg %q: %w", cfg.Rules[i].Name, arg, err)
			}
			// Matcher is stored by value in the map, so the compiled state has
			// to be written back or it is discarded.
			cfg.Rules[i].Match.Args[arg] = m
		}
	}
	return &Engine{cfg: cfg}, nil
}

// Config exposes the loaded configuration for callers that need audit or
// approval settings.
func (e *Engine) Config() *Config { return e.cfg }

// Evaluate applies the policy in declaration order and returns the first
// matching rule's action, or the configured default.
//
// Any error encountered while evaluating a rule is a denial attributed to that
// rule. It is deliberately not a fall-through: continuing to the next rule after
// a type-confused argument is precisely how such an argument becomes a bypass.
func (e *Engine) Evaluate(req Request) Decision {
	for _, rule := range e.cfg.Rules {
		if !e.ruleTargets(rule, req.Server, req.Tool) {
			continue
		}

		matched, reason, err := e.argsMatch(rule, req.Args)
		if err != nil {
			return Decision{
				Action: ActionDeny,
				Rule:   rule.Name,
				Reason: fmt.Sprintf("evaluation error, denying: %v", err),
			}
		}
		if !matched {
			continue
		}

		return Decision{
			Action:  rule.Action,
			Rule:    rule.Name,
			Message: rule.Message,
			Reason:  reason,
		}
	}

	return Decision{
		Action: e.cfg.Defaults.Action,
		Reason: fmt.Sprintf("no rule matched %s/%s; applying defaults.action=%s",
			req.Server, req.Tool, e.cfg.Defaults.Action),
	}
}

// ruleTargets reports whether a rule applies to this server and tool, ignoring
// argument matchers.
func (e *Engine) ruleTargets(rule Rule, server, tool string) bool {
	// An omitted servers list matches every server, which is what lets a single
	// config file work unchanged when the same policy is reused across servers.
	if len(rule.Servers) > 0 && !contains(rule.Servers, server) {
		return false
	}
	for _, pattern := range rule.Tools {
		if GlobMatch(pattern, tool) {
			return true
		}
	}
	return false
}

// argsMatch evaluates a rule's argument constraints.
//
// It returns a human-readable reason on success so the audit log and `explain`
// can show why a rule matched, not merely that it did.
func (e *Engine) argsMatch(rule Rule, args map[string]any) (bool, string, error) {
	if rule.Match == nil || len(rule.Match.Args) == 0 {
		// A rule with no argument constraints matches on server and tool alone.
		// additional_args cannot apply here: there is no named set for other
		// arguments to be additional to.
		return true, "matched on tool name; rule constrains no arguments", nil
	}

	// Deterministic iteration so the reason string and any error are stable
	// across runs. Map order would otherwise make failures hard to reproduce.
	names := make([]string, 0, len(rule.Match.Args))
	for name := range rule.Match.Args {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		matcher := rule.Match.Args[name]
		value, present := args[name]

		ok, err := matcher.Match(value, present)
		if err != nil {
			return false, "", fmt.Errorf("argument %q: %w", name, err)
		}
		if !ok {
			return false, "", nil
		}
	}

	if err := e.checkAdditionalArgs(rule, args, names); err != nil {
		return false, "", err
	}

	return true, "matched constrained arguments: " + strings.Join(names, ", "), nil
}

// checkAdditionalArgs enforces that a rule is an exhaustive statement about the
// call unless it explicitly opts out.
//
// Without this, a rule constraining path says nothing about follow_symlinks, and
// a caller can attach any argument the tool happens to accept.
func (e *Engine) checkAdditionalArgs(rule Rule, args map[string]any, named []string) error {
	policyFor := e.cfg.Defaults.AdditionalArgs
	if rule.AdditionalArgs != nil {
		policyFor = *rule.AdditionalArgs
	}
	if policyFor == ActionAllow {
		return nil
	}

	extra := make([]string, 0)
	for name := range args {
		if !contains(named, name) {
			extra = append(extra, name)
		}
	}
	if len(extra) == 0 {
		return nil
	}
	sort.Strings(extra)
	return fmt.Errorf("rule %q does not constrain argument(s) %s and additional_args is deny",
		rule.Name, strings.Join(extra, ", "))
}

// ToolVisible reports whether a tool should be advertised in tools/list.
//
// The question is "could this tool ever be permitted?", so a rule's own
// argument matchers never rule the tool out — only the server and tool
// patterns are consulted when asking whether a rule targets the call.
//
// A rule with no match block applies unconditionally to every call that
// reaches it, so it is a definitive verdict: if Evaluate would always land on
// this rule, its action is the answer. A rule with a match block, by contrast,
// only conditionally applies — some arguments satisfy it and some do not — so
// an earlier scoped deny (like "path starts with /etc/") must not hide a tool
// that a later scoped allow ("path starts with /srv/") can still reach; only a
// scoped rule's own allow/approve is decisive, never its deny.
func (e *Engine) ToolVisible(server, tool string) bool {
	for _, rule := range e.cfg.Rules {
		if !e.ruleTargets(rule, server, tool) {
			continue
		}
		// approve counts as visible: the tool is usable, just gated.
		visible := rule.Action == ActionAllow || rule.Action == ActionApprove

		if rule.Match == nil {
			// Unconditional: every call that reaches this rule matches it, so
			// its action is the final word regardless of what follows.
			return visible
		}
		if visible {
			// Scoped, but some argument set reaches an allow/approve here —
			// that alone is enough to advertise the tool.
			return true
		}
		// Scoped deny: other argument sets may dodge this rule and reach a
		// later one, so evaluation continues rather than deciding here.
	}
	return e.cfg.Defaults.Action == ActionAllow || e.cfg.Defaults.Action == ActionApprove
}

func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
