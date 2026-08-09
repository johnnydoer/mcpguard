// Package fuzz mutates permitted calls to prove an allowlist survives
// adversarial input.
//
// The premise: a policy test asserting that /srv/data/public/a.txt is allowed
// proves the happy path. It says nothing about whether
// /srv/data/public/../../etc/shadow is also allowed. This package takes every
// permitted case and tries to break it.
package fuzz

import (
	"strings"

	"github.com/JohnnyDoer/mcpguard/internal/canon"
	"github.com/JohnnyDoer/mcpguard/internal/policy"
)

// Mutation is one adversarial variant of a call's arguments or tool name.
type Mutation struct {
	Strategy string
	Arg      string
	Tool     string // non-empty only for tool-mutation strategy
	Args     map[string]any
}

// Bypass is a mutation that was still permitted.
type Bypass struct {
	Case     string
	Mutation Mutation
	GotRule  string
}

// MutateString returns adversarial variants of a string value.
//
// Every strategy corresponds to a real bypass class rather than random noise.
// Random bytes would mostly produce values that fail to match anything, which
// looks like a pass and proves nothing.
func MutateString(s string) []string {
	variants := []string{
		// Traversal, plain and encoded. The encoded forms matter because a check
		// applied before percent-decoding misses them entirely.
		s + "/../../etc/shadow",
		insertAfterFirstSlash(s, "../"),
		strings.Replace(s, "/", "/../", 1),
		s + "/%2e%2e/%2e%2e/etc/shadow",
		s + "/%2E%2E/etc/shadow",
		// Truncation via NUL: a Go-side prefix check passes while a C syscall
		// layer stops at the NUL.
		s + "\x00/../../etc/shadow",
		s + "\x00",
		// Separator and case variation.
		strings.ReplaceAll(s, "/", "//"),
		strings.ToUpper(s),
		// Relative form: resolves against the server's cwd, not the policy's
		// assumption.
		strings.TrimPrefix(s, "/"),
		"./" + strings.TrimPrefix(s, "/"),
		// Unicode: a full-width solidus that some normalizers fold to "/".
		strings.ReplaceAll(s, "/", "／"),
		// Trailing whitespace, which a naive equals check may tolerate.
		s + " ",
	}

	out := make([]string, 0, len(variants))
	for _, v := range variants {
		// A mutation equal to the input would report a false bypass, since the
		// input is permitted by definition.
		if v != s && v != "" {
			out = append(out, v)
		}
	}
	return out
}

func insertAfterFirstSlash(s, insert string) string {
	idx := strings.Index(s, "/")
	if idx < 0 {
		return insert + s
	}
	return s[:idx+1] + insert + s[idx+1:]
}

// MutateArgs returns adversarial variants of an argument map.
func MutateArgs(args map[string]any) []Mutation {
	var out []Mutation

	for name, value := range args {
		if s, ok := value.(string); ok {
			for _, variant := range MutateString(s) {
				out = append(out, Mutation{
					Strategy: "string-mutation", Arg: name,
					Args: withArg(args, name, variant),
				})
			}

			// Type swaps. The array case is the classic type-confusion bypass:
			// a matcher that assumes string and sees a slice must not pass.
			out = append(out,
				Mutation{Strategy: "type-swap-array", Arg: name,
					Args: withArg(args, name, []any{s, "/etc/shadow"})},
				Mutation{Strategy: "type-swap-object", Arg: name,
					Args: withArg(args, name, map[string]any{"value": s})},
				Mutation{Strategy: "type-swap-number", Arg: name,
					Args: withArg(args, name, float64(1))},
				Mutation{Strategy: "type-swap-bool", Arg: name,
					Args: withArg(args, name, true)},
				Mutation{Strategy: "type-swap-null", Arg: name,
					Args: withArg(args, name, nil)},
			)
		}

		// Removing a constrained argument: if the matcher is skipped rather than
		// failed when the value is absent, this is a bypass.
		out = append(out, Mutation{
			Strategy: "arg-removal", Arg: name, Args: without(args, name),
		})
	}

	// Injecting an unnamed argument, which tests additional_args specifically.
	out = append(out, Mutation{
		Strategy: "extra-arg-injection", Arg: "mcpguard_injected",
		Args: withArg(args, "mcpguard_injected", true),
	})

	return out
}

func withArg(args map[string]any, name string, value any) map[string]any {
	out := make(map[string]any, len(args)+1)
	for k, v := range args {
		out[k] = v
	}
	out[name] = value
	return out
}

func without(args map[string]any, name string) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		if k != name {
			out[k] = v
		}
	}
	return out
}

// FindBypasses mutates every allow case and reports any mutation still allowed.
//
// Only allow cases are fuzzed: mutating an already-denied call proves nothing,
// and a mutation that stays denied is the expected outcome, not a finding.
//
// A mutation that is still allowed after canonicalising its string arguments is
// within scope and is not a bypass — it is the policy working correctly on a
// syntactic variant of an allowed path (double slashes, percent-literal names,
// trailing whitespace). Only mutations that are allowed in raw form but denied
// after canonical re-evaluation represent a real finding: the raw form smuggled
// something that canonicalisation would have blocked.
func FindBypasses(e *policy.Engine, pt *policy.PolicyTest) []Bypass {
	var found []Bypass

	for _, c := range pt.Cases {
		if c.Expect != policy.ActionAllow {
			continue
		}
		method := c.Method
		if method == "" {
			method = "tools/call"
		}

		for _, m := range MutateArgs(c.Args) {
			d := e.Evaluate(policy.Request{
				Server: c.Server, Method: method, Tool: c.Tool, Args: m.Args,
			})
			if d.Action != policy.ActionAllow {
				continue
			}
			// Re-evaluate with canonical forms of all string args. If the
			// canonical form is also allowed, the mutation is a legitimate
			// variant inside the allowed scope — not a bypass.
			dc := e.Evaluate(policy.Request{
				Server: c.Server, Method: method, Tool: c.Tool,
				Args: canonicalStringArgs(m.Args),
			})
			if dc.Action != policy.ActionAllow {
				found = append(found, Bypass{Case: c.Name, Mutation: m, GotRule: d.Rule})
			}
		}

		// Mutate the Tool field. For resources/read the tool is a URI, making it
		// the primary traversal target. The canonical re-evaluation gate mirrors
		// the one in Interceptor.handleResourcesRead: a raw bypass that disappears
		// after canonicalization is a real finding.
		for _, variant := range MutateString(c.Tool) {
			d := e.Evaluate(policy.Request{
				Server: c.Server, Method: method, Tool: variant, Args: c.Args,
			})
			if d.Action != policy.ActionAllow {
				continue
			}
			dc := e.Evaluate(policy.Request{
				Server: c.Server, Method: method, Tool: canonicalTool(variant), Args: c.Args,
			})
			if dc.Action != policy.ActionAllow {
				found = append(found, Bypass{
					Case: c.Name,
					Mutation: Mutation{
						Strategy: "tool-mutation", Arg: "tool",
						Tool: variant, Args: c.Args,
					},
					GotRule: d.Rule,
				})
			}
		}
	}
	return found
}

// canonicalTool returns the canonical form of a Tool field value for
// re-evaluation after a tool-mutation bypass candidate is found.
//
// For file:// URIs the path is cleaned and traversal elements cause the
// function to return the empty string, which matches nothing. For other
// strings canon.Path is applied as a best-effort normalization.
func canonicalTool(tool string) string {
	if strings.HasPrefix(tool, "file://") {
		p, err := canon.FileURIPath(tool)
		if err != nil {
			return ""
		}
		return "file://" + p
	}
	canonical, err := canon.Path(tool)
	if err != nil {
		return ""
	}
	return canonical
}

// canonicalStringArgs returns a copy of args with every string value replaced
// by its canonical filesystem-path form, or by the empty string when
// canonicalisation fails (traversal element, NUL byte, relative path, etc.).
//
// The result is used to re-evaluate a mutation: if the canonical form is also
// allowed, the mutation is within scope; if it is denied, the raw form
// smuggled something past a check that canonicalisation would have caught.
func canonicalStringArgs(args map[string]any) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		if s, ok := v.(string); ok {
			if canonical, err := canon.Path(s); err == nil {
				out[k] = canonical
			} else {
				out[k] = ""
			}
		} else {
			out[k] = v
		}
	}
	return out
}
