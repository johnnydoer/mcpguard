package policy

import (
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }

func mustCompile(t *testing.T, m *Matcher) *Matcher {
	t.Helper()
	if err := m.compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	return m
}

func TestMatcherEquals(t *testing.T) {
	m := mustCompile(t, &Matcher{Equals: ptr("main")})
	assertMatch(t, m, "main", true, true)
	assertMatch(t, m, "develop", true, false)
}

func TestMatcherNotEquals(t *testing.T) {
	m := mustCompile(t, &Matcher{NotEquals: ptr("main")})
	assertMatch(t, m, "develop", true, true)
	assertMatch(t, m, "main", true, false)
}

func TestMatcherInSupportsGlobs(t *testing.T) {
	// A plain string is its own glob, so one list handles both exact names and
	// patterns. This is what makes in: [main, "release/*"] work as written.
	m := mustCompile(t, &Matcher{In: []string{"main", "release/*"}})
	assertMatch(t, m, "main", true, true)
	assertMatch(t, m, "release/1.2", true, true)
	assertMatch(t, m, "feature/x", true, false)
}

func TestMatcherNotIn(t *testing.T) {
	m := mustCompile(t, &Matcher{NotIn: []string{"main"}})
	assertMatch(t, m, "develop", true, true)
	assertMatch(t, m, "main", true, false)
}

func TestMatcherPrefixSuffixContains(t *testing.T) {
	assertMatch(t, mustCompile(t, &Matcher{Prefix: ptr("/srv/")}), "/srv/a", true, true)
	assertMatch(t, mustCompile(t, &Matcher{Prefix: ptr("/srv/")}), "/etc/a", true, false)
	assertMatch(t, mustCompile(t, &Matcher{Suffix: ptr(".txt")}), "a.txt", true, true)
	assertMatch(t, mustCompile(t, &Matcher{Contains: ptr("mid")}), "a-mid-b", true, true)
}

func TestMatcherRegex(t *testing.T) {
	m := mustCompile(t, &Matcher{Regex: ptr(`^v[0-9]+$`)})
	assertMatch(t, m, "v12", true, true)
	assertMatch(t, m, "v12x", true, false)
}

func TestMatcherCIDR(t *testing.T) {
	m := mustCompile(t, &Matcher{CIDR: ptr("172.16.0.0/16")})
	assertMatch(t, m, "172.16.4.2", true, true)
	assertMatch(t, m, "10.0.0.1", true, false)
}

func TestMatcherCIDRRejectsNonIP(t *testing.T) {
	m := mustCompile(t, &Matcher{CIDR: ptr("172.16.0.0/16")})
	if _, err := m.Match("not-an-ip", true); err == nil {
		t.Error("a non-IP value against a cidr matcher must error, so the caller denies")
	}
}

func TestMatcherExistsAndAbsent(t *testing.T) {
	exists := mustCompile(t, &Matcher{Exists: ptr(true)})
	assertMatch(t, exists, "anything", true, true)
	assertMatch(t, exists, nil, false, false)

	absent := mustCompile(t, &Matcher{Absent: ptr(true)})
	assertMatch(t, absent, nil, false, true)
	assertMatch(t, absent, "anything", true, false)
}

func TestMatcherOnMissingArgumentDoesNotMatch(t *testing.T) {
	// A constraint on an argument that is not present must not match. Matching
	// would let a rule intended to narrow access instead widen it: omit the
	// argument and the constraint evaporates.
	m := mustCompile(t, &Matcher{Prefix: ptr("/srv/")})
	assertMatch(t, m, nil, false, false)
}

func TestMatcherNumericComparison(t *testing.T) {
	// JSON numbers decode as float64.
	m := mustCompile(t, &Matcher{GT: ptr(10.0), LT: ptr(20.0)})
	assertMatch(t, m, float64(15), true, true)
	assertMatch(t, m, float64(5), true, false)
	assertMatch(t, m, float64(25), true, false)
}

func TestMatcherTypeEnforcementDeniesConfusion(t *testing.T) {
	// The bypass this prevents: {"path": ["/srv/ok", "/etc/shadow"]} against a
	// matcher that assumes string. Returning "no match" would be wrong too,
	// because the caller would fall through to the next rule; an error is the
	// only correct answer, and the caller turns it into a denial.
	m := mustCompile(t, &Matcher{Type: "string", Prefix: ptr("/srv/")})
	if _, err := m.Match([]any{"/srv/ok", "/etc/shadow"}, true); err == nil {
		t.Error("an array against a string matcher must error")
	}
	if _, err := m.Match(float64(1), true); err == nil {
		t.Error("a number against a string matcher must error")
	}
	if _, err := m.Match(map[string]any{"a": 1}, true); err == nil {
		t.Error("an object against a string matcher must error")
	}
}

func TestMatcherTypeEnforcementForNumberAndBool(t *testing.T) {
	num := mustCompile(t, &Matcher{Type: "number", GT: ptr(1.0)})
	if _, err := num.Match("5", true); err == nil {
		t.Error("a string against a number matcher must error")
	}
	b := mustCompile(t, &Matcher{Type: "bool", Equals: ptr("true")})
	if _, err := b.Match("true", true); err == nil {
		t.Error("a string against a bool matcher must error")
	}
	assertMatch(t, b, true, true, true)
}

func TestMatcherUntypedStringMatcherStillRejectsNonString(t *testing.T) {
	// Even without an explicit type, a string operator applied to a non-string
	// must error rather than silently stringify. Stringifying would make
	// prefix: /srv/ match the value ["/srv/x"] via its Go representation.
	m := mustCompile(t, &Matcher{Prefix: ptr("/srv/")})
	if _, err := m.Match([]any{"/srv/x"}, true); err == nil {
		t.Error("array against an untyped prefix matcher must error")
	}
}

func TestMatcherCanonicalizePathBlocksTraversal(t *testing.T) {
	m := mustCompile(t, &Matcher{Type: "string", Canonicalize: "path", Prefix: ptr("/srv/data/public/")})

	assertMatch(t, m, "/srv/data/public/report.txt", true, true)

	// Canonicalization rejects the traversal, which surfaces as an error and
	// therefore a denial — never as a successful prefix match.
	if _, err := m.Match("/srv/data/public/../../etc/shadow", true); err == nil {
		t.Error("traversal must produce an error from the canonicalizer")
	}
}

func TestMatcherCanonicalizeURL(t *testing.T) {
	m := mustCompile(t, &Matcher{Canonicalize: "url", Prefix: ptr("https://example.com/")})
	assertMatch(t, m, "HTTPS://Example.COM:443/a", true, true)
}

func TestMatcherRejectsUnknownCanonicalizer(t *testing.T) {
	m := &Matcher{Canonicalize: "telepathy", Prefix: ptr("x")}
	if err := m.compile(); err == nil {
		t.Error("an unknown canonicalize value must fail at load time")
	}
}

func TestMatcherRejectsUnknownType(t *testing.T) {
	m := &Matcher{Type: "quaternion", Equals: ptr("x")}
	if err := m.compile(); err == nil {
		t.Error("an unknown type must fail at load time")
	}
}

func TestMatcherRejectsEmptyMatcher(t *testing.T) {
	// A matcher with no operators would match everything, silently turning a
	// narrowing rule into a permissive one.
	if err := (&Matcher{}).compile(); err == nil {
		t.Error("a matcher with no operators must be rejected")
	}
}

func TestMatcherAllRequiresEveryChild(t *testing.T) {
	m := mustCompile(t, &Matcher{All: []Matcher{
		{Prefix: ptr("/srv/")},
		{Suffix: ptr(".txt")},
	}})
	assertMatch(t, m, "/srv/a.txt", true, true)
	assertMatch(t, m, "/srv/a.md", true, false)
}

func TestMatcherAnyRequiresOneChild(t *testing.T) {
	m := mustCompile(t, &Matcher{Any: []Matcher{
		{Equals: ptr("a")},
		{Equals: ptr("b")},
	}})
	assertMatch(t, m, "a", true, true)
	assertMatch(t, m, "b", true, true)
	assertMatch(t, m, "c", true, false)
}

func TestMatcherNotInverts(t *testing.T) {
	m := mustCompile(t, &Matcher{Not: &Matcher{Equals: ptr("main")}})
	assertMatch(t, m, "develop", true, true)
	assertMatch(t, m, "main", true, false)
}

func TestMatcherNestedCombinators(t *testing.T) {
	m := mustCompile(t, &Matcher{All: []Matcher{
		{Prefix: ptr("/srv/")},
		{Not: &Matcher{Contains: ptr("secret")}},
	}})
	assertMatch(t, m, "/srv/public/a", true, true)
	assertMatch(t, m, "/srv/secret/a", true, false)
}

func TestMatcherChildErrorPropagates(t *testing.T) {
	// An error inside a combinator must reach the caller, not be swallowed into
	// a false. A swallowed error means fall-through to the next rule.
	m := mustCompile(t, &Matcher{All: []Matcher{{Type: "string", Prefix: ptr("/srv/")}}})
	if _, err := m.Match(float64(1), true); err == nil {
		t.Error("a child type error must propagate out of All")
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"get_*", "get_file", true},
		{"get_*", "getfile", false},
		{"*", "anything", true},
		{"*", "", true},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"a*c", "abc", true},
		{"a*c", "ac", true},
		{"a*c", "abd", false},
		{"*_file", "read_file", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxc", false},
		// Path separators are NOT special: tool names and resource URIs both
		// need to glob freely, and path.Match's separator handling would make
		// "release/*" behave inconsistently between the two.
		{"release/*", "release/1.2", true},
		{"*/*", "a/b", true},
	}
	for _, c := range cases {
		if got := GlobMatch(c.pattern, c.s); got != c.want {
			t.Errorf("GlobMatch(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

// TestLoadedRegexMatcherActuallyRejects is a regression guard for the fail-open
// bug Task 8's review found: ranging `for arg, m := range r.Match.Args` yields a
// copy of the map value, so if config.go's validateRules ever stops writing the
// compiled matcher back into the map, m.re on the stored Matcher stays nil.
// matchString only checks the regex when m.re != nil, so a nil compiled regex is
// silently SKIPPED rather than failed. On an allow rule that turns "regex:
// ^v[0-9]+$" into "matches anything" — a policy bypass, not a crash, so nothing
// short of asserting a genuine rejection through a config loaded via Load will
// catch its return. Do not delete this as redundant with TestMatcherRegex: that
// test constructs a Matcher directly and calls compile() itself, so it can never
// observe the map-writeback bug.
func TestLoadedRegexMatcherActuallyRejects(t *testing.T) {
	const cfg = `
version: v1
servers: [{name: s, transport: stdio, command: ["true"]}]
rules:
  - name: tag-must-look-like-a-version
    servers: [s]
    tools: ["*"]
    match:
      args:
        tag:
          type: string
          regex: "^v[0-9]+$"
    action: allow
`
	c, err := Load(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := c.Rules[0].Match.Args["tag"]

	ok, err := m.Match("not-a-version-tag", true)
	if err != nil {
		t.Fatalf("Match: unexpected error %v", err)
	}
	if ok {
		t.Fatal("a value that fails the regex matched anyway: the compiled " +
			"regexp was not written back into the map, so the constraint was " +
			"silently skipped instead of enforced (fail-open regression)")
	}

	ok, err = m.Match("v12", true)
	if err != nil {
		t.Fatalf("Match: unexpected error %v", err)
	}
	if !ok {
		t.Error("a value that satisfies the regex should match")
	}
}

// TestLoadedCIDRMatcherActuallyRejects is the CIDR half of the same regression
// guard: m.ipNet is cached by compile() and must survive the same map
// writeback. A nil m.ipNet makes matchString skip the cidr check entirely,
// which for an allow rule widens access to any string, IP or not. See
// TestLoadedRegexMatcherActuallyRejects for the full explanation; do not delete
// either as redundant with the direct-construction CIDR tests above, which
// never exercise config.go's map range at all.
func TestLoadedCIDRMatcherActuallyRejects(t *testing.T) {
	const cfg = `
version: v1
servers: [{name: s, transport: stdio, command: ["true"]}]
rules:
  - name: source-must-be-internal
    servers: [s]
    tools: ["*"]
    match:
      args:
        source_ip:
          type: string
          cidr: 172.16.0.0/16
    action: allow
`
	c, err := Load(strings.NewReader(cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := c.Rules[0].Match.Args["source_ip"]

	ok, err := m.Match("10.0.0.1", true)
	if err != nil {
		t.Fatalf("Match: unexpected error %v", err)
	}
	if ok {
		t.Fatal("an IP outside the CIDR matched anyway: the compiled IPNet was " +
			"not written back into the map, so the constraint was silently " +
			"skipped instead of enforced (fail-open regression)")
	}

	ok, err = m.Match("172.16.4.2", true)
	if err != nil {
		t.Fatalf("Match: unexpected error %v", err)
	}
	if !ok {
		t.Error("an IP inside the CIDR should match")
	}
}

// TestLoadRejectsInvalidRegexNestedInsideAll verifies that compile()'s
// recursion through combinators is actually wired up end to end through Load,
// not just when a top-level matcher is constructed and compiled directly.
// Every other regex-validity test in this file (and the whole invalid-config
// surface in config_test.go) only exercises a top-level Regex field, so a
// broken or missing recursion into All/Any/Not would pass every existing test
// while still letting a bad pattern reach production inside a combinator —
// exactly the "fail at load, not first use" property this guards. Do not
// delete this as redundant with TestMatcherRejectsUnknownType/Canonicalizer:
// those also compile a top-level matcher directly, never nested.
func TestLoadRejectsInvalidRegexNestedInsideAll(t *testing.T) {
	const cfg = `
version: v1
servers: [{name: s, transport: stdio, command: ["true"]}]
rules:
  - name: bad-nested-regex
    servers: [s]
    tools: ["*"]
    match:
      args:
        tag:
          all:
            - prefix: v
            - regex: "["
    action: allow
`
	if _, err := Load(strings.NewReader(cfg)); err == nil {
		t.Error("Load must reject an invalid regex nested inside all, not merely a top-level one")
	}
}

// assertMatch runs a matcher and checks the boolean result, failing on any error.
func assertMatch(t *testing.T, m *Matcher, value any, present, want bool) {
	t.Helper()
	got, err := m.Match(value, present)
	if err != nil {
		t.Fatalf("Match(%v, %v): unexpected error %v", value, present, err)
	}
	if got != want {
		t.Errorf("Match(%v, %v) = %v, want %v", value, present, got, want)
	}
}
