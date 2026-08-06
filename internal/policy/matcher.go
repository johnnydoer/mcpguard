package policy

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/JohnnyDoer/mcpguard/internal/canon"
)

// Matcher constrains one argument value.
//
// Every operator is a pointer or slice so that "unset" is distinguishable from
// a zero value: Equals: ptr("") is a meaningful constraint, whereas an unset
// Equals must be ignored.
type Matcher struct {
	Type         string `yaml:"type"`
	Canonicalize string `yaml:"canonicalize"`

	Equals    *string  `yaml:"equals"`
	NotEquals *string  `yaml:"not_equals"`
	In        []string `yaml:"in"`
	NotIn     []string `yaml:"not_in"`
	Prefix    *string  `yaml:"prefix"`
	Suffix    *string  `yaml:"suffix"`
	Contains  *string  `yaml:"contains"`
	Regex     *string  `yaml:"regex"`
	CIDR      *string  `yaml:"cidr"`
	Exists    *bool    `yaml:"exists"`
	Absent    *bool    `yaml:"absent"`
	GT        *float64 `yaml:"gt"`
	LT        *float64 `yaml:"lt"`

	All []Matcher `yaml:"all"`
	Any []Matcher `yaml:"any"`
	Not *Matcher  `yaml:"not"`

	// Compiled at load time so a bad pattern fails when the config is read
	// rather than on the first request that reaches the rule.
	re    *regexp.Regexp
	ipNet *net.IPNet
}

// ErrTypeMismatch indicates a value was not the type the matcher requires.
var ErrTypeMismatch = errors.New("policy: argument type does not match the matcher")

// compile validates the matcher and caches derived state. Called during config
// validation for every matcher, including nested ones.
func (m *Matcher) compile() error {
	switch m.Type {
	case "", "string", "number", "bool", "array", "object":
	default:
		return fmt.Errorf("unknown type %q (want string, number, bool, array, or object)", m.Type)
	}
	switch m.Canonicalize {
	case "", "none", "path", "url":
	default:
		return fmt.Errorf("unknown canonicalize %q (want path, url, or none)", m.Canonicalize)
	}

	if m.Regex != nil {
		re, err := compileRegex(*m.Regex)
		if err != nil {
			return err
		}
		m.re = re
	}
	if m.CIDR != nil {
		_, ipNet, err := net.ParseCIDR(*m.CIDR)
		if err != nil {
			return fmt.Errorf("cidr %q is invalid: %w", *m.CIDR, err)
		}
		m.ipNet = ipNet
	}

	for i := range m.All {
		if err := m.All[i].compile(); err != nil {
			return fmt.Errorf("all[%d]: %w", i, err)
		}
	}
	for i := range m.Any {
		if err := m.Any[i].compile(); err != nil {
			return fmt.Errorf("any[%d]: %w", i, err)
		}
	}
	if m.Not != nil {
		if err := m.Not.compile(); err != nil {
			return fmt.Errorf("not: %w", err)
		}
	}

	if !m.hasOperator() {
		// A matcher with no operators matches everything, silently converting a
		// narrowing rule into a permissive one.
		return errors.New("matcher has no operators; it would match every value")
	}
	return nil
}

func (m *Matcher) hasOperator() bool {
	return m.Equals != nil || m.NotEquals != nil || len(m.In) > 0 || len(m.NotIn) > 0 ||
		m.Prefix != nil || m.Suffix != nil || m.Contains != nil || m.Regex != nil ||
		m.CIDR != nil || m.Exists != nil || m.Absent != nil || m.GT != nil || m.LT != nil ||
		len(m.All) > 0 || len(m.Any) > 0 || m.Not != nil
}

// Match reports whether value satisfies the matcher.
//
// present distinguishes "the argument was absent" from "the argument was
// present and null", which matters for exists and absent.
func (m *Matcher) Match(value any, present bool) (bool, error) {
	// Presence operators are evaluated first because they are the only ones
	// meaningful when the argument is missing.
	if m.Absent != nil {
		return *m.Absent == !present, nil
	}
	if m.Exists != nil {
		return *m.Exists == present, nil
	}
	if !present {
		// A constraint on an absent argument does not match. Matching would let
		// a rule meant to narrow access widen it: omit the argument and the
		// constraint evaporates.
		return false, nil
	}

	if err := m.checkType(value); err != nil {
		return false, err
	}

	// Combinators are evaluated before leaf operators so a matcher that mixes
	// both behaves as an implicit conjunction.
	for i := range m.All {
		ok, err := m.All[i].Match(value, present)
		if err != nil {
			return false, fmt.Errorf("all[%d]: %w", i, err)
		}
		if !ok {
			return false, nil
		}
	}
	if len(m.Any) > 0 {
		matched := false
		for i := range m.Any {
			ok, err := m.Any[i].Match(value, present)
			if err != nil {
				return false, fmt.Errorf("any[%d]: %w", i, err)
			}
			if ok {
				matched = true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}
	if m.Not != nil {
		ok, err := m.Not.Match(value, present)
		if err != nil {
			return false, fmt.Errorf("not: %w", err)
		}
		if ok {
			return false, nil
		}
	}

	if m.needsNumber() {
		return m.matchNumber(value)
	}
	if m.needsString() {
		return m.matchString(value)
	}
	// Only combinators were present, and they all passed.
	return true, nil
}

func (m *Matcher) needsString() bool {
	return m.Equals != nil || m.NotEquals != nil || len(m.In) > 0 || len(m.NotIn) > 0 ||
		m.Prefix != nil || m.Suffix != nil || m.Contains != nil || m.Regex != nil || m.CIDR != nil
}

func (m *Matcher) needsNumber() bool { return m.GT != nil || m.LT != nil }

func (m *Matcher) checkType(value any) error {
	if m.Type == "" || m.Type == "none" {
		return nil
	}
	ok := false
	switch m.Type {
	case "string":
		_, ok = value.(string)
	case "number":
		_, ok = value.(float64)
	case "bool":
		_, ok = value.(bool)
	case "array":
		_, ok = value.([]any)
	case "object":
		_, ok = value.(map[string]any)
	}
	if !ok {
		return fmt.Errorf("%w: want %s, got %T", ErrTypeMismatch, m.Type, value)
	}
	return nil
}

// matchString applies the string operators, canonicalizing first.
func (m *Matcher) matchString(value any) (bool, error) {
	s, ok := value.(string)
	if !ok {
		if m.Type == "bool" {
			// Type is explicitly "bool" and checkType has already confirmed value
			// really is one, so its canonical two-value string form is exact, not
			// a guess: unlike an array or a float, there is no ambiguous Go
			// representation to worry about here.
			if b, isBool := value.(bool); isBool {
				s, ok = strconv.FormatBool(b), true
			}
		}
	}
	if !ok {
		// Reached even without an explicit type. Stringifying instead would make
		// prefix: /srv/ match the array ["/srv/x"] via its Go representation.
		return false, fmt.Errorf("%w: string operator applied to %T", ErrTypeMismatch, value)
	}

	switch m.Canonicalize {
	case "path":
		canonical, err := canon.Path(s)
		if err != nil {
			// Traversal, a NUL byte, or a relative path all land here and become
			// denials rather than comparisons against the raw string.
			return false, fmt.Errorf("canonicalize path: %w", err)
		}
		s = canonical
	case "url":
		canonical, err := canon.URL(s)
		if err != nil {
			return false, fmt.Errorf("canonicalize url: %w", err)
		}
		s = canonical
	}

	if m.Equals != nil && s != *m.Equals {
		return false, nil
	}
	if m.NotEquals != nil && s == *m.NotEquals {
		return false, nil
	}
	if len(m.In) > 0 && !anyGlob(m.In, s) {
		return false, nil
	}
	if len(m.NotIn) > 0 && anyGlob(m.NotIn, s) {
		return false, nil
	}
	if m.Prefix != nil && !strings.HasPrefix(s, *m.Prefix) {
		return false, nil
	}
	if m.Suffix != nil && !strings.HasSuffix(s, *m.Suffix) {
		return false, nil
	}
	if m.Contains != nil && !strings.Contains(s, *m.Contains) {
		return false, nil
	}
	if m.re != nil && !m.re.MatchString(s) {
		return false, nil
	}
	if m.ipNet != nil {
		ip := net.ParseIP(s)
		if ip == nil {
			return false, fmt.Errorf("%w: cidr matcher needs an IP, got %q", ErrTypeMismatch, s)
		}
		if !m.ipNet.Contains(ip) {
			return false, nil
		}
	}
	return true, nil
}

func (m *Matcher) matchNumber(value any) (bool, error) {
	n, ok := value.(float64)
	if !ok {
		return false, fmt.Errorf("%w: numeric operator applied to %T", ErrTypeMismatch, value)
	}
	if m.GT != nil && !(n > *m.GT) {
		return false, nil
	}
	if m.LT != nil && !(n < *m.LT) {
		return false, nil
	}
	return true, nil
}

func anyGlob(patterns []string, s string) bool {
	for _, p := range patterns {
		if GlobMatch(p, s) {
			return true
		}
	}
	return false
}

// GlobMatch reports whether s matches a pattern containing only "*" wildcards.
//
// Deliberately not path.Match: separators must not be special, because the same
// helper globs tool names and resource URIs, and path.Match would make
// "release/*" behave inconsistently between them. Deliberately not regex either
// — a mistyped regex in an allow rule is an unbounded hole, whereas the worst a
// mistyped glob can do is match too few things.
func GlobMatch(pattern, s string) bool {
	segments := strings.Split(pattern, "*")
	if len(segments) == 1 {
		return pattern == s
	}

	// The first segment must be a prefix.
	if !strings.HasPrefix(s, segments[0]) {
		return false
	}
	s = s[len(segments[0]):]

	// The last segment must be a suffix; everything between must appear in order.
	last := segments[len(segments)-1]
	middle := segments[1 : len(segments)-1]

	for _, seg := range middle {
		if seg == "" {
			continue
		}
		idx := strings.Index(s, seg)
		if idx < 0 {
			return false
		}
		s = s[idx+len(seg):]
	}

	return strings.HasSuffix(s, last)
}
