package policy

import (
	"errors"
	"fmt"
	"net"
	"regexp"
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
