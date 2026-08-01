// Package policy loads, validates, and evaluates mcpguard's authorization rules.
//
// This package performs no I/O beyond reading from an io.Reader handed to it, and
// depends on nothing outside the standard library except gopkg.in/yaml.v3. That
// constraint is deliberate: it is the component that makes authorization
// decisions, so it must stay small enough to audit by reading, and a supply chain
// compromise here would be the worst possible place for one.
package policy

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Action is what a rule decides.
type Action string

// The set of valid Action values.
const (
	ActionAllow   Action = "allow"
	ActionDeny    Action = "deny"
	ActionApprove Action = "approve"
)

func (a Action) valid() bool {
	switch a {
	case ActionAllow, ActionDeny, ActionApprove:
		return true
	default:
		return false
	}
}

// Mode selects whether decisions are enforced or only recorded.
type Mode string

// The set of valid Mode values.
const (
	ModeEnforce Mode = "enforce"
	ModeAudit   Mode = "audit"
)

// AuditOnError selects behaviour when the audit log cannot be written.
type AuditOnError string

// The set of valid AuditOnError values.
const (
	OnErrorHalt     AuditOnError = "halt"
	OnErrorDeny     AuditOnError = "deny"
	OnErrorContinue AuditOnError = "continue"
)

// DefaultApprovalTimeout is deliberately shorter than a typical MCP client's
// own request timeout. A longer window surfaces as a hang rather than a denial.
const DefaultApprovalTimeout = 120 * time.Second

// Config is the top-level policy document.
type Config struct {
	Version  string         `yaml:"version"`
	Mode     Mode           `yaml:"mode"`
	Defaults Defaults       `yaml:"defaults"`
	Audit    AuditConfig    `yaml:"audit"`
	Approval ApprovalConfig `yaml:"approval"`
	Servers  []Server       `yaml:"servers"`
	Rules    []Rule         `yaml:"rules"`
}

// Defaults are the fallback actions applied when a rule does not specify one.
type Defaults struct {
	Action         Action `yaml:"action"`
	AdditionalArgs Action `yaml:"additional_args"`
}

// AuditConfig configures the audit log.
type AuditConfig struct {
	Path    string       `yaml:"path"`
	OnError AuditOnError `yaml:"on_error"`
	Redact  []string     `yaml:"redact"`
}

// ApprovalConfig configures out-of-band human approval for approve-action rules.
type ApprovalConfig struct {
	Channel   string        `yaml:"channel"`
	URL       string        `yaml:"url"`
	Topic     string        `yaml:"topic"`
	Timeout   time.Duration `yaml:"timeout"`
	OnTimeout Action        `yaml:"on_timeout"`
}

// Server is one upstream MCP server this proxy fronts.
type Server struct {
	Name      string   `yaml:"name"`
	Transport string   `yaml:"transport"`
	Command   []string `yaml:"command"`
	URL       string   `yaml:"url"`
}

// Rule is one ordered entry in the policy. Evaluation is first-match-wins.
type Rule struct {
	Name    string   `yaml:"name"`
	Servers []string `yaml:"servers"`
	Tools   []string `yaml:"tools"`
	Match   *Match   `yaml:"match"`
	Action  Action   `yaml:"action"`
	Message string   `yaml:"message"`

	// AdditionalArgs overrides Defaults.AdditionalArgs for this rule. A pointer
	// so "unset" is distinguishable from an explicit value.
	AdditionalArgs *Action `yaml:"additional_args"`
}

// Match constrains a rule to tool calls whose arguments satisfy every named matcher.
type Match struct {
	Args map[string]Matcher `yaml:"args"`
}

// ServerNames returns the configured server names in declaration order.
func (c *Config) ServerNames() []string {
	names := make([]string, 0, len(c.Servers))
	for _, s := range c.Servers {
		names = append(names, s.Name)
	}
	return names
}

// ServerByName returns the named server, or false if it is not configured.
func (c *Config) ServerByName(name string) (Server, bool) {
	for _, s := range c.Servers {
		if s.Name == name {
			return s, true
		}
	}
	return Server{}, false
}

// LoadFile reads and validates a policy file.
func LoadFile(path string) (*Config, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is an operator-supplied config location, not user input, matching the G204 rationale in .golangci.yml.
	if err != nil {
		return nil, fmt.Errorf("policy: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return Load(f)
}

// Load reads and validates a policy from r.
func Load(r io.Reader) (*Config, error) {
	dec := yaml.NewDecoder(r)
	// A typo'd key must be an error rather than silently ignored. "acton: allow"
	// that loads as a zero Action and then falls back to a default is exactly the
	// class of bug this prevents.
	dec.KnownFields(true)

	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("policy: parse: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applyDefaults fills unset fields. Every default is the safe value: an omitted
// field can never widen access.
func (c *Config) applyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeEnforce
	}
	if c.Defaults.Action == "" {
		c.Defaults.Action = ActionDeny
	}
	if c.Defaults.AdditionalArgs == "" {
		c.Defaults.AdditionalArgs = ActionDeny
	}
	if c.Audit.OnError == "" {
		c.Audit.OnError = OnErrorDeny
	}
	if c.Approval.Timeout == 0 {
		c.Approval.Timeout = DefaultApprovalTimeout
	}
	if c.Approval.OnTimeout == "" {
		c.Approval.OnTimeout = ActionDeny
	}
}

func (c *Config) validate() error {
	if c.Version != "v1" {
		return fmt.Errorf("policy: unsupported version %q, want v1", c.Version)
	}
	if c.Mode != ModeEnforce && c.Mode != ModeAudit {
		return fmt.Errorf("policy: invalid mode %q, want enforce or audit", c.Mode)
	}
	if !c.Defaults.Action.valid() {
		return fmt.Errorf("policy: invalid defaults.action %q", c.Defaults.Action)
	}
	if c.Defaults.AdditionalArgs != ActionAllow && c.Defaults.AdditionalArgs != ActionDeny {
		return fmt.Errorf("policy: defaults.additional_args must be allow or deny, got %q",
			c.Defaults.AdditionalArgs)
	}
	switch c.Audit.OnError {
	case OnErrorHalt, OnErrorDeny, OnErrorContinue:
	default:
		return fmt.Errorf("policy: invalid audit.on_error %q", c.Audit.OnError)
	}
	if c.Approval.OnTimeout == ActionAllow {
		// An unanswered high-risk call must never proceed. There is no
		// configuration in which this is defensible, so it is rejected rather
		// than warned about.
		return errors.New("policy: approval.on_timeout must not be allow")
	}
	if !c.Approval.OnTimeout.valid() {
		return fmt.Errorf("policy: invalid approval.on_timeout %q", c.Approval.OnTimeout)
	}

	if err := c.validateServers(); err != nil {
		return err
	}
	return c.validateRules()
}

func (c *Config) validateServers() error {
	seen := map[string]bool{}
	for i, s := range c.Servers {
		if s.Name == "" {
			return fmt.Errorf("policy: servers[%d] has no name", i)
		}
		if seen[s.Name] {
			return fmt.Errorf("policy: duplicate server name %q", s.Name)
		}
		seen[s.Name] = true

		switch s.Transport {
		case "stdio":
			if len(s.Command) == 0 {
				return fmt.Errorf("policy: server %q uses stdio and needs a command", s.Name)
			}
		case "http":
			if s.URL == "" {
				return fmt.Errorf("policy: server %q uses http and needs a url", s.Name)
			}
		default:
			return fmt.Errorf("policy: server %q has invalid transport %q, want stdio or http",
				s.Name, s.Transport)
		}
	}
	return nil
}

func (c *Config) validateRules() error {
	known := map[string]bool{}
	for _, s := range c.Servers {
		known[s.Name] = true
	}

	seen := map[string]bool{}
	for i, r := range c.Rules {
		if r.Name == "" {
			return fmt.Errorf("policy: rules[%d] has no name; names appear in audit "+
				"logs and deny messages and must be unique", i)
		}
		if seen[r.Name] {
			return fmt.Errorf("policy: duplicate rule name %q", r.Name)
		}
		seen[r.Name] = true

		if !r.Action.valid() {
			return fmt.Errorf("policy: rule %q has invalid action %q", r.Name, r.Action)
		}
		if len(r.Tools) == 0 {
			return fmt.Errorf("policy: rule %q has no tools; use [\"*\"] to match all "+
				"tools rather than leaving it empty", r.Name)
		}
		for _, name := range r.Servers {
			if !known[name] {
				return fmt.Errorf("policy: rule %q references unknown server %q", r.Name, name)
			}
		}
		if r.AdditionalArgs != nil &&
			*r.AdditionalArgs != ActionAllow && *r.AdditionalArgs != ActionDeny {
			return fmt.Errorf("policy: rule %q additional_args must be allow or deny, got %q",
				r.Name, *r.AdditionalArgs)
		}
		if r.Match != nil {
			for arg, m := range r.Match.Args {
				if err := m.compile(); err != nil {
					return fmt.Errorf("policy: rule %q arg %q: %w", r.Name, arg, err)
				}
				// range over a map[string]Matcher yields a copy of the value; the
				// compiled regexp/CIDR state on m must be written back into the map
				// or it is silently discarded and Task 9's matching sees a nil re.
				r.Match.Args[arg] = m
			}
		}
	}
	return nil
}

// compileRegex is used by Matcher.compile; declared here so config validation
// and matching share one implementation.
func compileRegex(pattern string) (*regexp.Regexp, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("regex %q does not compile: %w", pattern, err)
	}
	return re, nil
}
