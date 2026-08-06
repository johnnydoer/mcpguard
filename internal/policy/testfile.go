package policy

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	testAPIVersion = "mcpguard.dev/v1"
	testKind       = "PolicyTest"
)

// PolicyTest is a declarative set of expectations about a policy.
//
// Tests run entirely offline: no MCP server, no network, no agent. That is a
// direct consequence of the policy package having no I/O, and it is what makes
// running the full suite on every commit practical.
//
// The name stutters as policy.PolicyTest, but it is part of this task's fixed
// public contract, and policy.Test would read as a test of the package itself
// rather than of a loaded policy document.
//
//nolint:revive // see doc comment above.
type PolicyTest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Policy     string `yaml:"policy"`
	Cases      []Case `yaml:"cases"`
}

// Case is one expectation.
type Case struct {
	Name   string         `yaml:"name"`
	Server string         `yaml:"server"`
	Tool   string         `yaml:"tool"`
	Method string         `yaml:"method"`
	Args   map[string]any `yaml:"args"`
	Expect Action         `yaml:"expect"`

	// ExpectRule asserts which rule produced the decision. A pointer because
	// three states are meaningful: unset means "do not check", "" means "assert
	// that no rule matched and the default applied", and a name asserts that
	// rule. The middle state is what distinguishes a deliberate default-deny
	// from a rule that happened to fire.
	ExpectRule *string `yaml:"expect_rule"`
}

// CaseResult is the outcome of evaluating one Case against an Engine.
type CaseResult struct {
	Case      Case
	Pass      bool
	GotAction Action
	GotRule   string
	Detail    string
}

// Report is the outcome of running every Case in a PolicyTest.
type Report struct {
	Results []CaseResult
	Passed  int
	Failed  int
}

// OK reports whether every case passed.
func (r Report) OK() bool { return r.Failed == 0 }

// LoadTestFile reads a policy test file.
func LoadTestFile(path string) (*PolicyTest, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is an operator-supplied test file location, not user input, matching the LoadFile rationale in config.go.
	if err != nil {
		return nil, fmt.Errorf("policy: open test %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	return LoadTest(f)
}

// LoadTest parses and validates a policy test.
func LoadTest(r io.Reader) (*PolicyTest, error) {
	dec := yaml.NewDecoder(r)
	// A typo'd field would silently drop an assertion, leaving a test that
	// passes because it checks nothing.
	dec.KnownFields(true)

	var pt PolicyTest
	if err := dec.Decode(&pt); err != nil {
		return nil, fmt.Errorf("policy: parse test: %w", err)
	}

	if pt.APIVersion != testAPIVersion {
		return nil, fmt.Errorf("policy: test apiVersion %q, want %q", pt.APIVersion, testAPIVersion)
	}
	if pt.Kind != testKind {
		return nil, fmt.Errorf("policy: test kind %q, want %q", pt.Kind, testKind)
	}
	for i, c := range pt.Cases {
		if c.Name == "" {
			return nil, fmt.Errorf("policy: test cases[%d] has no name", i)
		}
		if !c.Expect.valid() {
			return nil, fmt.Errorf("policy: test case %q has invalid or missing expect %q",
				c.Name, c.Expect)
		}
	}
	return &pt, nil
}

// RunTest evaluates every case and reports the outcome.
func RunTest(e *Engine, pt *PolicyTest) Report {
	report := Report{Results: make([]CaseResult, 0, len(pt.Cases))}

	for _, c := range pt.Cases {
		method := c.Method
		if method == "" {
			method = "tools/call"
		}
		d := e.Evaluate(Request{
			Server: c.Server, Method: method, Tool: c.Tool, Args: c.Args,
		})

		result := CaseResult{Case: c, GotAction: d.Action, GotRule: d.Rule, Pass: true}

		switch {
		case d.Action != c.Expect:
			result.Pass = false
			result.Detail = fmt.Sprintf("action = %s, want %s (reason: %s)",
				d.Action, c.Expect, d.Reason)
		case c.ExpectRule != nil && d.Rule != *c.ExpectRule:
			want := *c.ExpectRule
			if want == "" {
				want = "<no rule; defaults applied>"
			}
			got := d.Rule
			if got == "" {
				got = "<no rule; defaults applied>"
			}
			result.Pass = false
			// The action was right but the reason was not, which is the failure
			// mode expect_rule exists to catch.
			result.Detail = fmt.Sprintf("action %s is correct but rule = %s, want %s",
				d.Action, got, want)
		}

		if result.Pass {
			report.Passed++
		} else {
			report.Failed++
		}
		report.Results = append(report.Results, result)
	}
	return report
}
