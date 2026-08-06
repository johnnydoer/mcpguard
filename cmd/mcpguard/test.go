package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/JohnnyDoer/mcpguard/internal/policy"
)

func init() { register("test", testCmd) }

func testCmd(args []string, stdout, stderr io.Writer) int {
	flagSet := flag.NewFlagSet("test", flag.ContinueOnError)
	flagSet.SetOutput(stderr)
	verbose := flagSet.Bool("v", false, "print every case, not just failures")
	flagSet.Usage = func() {
		_, _ = fmt.Fprintf(stderr, "usage: mcpguard test [-v] <path>...\n\n"+
			"Each path is a policy test file or a directory searched recursively for\n"+
			"files named policy-test.yaml. Runs entirely offline.\n\n")
		flagSet.PrintDefaults()
	}
	if err := flagSet.Parse(args); err != nil {
		return 2
	}
	paths := flagSet.Args()
	if len(paths) == 0 {
		flagSet.Usage()
		return 2
	}

	files, err := collectTestFiles(paths)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "mcpguard: %v\n", err)
		return 2
	}
	if len(files) == 0 {
		_, _ = fmt.Fprintf(stderr, "mcpguard: no policy-test.yaml files found in %s\n",
			strings.Join(paths, ", "))
		return 2
	}

	totalPassed, totalFailed := 0, 0
	for _, file := range files {
		passed, failed, err := runOneTestFile(file, *verbose, stdout)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "mcpguard: %s: %v\n", file, err)
			return 2
		}
		totalPassed += passed
		totalFailed += failed
	}

	_, _ = fmt.Fprintf(stdout, "\nTest Summary: %d passed, %d failed\n", totalPassed, totalFailed)
	if totalFailed > 0 {
		return 1
	}
	return 0
}

func runOneTestFile(file string, verbose bool, stdout io.Writer) (int, int, error) {
	pt, err := policy.LoadTestFile(file)
	if err != nil {
		return 0, 0, err
	}
	if pt.Policy == "" {
		return 0, 0, errors.New("test file does not name a policy")
	}

	// The policy path is relative to the test file, so a test directory can be
	// moved without editing every path inside it.
	policyPath := pt.Policy
	if !filepath.IsAbs(policyPath) {
		policyPath = filepath.Join(filepath.Dir(file), policyPath)
	}
	cfg, err := policy.LoadFile(policyPath)
	if err != nil {
		return 0, 0, err
	}
	engine, err := policy.New(cfg)
	if err != nil {
		return 0, 0, err
	}

	report := policy.RunTest(engine, pt)
	_, _ = fmt.Fprintf(stdout, "%s\n", file)
	for _, r := range report.Results {
		switch {
		case !r.Pass:
			_, _ = fmt.Fprintf(stdout, "  FAIL  %s\n        %s\n", r.Case.Name, r.Detail)
		case verbose:
			_, _ = fmt.Fprintf(stdout, "  ok    %s\n", r.Case.Name)
		}
	}
	return report.Passed, report.Failed, nil
}

// collectTestFiles expands directories into the policy-test.yaml files under them.
func collectTestFiles(paths []string) ([]string, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && d.Name() == "policy-test.yaml" {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}
