// Package tests wires the declarative YAML test suites in tests/rules/ into
// the standard Go testing framework.  Each *_test.yaml file becomes a sub-test
// of TestRuleSuites.  Suites whose rules_path cannot be resolved on disk are
// skipped automatically (see issue #5).
package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/ruletest"
)

func TestRuleSuites(t *testing.T) {
	entries, err := os.ReadDir("rules")
	if err != nil {
		t.Fatalf("cannot read tests/rules directory: %v", err)
	}

	ran := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		suitePath := filepath.Join("rules", e.Name())
		suiteName := e.Name()
		ran++
		t.Run(suiteName, func(t *testing.T) {
			ruletest.RunSuite(t, suitePath, ruletest.RunnerOptions{})
		})
	}

	if ran == 0 {
		t.Fatal("no *_test.yaml suites found in tests/rules/")
	}
}
