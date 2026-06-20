package ruletest

import (
	"fmt"
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// RunnerOptions controls optional Runner behaviour.
type RunnerOptions struct {
	// RulesDir is a fallback directory used when a suite's rules_path is empty.
	// Ignored when rules_path is set in the YAML file.
	RulesDir string
}

// RunSuite loads a *_test.yaml file, resolves its rules, and runs each
// TestCase as a sub-test under t. Suites whose rules file is missing are
// skipped with a diagnostic message rather than failing — this handles the
// rules_path-outside-repo problem described in issue #5.
func RunSuite(t *testing.T, suitePath string, opts RunnerOptions) {
	t.Helper()

	suite, rulesPath, err := LoadSuite(suitePath)
	if err != nil {
		t.Fatalf("load suite %s: %v", suitePath, err)
	}

	if rulesPath == "" && opts.RulesDir != "" {
		rulesPath = opts.RulesDir
	}

	if rulesPath == "" {
		t.Skipf("suite %q has no rules_path and no RulesDir fallback (see issue #5)", suite.Suite)
		return
	}
	if _, err := os.Stat(rulesPath); os.IsNotExist(err) {
		t.Skipf("rules file %q not found (see issue #5 — rules live outside this repo)", rulesPath)
		return
	}

	rs, err := loadRuleSet(rulesPath)
	if err != nil {
		t.Fatalf("load rules %s: %v", rulesPath, err)
	}
	engine := correlator.NewRuleEngine(rs.Rules)
	if err := engine.CompileErrors(); err != nil {
		t.Fatalf("rule compile errors in %s: %v", rulesPath, err)
	}

	for _, tc := range suite.Tests {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			runTestCase(t, engine, tc)
		})
	}
}

func runTestCase(t *testing.T, engine *correlator.RuleEngine, tc TestCase) {
	t.Helper()

	event, err := tc.Event.Build()
	if err != nil {
		t.Fatalf("build event: %v", err)
	}

	alerts := engine.Evaluate(event)
	defer correlator.ReleaseAlerts(alerts)

	switch tc.Expect {
	case ExpectAlert:
		if len(alerts) == 0 {
			t.Errorf("expected alert but got none (rule_id=%q)", tc.effectiveExpectRuleID())
			return
		}
		assertRuleID(t, alerts, tc.effectiveExpectRuleID())
		assertSeverity(t, alerts, tc.ExpectSeverity)

	case ExpectDrop:
		if len(alerts) == 0 {
			t.Errorf("expected drop-action alert but got none (rule_id=%q)", tc.effectiveExpectRuleID())
			return
		}
		assertRuleID(t, alerts, tc.effectiveExpectRuleID())
		found := false
		for _, a := range alerts {
			if a.Action == "drop" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected action=drop but alerts were: %v", alertIDs(alerts))
		}

	case ExpectNoAlert:
		if len(alerts) > 0 {
			t.Errorf("expected no_alert but rules fired: %v", alertIDs(alerts))
		}

	default:
		t.Errorf("unknown expectation %q (want alert|no_alert|drop)", tc.Expect)
	}
}

func assertRuleID(t *testing.T, alerts []types.Alert, ruleID string) {
	t.Helper()
	if ruleID == "" {
		return
	}
	for _, a := range alerts {
		if a.RuleID == ruleID {
			return
		}
	}
	t.Errorf("rule %q not in fired alerts %v", ruleID, alertIDs(alerts))
}

func assertSeverity(t *testing.T, alerts []types.Alert, want string) {
	t.Helper()
	if want == "" {
		return
	}
	for _, a := range alerts {
		if string(a.Severity) == want {
			return
		}
	}
	t.Errorf("severity %q not found in alerts %v", want, alertIDs(alerts))
}

func alertIDs(alerts []types.Alert) []string {
	ids := make([]string, len(alerts))
	for i, a := range alerts {
		ids[i] = a.RuleID
	}
	return ids
}

func loadRuleSet(path string) (correlator.RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return correlator.RuleSet{}, fmt.Errorf("read %s: %w", path, err)
	}
	var rs correlator.RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return correlator.RuleSet{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return rs, nil
}
