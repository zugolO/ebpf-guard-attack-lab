package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/ruletest"
)

// allKnownOperators is the full set of operators supported by the rule engine.
var allKnownOperators = []string{
	"in", "not_in", "equals", "not_equals",
	"prefix", "not_prefix", "suffix", "not_suffix",
	"contains", "regex", "gt", "lt", "gte", "lte",
	"in_cidr", "not_in_cidr", "caps_gained", "caps_dropped",
}

type deadTestRef struct {
	file   string
	name   string
	ruleID string
}

// TestCoverageMatrix reports per-rule and per-operator test coverage and fails
// CI when any test references a rule_id that does not exist in the loaded rules
// (dead-test detection).
func TestCoverageMatrix(t *testing.T) {
	allRules, err := loadAllRulesFromDir("../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	if len(allRules) == 0 {
		t.Fatal("no rules loaded from ../rules")
	}

	ruleByID := make(map[string]correlator.Rule, len(allRules))
	for _, r := range allRules {
		ruleByID[r.ID] = r
	}

	// Load all test suites from tests/rules/.
	suiteEntries, err := os.ReadDir("rules")
	if err != nil {
		t.Fatalf("read tests/rules dir: %v", err)
	}

	positiveRules := make(map[string]bool) // rule_id → has ≥1 positive test
	negativeRules := make(map[string]bool) // rule_id → has ≥1 negative test
	var deadTests []deadTestRef

	for _, e := range suiteEntries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		suitePath := filepath.Join("rules", e.Name())
		suite, _, err := ruletest.LoadSuite(suitePath)
		if err != nil {
			t.Logf("warning: load suite %s: %v", suitePath, err)
			continue
		}

		for _, tc := range suite.Tests {
			id := tc.ExpectRuleID
			if id == "" {
				id = tc.RuleID
			}
			if id == "" {
				continue
			}
			if _, ok := ruleByID[id]; !ok {
				deadTests = append(deadTests, deadTestRef{file: e.Name(), name: tc.Name, ruleID: id})
				continue
			}
			switch tc.Expect {
			case ruletest.ExpectAlert, ruletest.ExpectDrop:
				positiveRules[id] = true
			case ruletest.ExpectNoAlert:
				negativeRules[id] = true
			}
		}

		for _, ct := range suite.Chains {
			for _, step := range ct.Chain {
				if step.RuleID == "" {
					continue
				}
				if _, ok := ruleByID[step.RuleID]; !ok {
					label := step.Name
					if label == "" {
						label = ct.Name
					}
					deadTests = append(deadTests, deadTestRef{file: e.Name(), name: label, ruleID: step.RuleID})
				} else {
					// Chain steps that name a rule count as positive coverage when
					// the chain expects all_fire, and negative when it expects none_fire.
					switch ct.ExpectChain {
					case "all_fire", "any_fire":
						positiveRules[step.RuleID] = true
					case "none_fire":
						negativeRules[step.RuleID] = true
					}
				}
			}
		}
	}

	// Dead tests fail CI — a rule_id that doesn't exist silently passes no_alert
	// checks, hiding the fact that the referenced rule was removed or renamed.
	for _, dt := range deadTests {
		t.Errorf("DEAD TEST in %s %q: rule_id %q not found in any rule file",
			dt.file, dt.name, dt.ruleID)
	}

	// Categorise rules by coverage level (warnings only — do not fail CI).
	var noTests, noPositive, noNegative []string
	for id := range ruleByID {
		hasPos := positiveRules[id]
		hasNeg := negativeRules[id]
		switch {
		case !hasPos && !hasNeg:
			noTests = append(noTests, id)
		case !hasPos:
			noPositive = append(noPositive, id)
		case !hasNeg:
			noNegative = append(noNegative, id)
		}
	}
	sort.Strings(noTests)
	sort.Strings(noPositive)
	sort.Strings(noNegative)

	// Operator coverage: an operator is "exercised" if it appears in the
	// conditions of at least one rule that has a positive test.
	exercised := make(map[string]bool, len(allKnownOperators))
	for id := range positiveRules {
		r := ruleByID[id]
		for _, op := range collectRuleOperators(r) {
			exercised[op] = true
		}
	}

	// ── Report ───────────────────────────────────────────────────────────────
	t.Logf("RULE COVERAGE REPORT")
	t.Logf("  rules loaded:                  %d", len(allRules))
	t.Logf("  rules with ≥1 positive test:  %d  (%.1f%%)",
		len(positiveRules), pct(len(positiveRules), len(allRules)))
	t.Logf("  rules with ≥1 negative test:  %d  (%.1f%%)",
		len(negativeRules), pct(len(negativeRules), len(allRules)))

	if len(noTests) > 0 {
		t.Logf("  rules with NO tests at all:    %d  ← WARN", len(noTests))
		for _, id := range noTests {
			t.Logf("    - %s", id)
		}
	}
	if len(noPositive) > 0 {
		t.Logf("  rules with no positive test:   %d  ← WARN", len(noPositive))
		for _, id := range noPositive {
			t.Logf("    - %s", id)
		}
	}
	if len(noNegative) > 0 {
		t.Logf("  rules with no negative test:   %d  ← WARN", len(noNegative))
		for _, id := range noNegative {
			t.Logf("    - %s", id)
		}
	}

	t.Logf("")
	t.Logf("OPERATOR COVERAGE")
	for _, op := range allKnownOperators {
		if exercised[op] {
			t.Logf("  %-16s exercised ✓", op+":")
		} else {
			t.Logf("  %-16s NOT exercised ✗", op+":")
		}
	}

	if len(deadTests) > 0 {
		t.Logf("")
		t.Logf("DEAD TESTS (rule_id not found in loaded rules)")
		for _, dt := range deadTests {
			t.Logf("  %s  %q  rule_id: %s", dt.file, dt.name, dt.ruleID)
		}
	}
}

func pct(n, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100.0 * float64(n) / float64(total)
}

// loadAllRulesFromDir reads every *.yaml file in dir and returns the union of
// their rule sets. Used by coverage, snapshot, and replay tests.
func loadAllRulesFromDir(dir string) ([]correlator.Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}
	var rules []correlator.Rule
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var rs correlator.RuleSet
		if err := yaml.Unmarshal(data, &rs); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		rules = append(rules, rs.Rules...)
	}
	return rules, nil
}

// collectRuleOperators returns all operator strings used in a rule's conditions.
func collectRuleOperators(r correlator.Rule) []string {
	if r.ConditionGroup != nil {
		return collectGroupOperators(r.ConditionGroup)
	}
	if r.Condition.Op != "" {
		return []string{string(r.Condition.Op)}
	}
	return nil
}

func collectGroupOperators(g *correlator.RuleConditionGroup) []string {
	if g == nil {
		return nil
	}
	var ops []string
	for _, c := range g.Conditions {
		if c.Op != "" {
			ops = append(ops, string(c.Op))
		}
	}
	for i := range g.SubGroups {
		ops = append(ops, collectGroupOperators(&g.SubGroups[i])...)
	}
	return ops
}
