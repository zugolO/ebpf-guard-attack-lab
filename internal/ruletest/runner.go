package ruletest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

	for _, ct := range suite.Chains {
		ct := ct
		t.Run(ct.Name, func(t *testing.T) {
			runChainTest(t, engine, ct)
		})
	}

	for _, tt := range suite.ThrottleTests {
		tt := tt
		t.Run(tt.Name, func(t *testing.T) {
			runThrottleTest(t, engine, tt)
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

	// Expand each mutant as a sub-test.
	for _, m := range tc.Mutants {
		m := m
		t.Run("mutant:"+m.Description, func(t *testing.T) {
			runMutant(t, engine, tc, m)
		})
	}
}

// runMutant applies a patch to the base test case event and asserts the outcome.
// When m.KnownBypass is true, Expect records the bypass outcome itself (usually
// no_alert); a mismatch means the gap was closed and fails as a stale flag.
func runMutant(t *testing.T, engine *correlator.RuleEngine, base TestCase, m MutantSpec) {
	t.Helper()

	patched, err := applyMutantPatch(base.Event, m.Patch)
	if err != nil {
		t.Fatalf("apply mutant patch: %v", err)
	}

	event, err := patched.Build()
	if err != nil {
		t.Fatalf("build mutant event: %v", err)
	}

	alerts := engine.Evaluate(event)
	defer correlator.ReleaseAlerts(alerts)

	expect := m.Expect
	if expect == "" {
		expect = base.Expect
	}

	fail := t.Errorf
	if m.KnownBypass {
		// The mutant encodes the bypass outcome, so a mismatch means the gap
		// was closed. Fail loudly so the stale known_bypass flag is removed and
		// the expectation flipped, instead of silently keeping an outdated record.
		fail = func(format string, args ...any) {
			t.Errorf("stale known_bypass (gap appears closed — drop the flag and flip expect): "+format, args...)
		}
	}

	switch expect {
	case ExpectAlert:
		if len(alerts) == 0 {
			fail("mutant %q: expected alert but got none — evasion bypass (rule_id=%q)", m.Description, base.effectiveExpectRuleID())
		}
	case ExpectNoAlert:
		if len(alerts) > 0 {
			fail("mutant %q: expected no_alert but rules fired: %v", m.Description, alertIDs(alerts))
		}
	case ExpectDrop:
		if len(alerts) == 0 {
			fail("mutant %q: expected drop-action alert but got none", m.Description)
		} else {
			found := false
			for _, a := range alerts {
				if a.Action == "drop" {
					found = true
					break
				}
			}
			if !found {
				fail("mutant %q: expected action=drop but alerts were: %v", m.Description, alertIDs(alerts))
			}
		}
	default:
		t.Errorf("mutant %q: unknown expectation %q (want alert|no_alert|drop)", m.Description, expect)
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

// runChainTest injects each step's event in order and asserts the aggregate
// outcome according to ct.ExpectChain.
func runChainTest(t *testing.T, engine *correlator.RuleEngine, ct ChainTest) {
	t.Helper()

	if len(ct.Chain) == 0 {
		t.Errorf("chain test %q has no steps", ct.Name)
		return
	}

	type stepResult struct {
		stepIdx int
		alerts  []types.Alert
	}
	results := make([]stepResult, 0, len(ct.Chain))

	for i, step := range ct.Chain {
		event, err := step.Event.Build()
		if err != nil {
			t.Fatalf("chain step %d build event: %v", i, err)
		}
		alerts := engine.Evaluate(event)
		// Copy alerts before releasing the slice — we need them for assertions.
		copied := make([]types.Alert, len(alerts))
		copy(copied, alerts)
		correlator.ReleaseAlerts(alerts)
		results = append(results, stepResult{stepIdx: i, alerts: copied})
	}

	switch ct.ExpectChain {
	case "all_fire":
		for i, res := range results {
			step := ct.Chain[i]
			if len(res.alerts) == 0 {
				label := step.Name
				if label == "" {
					label = fmt.Sprintf("step %d", i)
				}
				t.Errorf("chain %q: expected alert at %s but got none", ct.Name, label)
				continue
			}
			if step.RuleID != "" {
				found := false
				for _, a := range res.alerts {
					if a.RuleID == step.RuleID {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("chain %q step %d: rule %q not in fired alerts %v",
						ct.Name, i, step.RuleID, alertIDs(res.alerts))
				}
			}
		}

	case "any_fire":
		anyFired := false
		for _, res := range results {
			if len(res.alerts) > 0 {
				anyFired = true
				break
			}
		}
		if !anyFired {
			t.Errorf("chain %q: expected at least one step to fire but none did", ct.Name)
		}

	case "none_fire":
		for i, res := range results {
			if len(res.alerts) > 0 {
				step := ct.Chain[i]
				label := step.Name
				if label == "" {
					label = fmt.Sprintf("step %d", i)
				}
				t.Errorf("chain %q: expected no alert at %s but rules fired: %v",
					ct.Name, label, alertIDs(res.alerts))
			}
		}

	default:
		t.Errorf("chain %q: unknown expect_chain value %q (want all_fire|any_fire|none_fire)",
			ct.Name, ct.ExpectChain)
	}
}

// runThrottleTest injects the same event Repeat times and verifies that the
// first ExpectFirstN iterations each produce an alert and the remainder match
// ExpectRemaining.
func runThrottleTest(t *testing.T, engine *correlator.RuleEngine, tt ThrottleTest) {
	t.Helper()

	if tt.Repeat <= 0 {
		t.Errorf("throttle test %q: repeat must be > 0, got %d", tt.Name, tt.Repeat)
		return
	}
	if tt.ExpectFirstN < 0 || tt.ExpectFirstN > tt.Repeat {
		t.Errorf("throttle test %q: expect_first_n=%d must be in [0, repeat=%d]",
			tt.Name, tt.ExpectFirstN, tt.Repeat)
		return
	}

	remaining := tt.ExpectRemaining
	if remaining == "" {
		remaining = ExpectNoAlert
	}

	event, err := tt.Event.Build()
	if err != nil {
		t.Fatalf("throttle test %q: build event: %v", tt.Name, err)
	}

	for i := 0; i < tt.Repeat; i++ {
		alerts := engine.Evaluate(event)
		copied := make([]types.Alert, len(alerts))
		copy(copied, alerts)
		correlator.ReleaseAlerts(alerts)

		if i < tt.ExpectFirstN {
			// Must fire.
			if len(copied) == 0 {
				t.Errorf("throttle test %q: iteration %d/%d expected alert but got none",
					tt.Name, i+1, tt.Repeat)
				continue
			}
			if tt.RuleID != "" {
				assertRuleID(t, copied, tt.RuleID)
			}
		} else {
			// Must match ExpectRemaining.
			switch remaining {
			case ExpectNoAlert:
				if len(copied) > 0 {
					t.Errorf("throttle test %q: iteration %d/%d expected no_alert but rules fired: %v",
						tt.Name, i+1, tt.Repeat, alertIDs(copied))
				}
			case ExpectAlert:
				if len(copied) == 0 {
					t.Errorf("throttle test %q: iteration %d/%d expected alert but got none",
						tt.Name, i+1, tt.Repeat)
				}
			}
		}
	}
}

// loadRuleSet loads the rules referenced by path. It honours the documented
// Suite.RulesPath contract ("rule file or directory"): a regular file is parsed
// directly, while a directory contributes every *.yaml file inside it, merged in
// deterministic sorted order. Directory loading lets a single suite build
// cross-category chains from rules/ without duplicating rule definitions.
func loadRuleSet(path string) (correlator.RuleSet, error) {
	info, err := os.Stat(path)
	if err != nil {
		return correlator.RuleSet{}, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.IsDir() {
		return loadRuleFile(path)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return correlator.RuleSet{}, fmt.Errorf("read dir %s: %w", path, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names) // deterministic merge order across runs

	var merged correlator.RuleSet
	for _, name := range names {
		rs, err := loadRuleFile(filepath.Join(path, name))
		if err != nil {
			return correlator.RuleSet{}, err
		}
		merged.Rules = append(merged.Rules, rs.Rules...)
	}
	return merged, nil
}

// loadRuleFile parses a single rule YAML file.
func loadRuleFile(path string) (correlator.RuleSet, error) {
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
