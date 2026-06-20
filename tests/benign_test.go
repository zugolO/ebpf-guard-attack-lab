package tests

// TestBenignCorpus loads every YAML file in tests/benign/, runs each event
// through the full ruleset (all rules/*.yaml merged), counts alerts as
// false positives, and fails if the FP rate exceeds fpBudget.
//
// Run with: go test -run TestBenignCorpus ./tests/...
//
// The budget ensures that adding or modifying rules cannot silently inflate
// the false-positive rate on normal workload traffic.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/ruletest"
)

// fpBudget is the maximum acceptable false-positive rate across the full
// benign corpus. Exceeding this value fails the test.
const fpBudget = 0.001 // 0.1%

// benignCorpus is the YAML schema for a single corpus file in tests/benign/.
type benignCorpus struct {
	Corpus      string             `yaml:"corpus"`
	Description string             `yaml:"description"`
	Events      []ruletest.EventSpec `yaml:"events"`
}

func TestBenignCorpus(t *testing.T) {
	engine := loadAllRulesEngine(t)

	entries, err := os.ReadDir("benign")
	if err != nil {
		t.Fatalf("cannot read tests/benign directory: %v", err)
	}

	var totalEvents, totalAlerts int
	offendingRules := map[string]int{}

	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}

		corpusPath := filepath.Join("benign", e.Name())
		data, err := os.ReadFile(corpusPath)
		if err != nil {
			t.Fatalf("read %s: %v", corpusPath, err)
		}

		var corpus benignCorpus
		if err := yaml.Unmarshal(data, &corpus); err != nil {
			t.Fatalf("parse %s: %v", corpusPath, err)
		}
		if corpus.Corpus == "" {
			corpus.Corpus = strings.TrimSuffix(e.Name(), ".yaml")
		}

		corpusAlerts := 0
		for i, spec := range corpus.Events {
			event, err := spec.Build()
			if err != nil {
				t.Fatalf("%s event[%d]: build: %v", corpus.Corpus, i, err)
			}
			totalEvents++

			alerts := engine.Evaluate(event)
			n := len(alerts)
			for _, a := range alerts {
				offendingRules[a.RuleID]++
			}
			correlator.ReleaseAlerts(alerts)

			totalAlerts += n
			corpusAlerts += n
		}

		t.Logf("corpus %-30s  events=%d  alerts(FP)=%d", corpus.Corpus, len(corpus.Events), corpusAlerts)
	}

	if totalEvents == 0 {
		t.Fatal("no benign events found in tests/benign/ — add corpus YAML files")
	}

	fpRate := float64(totalAlerts) / float64(totalEvents)

	// Sort offending rules for deterministic output.
	type ruleCount struct {
		id    string
		count int
	}
	var sorted []ruleCount
	for id, n := range offendingRules {
		sorted = append(sorted, ruleCount{id, n})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].count != sorted[j].count {
			return sorted[i].count > sorted[j].count
		}
		return sorted[i].id < sorted[j].id
	})

	var offendingStr string
	if len(sorted) > 0 {
		parts := make([]string, len(sorted))
		for i, rc := range sorted {
			parts[i] = fmt.Sprintf("%s(%d)", rc.id, rc.count)
		}
		offendingStr = strings.Join(parts, ", ")
	} else {
		offendingStr = "none"
	}

	t.Logf("BENIGN CORPUS RESULTS")
	t.Logf("  total events:       %d", totalEvents)
	t.Logf("  total alerts fired: %d", totalAlerts)
	t.Logf("  FP rate:            %.4f%%", fpRate*100)
	t.Logf("  FP budget:          %.4f%%", fpBudget*100)
	t.Logf("  Offending rules:    [%s]", offendingStr)

	if fpRate > fpBudget {
		t.Errorf("FP rate %.4f%% exceeds budget %.4f%% — offending rules: [%s]",
			fpRate*100, fpBudget*100, offendingStr)
	}
}

// loadAllRulesEngine reads every *.yaml from rules/ and returns a single
// RuleEngine loaded with the union of all rules.
func loadAllRulesEngine(t *testing.T) *correlator.RuleEngine {
	t.Helper()

	entries, err := os.ReadDir("../rules")
	if err != nil {
		t.Fatalf("cannot read rules directory: %v", err)
	}

	var allRules []correlator.Rule
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		rulePath := filepath.Join("../rules", e.Name())
		data, err := os.ReadFile(rulePath)
		if err != nil {
			t.Fatalf("read rule file %s: %v", rulePath, err)
		}
		var rs correlator.RuleSet
		if err := yaml.Unmarshal(data, &rs); err != nil {
			t.Fatalf("parse rule file %s: %v", rulePath, err)
		}
		allRules = append(allRules, rs.Rules...)
	}

	if len(allRules) == 0 {
		t.Fatal("no rules loaded from rules/ directory")
	}

	engine := correlator.NewRuleEngine(allRules)
	if err := engine.CompileErrors(); err != nil {
		t.Fatalf("rule compile errors: %v", err)
	}
	return engine
}
