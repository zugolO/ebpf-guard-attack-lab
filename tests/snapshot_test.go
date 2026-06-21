package tests

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/ruletest"
)

var updateSnapshot = flag.Bool("update", false, "update snapshot baseline files")

const (
	corpusPath   = "corpus/events.yaml"
	baselinePath = "corpus/snapshots/baseline.json"
)

type corpusFile struct {
	Events []ruletest.EventSpec `yaml:"events"`
}

type snapshotEntry struct {
	EventIdx int    `json:"event_idx"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
}

// TestSnapshot runs the fixed event corpus through the current rule engine and
// diffs the result against the committed baseline snapshot. Any added or removed
// alert causes the test to fail, making engine/rule regressions visible in CI.
//
// To update the baseline after an intentional rule change:
//
//	go test -run TestSnapshot -update ./tests/...
func TestSnapshot(t *testing.T) {
	rules, err := loadAllRulesFromDir("../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	engine := correlator.NewRuleEngine(rules)
	if err := engine.CompileErrors(); err != nil {
		t.Fatalf("rule compile errors: %v", err)
	}

	corpus, err := loadCorpus(corpusPath)
	if err != nil {
		t.Fatalf("load corpus %s: %v", corpusPath, err)
	}

	current := runCorpus(t, engine, corpus)

	if *updateSnapshot {
		writeBaseline(t, baselinePath, current)
		t.Logf("baseline updated: %s (%d entries)", baselinePath, len(current))
		return
	}

	baseline, err := loadBaseline(baselinePath)
	if err != nil {
		t.Skipf("no baseline snapshot found at %s — run with -update to create one", baselinePath)
		return
	}

	diff := diffSnapshots(baseline, current)
	if len(diff) == 0 {
		t.Logf("snapshot matches baseline (%d entries)", len(baseline))
		return
	}

	t.Errorf("snapshot diff against baseline (%d change(s)):", len(diff))
	for _, d := range diff {
		t.Errorf("  %s", d)
	}
}

func loadCorpus(path string) ([]ruletest.EventSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cf corpusFile
	if err := yaml.Unmarshal(data, &cf); err != nil {
		return nil, err
	}
	return cf.Events, nil
}

func runCorpus(t *testing.T, engine *correlator.RuleEngine, events []ruletest.EventSpec) []snapshotEntry {
	t.Helper()
	var entries []snapshotEntry
	for idx, spec := range events {
		ev, err := spec.Build()
		if err != nil {
			t.Logf("warning: corpus event %d build error: %v", idx, err)
			continue
		}
		alerts := engine.Evaluate(ev)
		for _, a := range alerts {
			entries = append(entries, snapshotEntry{
				EventIdx: idx,
				RuleID:   a.RuleID,
				Severity: string(a.Severity),
			})
		}
		correlator.ReleaseAlerts(alerts)
	}
	sortSnapshot(entries)
	return entries
}

func sortSnapshot(s []snapshotEntry) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].EventIdx != s[j].EventIdx {
			return s[i].EventIdx < s[j].EventIdx
		}
		return s[i].RuleID < s[j].RuleID
	})
}

func writeBaseline(t *testing.T, path string, entries []snapshotEntry) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write baseline %s: %v", path, err)
	}
}

func loadBaseline(path string) ([]snapshotEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entries []snapshotEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// diffSnapshots returns human-readable diff lines for added/removed entries.
func diffSnapshots(baseline, current []snapshotEntry) []string {
	baseMap := make(map[string]bool, len(baseline))
	for _, e := range baseline {
		baseMap[snapshotKey(e)] = true
	}
	curMap := make(map[string]bool, len(current))
	for _, e := range current {
		curMap[snapshotKey(e)] = true
	}

	var diffs []string
	for _, e := range baseline {
		if !curMap[snapshotKey(e)] {
			diffs = append(diffs, "- removed: "+snapshotKey(e))
		}
	}
	for _, e := range current {
		if !baseMap[snapshotKey(e)] {
			diffs = append(diffs, "+ added:   "+snapshotKey(e))
		}
	}
	sort.Strings(diffs)
	return diffs
}

func snapshotKey(e snapshotEntry) string {
	return "event=" + itoa(e.EventIdx) + " rule=" + e.RuleID + " sev=" + e.Severity
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{digits[n%10]}, buf...)
		n /= 10
	}
	return string(buf)
}
