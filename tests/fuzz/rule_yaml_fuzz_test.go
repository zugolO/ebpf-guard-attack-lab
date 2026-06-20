// Package fuzz contains Go fuzz targets for the ebpf-guard rule engine parsers.
// Run a target with: go test -fuzz=FuzzRuleSetYAML ./tests/fuzz/
package fuzz

import (
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/ruletest"
)

// FuzzRuleSetYAML feeds arbitrary bytes into the RuleSet YAML parser and then
// into NewRuleEngine. The goal is to ensure neither the YAML unmarshaler nor
// the rule compiler panics on malformed or adversarial input.
func FuzzRuleSetYAML(f *testing.F) {
	f.Add([]byte(`rules: []`))
	f.Add([]byte(`rules:
  - id: fuzz_seed
    event_type: 3
    condition:
      field: comm
      op: in
      values: [bash, sh]
    severity: warning
    action: alert`))
	f.Add([]byte(`rules:
  - id: fuzz_group
    event_type: 1
    condition_group:
      operator: and
      conditions:
        - field: nr
          op: equals
          values: ["59"]
        - field: comm
          op: not_in
          values: [safe]
    severity: critical
    action: alert`))
	f.Add([]byte(`rules:
  - id: fuzz_regex
    event_type: 3
    condition:
      field: filename
      op: regex
      values: ["^/etc/.*\\.conf$"]
    severity: warning
    action: alert`))
	f.Add([]byte(`rules:
  - id: fuzz_cidr
    event_type: 2
    condition:
      field: daddr
      op: in_cidr
      values: ["10.0.0.0/8"]
    severity: warning
    action: alert`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var rs correlator.RuleSet
		if err := yaml.Unmarshal(data, &rs); err != nil {
			return // invalid YAML is not a bug
		}
		engine := correlator.NewRuleEngine(rs.Rules)
		// CompileErrors may return an error for bad regex/CIDR — that is fine.
		_ = engine.CompileErrors()
	})
}

// FuzzSuiteYAML feeds arbitrary bytes into the ruletest suite YAML loader,
// exercising the full Suite/TestCase/EventSpec unmarshal path.
func FuzzSuiteYAML(f *testing.F) {
	f.Add([]byte(`suite: fuzz
tests: []`))
	f.Add([]byte(`suite: fuzz
rules_path: ""
tests:
  - name: "seed"
    event:
      type: file
      comm: bash
      file:
        filename: /etc/passwd
        op: read
    expect: no_alert`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var suite ruletest.Suite
		// Unmarshal must not panic on arbitrary input.
		_ = yaml.Unmarshal(data, &suite)
	})
}
