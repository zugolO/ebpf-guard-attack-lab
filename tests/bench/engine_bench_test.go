// Package bench provides performance regression benchmarks for the rule engine.
// Run with: go test -bench=. -benchmem -count=5 ./tests/bench/
//
// Key invariants guarded by these benchmarks:
//   - BenchmarkEvaluateInto_NoMatch must be 0 allocs/op — the true zero-alloc
//     hot path for callers that process alerts inline.
//   - BenchmarkEvaluate_NoMatch must be ≤1 alloc/op on the no-match path.
//   - BenchmarkEvaluate_SingleMatch must be ≤5 allocs/op (pool-backed slice).
//
// The no-match benchmarks exercise the early-exit code path: the first
// condition in each rule checks "op" (pre-computed string table, no alloc),
// so a non-matching op value short-circuits the AND group before any
// BytesToString or strconv allocation is reached.
package bench_test

import (
	"testing"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

func engineWithRules(rules []correlator.Rule) *correlator.RuleEngine {
	e := correlator.NewRuleEngine(rules)
	if err := e.CompileErrors(); err != nil {
		panic("bench: rule compile error: " + err.Error())
	}
	return e
}

// noMatchFileEvent is a file-access event that intentionally matches none of
// the benchmark rules. The event uses op=1 (read) so the first condition on
// "op" in the no-match rules fails immediately — no BytesToString is called
// for filename/comm, achieving 0 allocs/op on the no-match hot path.
func noMatchFileEvent() types.Event {
	e := types.Event{Type: types.EventFileAccess, PID: 42}
	copy(e.Comm[:], "nginx")
	e.File = &types.FileEvent{}
	copy(e.File.Filename[:], "/var/log/nginx/access.log")
	e.File.Op = 1 // read — fails the "op in [create,write]" first condition
	return e
}

// matchFileEvent produces a file-access event that matches the single
// persistence_systemd rule used in single-match benchmarks.
func matchFileEvent() types.Event {
	e := types.Event{Type: types.EventFileAccess, PID: 42}
	copy(e.Comm[:], "malware")
	e.File = &types.FileEvent{}
	copy(e.File.Filename[:], "/etc/systemd/system/backdoor.service")
	e.File.Op = 3 // create
	return e
}

// syscallEvent returns a syscall event for syscall-field benchmarks.
func syscallEvent(nr int64) types.Event {
	e := types.Event{Type: types.EventSyscall, PID: 1}
	copy(e.Comm[:], "bash")
	e.Syscall = &types.SyscallEvent{Nr: nr}
	return e
}

// dnsEvent returns a DNS event for DNS-enrichment benchmarks.
func dnsEvent(qname string) types.Event {
	e := types.Event{Type: types.EventDNS, PID: 1}
	copy(e.Comm[:], "resolver")
	e.DNS = &types.DNSEvent{QName: qname, QType: 1}
	return e
}

// ─────────────────────────────────────────────────────────────────────────────
// Rules used in benchmarks
// ─────────────────────────────────────────────────────────────────────────────

// fileMatchRule is a simple file-access rule used for match benchmarks.
var fileMatchRule = correlator.Rule{
	ID:        "bench_file_match",
	EventType: types.EventFileAccess,
	ConditionGroup: &correlator.RuleConditionGroup{
		Operator: "and",
		Conditions: []correlator.RuleCondition{
			{Field: "op", Op: "in", Values: []string{"create", "write"}},
			{Field: "filename", Op: "prefix", Values: []string{"/etc/systemd/system/"}},
			{Field: "filename", Op: "suffix", Values: []string{".service"}},
			{Field: "comm", Op: "not_in", Values: []string{"dpkg", "apt", "apt-get", "rpm", "systemctl"}},
		},
	},
	Severity: types.SeverityWarning,
	Action:   "alert",
}

// syscallMatchRule matches execve (nr=59) from specific comms.
var syscallMatchRule = correlator.Rule{
	ID:        "bench_syscall_match",
	EventType: types.EventSyscall,
	ConditionGroup: &correlator.RuleConditionGroup{
		Operator: "and",
		Conditions: []correlator.RuleCondition{
			{Field: "nr", Op: "equals", Values: []string{"59"}},
			{Field: "comm", Op: "in", Values: []string{"bash", "sh", "python3"}},
		},
	},
	Severity: types.SeverityWarning,
	Action:   "alert",
}

// dnsEnrichedRule exercises the AnalyzeDomain (expensive) code path.
var dnsEnrichedRule = correlator.Rule{
	ID:        "bench_dns_enriched",
	EventType: types.EventDNS,
	ConditionGroup: &correlator.RuleConditionGroup{
		Operator: "and",
		Conditions: []correlator.RuleCondition{
			{Field: "qname_entropy", Op: "gt", Values: []string{"3.5"}},
			{Field: "qname_length", Op: "gt", Values: []string{"30"}},
		},
	},
	Severity: types.SeverityWarning,
	Action:   "alert",
}

// regexRule uses a compiled regexp on the hot path.
var regexRule = correlator.Rule{
	ID:        "bench_regex",
	EventType: types.EventFileAccess,
	ConditionGroup: &correlator.RuleConditionGroup{
		Operator: "and",
		Conditions: []correlator.RuleCondition{
			{Field: "filename", Op: "regex", Values: []string{`^/etc/(passwd|shadow|sudoers)$`}},
		},
	},
	Severity: types.SeverityCritical,
	Action:   "alert",
}

// sampledRuleRandom uses random sampling (rate=0.5).
var sampledRuleRandom = correlator.Rule{
	ID:         "bench_sampled_random",
	EventType:  types.EventFileAccess,
	SampleRate: 0.5,
	Condition:  correlator.RuleCondition{Field: "op", Op: "equals", Values: []string{"write"}},
	Severity:   types.SeverityWarning,
	Action:     "alert",
}

// sampledRuleDeterministic uses hash_pid sampling (rate=0.5).
var sampledRuleDeterministic = correlator.Rule{
	ID:                  "bench_sampled_deterministic",
	EventType:           types.EventFileAccess,
	SampleRate:          0.5,
	SampleDeterministic: true,
	Condition:           correlator.RuleCondition{Field: "op", Op: "equals", Values: []string{"write"}},
	Severity:            types.SeverityWarning,
	Action:              "alert",
}

// valueSetSmall has ≤8 values — engine uses linear scan.
var valueSetSmallRule = correlator.Rule{
	ID:        "bench_vset_small",
	EventType: types.EventFileAccess,
	Condition: correlator.RuleCondition{
		Field:  "comm",
		Op:     "in",
		Values: []string{"dpkg", "apt", "rpm", "yum"},
	},
	Severity: types.SeverityWarning,
	Action:   "alert",
}

// valueSetLarge has >8 values — engine uses map lookup.
var valueSetLargeRule = correlator.Rule{
	ID:        "bench_vset_large",
	EventType: types.EventFileAccess,
	Condition: correlator.RuleCondition{
		Field:  "comm",
		Op:     "in",
		Values: []string{"dpkg", "apt", "rpm", "yum", "snap", "brew", "pip", "cargo", "npm", "go", "gem", "composer"},
	},
	Severity: types.SeverityWarning,
	Action:   "alert",
}

// ─────────────────────────────────────────────────────────────────────────────
// Benchmarks
// ─────────────────────────────────────────────────────────────────────────────

// BenchmarkEvaluate_NoMatch measures Evaluate on an event that matches no rule.
// The first condition in fileMatchRule checks "op" (pre-computed string table),
// which fails for the read-op event without any BytesToString allocation.
// Budget: ≤1 alloc/op.
func BenchmarkEvaluate_NoMatch(b *testing.B) {
	engine := engineWithRules([]correlator.Rule{fileMatchRule})
	event := noMatchFileEvent()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		alerts := engine.Evaluate(event)
		correlator.ReleaseAlerts(alerts)
	}
}

// BenchmarkEvaluate_SingleMatch measures Evaluate on an event matching one rule.
// Budget: ≤5 allocs/op (BytesToString for filename+comm fields, plus alertsPool).
func BenchmarkEvaluate_SingleMatch(b *testing.B) {
	engine := engineWithRules([]correlator.Rule{fileMatchRule})
	event := matchFileEvent()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		alerts := engine.Evaluate(event)
		correlator.ReleaseAlerts(alerts)
	}
}

// BenchmarkEvaluateInto_NoMatch measures the zero-alloc EvaluateInto path.
// Budget: 0 allocs/op — no slice is allocated; fn is never called on no-match.
func BenchmarkEvaluateInto_NoMatch(b *testing.B) {
	engine := engineWithRules([]correlator.Rule{fileMatchRule})
	event := noMatchFileEvent()
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		engine.EvaluateInto(event, func(_ types.Alert) {})
	}
}

// BenchmarkShouldSample_Random benchmarks the random-sampling code path.
// Exercises shouldSample(deterministic=false) via a rule with SampleRate=0.5.
func BenchmarkShouldSample_Random(b *testing.B) {
	engine := engineWithRules([]correlator.Rule{sampledRuleRandom})
	event := noMatchFileEvent()
	event.File.Op = 2 // write — matches the sample rule's condition
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		alerts := engine.Evaluate(event)
		correlator.ReleaseAlerts(alerts)
	}
}

// BenchmarkShouldSample_Deterministic benchmarks the FNV hash-based sampling path.
// Exercises shouldSample(deterministic=true) + fnvHasherPool via SampleDeterministic=true.
func BenchmarkShouldSample_Deterministic(b *testing.B) {
	engine := engineWithRules([]correlator.Rule{sampledRuleDeterministic})
	event := noMatchFileEvent()
	event.File.Op = 2 // write
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		alerts := engine.Evaluate(event)
		correlator.ReleaseAlerts(alerts)
	}
}

// BenchmarkGetFieldValue_Syscall benchmarks getFieldValue for syscall events
// (nr string lookup from pre-computed syscallNrStrings table).
func BenchmarkGetFieldValue_Syscall(b *testing.B) {
	engine := engineWithRules([]correlator.Rule{syscallMatchRule})
	event := syscallEvent(59)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		alerts := engine.Evaluate(event)
		correlator.ReleaseAlerts(alerts)
	}
}

// BenchmarkGetFieldValue_DNS_Enriched benchmarks getFieldValue for DNS events
// with enriched fields (qname_entropy, qname_length). AnalyzeDomain is the
// most expensive operation on the DNS code path.
func BenchmarkGetFieldValue_DNS_Enriched(b *testing.B) {
	engine := engineWithRules([]correlator.Rule{dnsEnrichedRule})
	// Long, high-entropy domain name to exercise the DGA scoring path.
	event := dnsEvent("a1b2c3d4e5f6g7h8i9j0.randomlonghostname.example.com")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		alerts := engine.Evaluate(event)
		correlator.ReleaseAlerts(alerts)
	}
}

// BenchmarkCompilePatterns_RegexHeavy benchmarks NewRuleEngine construction
// with multiple regex patterns (compilePatterns cold path).
func BenchmarkCompilePatterns_RegexHeavy(b *testing.B) {
	rules := []correlator.Rule{
		regexRule,
		{
			ID:        "bench_regex2",
			EventType: types.EventFileAccess,
			Condition: correlator.RuleCondition{
				Field: "filename", Op: "regex",
				Values: []string{`\.(php|jsp|asp|aspx|phar)$`},
			},
			Severity: types.SeverityCritical,
			Action:   "alert",
		},
		{
			ID:        "bench_regex3",
			EventType: types.EventFileAccess,
			Condition: correlator.RuleCondition{
				Field: "filename", Op: "regex",
				Values: []string{`^/(tmp|dev/shm)/[^/]+\.(sh|py|elf|bin)$`},
			},
			Severity: types.SeverityCritical,
			Action:   "alert",
		},
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e := correlator.NewRuleEngine(rules)
		_ = e.CompileErrors()
	}
}

// BenchmarkValueSetLookup_Small benchmarks OpIn with ≤8 values (linear scan).
func BenchmarkValueSetLookup_Small(b *testing.B) {
	engine := engineWithRules([]correlator.Rule{valueSetSmallRule})
	// comm matches one of the 4 values.
	event := noMatchFileEvent()
	copy(event.Comm[:], "apt")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		alerts := engine.Evaluate(event)
		correlator.ReleaseAlerts(alerts)
	}
}

// BenchmarkValueSetLookup_Large benchmarks OpIn with >8 values (map lookup).
func BenchmarkValueSetLookup_Large(b *testing.B) {
	engine := engineWithRules([]correlator.Rule{valueSetLargeRule})
	// comm matches one of the 12 values.
	event := noMatchFileEvent()
	copy(event.Comm[:], "cargo")
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		alerts := engine.Evaluate(event)
		correlator.ReleaseAlerts(alerts)
	}
}
