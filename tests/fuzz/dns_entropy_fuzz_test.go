package fuzz

import (
	"testing"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// dnsEngine is pre-built with DNS entropy/DGA rules.
var dnsEngine = newDNSEngine()

func newDNSEngine() *correlator.RuleEngine {
	rules := []correlator.Rule{
		{
			ID:        "fuzz_dns_entropy",
			EventType: types.EventDNS,
			Condition: correlator.RuleCondition{
				Field: "qname_entropy", Op: correlator.OpGreaterThan,
				Values: []string{"3.8"},
			},
			Severity: types.SeverityWarning,
			Action:   "alert",
		},
		{
			ID:        "fuzz_dns_dga",
			EventType: types.EventDNS,
			Condition: correlator.RuleCondition{
				Field: "qname_is_dga", Op: correlator.OpEquals,
				Values: []string{"true"},
			},
			Severity: types.SeverityCritical,
			Action:   "alert",
		},
		{
			ID:        "fuzz_dns_digit_ratio",
			EventType: types.EventDNS,
			Condition: correlator.RuleCondition{
				Field: "qname_digit_ratio", Op: correlator.OpGreaterOrEqual,
				Values: []string{"0.4"},
			},
			Severity: types.SeverityWarning,
			Action:   "alert",
		},
		{
			ID:        "fuzz_dns_subdomain_count",
			EventType: types.EventDNS,
			Condition: correlator.RuleCondition{
				Field: "qname_subdomain_count", Op: correlator.OpGreaterThan,
				Values: []string{"5"},
			},
			Severity: types.SeverityWarning,
			Action:   "alert",
		},
	}
	return correlator.NewRuleEngine(rules)
}

// FuzzDNSEntropyAnalyzeDomain directly exercises AnalyzeDomain with arbitrary
// domain name strings, ensuring no panics on edge cases (empty labels, very
// long strings, unicode, embedded nulls, trailing dots, etc.).
func FuzzDNSEntropyAnalyzeDomain(f *testing.F) {
	calc := correlator.NewDNSEntropyCalculator()

	f.Add("google.com")
	f.Add("a1b2c3d4e5f6g7h8.malware.example.com")
	f.Add("xn--nxasmq6b3psrzhufppufr.com") // punycode
	f.Add(".")
	f.Add("")
	f.Add("a")
	f.Add(string(make([]byte, 512)))
	f.Add("sub.sub.sub.sub.sub.sub.sub.sub.example.com")
	f.Add("12345678901234567890.example.com")

	f.Fuzz(func(t *testing.T, qname string) {
		da := calc.AnalyzeDomain(qname)
		// Sanity invariants that must hold for all inputs.
		if da.Entropy < 0 {
			t.Fatalf("entropy < 0 for qname %q: %f", qname, da.Entropy)
		}
		if da.DigitRatio < 0 || da.DigitRatio > 1 {
			t.Fatalf("digit_ratio out of [0,1] for qname %q: %f", qname, da.DigitRatio)
		}
		if da.SubdomainCount < 0 {
			t.Fatalf("subdomain_count < 0 for qname %q: %d", qname, da.SubdomainCount)
		}
	})
}

// FuzzDNSEvaluate exercises the full rule evaluation path for DNS events,
// driving both AnalyzeDomain and the enriched field (qname_entropy, qname_is_dga,
// qname_dga_score, qname_digit_ratio, qname_subdomain_count) evaluations.
func FuzzDNSEvaluate(f *testing.F) {
	f.Add("google.com", uint16(1))
	f.Add("xkcd.com", uint16(28))
	f.Add("a1b2c3xzqw9k.evil.io", uint16(1))
	f.Add("", uint16(0))
	f.Add(string(make([]byte, 255)), uint16(1))

	f.Fuzz(func(t *testing.T, qname string, qtype uint16) {
		e := types.Event{
			Type: types.EventDNS,
			DNS:  &types.DNSEvent{QName: qname, QType: qtype},
		}
		alerts := dnsEngine.Evaluate(e)
		correlator.ReleaseAlerts(alerts)
	})
}
