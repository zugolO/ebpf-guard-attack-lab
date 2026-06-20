package correlator

import (
	"strconv"
	"sync"
	"sync/atomic"
)

// RuleSampling is the nested per-rule sampling configuration block.
//
//	sampling:
//	  rate: 0.1       # evaluate 10 % of matching events
//	  mode: hash_pid  # "random" (default) or "hash_pid"
type RuleSampling struct {
	Rate float64 `yaml:"rate"`
	Mode string  `yaml:"mode"`
}

type samplerEntry struct {
	rate          float64
	deterministic bool
	mode          string
	rateStr       string
}

// RuleSampler manages per-rule static sample rates and adaptive overrides.
//
// The adaptive-override path (entryCount > 0) is intentionally left as a
// stub: in the attack-lab context only static rates from rule YAML matter.
type RuleSampler struct {
	entries    map[string]samplerEntry
	mu         sync.RWMutex
	entryCount atomic.Int64
}

// NewRuleSampler builds a RuleSampler from the static SampleRate fields of
// the provided rules. Rules without a configured rate are not stored.
func NewRuleSampler(rules []Rule) *RuleSampler {
	rs := &RuleSampler{
		entries: make(map[string]samplerEntry),
	}
	for _, r := range rules {
		rate := r.SampleRate
		det := r.SampleDeterministic
		mode := "random"

		// Nested sampling block takes precedence over flat fields.
		if r.Sampling != nil && r.Sampling.Rate > 0 && r.Sampling.Rate < 1.0 {
			rate = r.Sampling.Rate
			if r.Sampling.Mode == "hash_pid" {
				det = true
				mode = "hash_pid"
			}
		}

		if rate > 0 && rate < 1.0 {
			if det {
				mode = "hash_pid"
			}
			rs.entries[r.ID] = samplerEntry{
				rate:          rate,
				deterministic: det,
				mode:          mode,
				rateStr:       strconv.FormatFloat(rate, 'f', -1, 64),
			}
		}
	}
	// entryCount tracks adaptive overrides only (set to 0 here; no adaptive
	// overrides are active in the attack-lab context).
	return rs
}

// CheckSampling decides whether to evaluate (or skip) an event for ruleID.
//
// Returns:
//   - active=false when no static rate is configured for ruleID (fast-path).
//   - skip=true  when the sampling gate says to drop this event.
//   - skip=false when the event should be evaluated.
func (rs *RuleSampler) CheckSampling(ruleID string, pid uint32, ts uint64) (active, skip bool, mode, rateStr string) {
	rs.mu.RLock()
	entry, ok := rs.entries[ruleID]
	rs.mu.RUnlock()
	if !ok {
		return false, false, "", ""
	}
	sample := shouldSample(pid, ts, entry.rate, entry.deterministic)
	return true, !sample, entry.mode, entry.rateStr
}

// HasSampling reports whether ruleID has any sampling configuration.
func (rs *RuleSampler) HasSampling(ruleID string) bool {
	rs.mu.RLock()
	_, ok := rs.entries[ruleID]
	rs.mu.RUnlock()
	return ok
}
