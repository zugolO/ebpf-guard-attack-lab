package correlator

import (
	"math"
	"strings"
	"unicode"
)

// DomainAnalysis holds pre-computed metrics for a DNS query name.
// All fields are computed once per event by AnalyzeDomain and shared
// across all enriched rule conditions (qname_entropy, qname_dga_score,
// qname_digit_ratio, qname_subdomain_count, qname_is_dga).
type DomainAnalysis struct {
	Entropy        float64 // Shannon entropy of the first (longest) label
	NgramScore     float64 // bigram-based DGA suspicion score (higher = more suspicious)
	DigitRatio     float64 // fraction of alphanumeric chars that are digits
	SubdomainCount int     // number of dot-separated labels excluding TLD
	IsDGA          bool    // true when heuristics strongly indicate a DGA domain
}

// DNSEntropyCalculator computes DomainAnalysis for query names.
type DNSEntropyCalculator struct {
	detector *NgramDGADetector
}

// NewDNSEntropyCalculator returns a calculator backed by the default n-gram detector.
func NewDNSEntropyCalculator() *DNSEntropyCalculator {
	return &DNSEntropyCalculator{detector: DefaultNgramDGADetector()}
}

// AnalyzeDomain computes entropy, DGA score, digit ratio, and subdomain count
// for the given fully-qualified domain name.
func (d *DNSEntropyCalculator) AnalyzeDomain(qname string) DomainAnalysis {
	qname = strings.TrimSuffix(qname, ".")
	if qname == "" {
		return DomainAnalysis{}
	}

	labels := strings.Split(qname, ".")
	// Exclude the TLD (last label) from subdomain count.
	subdomainCount := len(labels) - 1
	if subdomainCount < 0 {
		subdomainCount = 0
	}

	// Use the longest label for entropy / DGA scoring (typically the random part).
	longest := longestLabel(labels)

	entropy := shannonEntropy(longest)
	ngramScore := d.detector.Score(longest)
	digitRatio := digitFraction(longest)
	isDGA := d.detector.IsDGA(longest, entropy, digitRatio)

	return DomainAnalysis{
		Entropy:        entropy,
		NgramScore:     ngramScore,
		DigitRatio:     digitRatio,
		SubdomainCount: subdomainCount,
		IsDGA:          isDGA,
	}
}

// NgramDGADetector scores a domain label based on uncommon character bigrams.
// A higher score indicates more random / DGA-like character sequences.
type NgramDGADetector struct {
	threshold float64
}

// DefaultNgramDGADetector returns the default detector with a threshold tuned
// to minimise false positives on common English-word domains.
func DefaultNgramDGADetector() *NgramDGADetector {
	return &NgramDGADetector{threshold: 3.5}
}

// Score returns a suspicion score for the label. The score is the fraction of
// consecutive character pairs (bigrams) that are uncommon in natural English
// words, normalised to [0, ∞). Higher values indicate more randomness.
func (d *NgramDGADetector) Score(label string) float64 {
	label = strings.ToLower(label)
	if len(label) < 2 {
		return 0
	}
	// Common English bigrams — their absence drives a higher score.
	commonBigrams := map[string]bool{
		"th": true, "he": true, "in": true, "er": true, "an": true,
		"re": true, "on": true, "at": true, "en": true, "nd": true,
		"ti": true, "es": true, "or": true, "te": true, "of": true,
		"ed": true, "is": true, "it": true, "al": true, "ar": true,
		"st": true, "to": true, "nt": true, "ng": true, "se": true,
		"ha": true, "as": true, "ou": true, "io": true, "le": true,
		"ve": true, "co": true, "me": true, "de": true, "hi": true,
		"ri": true, "ro": true, "ic": true, "ne": true, "ea": true,
		"ra": true, "ce": true, "li": true, "ch": true, "ll": true,
		"be": true, "ma": true, "si": true, "om": true, "ur": true,
	}
	uncommon := 0
	total := 0
	for i := 0; i < len(label)-1; i++ {
		if label[i] >= 'a' && label[i] <= 'z' && label[i+1] >= 'a' && label[i+1] <= 'z' {
			total++
			bg := label[i : i+2]
			if !commonBigrams[bg] {
				uncommon++
			}
		}
	}
	if total == 0 {
		return 0
	}
	return float64(uncommon) / float64(total) * 5.0
}

// IsDGA applies combined heuristics to classify a label as likely DGA-generated.
func (d *NgramDGADetector) IsDGA(label string, entropy, digitRatio float64) bool {
	if len(label) < 8 {
		return false
	}
	return entropy > 3.8 && d.Score(label) >= d.threshold || digitRatio > 0.4
}

// shannonEntropy computes the Shannon entropy (in bits) of a string.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int, len(s))
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	var h float64
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// digitFraction returns the fraction of alphanumeric characters that are digits.
func digitFraction(s string) float64 {
	var digits, alphanum int
	for _, c := range s {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			alphanum++
			if unicode.IsDigit(c) {
				digits++
			}
		}
	}
	if alphanum == 0 {
		return 0
	}
	return float64(digits) / float64(alphanum)
}

// longestLabel returns the longest element from labels, or "" if labels is empty.
func longestLabel(labels []string) string {
	best := ""
	for _, l := range labels {
		if len(l) > len(best) {
			best = l
		}
	}
	return best
}
