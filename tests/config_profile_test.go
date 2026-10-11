// Package tests also guards the integration-environment test profile
// (hack/ebpf-guard.test.yaml). The profile shortens the EWMA profiler's
// learning window so anomaly tests finish in seconds, and is mounted by
// docker-compose.test.yml + surfaced through EBPF_GUARD_CONFIG by the
// Makefile. These tests are pure YAML parsing and must not depend on the
// ebpf-guard daemon source (only on gopkg.in/yaml.v3).
package tests

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// CI ceilings: the test profile must stay well under the production
// learning_period (3600s) so a future edit cannot silently restore the hour-long
// wait that issue #29 depends on removing.
const (
	ciMaxLearningPeriod     = 60 // seconds
	ciMaxMinLearningSamples = 50
)

// testProfile mirrors only the knobs hack/ebpf-guard.test.yaml overrides.
// Pointers distinguish "explicitly false" from "absent".
type testProfile struct {
	ConfigVersion string `yaml:"config_version"`
	Profiler      struct {
		Enabled            *bool   `yaml:"enabled"`
		LearningPeriod     int     `yaml:"learning_period"`
		MinLearningSamples int     `yaml:"min_learning_samples"`
		AnomalyThreshold   float64 `yaml:"anomaly_threshold"`
		// Nested v0.2.0 schema, with the legacy flat key as a fallback.
		EWMA struct {
			Weight float64 `yaml:"weight"`
		} `yaml:"ewma"`
		EWMAWeight float64 `yaml:"ewma_weight"`
	} `yaml:"profiler"`
	Watchdog struct {
		MemoryPressure struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"memory_pressure"`
		CPUPressure struct {
			Enabled *bool `yaml:"enabled"`
		} `yaml:"cpu_pressure"`
	} `yaml:"watchdog"`
}

func TestTestConfigProfileIsShort(t *testing.T) {
	data, err := os.ReadFile("../hack/ebpf-guard.test.yaml")
	if err != nil {
		t.Fatalf("cannot read hack/ebpf-guard.test.yaml: %v", err)
	}

	var p testProfile
	if err := yaml.Unmarshal(data, &p); err != nil {
		t.Fatalf("hack/ebpf-guard.test.yaml is not valid YAML: %v", err)
	}

	if p.ConfigVersion != "v0.1" {
		t.Errorf("config_version = %q, want %q", p.ConfigVersion, "v0.1")
	}

	if p.Profiler.Enabled == nil || !*p.Profiler.Enabled {
		t.Errorf("profiler.enabled = %v, want true (EWMA tests need the profiler on)", p.Profiler.Enabled)
	}

	if p.Profiler.LearningPeriod <= 0 {
		t.Errorf("profiler.learning_period = %d, want > 0", p.Profiler.LearningPeriod)
	}
	if p.Profiler.LearningPeriod > ciMaxLearningPeriod {
		t.Errorf("profiler.learning_period = %d, want <= %d so EWMA tests stay CI-friendly",
			p.Profiler.LearningPeriod, ciMaxLearningPeriod)
	}

	if p.Profiler.MinLearningSamples <= 0 {
		t.Errorf("profiler.min_learning_samples = %d, want > 0", p.Profiler.MinLearningSamples)
	}
	if p.Profiler.MinLearningSamples > ciMaxMinLearningSamples {
		t.Errorf("profiler.min_learning_samples = %d, want <= %d so learning completes in seconds",
			p.Profiler.MinLearningSamples, ciMaxMinLearningSamples)
	}

	// Nested profiler.ewma.weight takes precedence; fall back to the legacy flat
	// key so the guard keeps working if the profile is migrated.
	weight := p.Profiler.EWMA.Weight
	if weight == 0 {
		weight = p.Profiler.EWMAWeight
	}
	if weight <= 0 || weight > 1 {
		t.Errorf("profiler EWMA weight = %v, want in (0, 1]", weight)
	}

	if p.Profiler.AnomalyThreshold != 0 &&
		(p.Profiler.AnomalyThreshold <= 0 || p.Profiler.AnomalyThreshold > 1) {
		t.Errorf("profiler.anomaly_threshold = %v, want in (0, 1]", p.Profiler.AnomalyThreshold)
	}

	// Pressure watchers must be off so the daemon cannot shed collectors
	// mid-test; determinism is the whole point of this profile.
	if p.Watchdog.MemoryPressure.Enabled == nil || *p.Watchdog.MemoryPressure.Enabled {
		t.Errorf("watchdog.memory_pressure.enabled = %v, want false", p.Watchdog.MemoryPressure.Enabled)
	}
	if p.Watchdog.CPUPressure.Enabled == nil || *p.Watchdog.CPUPressure.Enabled {
		t.Errorf("watchdog.cpu_pressure.enabled = %v, want false", p.Watchdog.CPUPressure.Enabled)
	}
}

// composeFile captures just the daemon service, so the test stays valid if
// unrelated services change. Service bodies are kept as yaml.Node because the
// attack-lab service declares `command` as a folded scalar, not a list.
type composeFile struct {
	Services map[string]yaml.Node `yaml:"services"`
}

type composeService struct {
	Volumes []string `yaml:"volumes"`
	Command []string `yaml:"command"`
}

func TestDockerComposeUsesTestConfigProfile(t *testing.T) {
	data, err := os.ReadFile("../docker-compose.test.yml")
	if err != nil {
		t.Fatalf("cannot read docker-compose.test.yml: %v", err)
	}

	var c composeFile
	if err := yaml.Unmarshal(data, &c); err != nil {
		t.Fatalf("docker-compose.test.yml is not valid YAML: %v", err)
	}

	svcNode, ok := c.Services["ebpf-guard"]
	if !ok {
		t.Fatal("docker-compose.test.yml has no ebpf-guard service")
	}
	var svc composeService
	if err := svcNode.Decode(&svc); err != nil {
		t.Fatalf("cannot decode ebpf-guard service: %v", err)
	}

	configFlag := false
	for _, arg := range svc.Command {
		if strings.HasPrefix(arg, "--config=") {
			configFlag = true
			if !strings.HasSuffix(arg, "/etc/ebpf-guard/config.yaml") {
				t.Errorf("daemon --config points at %q, want /etc/ebpf-guard/config.yaml", arg)
			}
		}
	}
	if !configFlag {
		t.Error("ebpf-guard command lacks --config=/etc/ebpf-guard/config.yaml")
	}

	mounted := false
	for _, v := range svc.Volumes {
		if strings.Contains(v, "hack/ebpf-guard.test.yaml") &&
			strings.Contains(v, "/etc/ebpf-guard/config.yaml") {
			mounted = true
		}
	}
	if !mounted {
		t.Error("ebpf-guard does not mount hack/ebpf-guard.test.yaml at /etc/ebpf-guard/config.yaml")
	}
}
