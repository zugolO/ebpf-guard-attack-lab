package tests

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/internal/ruletest"
)

// traceEvent is the JSON-tagged equivalent of ruletest.EventSpec used in
// .json.gz trace files. Fields mirror EventSpec so that toEventSpec() is
// a straight copy without lossy conversion.
type traceEvent struct {
	TS         int64            `json:"ts,omitempty"`
	Type       string           `json:"type"`
	PID        uint32           `json:"pid,omitempty"`
	TGID       uint32           `json:"tgid,omitempty"`
	UID        uint32           `json:"uid,omitempty"`
	Comm       string           `json:"comm,omitempty"`
	ParentComm string           `json:"parent_comm,omitempty"`
	ProcArgs   string           `json:"proc_args,omitempty"`
	Syscall    *traceSyscall    `json:"syscall,omitempty"`
	Network    *traceNetwork    `json:"network,omitempty"`
	File       *traceFile       `json:"file,omitempty"`
	DNS        *traceDNS        `json:"dns,omitempty"`
	Privesc    *tracePrivesc    `json:"privesc,omitempty"`
	TLS        *traceTLS        `json:"tls,omitempty"`
	BPFProgram *traceBPFProgram `json:"bpf_program,omitempty"`
	IOUring    *traceIOUring    `json:"iouring,omitempty"`
	Kmod       *traceKmod       `json:"kmod,omitempty"`
}

type traceSyscall struct {
	NR   int64    `json:"nr"`
	Ret  int64    `json:"ret,omitempty"`
	Args []uint64 `json:"args,omitempty"`
}

type traceNetwork struct {
	SrcIP  string `json:"src_ip,omitempty"`
	DstIP  string `json:"dst_ip,omitempty"`
	Sport  uint16 `json:"sport,omitempty"`
	Dport  uint16 `json:"dport,omitempty"`
	Family string `json:"family,omitempty"`
}

type traceFile struct {
	Filename string `json:"filename,omitempty"`
	FDName   string `json:"fd_name,omitempty"`
	Flags    int32  `json:"flags,omitempty"`
	Mode     uint32 `json:"mode,omitempty"`
	Op       string `json:"op,omitempty"`
}

type traceDNS struct {
	QName string `json:"qname"`
	QType uint16 `json:"qtype,omitempty"`
	RCode uint16 `json:"rcode,omitempty"`
}

type tracePrivesc struct {
	OldCaps uint64 `json:"old_caps,omitempty"`
	NewCaps uint64 `json:"new_caps,omitempty"`
}

type traceTLS struct {
	Data      string `json:"data,omitempty"`
	DataLen   uint32 `json:"data_len,omitempty"`
	Direction string `json:"direction,omitempty"`
	JA3       string `json:"ja3,omitempty"`
	JA4       string `json:"ja4,omitempty"`
	JA3S      string `json:"ja3s,omitempty"`
}

type traceBPFProgram struct {
	CmdNr    uint32 `json:"cmd_nr"`
	ProgType string `json:"prog_type,omitempty"`
	Ret      int32  `json:"ret,omitempty"`
}

type traceIOUring struct {
	Op       string `json:"op"`
	Flags    uint32 `json:"flags,omitempty"`
	Fd       int32  `json:"fd,omitempty"`
	ToSubmit uint32 `json:"to_submit,omitempty"`
}

type traceKmod struct {
	Name      string `json:"name,omitempty"`
	FromTmpfs bool   `json:"from_tmpfs,omitempty"`
}

// expectedAlertsFile is the YAML format for .expected.yaml files.
type expectedAlertsFile struct {
	Alerts []expectedAlert `yaml:"alerts"`
}

type expectedAlert struct {
	RuleID  string `yaml:"rule_id"`
	AtEvent int    `yaml:"at_event"`
}

// firedAlert records a rule that fired at a specific event index.
type firedAlert struct {
	RuleID  string
	AtEvent int
}

// TestReplayTraces replays every *.json.gz trace under tests/traces/ against
// the rule engine and checks the result against the companion *.expected.yaml
// file. This exercises multi-event, real-world-shaped attack sequences without
// requiring a live kernel, BPF programs, or root privileges.
func TestReplayTraces(t *testing.T) {
	rules, err := loadAllRulesFromDir("../rules")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	engine := correlator.NewRuleEngine(rules)
	if err := engine.CompileErrors(); err != nil {
		t.Fatalf("rule compile errors: %v", err)
	}

	traceFiles, err := filepath.Glob("traces/*.json.gz")
	if err != nil {
		t.Fatalf("glob traces: %v", err)
	}
	// Also support uncompressed .json traces for developer convenience.
	jsonFiles, err := filepath.Glob("traces/*.json")
	if err != nil {
		t.Fatalf("glob traces: %v", err)
	}
	// Exclude files that are already matched as .json.gz.
	for _, jf := range jsonFiles {
		if !strings.HasSuffix(jf, ".json.gz") {
			traceFiles = append(traceFiles, jf)
		}
	}

	if len(traceFiles) == 0 {
		t.Skip("no trace files found in tests/traces/")
	}

	for _, tracePath := range traceFiles {
		tracePath := tracePath
		name := traceNameFromPath(tracePath)
		t.Run(name, func(t *testing.T) {
			runTraceTest(t, engine, tracePath)
		})
	}
}

func runTraceTest(t *testing.T, engine *correlator.RuleEngine, tracePath string) {
	t.Helper()

	events, err := loadTrace(tracePath)
	if err != nil {
		t.Fatalf("load trace %s: %v", tracePath, err)
	}

	expectedPath := expectedPathFor(tracePath)
	expected, err := loadExpectedAlerts(expectedPath)
	if err != nil {
		t.Fatalf("load expected alerts %s: %v", expectedPath, err)
	}

	// Sort events by timestamp for correct replay order.
	sort.Slice(events, func(i, j int) bool {
		return events[i].TS < events[j].TS
	})

	// Feed each event through the engine, collecting (at_event, rule_id) pairs.
	var fired []firedAlert
	for idx, te := range events {
		spec := te.toEventSpec()
		ev, err := spec.Build()
		if err != nil {
			t.Fatalf("build event %d: %v", idx, err)
		}
		alerts := engine.Evaluate(ev)
		for _, a := range alerts {
			fired = append(fired, firedAlert{RuleID: a.RuleID, AtEvent: idx})
		}
		correlator.ReleaseAlerts(alerts)
	}

	// Compare fired alerts against expectations.
	checkReplayAlerts(t, expected, fired)
}

// checkReplayAlerts verifies that every expected alert fired and no unexpected
// alerts were produced.
func checkReplayAlerts(t *testing.T, expected []expectedAlert, fired []firedAlert) {
	t.Helper()

	// Build a set of what was actually fired.
	firedSet := make(map[string]bool, len(fired))
	for _, f := range fired {
		firedSet[replayKey(f.AtEvent, f.RuleID)] = true
	}

	// Check every expected alert appeared.
	for _, e := range expected {
		key := replayKey(e.AtEvent, e.RuleID)
		if !firedSet[key] {
			t.Errorf("expected alert at_event=%d rule_id=%q did not fire", e.AtEvent, e.RuleID)
		}
	}

	// Check for unexpected alerts.
	expectedSet := make(map[string]bool, len(expected))
	for _, e := range expected {
		expectedSet[replayKey(e.AtEvent, e.RuleID)] = true
	}
	for _, f := range fired {
		key := replayKey(f.AtEvent, f.RuleID)
		if !expectedSet[key] {
			t.Errorf("unexpected alert at_event=%d rule_id=%q fired (not in expected)", f.AtEvent, f.RuleID)
		}
	}
}

func replayKey(eventIdx int, ruleID string) string {
	return fmt.Sprintf("%d:%s", eventIdx, ruleID)
}

// loadTrace reads a .json.gz or .json trace file and returns the events.
func loadTrace(path string) ([]traceEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gr, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("gzip open: %w", err)
		}
		defer gr.Close()
		r = gr
	}

	var events []traceEvent
	if err := json.NewDecoder(r).Decode(&events); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return events, nil
}

func loadExpectedAlerts(path string) ([]expectedAlert, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ef expectedAlertsFile
	if err := yaml.Unmarshal(data, &ef); err != nil {
		return nil, err
	}
	return ef.Alerts, nil
}

// expectedPathFor returns the .expected.yaml path for a given trace path.
func expectedPathFor(tracePath string) string {
	base := strings.TrimSuffix(tracePath, ".gz")
	base = strings.TrimSuffix(base, ".json")
	return base + ".expected.yaml"
}

func traceNameFromPath(tracePath string) string {
	base := filepath.Base(tracePath)
	base = strings.TrimSuffix(base, ".json.gz")
	base = strings.TrimSuffix(base, ".json")
	return base
}

// toEventSpec converts a JSON trace entry to an ruletest.EventSpec for Build().
func (te traceEvent) toEventSpec() ruletest.EventSpec {
	s := ruletest.EventSpec{
		Type:       te.Type,
		PID:        te.PID,
		TGID:       te.TGID,
		UID:        te.UID,
		Comm:       te.Comm,
		ParentComm: te.ParentComm,
		ProcArgs:   te.ProcArgs,
	}
	if te.Syscall != nil {
		s.Syscall = &ruletest.SyscallSpec{
			NR:   te.Syscall.NR,
			Ret:  te.Syscall.Ret,
			Args: te.Syscall.Args,
		}
	}
	if te.Network != nil {
		s.Network = &ruletest.NetworkSpec{
			SrcIP:  te.Network.SrcIP,
			DstIP:  te.Network.DstIP,
			Sport:  te.Network.Sport,
			Dport:  te.Network.Dport,
			Family: te.Network.Family,
		}
	}
	if te.File != nil {
		s.File = &ruletest.FileSpec{
			Filename: te.File.Filename,
			FDName:   te.File.FDName,
			Flags:    te.File.Flags,
			Mode:     te.File.Mode,
			Op:       te.File.Op,
		}
	}
	if te.DNS != nil {
		s.DNS = &ruletest.DNSSpec{
			QName: te.DNS.QName,
			QType: te.DNS.QType,
			RCode: te.DNS.RCode,
		}
	}
	if te.Privesc != nil {
		s.Privesc = &ruletest.PrivescSpec{
			OldCaps: te.Privesc.OldCaps,
			NewCaps: te.Privesc.NewCaps,
		}
	}
	if te.TLS != nil {
		s.TLS = &ruletest.TLSSpec{
			Data:      te.TLS.Data,
			DataLen:   te.TLS.DataLen,
			Direction: te.TLS.Direction,
			JA3:       te.TLS.JA3,
			JA4:       te.TLS.JA4,
			JA3S:      te.TLS.JA3S,
		}
	}
	if te.BPFProgram != nil {
		s.BPFProgram = &ruletest.BPFProgramSpec{
			CmdNr:    te.BPFProgram.CmdNr,
			ProgType: te.BPFProgram.ProgType,
			Ret:      te.BPFProgram.Ret,
		}
	}
	if te.IOUring != nil {
		s.IOUring = &ruletest.IOUringSpec{
			Op:       te.IOUring.Op,
			Flags:    te.IOUring.Flags,
			Fd:       te.IOUring.Fd,
			ToSubmit: te.IOUring.ToSubmit,
		}
	}
	if te.Kmod != nil {
		s.Kmod = &ruletest.KmodSpec{
			Name:      te.Kmod.Name,
			FromTmpfs: te.Kmod.FromTmpfs,
		}
	}
	return s
}
