package fuzz

import (
	"encoding/binary"
	"testing"

	"github.com/zugolO/ebpf-guard/internal/correlator"
	"github.com/zugolO/ebpf-guard/pkg/types"
)

// fileEngine and syscallEngine are built once and reused across fuzz iterations
// to avoid the cost of re-compiling rule patterns on every call.
var (
	fileEngine    = newFileEngine()
	syscallEngine = newSyscallEngine()
	netEngine     = newNetEngine()
)

func newFileEngine() *correlator.RuleEngine {
	rules := []correlator.Rule{
		{
			ID:        "fuzz_file_prefix",
			EventType: types.EventFileAccess,
			Condition: correlator.RuleCondition{
				Field: "filename", Op: correlator.OpPrefix,
				Values: []string{"/etc/", "/var/", "/tmp/"},
			},
			Severity: types.SeverityWarning,
			Action:   "alert",
		},
		{
			ID:        "fuzz_file_suffix",
			EventType: types.EventFileAccess,
			Condition: correlator.RuleCondition{
				Field: "extension", Op: correlator.OpIn,
				Values: []string{".php", ".sh", ".py"},
			},
			Severity: types.SeverityCritical,
			Action:   "alert",
		},
		{
			ID:        "fuzz_file_regex",
			EventType: types.EventFileAccess,
			Condition: correlator.RuleCondition{
				Field: "filename", Op: correlator.OpRegex,
				Values: []string{`^/usr/(bin|lib)/[^/]+$`},
			},
			Severity: types.SeverityWarning,
			Action:   "alert",
		},
		{
			ID:        "fuzz_comm_notin",
			EventType: types.EventFileAccess,
			Condition: correlator.RuleCondition{
				Field: "comm", Op: correlator.OpNotIn,
				Values: []string{"apt", "dpkg", "rpm"},
			},
			Severity: types.SeverityWarning,
			Action:   "alert",
		},
	}
	return correlator.NewRuleEngine(rules)
}

func newSyscallEngine() *correlator.RuleEngine {
	rules := []correlator.Rule{
		{
			ID:        "fuzz_syscall_nr",
			EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{
				Field: "nr", Op: correlator.OpIn,
				Values: []string{"59", "322", "321"},
			},
			Severity: types.SeverityWarning,
			Action:   "alert",
		},
		{
			ID:        "fuzz_syscall_comm",
			EventType: types.EventSyscall,
			Condition: correlator.RuleCondition{
				Field: "comm", Op: correlator.OpNotIn,
				Values: []string{"bash", "sh", "python3"},
			},
			Severity: types.SeverityCritical,
			Action:   "alert",
		},
	}
	return correlator.NewRuleEngine(rules)
}

func newNetEngine() *correlator.RuleEngine {
	rules := []correlator.Rule{
		{
			ID:        "fuzz_net_cidr",
			EventType: types.EventTCPConnect,
			Condition: correlator.RuleCondition{
				Field: "daddr", Op: correlator.OpInCIDR,
				Values: []string{"10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"},
			},
			Severity: types.SeverityWarning,
			Action:   "alert",
		},
		{
			ID:        "fuzz_net_dport",
			EventType: types.EventTCPConnect,
			Condition: correlator.RuleCondition{
				Field: "dport", Op: correlator.OpNotIn,
				Values: []string{"80", "443", "22"},
			},
			Severity: types.SeverityWarning,
			Action:   "alert",
		},
	}
	return correlator.NewRuleEngine(rules)
}

// FuzzEvaluateFileFilename exercises getFieldValue("filename") and the
// prefix/regex/extension evaluateCondition paths with arbitrary file paths.
func FuzzEvaluateFileFilename(f *testing.F) {
	f.Add("/etc/passwd", "bash", uint8(0))
	f.Add("/var/www/html/shell.php", "curl", uint8(3))
	f.Add("/tmp/evil.sh", "wget", uint8(2))
	f.Add("", "", uint8(0))
	f.Add(string(make([]byte, 255)), "x", uint8(1))

	f.Fuzz(func(t *testing.T, filename, comm string, op uint8) {
		e := types.Event{
			Type: types.EventFileAccess,
			File: &types.FileEvent{Op: op % 8},
		}
		copy(e.Comm[:], comm)
		copy(e.File.Filename[:], filename)

		alerts := fileEngine.Evaluate(e)
		correlator.ReleaseAlerts(alerts)
	})
}

// FuzzEvaluateSyscallNR exercises getFieldValue("nr") and "comm" for syscall
// events, hitting the integer-dispatch path in evaluateCondition.
func FuzzEvaluateSyscallNR(f *testing.F) {
	f.Add(int64(59), "bash", uint32(0))
	f.Add(int64(0), "", uint32(1000))
	f.Add(int64(322), "curl", uint32(0))
	f.Add(int64(-1), "unknown", uint32(0))
	f.Add(int64(512), "x", uint32(0))

	f.Fuzz(func(t *testing.T, nr int64, comm string, uid uint32) {
		e := types.Event{
			Type: types.EventSyscall,
			UID:  uid,
			Syscall: &types.SyscallEvent{
				Nr: nr,
			},
		}
		copy(e.Comm[:], comm)

		alerts := syscallEngine.Evaluate(e)
		correlator.ReleaseAlerts(alerts)
	})
}

// FuzzEvaluateNetworkCIDR exercises the in_cidr evaluateCondition path and
// getFieldValue("daddr") with arbitrary IP byte sequences.
func FuzzEvaluateNetworkCIDR(f *testing.F) {
	f.Add(uint32(0x0a000001), uint16(4444), uint16(1234)) // 10.0.0.1
	f.Add(uint32(0xc0a80001), uint16(443), uint16(9999))  // 192.168.0.1
	f.Add(uint32(0x08080808), uint16(80), uint16(54321))  // 8.8.8.8
	f.Add(uint32(0), uint16(0), uint16(0))

	f.Fuzz(func(t *testing.T, daddr uint32, dport, sport uint16) {
		e := types.Event{
			Type: types.EventTCPConnect,
			Network: &types.NetworkEvent{
				Family: types.AFInet,
				Dport:  dport,
				Sport:  sport,
				Proto:  6,
			},
		}
		binary.BigEndian.PutUint32(e.Network.Daddr[:4], daddr)

		alerts := netEngine.Evaluate(e)
		correlator.ReleaseAlerts(alerts)
	})
}
