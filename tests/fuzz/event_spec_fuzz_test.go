package fuzz

import (
	"testing"

	"github.com/zugolO/ebpf-guard/internal/ruletest"
)

// FuzzEventSpecBuildFile exercises EventSpec.Build() for file events with
// arbitrary filenames, comm strings, and op strings.
func FuzzEventSpecBuildFile(f *testing.F) {
	f.Add("/etc/passwd", "bash", "read")
	f.Add("/var/www/shell.php", "curl", "write")
	f.Add("", "", "")
	f.Add(string(make([]byte, 512)), "x", "create")
	f.Add("/tmp/test", "python3", "rename")
	f.Add("/usr/bin/ls", "", "open")

	f.Fuzz(func(t *testing.T, filename, comm, op string) {
		spec := ruletest.EventSpec{
			Type: "file",
			Comm: comm,
			File: &ruletest.FileSpec{
				Filename: filename,
				Op:       op,
			},
		}
		_, _ = spec.Build()
	})
}

// FuzzEventSpecBuildSyscall exercises EventSpec.Build() for syscall events.
func FuzzEventSpecBuildSyscall(f *testing.F) {
	f.Add(int64(59), "bash", uint32(1000))
	f.Add(int64(-1), "", uint32(0))
	f.Add(int64(0), "x", uint32(0))
	f.Add(int64(9999999), "curl", uint32(65535))

	f.Fuzz(func(t *testing.T, nr int64, comm string, uid uint32) {
		spec := ruletest.EventSpec{
			Type: "syscall",
			UID:  uid,
			Comm: comm,
			Syscall: &ruletest.SyscallSpec{
				NR: nr,
			},
		}
		_, _ = spec.Build()
	})
}

// FuzzEventSpecBuildNetwork exercises EventSpec.Build() for network events,
// including the IPv4/IPv6 address parse path.
func FuzzEventSpecBuildNetwork(f *testing.F) {
	f.Add("192.168.1.1", "10.0.0.1", uint16(4444), "ipv4")
	f.Add("::1", "2001:db8::1", uint16(443), "ipv6")
	f.Add("", "", uint16(0), "")
	f.Add("not-an-ip", "256.256.256.256", uint16(80), "ipv4")
	f.Add("0.0.0.0", "255.255.255.255", uint16(65535), "ipv4")

	f.Fuzz(func(t *testing.T, srcIP, dstIP string, dport uint16, family string) {
		spec := ruletest.EventSpec{
			Type: "network",
			Network: &ruletest.NetworkSpec{
				SrcIP:  srcIP,
				DstIP:  dstIP,
				Dport:  dport,
				Family: family,
			},
		}
		_, _ = spec.Build() // invalid IPs return an error; must not panic
	})
}

// FuzzEventSpecBuildDNS exercises EventSpec.Build() for DNS events with
// arbitrary query names.
func FuzzEventSpecBuildDNS(f *testing.F) {
	f.Add("example.com", uint16(1))
	f.Add("", uint16(0))
	f.Add(string(make([]byte, 512)), uint16(28))
	f.Add("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.example.com", uint16(255))

	f.Fuzz(func(t *testing.T, qname string, qtype uint16) {
		spec := ruletest.EventSpec{
			Type: "dns",
			DNS:  &ruletest.DNSSpec{QName: qname, QType: qtype},
		}
		_, _ = spec.Build()
	})
}

// FuzzEventSpecBuildUnknownType exercises the default/error branch of
// EventSpec.Build() with arbitrary event type strings.
func FuzzEventSpecBuildUnknownType(f *testing.F) {
	f.Add("syscall")
	f.Add("file")
	f.Add("network")
	f.Add("dns")
	f.Add("tls")
	f.Add("")
	f.Add("UNKNOWN_TYPE_9999")
	f.Add(string(make([]byte, 64)))

	f.Fuzz(func(t *testing.T, eventType string) {
		spec := ruletest.EventSpec{Type: eventType}
		// All type strings are safe to pass — unknown types return an error,
		// known types may also return an error if required sub-specs are nil.
		_, _ = spec.Build()
	})
}
