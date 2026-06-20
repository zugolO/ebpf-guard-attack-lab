package util

import (
	"bytes"
	"net"

	"github.com/zugolO/ebpf-guard/pkg/types"
)

// BytesToString converts a null-terminated byte slice to a string, trimming
// any bytes at and after the first null byte.
func BytesToString(b []byte) string {
	if n := bytes.IndexByte(b, 0); n >= 0 {
		return string(b[:n])
	}
	return string(b)
}

// FormatIP formats a 16-byte address into a dotted-decimal (IPv4) or
// colon-hex (IPv6) string, using the address family to disambiguate.
func FormatIP(b []byte, family types.AddressFamily) string {
	if len(b) < 4 {
		return "<invalid>"
	}
	if family == types.AFInet6 {
		if len(b) < 16 {
			return "<invalid>"
		}
		return net.IP(b[:16]).String()
	}
	return net.IPv4(b[0], b[1], b[2], b[3]).To4().String()
}
