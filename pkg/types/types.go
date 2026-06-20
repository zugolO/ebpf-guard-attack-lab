package types

import (
	"strconv"
	"time"
)

// EventType identifies the kind of kernel event.
type EventType uint8

const (
	EventSyscall    EventType = 1
	EventTCPConnect EventType = 2
	EventFileAccess EventType = 3
	EventDNS        EventType = 4
	EventPrivesc    EventType = 5
	EventTLS        EventType = 6
	EventBPFProgram EventType = 7
	EventIOUring    EventType = 8
	EventKmodLoad   EventType = 9
	EventNetClose   EventType = 10
	EventGPU        EventType = 11
	EventCloudAudit EventType = 12
)

// AlertSeverity is the severity level of a fired alert.
type AlertSeverity string

const (
	SeverityWarning  AlertSeverity = "warning"
	SeverityCritical AlertSeverity = "critical"
)

// AddressFamily matches the Linux socket address family constants.
type AddressFamily uint8

const (
	AFInet  AddressFamily = 2
	AFInet6 AddressFamily = 10
)

// TLSDirection indicates whether a TLS payload is outbound or inbound.
type TLSDirection uint8

const (
	TLSDirectionWrite TLSDirection = 0
	TLSDirectionRead  TLSDirection = 1
)

// SyscallEvent carries the raw syscall arguments and return value.
type SyscallEvent struct {
	Nr   int64
	Ret  int64
	Args [6]uint64
}

// NetworkEvent carries TCP-connect metadata.
type NetworkEvent struct {
	Sport  uint16
	Dport  uint16
	Proto  uint8
	Family AddressFamily
	Saddr  [16]byte
	Daddr  [16]byte
}

// FileEvent carries file-access metadata.
type FileEvent struct {
	Filename        [256]byte
	FDPath          string
	FDPathTruncated bool
	Flags           int32
	Mode            uint32
	Op              uint8
}

// DNSEvent carries a DNS query observation.
type DNSEvent struct {
	QName     string
	QType     uint16
	RCode     uint16
	Direction uint8
}

// PrivescEvent carries privilege-change bitmasks.
type PrivescEvent struct {
	OldCaps uint64
	NewCaps uint64
}

// TLSEvent carries a plaintext TLS payload snapshot.
type TLSEvent struct {
	Data      [256]byte
	DataLen   uint32
	Direction TLSDirection
	JA3       string
	JA4       string
	JA3S      string
}

// BPFProgramEvent carries bpf() syscall metadata.
type BPFProgramEvent struct {
	Cmd      uint32
	Ret      int32
	ProgType uint32
}

// IOUringEvent carries io_uring setup/enter metadata.
type IOUringEvent struct {
	Op       uint8
	Flags    uint32
	Fd       int32
	ToSubmit uint32
}

// KmodEvent carries kernel-module load metadata.
type KmodEvent struct {
	ModName   string
	FromTmpfs bool
}

// NetCloseEvent carries TCP-connection-close metadata including duration.
type NetCloseEvent struct {
	Dport    uint16
	Sport    uint16
	Daddr    [16]byte
	Saddr    [16]byte
	Family   AddressFamily
	Duration time.Duration
}

// GPUEvent carries GPU operation metadata (CUDA/ROCm intercept).
type GPUEvent struct {
	Op      uint8
	Size    uint64
	DevPtr  uint64
	HostPtr uint64
}

// CloudAuditEvent carries a cloud-provider audit log entry.
type CloudAuditEvent struct {
	Provider    string
	Service     string
	Action      string
	Principal   string
	ResourceARN string
	SourceIP    string
	UserAgent   string
	ErrorCode   string
	Region      string
	EventID     string
}

// Event is the unified kernel event passed to the rule engine.
type Event struct {
	PID               uint32
	TGID              uint32
	UID               uint32
	Comm              [16]byte
	ParentComm        [16]byte
	ProcArgs          string
	ProcArgsTruncated bool
	Type              EventType
	Timestamp         uint64

	Syscall    *SyscallEvent
	Network    *NetworkEvent
	File       *FileEvent
	DNS        *DNSEvent
	Privesc    *PrivescEvent
	TLS        *TLSEvent
	BPFProgram *BPFProgramEvent
	IOUring    *IOUringEvent
	Kmod       *KmodEvent
	NetClose   *NetCloseEvent
	GPU        *GPUEvent
	CloudAudit *CloudAuditEvent
}

// Alert is produced when a rule matches an event.
type Alert struct {
	Timestamp time.Time
	RuleID    string
	RuleName  string
	Severity  AlertSeverity
	Message   string
	PID       uint32
	Comm      string
	Event     Event
	Action    string
}

var bpfCmdNames = map[uint32]string{
	0: "BPF_MAP_CREATE", 1: "BPF_MAP_LOOKUP_ELEM", 2: "BPF_MAP_UPDATE_ELEM",
	3: "BPF_MAP_DELETE_ELEM", 4: "BPF_MAP_GET_NEXT_KEY", 5: "BPF_PROG_LOAD",
	6: "BPF_OBJ_PIN", 7: "BPF_OBJ_GET", 8: "BPF_PROG_ATTACH",
	9: "BPF_PROG_DETACH", 10: "BPF_PROG_TEST_RUN", 11: "BPF_PROG_GET_NEXT_ID",
	12: "BPF_MAP_GET_NEXT_ID", 13: "BPF_PROG_GET_FD_BY_ID",
	14: "BPF_MAP_GET_FD_BY_ID", 15: "BPF_OBJ_GET_INFO_BY_FD",
	16: "BPF_PROG_QUERY", 17: "BPF_RAW_TRACEPOINT_OPEN", 18: "BPF_BTF_LOAD",
	19: "BPF_BTF_GET_FD_BY_ID", 20: "BPF_TASK_FD_QUERY",
	21: "BPF_MAP_LOOKUP_AND_DELETE_ELEM", 22: "BPF_MAP_FREEZE",
	23: "BPF_BTF_GET_NEXT_ID", 24: "BPF_MAP_LOOKUP_BATCH",
	25: "BPF_MAP_UPDATE_BATCH", 26: "BPF_MAP_DELETE_BATCH",
}

// BPFCmdName returns a human-readable name for a bpf() command number.
func BPFCmdName(cmd uint32) string {
	if name, ok := bpfCmdNames[cmd]; ok {
		return name
	}
	return "BPF_CMD_" + strconv.FormatUint(uint64(cmd), 10)
}

// bpfProgTypeNames matches the mapping used by ruletest.bpfProgTypeByName so
// that prog_type round-trips through Build() → BPFProgTypeName correctly.
var bpfProgTypeNames = map[uint32]string{
	0: "SOCKET_FILTER", 3: "SCHED_CLS", 4: "SCHED_ACT",
	5: "TRACEPOINT", 6: "XDP", 8: "CGROUP_SKB",
	11: "SK_MSG", 15: "KPROBE", 17: "CGROUP_SOCK_ADDR",
	26: "LSM", 28: "STRUCT_OPS", 31: "SK_LOOKUP",
}

// BPFProgTypeName returns a human-readable name for a BPF program type number.
func BPFProgTypeName(progType uint32) string {
	if name, ok := bpfProgTypeNames[progType]; ok {
		return name
	}
	return "PROG_TYPE_" + strconv.FormatUint(uint64(progType), 10)
}
