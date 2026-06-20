"""BPF / eBPF subversion attack generators."""

import ctypes
import os
import struct
import subprocess


BPF_PROG_LOAD = 5
BPF_MAP_CREATE = 0

# Minimal valid BPF_PROG_TYPE_SOCKET_FILTER program: r0=0; exit
_MINIMAL_BPF_INSN = struct.pack("BBHI", 0xb7, 0, 0, 0)  # mov r0, 0
_MINIMAL_BPF_INSN += struct.pack("BBHI", 0x95, 0, 0, 0)  # exit


def load_bpf_prog_via_subprocess() -> subprocess.Popen:
    """
    Spawn a subprocess that calls bpf(BPF_PROG_LOAD) with a minimal program.
    Uses subprocess so ebpf-guard sees a separate pid/comm.
    Requires CAP_BPF (root in test environment).
    """
    code = """
import ctypes, struct, os
NR_BPF = 321
BPF_PROG_LOAD = 5
insns = struct.pack("BBHI", 0xb7, 0, 0, 0) + struct.pack("BBHI", 0x95, 0, 0, 0)
license = b"GPL\\x00"
log_buf = ctypes.create_string_buffer(4096)
attr = struct.pack(
    "IIQQIII",
    0,           # prog_type = BPF_PROG_TYPE_SOCKET_FILTER
    len(insns)//8,
    ctypes.cast(ctypes.c_char_p(insns), ctypes.c_void_p).value or 0,
    ctypes.cast(ctypes.c_char_p(license), ctypes.c_void_p).value or 0,
    4, 4096,
    ctypes.cast(log_buf, ctypes.c_void_p).value or 0,
)
libc = ctypes.CDLL(None)
libc.syscall({NR_BPF}, BPF_PROG_LOAD, ctypes.c_char_p(attr), len(attr))
"""
    return subprocess.Popen(
        ["python3", "-c", code],
        stderr=subprocess.DEVNULL,
    )


def load_xdp_prog_via_subprocess() -> subprocess.Popen:
    """Attempt to load an XDP BPF program type — triggers xdp_tc_unauthorized."""
    code = """
import ctypes, struct
NR_BPF = 321
BPF_PROG_LOAD = 5
BPF_PROG_TYPE_XDP = 6
insns = struct.pack("BBHI", 0xb7, 0, 0, 0) + struct.pack("BBHI", 0x95, 0, 0, 0)
license = b"GPL\\x00"
log_buf = ctypes.create_string_buffer(4096)
attr = struct.pack(
    "IIQQIII",
    BPF_PROG_TYPE_XDP,
    len(insns)//8,
    ctypes.cast(ctypes.c_char_p(insns), ctypes.c_void_p).value or 0,
    ctypes.cast(ctypes.c_char_p(license), ctypes.c_void_p).value or 0,
    4, 4096,
    ctypes.cast(log_buf, ctypes.c_void_p).value or 0,
)
libc = ctypes.CDLL(None)
libc.syscall({NR_BPF}, BPF_PROG_LOAD, ctypes.c_char_p(attr), len(attr))
"""
    return subprocess.Popen(
        ["python3", "-c", code],
        stderr=subprocess.DEVNULL,
    )


def map_create_via_subprocess() -> subprocess.Popen:
    """
    Call bpf(BPF_MAP_CREATE) — should NOT trigger prog_load rules.
    Used in negative tests.
    """
    code = """
import ctypes, struct
NR_BPF = 321
BPF_MAP_CREATE = 0
BPF_MAP_TYPE_HASH = 1
attr = struct.pack("IIII", BPF_MAP_TYPE_HASH, 4, 4, 128)
libc = ctypes.CDLL(None)
libc.syscall({NR_BPF}, BPF_MAP_CREATE, ctypes.c_char_p(attr), len(attr))
"""
    return subprocess.Popen(
        ["python3", "-c", code],
        stderr=subprocess.DEVNULL,
    )
