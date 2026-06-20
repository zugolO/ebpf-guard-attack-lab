"""Privilege escalation attack generators."""

import subprocess


def gain_cap_sys_admin() -> subprocess.Popen:
    """
    Subprocess that calls capset() to gain CAP_SYS_ADMIN.
    Requires starting with sufficient privileges.
    Triggers privesc / caps_gained rules.
    """
    code = """
import ctypes, struct
CAP_SYS_ADMIN = 21
# _LINUX_CAPABILITY_VERSION_3 = 0x20080522
hdr = struct.pack("II", 0x20080522, 0)
data = struct.pack("IIII",
    (1 << CAP_SYS_ADMIN),  # effective
    (1 << CAP_SYS_ADMIN),  # permitted
    0, 0,                   # inheritable (both sets)
)
libc = ctypes.CDLL(None)
libc.capset(ctypes.c_char_p(hdr), ctypes.c_char_p(data))
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def setuid_to_root() -> subprocess.Popen:
    """Attempt setuid(0) — triggers uid-change rules."""
    code = "import os; os.setuid(0)"
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def gain_cap_net_raw() -> subprocess.Popen:
    """Gain CAP_NET_RAW (raw socket / packet capture capability)."""
    code = """
import ctypes, struct
CAP_NET_RAW = 13
hdr = struct.pack("II", 0x20080522, 0)
data = struct.pack("IIII", (1 << CAP_NET_RAW), (1 << CAP_NET_RAW), 0, 0)
libc = ctypes.CDLL(None)
libc.capset(ctypes.c_char_p(hdr), ctypes.c_char_p(data))
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def mount_proc_in_container() -> subprocess.Popen:
    """
    Attempt to remount /proc — container escape prerequisite.
    Triggers mount / container-escape rules.
    """
    return subprocess.Popen(
        ["python3", "-c",
         "import ctypes; libc=ctypes.CDLL(None); "
         "libc.mount(b'/proc', b'/proc', b'proc', 0, None)"],
        stderr=subprocess.DEVNULL,
    )


def nsenter_pid1() -> subprocess.Popen:
    """Enter PID namespace of PID 1 — container escape via nsenter."""
    return subprocess.Popen(
        ["nsenter", "--target", "1", "--pid", "--", "true"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
