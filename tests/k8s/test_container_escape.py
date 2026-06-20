"""
K8s integration tests: container escape detection.

Tests various container escape techniques that ebpf-guard should detect
at the kernel level regardless of K8s admission policies.
"""

import pytest
from conftest import kubectl_exec


pytestmark = pytest.mark.k8s


def test_mount_host_proc_fires_alert(attacker_privileged_pod, alert_collector):
    """Mounting host /proc inside container — escape prerequisite."""
    kubectl_exec(
        attacker_privileged_pod,
        "python3", "-c",
        "import ctypes; libc=ctypes.CDLL(None); "
        "libc.mount(b'/proc', b'/mnt', b'proc', 0, None)",
    )
    alert_collector.collect_for(seconds=5)
    alert_collector.assert_fired(
        predicate=lambda a: "mount" in a.get("rule_id","").lower()
                            or "escape" in a.get("rule_id","").lower(),
    )


def test_cgroup_release_agent_write_fires_alert(
    attacker_privileged_pod, alert_collector
):
    """
    Write to cgroup release_agent — classic privileged container escape.
    CVE-2022-0492 pattern.
    """
    kubectl_exec(
        attacker_privileged_pod,
        "sh", "-c",
        "echo '/tmp/x' > /sys/fs/cgroup/release_agent 2>/dev/null || true",
    )
    alert_collector.collect_for(seconds=5)
    alert_collector.assert_fired(
        predicate=lambda a: "cgroup" in a.get("rule_id","").lower()
                            or "escape" in a.get("rule_id","").lower(),
    )


def test_load_kernel_module_fires_alert(attacker_privileged_pod, alert_collector):
    """
    Attempt to load a kernel module from inside a container.
    Triggers kmod_load rules even if the module doesn't exist.
    """
    kubectl_exec(
        attacker_privileged_pod,
        "sh", "-c",
        "insmod /tmp/not_a_module.ko 2>/dev/null || true",
    )
    alert_collector.collect_for(seconds=5)
    alert_collector.assert_fired(
        predicate=lambda a: "kmod" in a.get("rule_id","").lower()
                            or "kernel" in a.get("rule_id","").lower(),
    )


def test_bpf_prog_load_from_container_fires_alert(
    attacker_privileged_pod, alert_collector
):
    """BPF program load from inside a privileged container."""
    kubectl_exec(
        attacker_privileged_pod,
        "python3", "-c",
        "import ctypes,struct\n"
        "NR=321; BPF_PROG_LOAD=5\n"
        "insns=struct.pack('BBHI',0xb7,0,0,0)+struct.pack('BBHI',0x95,0,0,0)\n"
        "lic=b'GPL\\x00'\n"
        "lb=ctypes.create_string_buffer(4096)\n"
        "a=struct.pack('IIQQIII',0,len(insns)//8,"
        "ctypes.cast(ctypes.c_char_p(insns),ctypes.c_void_p).value or 0,"
        "ctypes.cast(ctypes.c_char_p(lic),ctypes.c_void_p).value or 0,"
        "4,4096,ctypes.cast(lb,ctypes.c_void_p).value or 0)\n"
        "libc=ctypes.CDLL(None)\n"
        "libc.syscall(NR,BPF_PROG_LOAD,ctypes.c_char_p(a),len(a))\n",
    )
    alert_collector.collect_for(seconds=5)
    alert_collector.assert_fired(rule_id="bpf_prog_load_unauthorized")


def test_unprivileged_container_cannot_trigger_escape_alert(
    attacker_pod, alert_collector
):
    """Unprivileged pod attempt — should get permission denied, no escape alert."""
    kubectl_exec(
        attacker_pod,
        "sh", "-c",
        "nsenter --target 1 --pid -- id 2>/dev/null || true",
    )
    alert_collector.collect_for(seconds=3)
    # nsenter fails silently — no escape should have happened
    alert_collector.assert_not_fired(rule_id="container_escape_nsenter")
