"""
Integration tests: BPF rootkit / eBPF subversion detection.

Mirrors tests/rules/bpf_rootkit_test.yaml but generates real kernel events
by calling bpf(2) via subprocess, so ebpf-guard's eBPF programs capture them.
"""

import pytest
from attacks.bpf_attacks import (
    load_bpf_prog_via_subprocess,
    load_xdp_prog_via_subprocess,
    map_create_via_subprocess,
)


pytestmark = pytest.mark.integration


def test_unauthorized_bpf_prog_load_fires_alert(alerts):
    proc = load_bpf_prog_via_subprocess()
    pid = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        rule_id="bpf_prog_load_unauthorized",
        pid=pid,
        timeout=5,
    )
    assert alert.severity == "critical"
    assert alert.pid == pid


def test_xdp_prog_load_fires_alert(alerts):
    proc = load_xdp_prog_via_subprocess()
    pid = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        rule_id="bpf_xdp_tc_unauthorized",
        pid=pid,
        timeout=5,
    )
    assert alert.severity == "critical"


def test_bpf_map_create_does_not_fire_prog_load_rule(alerts):
    proc = map_create_via_subprocess()
    pid = proc.pid
    proc.wait(timeout=5)

    alerts.wait_for_no_alert(rule_id="bpf_prog_load_unauthorized", pid=pid, window=2)
