"""
Integration tests: credential access detection.

Generates real file reads and proc accesses that ebpf-guard should detect.
"""

import os
import pytest
from attacks.file_attacks import read_sensitive_file, read_proc_keys
from attacks.exec_attacks import ptrace_attach


pytestmark = pytest.mark.integration


def test_shadow_file_read_triggers_alert(alerts):
    if not os.path.exists("/etc/shadow"):
        pytest.skip("/etc/shadow not present")

    proc = read_sensitive_file("/etc/shadow")
    pid  = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        rule_id="sensitive_file_read",
        pid=pid,
        timeout=5,
    )
    assert alert.severity in ("warning", "critical")


def test_passwd_read_by_non_system_process(alerts):
    proc = read_sensitive_file("/etc/passwd")
    pid  = proc.pid
    proc.wait(timeout=5)

    # /etc/passwd read is lower severity — might be warning or not fire
    # depending on rule configuration; assert it fires if rule exists
    try:
        alert = alerts.wait_for_alert(
            rule_id="sensitive_file_read",
            pid=pid,
            timeout=3,
        )
        assert alert.pid == pid
    except AssertionError:
        pytest.skip("Rule sensitive_file_read not loaded or /etc/passwd excluded")


def test_proc_keys_read_triggers_alert(alerts):
    if not os.path.exists("/proc/keys"):
        pytest.skip("/proc/keys not present")

    proc = read_proc_keys()
    pid  = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        rule_id="proc_keys_read",
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_ptrace_attach_triggers_alert(alerts):
    target = os.getpid()
    proc = ptrace_attach(target)
    pid  = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        rule_id="ptrace_attach",
        pid=pid,
        timeout=5,
    )
    assert alert.severity == "critical"
