"""
Integration tests: living-off-the-land detection using real system binaries.

Unlike Go YAML tests that inject synthetic {comm, filename} events, these
tests spawn actual curl/wget/bash/find/dd processes so ebpf-guard sees
authentic comm/pid pairs and validates the full eBPF → daemon → rule → alert
pipeline.
"""

import pytest
from attacks.lotl_attacks import (
    curl_exfil_data,
    wget_download_payload,
    python_reverse_shell,
    bash_interactive_shell,
    find_sensitive_files,
    dd_disk_image,
    apt_list_packages,
)


pytestmark = pytest.mark.integration


def test_curl_exfil_fires_alert(alerts):
    proc = curl_exfil_data()
    pid = proc.pid
    proc.wait(timeout=10)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "exfil" in a.rule_id.lower() or "curl" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.severity in ("warning", "critical")


def test_wget_payload_download_fires_alert(alerts):
    proc = wget_download_payload()
    pid = proc.pid
    proc.wait(timeout=10)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "wget" in a.rule_id.lower() or "download" in a.rule_id.lower()
                             or "tmp" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_python_reverse_shell_fires_alert(alerts):
    proc = python_reverse_shell()
    pid = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "shell" in a.rule_id.lower() or "reverse" in a.rule_id.lower()
                             or "lotl" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_bash_interactive_shell_fires_alert(alerts):
    proc = bash_interactive_shell()
    pid = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "shell" in a.rule_id.lower() or "bash" in a.rule_id.lower()
                             or "interactive" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_find_sensitive_files_fires_alert(alerts):
    proc = find_sensitive_files()
    pid = proc.pid
    proc.wait(timeout=10)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "sensitive" in a.rule_id.lower() or "recon" in a.rule_id.lower()
                             or "find" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_dd_disk_image_fires_alert(alerts):
    proc = dd_disk_image()
    pid = proc.pid
    proc.wait(timeout=10)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "disk" in a.rule_id.lower() or "dd" in a.rule_id.lower()
                             or "raw_" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.severity in ("warning", "critical")


def test_apt_get_list_does_not_fire(alerts):
    proc = apt_list_packages()
    pid = proc.pid
    proc.wait(timeout=15)

    alerts.wait_for_no_alert(pid=pid, window=2)
