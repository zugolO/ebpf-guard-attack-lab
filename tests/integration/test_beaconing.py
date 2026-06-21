"""
Integration tests: C2 beaconing and long-lived connections (EventNetClose).

EventNetClose fires when a connection closes — tests wait for subprocess
completion before asserting alerts. EventNetClose is Python-layer only — see #6.
"""

import pytest
from attacks.beacon_attacks import (
    c2_beacon_fixed_interval,
    long_lived_tcp_connection,
    c2_beacon_jitter,
    dns_beacon,
    database_connection_pool,
)


pytestmark = pytest.mark.integration


def test_c2_fixed_interval_beacon_fires_alert(alerts):
    # Short interval and low count so the test finishes quickly.
    proc = c2_beacon_fixed_interval(interval=1.0, count=3)
    pid = proc.pid
    proc.wait(timeout=30)

    alert = alerts.wait_for_alert(
        rule_id="beacon_fixed_interval",
        pid=pid,
        timeout=10,
    )
    assert alert.severity in ("warning", "critical")


def test_long_lived_connection_fires_alert(alerts):
    proc = long_lived_tcp_connection(duration_sec=10)
    pid = proc.pid
    proc.wait(timeout=20)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "long" in a.rule_id.lower() or "connection" in a.rule_id.lower(),
        pid=pid,
        timeout=10,
    )
    assert alert.pid == pid


def test_jitter_beacon_fires_alert(alerts):
    proc = c2_beacon_jitter(base_interval=1.0, jitter=0.3, count=3)
    pid = proc.pid
    proc.wait(timeout=30)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "beacon" in a.rule_id.lower() or "c2" in a.rule_id.lower(),
        pid=pid,
        timeout=10,
    )
    assert alert.pid == pid


def test_dns_beacon_fires_alert(alerts):
    # Small interval and count to keep the test duration manageable.
    proc = dns_beacon(interval=1.0, count=3)
    pid = proc.pid
    proc.wait(timeout=30)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "dns" in a.rule_id.lower() or "beacon" in a.rule_id.lower(),
        pid=pid,
        timeout=10,
    )
    assert alert.pid == pid


def test_database_keepalive_does_not_fire(alerts):
    proc = database_connection_pool()
    pid = proc.pid
    proc.wait(timeout=15)

    alerts.wait_for_no_alert(
        rule_id="long_lived_connection_unusual",
        pid=pid,
        window=3,
    )
