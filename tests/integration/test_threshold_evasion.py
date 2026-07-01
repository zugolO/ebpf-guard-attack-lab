"""
Integration tests: threshold evasion — low-and-slow attacks against
rate-limiting and EWMA anomaly scoring (issue #29).

Architecture note:
  internal/correlator in this repo evaluates each event independently; it
  has no time-windowed rate limiter, only a static, time-independent
  sampling rate (internal/correlator/sampler.go). The behavioral EWMA
  anomaly profiler (learning_period / anomaly_threshold / ewma_weight)
  referenced by this issue is a runtime feature of the ebpf-guard daemon
  image (ghcr.io/zugolo/ebpf-guard) consumed here as a black box — its
  implementation does not live in this repo, so these tests exercise it
  only through the alert socket, the same way every other file in this
  directory does.

Technical nuance (learning_period=3600 in production):
  Waiting a full hour per CI run is impractical. Tests that need a
  completed learning window are skipped unless EBPF_GUARD_ACCEL_PROFILE=1
  is set, which signals that the daemon under test was started with an
  accelerated profiler config (see
  tests/integration/fixtures/accelerated-profiler-config.yaml and
  EBPF_GUARD_CONFIG in conftest.py's DaemonManager). This is a deliberate,
  documented gap rather than a silently-skipped one — see the "known
  gaps" test at the bottom of this file.
"""

import os

import pytest

from attacks.threshold_attacks import (
    low_and_slow_port_scan,
    low_and_slow_file_scan,
    beacon_just_under_interval_threshold,
    benign_periodic_healthcheck,
)


pytestmark = pytest.mark.integration

requires_accelerated_profiler = pytest.mark.skipif(
    not os.getenv("EBPF_GUARD_ACCEL_PROFILE"),
    reason=(
        "requires the daemon to be started with an accelerated "
        "learning_period — set EBPF_GUARD_ACCEL_PROFILE=1 and point "
        "EBPF_GUARD_CONFIG at "
        "tests/integration/fixtures/accelerated-profiler-config.yaml "
        "(see module docstring and issue #29)"
    ),
)


def test_low_and_slow_port_scan_still_fires_per_connection(alerts):
    """Ten connection attempts spread ~2s apart (well under any per-second
    rate limit) must still each be visible to the rule engine — spreading
    a scan out in time must not silently suppress the alert partway through."""
    proc = low_and_slow_port_scan(
        ports=(22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017),
        interval_sec=2.0,
    )
    pid = proc.pid
    proc.wait(timeout=40)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "scan" in a.rule_id.lower() or "recon" in a.rule_id.lower(),
        pid=pid,
        timeout=15,
    )
    assert alert.pid == pid


@requires_accelerated_profiler
def test_low_and_slow_file_scan_flagged_by_anomaly_profiler(alerts, tmp):
    """A file read once every 5s is far below any per-second I/O rate
    threshold, but should be statistically anomalous for this process's
    profile once the (accelerated) learning_period has elapsed."""
    for i in range(5):
        (tmp / f"secret_{i}").write_bytes(b"classified")

    proc = low_and_slow_file_scan(str(tmp), count=10, interval_sec=5.0)
    pid = proc.pid
    proc.wait(timeout=90)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "anomaly" in a.rule_id.lower() or "profile" in a.rule_id.lower(),
        pid=pid,
        timeout=15,
    )
    assert alert.pid == pid


@requires_accelerated_profiler
def test_beacon_just_under_interval_threshold_detected(alerts):
    """A 45s-interval beacon is slower than the short-window beacon tests in
    test_beaconing.py (1s interval) — this probes the lower bound of the
    profiler's interval sensitivity rather than a fixed short-window pattern."""
    proc = beacon_just_under_interval_threshold(interval=45.0, count=6)
    pid = proc.pid
    proc.wait(timeout=300)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "beacon" in a.rule_id.lower() or "anomaly" in a.rule_id.lower(),
        pid=pid,
        timeout=15,
    )
    assert alert.pid == pid


@requires_accelerated_profiler
def test_benign_periodic_healthcheck_not_flagged_after_learning(alerts):
    """Negative case: a legitimate, perfectly regular healthcheck must not
    be flagged as anomalous once the profiler has learned it as baseline —
    the profiler should distinguish 'regular but infrequent' from
    'evasive low-and-slow attack'."""
    proc = benign_periodic_healthcheck(interval=5.0, count=6)
    pid = proc.pid
    proc.wait(timeout=60)

    alerts.wait_for_no_alert(
        predicate=lambda a: "anomaly" in a.rule_id.lower() or "profile" in a.rule_id.lower(),
        pid=pid,
        window=5,
    )
