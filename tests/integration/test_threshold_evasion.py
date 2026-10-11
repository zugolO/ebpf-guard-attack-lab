"""
Integration tests: threshold evasion / low-and-slow (issue #29).

An attacker who keeps its rate just below a detection threshold can still
achieve its goal. Three different questions are tested here:

  * NO-SILENT-SUPPRESSION (EVASION guard): cred_shadow_read is a per-access
    *signature* rule. A low-and-slow sequence of /etc/shadow reads must produce
    an alert for EVERY access -- a rule-level rate limit that dropped the 2nd..Nth
    read would be a silent detection bypass, so the test asserts all N alerts.
  * EVASION: a slow, jittered TCP beacon must stay invisible to
    beacon_fixed_interval (which needs conn_periodic_count_5m > 2 and a low
    coefficient of variation), while a fixed-interval positive control DOES
    fire.
  * PROFILER NEGATIVE + POSITIVE CONTROL: a predictable benign healthcheck
    must NOT be scored as an anomaly_detection (EWMA profiler) anomaly, while a
    deliberate post-learning behaviour burst MUST be -- otherwise the negative
    would pass vacuously.

The EWMA/rate-limit code lives only in the real ebpf-guard daemon; this lab's
copied correlator has no threshold/EWMA logic, so these behaviours are
verifiable ONLY against the live daemon (the Python integration layer), never
in the Go/YAML rule engine. See tests/rules/threshold_evasion_test.yaml for the
Go-side regression guard.

CAVEAT (rule ids are daemon assumptions): neither "beacon_fixed_interval" nor
"anomaly_detection" appears in this repo's rules/ -- they name the live
daemon's rule set, and the thresholds asserted here (conn_periodic_count_5m > 2,
coefficient of variation < 0.35, learning_period 10s / min_learning_samples 10)
come from the test profile and the issue description. Both ids and thresholds
MUST be confirmed against the running daemon on the VM before trusting a green
run.

Requirements: root + a running ebpf-guard daemon + a Linux eBPF kernel. The
whole module skips otherwise, so it is safe to collect on a developer machine
(e.g. macOS). It is NOT executed on macOS.
"""

import os
from pathlib import Path

import pytest

from attacks.beacon_attacks import c2_beacon_fixed_interval
from attacks.threshold_attacks import (
    behavior_burst,
    benign_healthcheck,
    low_and_slow_shadow_reads,
    slow_jittered_beacon,
)


def _daemon_available() -> bool:
    sock = os.getenv("EBPF_GUARD_ALERT_SOCKET", "/run/ebpf-guard/alerts.sock")
    return Path(sock).exists() or bool(os.getenv("EBPF_GUARD_ALERT_LOG"))


_HAS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not (_HAS_ROOT and _daemon_available()),
        reason="requires root + a running ebpf-guard daemon (see conftest.py)",
    ),
]


def test_low_and_slow_shadow_reads_alert_on_every_access(alerts):
    """NO-SILENT-SUPPRESSION: 5 slow reads of /etc/shadow must alert 5 times.

    Expected: alert on EVERY access. A rate-limited engine that suppressed any
    access would let a low-and-slow credential thief read the shadow file
    silently, so this is the evasion guard for signature rules.
    """
    if not os.path.exists("/etc/shadow"):
        pytest.skip("/etc/shadow not present")

    count = 5
    proc = low_and_slow_shadow_reads(count=count, interval=1.0)
    pid = proc.pid
    proc.wait(timeout=20)
    assert proc.returncode == 0, "low-and-slow child failed before reading"

    # Consume exactly `count` matching alerts — one per access, none dropped.
    # Per-wait timeout 4s keeps the pathological path (5 x 4s waits + child)
    # comfortably inside the suite's `pytest --timeout=30`.
    for i in range(count):
        alert = alerts.wait_for_alert(
            rule_id="cred_shadow_read", pid=pid, timeout=4
        )
        assert alert.pid == pid
        assert alert.rule_id == "cred_shadow_read"


def test_slow_jittered_beacon_stays_below_threshold(alerts):
    """EVASION: a slow, jittered beacon must NOT trip beacon_fixed_interval.

    Three connections inside the 5-minute window *satisfy* the rule's count
    test (conn_periodic_count_5m > 2), so the evasion must come from timing:
    the two inter-connection gaps alternate high/low (4.5s, 1.5s with the
    defaults), giving a coefficient of variation of 0.5-0.71 -- well above the
    0.35 the rule requires. Expected: no alert. The beacon uses a unique dport
    (4455) so other suites' 4444 traffic cannot pollute the counter.
    """
    proc = slow_jittered_beacon(count=3, base_interval=3.0)
    pid = proc.pid
    proc.wait(timeout=20)
    assert proc.returncode == 0, "jittered-beacon child failed before connecting"

    alerts.wait_for_no_alert(rule_id="beacon_fixed_interval", pid=pid, window=3)


def test_fixed_interval_beacon_is_detected(alerts):
    """Positive control for the beacon test above: the same channel with a
    fixed interval and enough connections DOES fire beacon_fixed_interval.

    Expected: alert. Without this control, a 'no alert' result above could just
    mean the rule was never loaded or the dport is excluded.
    """
    proc = c2_beacon_fixed_interval(interval=1.0, count=3)
    pid = proc.pid
    proc.wait(timeout=20)

    alert = alerts.wait_for_alert(
        rule_id="beacon_fixed_interval", pid=pid, timeout=10
    )
    assert alert.pid == pid


def test_benign_healthcheck_does_not_trigger_anomaly(alerts):
    """NEGATIVE: a predictable periodic healthcheck must not become an anomaly.

    Production semantics: this pattern runs ~every 30s, which cannot fit inside
    the pytest --timeout=30 used by docker-compose.test.yml. The test profile
    (hack/ebpf-guard.test.yaml) shortens the profiler learning_period to 10s and
    min_learning_samples to 10. Its two-events-per-iteration shape means count=8
    emits ~16 events over ~16s, so this pid has actually left the learning phase
    before the assertion -- without that margin the negative would pass
    vacuously. Expected: no anomaly_detection alert for this pid. The positive
    control below proves the same rule can fire at all.
    """
    proc = benign_healthcheck(count=8, interval=2.0)
    pid = proc.pid
    proc.wait(timeout=25)
    assert proc.returncode == 0, "healthcheck child failed before emitting events"

    alerts.wait_for_no_alert(rule_id="anomaly_detection", pid=pid, window=3)


def test_behavior_burst_triggers_anomaly(alerts):
    """POSITIVE CONTROL: a post-learning behaviour burst MUST become an anomaly.

    The burst child emits a quiet baseline for > learning_period (10s) and
    >= min_learning_samples (10), then floods the same pid with rapid
    connections. Expected: an anomaly_detection alert for this pid. This is what
    keeps the preceding negative from being self-fulfilling.
    """
    proc = behavior_burst()
    pid = proc.pid
    proc.wait(timeout=20)
    assert proc.returncode == 0, "behaviour-burst child failed before emitting events"

    alert = alerts.wait_for_alert(
        rule_id="anomaly_detection", pid=pid, timeout=8
    )
    assert alert.pid == pid
