"""
Integration tests: watchdog / self-tamper evasion (issue #33).

The detector is itself a target: an attacker can kill the ebpf-guard process,
detach its BPF programs with bpftool, or flood the ring buffer until the
watchdog/attestation tick starves. These tests answer whether that tampering is
detectable *externally* -- via the heartbeat metric
(ebpf_guard_heartbeat_timestamp_seconds) and the alert stream -- rather than
only by the agent's own unit tests.

  * positive -- after the daemon is killed the externally scraped heartbeat
                stops advancing; after bpftool detaches its program a tamper
                signal (alert or heartbeat freeze) is observed.
  * negative -- a ring-buffer flood must NOT stop the heartbeat advancing
                (liveness survives the DoS).
  * negative control -- a normal SIGHUP reload must NOT be treated as tamper:
                the heartbeat keeps advancing and no tamper alert is emitted.

DESTRUCTIVE TESTS MUST RUN ON AN ISOLATED VM AGAINST A DISPOSABLE DAEMON.
Killing the daemon or detaching its programs invalidates the session-scoped
`alerts` fixture for the rest of the run, so those tests are gated behind
EBPF_GUARD_ALLOW_DESTRUCTIVE=1 and skip otherwise. Never enable that flag
against a daemon you care about.

SKIP-ON-MISSING: every test skips cleanly (never errors) when root, the daemon,
the heartbeat metric endpoint, the daemon pid or bpftool is unavailable, so the
module collects and runs safely on a developer machine (e.g. macOS).

UNCONFIRMED ON THE STAND: the rule_id / metric name of the daemon's self-tamper
alert is not part of this repo. `_is_tamper_alert` is a best-effort predicate
over the alert text and MUST be confirmed against a real daemon on the VM.
"""

import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

import pytest

from attacks.watchdog_attacks import (
    detach_bpf_program_via_bpftool,
    find_ebpf_guard_pid,
    flood_ring_buffer_to_starve_watchdog,
    kill_ebpf_guard_daemon,
    read_heartbeat_metric,
)


def _daemon_available() -> bool:
    sock = os.getenv("EBPF_GUARD_ALERT_SOCKET", "/run/ebpf-guard/alerts.sock")
    return Path(sock).exists() or bool(os.getenv("EBPF_GUARD_ALERT_LOG"))


_HAS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
_ALLOW_DESTRUCTIVE = os.getenv("EBPF_GUARD_ALLOW_DESTRUCTIVE") == "1"
_BPFTOOL = shutil.which("bpftool")
_HEARTBEAT_WINDOW = float(os.getenv("EBPF_GUARD_HEARTBEAT_WINDOW", "3"))
_METRICS_URL = os.getenv("EBPF_GUARD_METRICS_URL", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not (_HAS_ROOT and _daemon_available()),
        reason="requires root + a running ebpf-guard daemon (see conftest.py)",
    ),
]

# Tokens that identify the daemon's self-tamper alert. UNCONFIRMED on the stand.
# Deliberately excludes "watchdog"/"heartbeat": those words appear in benign
# informational alerts (which would make the SIGHUP negative control fail
# spuriously) while the heartbeat itself is checked via the metric, not text.
_TAMPER_SIGNATURE = ("tamper", "detach", "attest", "subversion")


def _is_tamper_alert(alert) -> bool:
    """Best-effort detection of a self-tamper alert from one collected Alert."""
    blob = " ".join(
        part for part in (alert.rule_id, alert.rule_name, alert.message) if part
    ).lower()
    return any(tok in blob for tok in _TAMPER_SIGNATURE)


def _wait_for_tamper_alert(alerts, *, timeout=5):
    """Return the first self-tamper alert, or None if none arrives in time.

    AlertCollector.wait_for_alert raises AssertionError on timeout, so a
    timeout is treated as "no tamper alert observed".
    """
    try:
        return alerts.wait_for_alert(predicate=_is_tamper_alert, timeout=timeout)
    except AssertionError:
        return None


def _heartbeat_or_skip() -> float:
    value = read_heartbeat_metric()
    if value is None:
        pytest.skip(
            "no heartbeat metric at "
            f"{_METRICS_URL or 'http://127.0.0.1:9090/metrics'} "
            "(set EBPF_GUARD_METRICS_URL)"
        )
    return value


def _require_pid() -> int:
    pid = find_ebpf_guard_pid()
    if pid is None:
        pytest.skip("ebpf-guard daemon pid not found (set EBPF_GUARD_PID)")
    return pid


def test_heartbeat_metric_advances(alerts):
    """PRECONDITION: the external heartbeat metric is scrapeable and advancing.

    This makes the self-tamper tests meaningful: if the heartbeat never moved,
    a frozen heartbeat after tampering would be indistinguishable from a dead
    metric endpoint. Skips when no metric endpoint is exposed.
    """
    before = _heartbeat_or_skip()
    time.sleep(_HEARTBEAT_WINDOW)
    after = read_heartbeat_metric()
    assert after is not None, "heartbeat metric disappeared while idle"
    assert after > before, f"heartbeat did not advance: before={before} after={after}"


def test_ring_buffer_flood_does_not_stop_heartbeat(alerts):
    """NEGATIVE: a ring-buffer flood must not starve the watchdog/attestation
    tick. Expected: the externally scraped heartbeat keeps advancing, i.e.
    liveness survives the DoS.

    The flood generator bursts for ~5s; keep EBPF_GUARD_HEARTBEAT_WINDOW below
    that (default 3s) so the second sample is taken while the buffer is still
    saturated -- otherwise the negative would pass vacuously.
    """
    before = _heartbeat_or_skip()
    flood = flood_ring_buffer_to_starve_watchdog(events_per_sec=100000)
    try:
        time.sleep(_HEARTBEAT_WINDOW)
        after = read_heartbeat_metric()
    finally:
        flood.terminate()
        try:
            flood.wait(timeout=5)
        except subprocess.TimeoutExpired:
            flood.kill()
    assert after is not None, (
        "daemon stopped exporting the heartbeat during the ring-buffer flood"
    )
    assert after > before, (
        f"ring-buffer flood froze the heartbeat: before={before} after={after}"
    )


def test_sighup_reload_is_not_tamper(alerts):
    """NEGATIVE CONTROL: a normal SIGHUP reload is not self-tamper.

    Expected: the heartbeat keeps advancing and no self-tamper alert is
    emitted. SIGHUP only reloads configuration, so treating it as an attack
    would be a false positive.
    """
    pid = _require_pid()
    before = _heartbeat_or_skip()
    os.kill(pid, signal.SIGHUP)
    time.sleep(_HEARTBEAT_WINDOW)
    after = read_heartbeat_metric()
    assert after is not None, "heartbeat metric gone after the SIGHUP reload"
    assert after > before, (
        f"heartbeat did not advance across the SIGHUP reload: "
        f"before={before} after={after}"
    )
    assert _wait_for_tamper_alert(alerts, timeout=1) is None, (
        "a normal SIGHUP reload was misclassified as self-tamper"
    )


@pytest.mark.skipif(
    not _ALLOW_DESTRUCTIVE,
    reason=(
        "destructive: set EBPF_GUARD_ALLOW_DESTRUCTIVE=1 on an isolated VM "
        "with a disposable daemon (killing it invalidates the session fixture)"
    ),
)
def test_kill_daemon_freezes_external_heartbeat(alerts):
    """POSITIVE (external self-tamper detection): after the daemon is killed,
    the externally scraped heartbeat stops advancing.

    Gated behind EBPF_GUARD_ALLOW_DESTRUCTIVE=1 because it deliberately
    invalidates the session-scoped `alerts` fixture."""
    pid = _require_pid()
    before = _heartbeat_or_skip()
    # Re-check that the heartbeat is actually advancing before the kill: a
    # frozen baseline would make the freeze assertion below pass vacuously even
    # if the metric endpoint were simply dead.
    time.sleep(_HEARTBEAT_WINDOW)
    baseline = read_heartbeat_metric()
    assert baseline is not None and baseline > before, (
        "heartbeat was not advancing before the kill, so the freeze assertion "
        f"would be vacuous (before={before} baseline={baseline})"
    )
    before = baseline
    kill_ebpf_guard_daemon(pid, signal.SIGTERM)
    time.sleep(_HEARTBEAT_WINDOW)
    after = read_heartbeat_metric()
    assert after is None or after <= before, (
        f"daemon was killed but the external heartbeat kept advancing: "
        f"before={before} after={after}"
    )


@pytest.mark.skipif(
    not _ALLOW_DESTRUCTIVE,
    reason=(
        "destructive: set EBPF_GUARD_ALLOW_DESTRUCTIVE=1 on an isolated VM "
        "with a disposable daemon (detaching blinds it permanently)"
    ),
)
@pytest.mark.skipif(_BPFTOOL is None, reason="bpftool not installed")
def test_bpftool_detach_fires_external_tamper(alerts):
    """POSITIVE: detaching ebpf-guard's BPF program is externally observable.

    Expected: a self-tamper alert (best-effort predicate over rule_id /
    rule_name / message -- the exact id is UNCONFIRMED on the stand) OR the
    external heartbeat freezing. Gated behind EBPF_GUARD_ALLOW_DESTRUCTIVE=1.
    """
    proc = detach_bpf_program_via_bpftool("ebpf_guard")
    if proc is None:
        pytest.skip(
            "bpftool not installed, or ebpf_guard is not attached via a "
            "bpf_link (bpftool cannot detach a legacy perf_event attach by name)"
        )
    proc.wait(timeout=10)
    assert proc.returncode == 0, (
        "bpftool failed to detach ebpf_guard's BPF link "
        f"(exit {proc.returncode}); the detach positive is not exercised"
    )

    alert = _wait_for_tamper_alert(alerts, timeout=5)
    if alert is not None:
        # Any self-tamper alert is the externally observed detection we need.
        assert alert.rule_id or alert.message, "tamper alert carried no details"
        return

    before = read_heartbeat_metric()
    time.sleep(_HEARTBEAT_WINDOW)
    after = read_heartbeat_metric()
    frozen = after is None or (before is not None and after <= before)
    assert frozen, (
        "no externally observable self-tamper signal after bpftool detach: "
        "expected a tamper alert (rule_id/rule_name/message containing one of "
        f"{_TAMPER_SIGNATURE}) or the heartbeat to freeze, but the heartbeat "
        f"kept advancing (before={before} after={after})"
    )
