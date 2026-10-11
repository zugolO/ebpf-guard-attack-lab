"""
Integration tests: multi-stage attack chains (issue #32).

A chain is two individually-detectable steps linked by process lineage into one
unifying alert. These tests spawn real processes and answer the central
question for #32: does ebpf-guard's correlator raise a *single* chain/lineage
alert when one process performs both steps, and does it stay silent when the
same two steps are performed by two unrelated processes?

  * positive – one process performs both steps (same pid): a unifying
               chain/lineage alert tied to that pid is expected.
  * negative – two unrelated pids each perform one step: no chain/lineage
               alert may fire (the individual per-event rule alerts may still
               fire, so the assertion filters on the chain/lineage signature).

Requirements: root + a running ebpf-guard daemon. The whole module skips
otherwise, so it is safe to collect on a developer machine (e.g. macOS).

IMPORTANT / UNVERIFIED: the exact rule_id and JSON shape of ebpf-guard's
unifying chain/lineage alert is not part of this repo. `_is_chain_alert` below
is therefore a best-effort predicate over the alert text (rule_id / rule_name /
message containing "chain", "lineage" or "correlat"). It MUST be confirmed
against a real daemon on the stand; this module does not claim the signature is
verified.
"""

import os
from pathlib import Path

import pytest

from attacks.chain_attacks import run_chain_same_pid, run_chain_two_pids


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

_CHAIN_ALERT_TIMEOUT = float(os.getenv("EBPF_GUARD_TIMEOUT", "5"))

# Tokens that identify a unifying chain/lineage alert as opposed to a per-event
# rule alert. UNCONFIRMED on the stand — see the module docstring.
_CHAIN_SIGNATURE = ("chain", "lineage", "correlat")


def _is_chain_alert(alert) -> bool:
    """Best-effort detection of a chain/lineage alert from one collected Alert."""
    blob = " ".join(
        part for part in (alert.rule_id, alert.rule_name, alert.message) if part
    ).lower()
    return any(tok in blob for tok in _CHAIN_SIGNATURE)


def _wait_for_chain_alert(alerts, *, pid=None, timeout=_CHAIN_ALERT_TIMEOUT):
    """Return the first chain/lineage alert (optionally scoped to one pid), or
    None if none arrives within the timeout.

    AlertCollector.wait_for_alert raises AssertionError on timeout and
    wait_for_no_alert cannot filter by predicate, so a timeout is treated as
    "no chain alert observed".
    """
    try:
        return alerts.wait_for_alert(
            predicate=_is_chain_alert, pid=pid, timeout=timeout
        )
    except AssertionError:
        return None


def test_same_parent_two_steps_raises_chain_alert(alerts):
    """Positive case: one process performs both steps in the same pid.

    A lineage-aware correlator must emit one unifying chain/lineage alert tied
    to that process's pid.
    """
    proc = run_chain_same_pid()
    pid = proc.pid
    proc.wait(timeout=10)
    assert proc.returncode == 0, "chain child failed before completing both steps"

    alert = _wait_for_chain_alert(alerts, pid=pid)
    assert alert is not None, (
        f"expected a unifying chain/lineage alert for parent pid={pid} after it "
        f"performed both steps; none seen within {_CHAIN_ALERT_TIMEOUT}s "
        f"(predicate: rule_id/rule_name/message containing {_CHAIN_SIGNATURE})"
    )
    assert alert.pid == pid


def test_two_unrelated_pids_do_not_raise_chain_alert(alerts):
    """Negative case: the same two steps from two unrelated pids.

    Neither process exhibits both steps, so no chain/lineage alert may fire.
    Per-event rule alerts for each pid are expected and ignored by the
    chain/lineage predicate.
    """
    credential_step, lateral_step = run_chain_two_pids()
    credential_step.wait(timeout=10)
    lateral_step.wait(timeout=10)
    assert credential_step.returncode == 0, "credential-step child failed"
    assert lateral_step.returncode == 0, "lateral-step child failed"

    # Scope to this test's own processes: the two step pids plus their shared
    # parent (pytest), which a process-tree-keyed correlator could wrongly use
    # to merge them. A late duplicate chain alert from the positive test (a
    # different pid) on the session-scoped collector must not fail this test.
    scope = {credential_step.pid, lateral_step.pid, os.getpid()}
    try:
        alert = alerts.wait_for_alert(
            predicate=lambda a: _is_chain_alert(a) and a.pid in scope,
            timeout=_CHAIN_ALERT_TIMEOUT,
        )
    except AssertionError:
        alert = None
    assert alert is None, (
        "two unrelated pids each performed one step; no unifying chain/lineage "
        f"alert may fire, but got rule_id={alert.rule_id} pid={alert.pid} "
        f"message={alert.message!r}"
    )
