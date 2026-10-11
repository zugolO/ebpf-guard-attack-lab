"""
Integration tests: TOCTOU / symlink-race (issue #33).

A checker that races an attacker's create/swap loop can be tricked into using a
sensitive file: the attacker presents a harmless-looking path at check time and
a symlink to /etc/shadow at use time. These tests spawn real processes and ask
what the live ebpf-guard daemon can observe externally:

  * the symlink(2) the racer issues IS observable (symlink-syscall rule), and
  * the *resolved* target of that symlink is NOT part of the event model, so a
    victim that opens the swapped path never produces a /etc/shadow alert.

KNOWN BYPASS (documented, not silently passed): the lab's event model has no
readlink / resolved-symlink-target field -- `EventSpec.FileSpec` exposes only
`filename`, `fd_name`, `op` (see internal/ruletest/types.go). The daemon
observes the userspace pathname handed to open(2)/symlink(2), not the inode a
symlink resolves to. The resolved-target test below therefore asserts the
documented NON-outcome (no cred_shadow_read) for the victim; if the daemon ever
gains resolved-target resolution the assertion flips and fails loudly, which is
the intended early warning. The rename(2) shape itself is still caught on the
Go/YAML side -- ransomware_mass_rename fires and is asserted as an alert in
tests/rules/toctou_watchdog_test.yaml -- so only the resolved target is a gap.

The cron case exercises the persistence variant: the probe passes a name-based
"create" check (a regular file inside the cron directory) and is then swapped
for a symlink to the payload, so the final target is invisible to a
name-at-create rule.

Requirements: root + a running ebpf-guard daemon + a Linux eBPF kernel. The
whole module skips otherwise, so it is safe to collect on a developer machine
(e.g. macOS). It is NOT executed on macOS.
"""

import os
from pathlib import Path

import pytest

from attacks.race_attacks import (
    benign_regular_write,
    cron_symlink_persistence_race,
    symlink_swap_race,
    toctou_victim_read,
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


def _cron_dir() -> str:
    """Return the cron directory used for the name-at-create positive.

    Defaults to /etc/cron.d (overridable via EBPF_GUARD_CRON_DIR for the
    container/VM) and skips when it is not a writable directory. The generator
    writes a unique, never-overwriting probe and removes it again.
    """
    cron_dir = os.getenv("EBPF_GUARD_CRON_DIR", "/etc/cron.d")
    if not os.path.isdir(cron_dir) or not os.access(cron_dir, os.W_OK):
        pytest.skip(f"{cron_dir} is not a writable cron directory")
    return cron_dir


def test_symlink_swap_race_fires_symlink_syscall_rule(alerts, tmp_path):
    """POSITIVE: the racer's symlink(2) is externally observed.

    persist_systemd_wants_symlink fires on any symlink syscall (nr=88) from a
    non-allowlisted comm, so it detects the swap half of the race regardless of
    the target. This is the non-vacuous positive for the known-bypass test
    below: the race really happens and really reaches the daemon.
    """
    benign = str(tmp_path / ".check_me")
    proc = symlink_swap_race(
        benign_path=benign, sensitive_target="/etc/shadow", iterations=50
    )
    pid = proc.pid
    proc.wait(timeout=20)
    assert proc.returncode == 0, "race child failed before creating a symlink"

    alert = alerts.wait_for_alert(
        rule_id="persist_systemd_wants_symlink", pid=pid, timeout=5
    )
    assert alert.pid == pid


def test_toctou_resolved_target_is_a_documented_known_bypass(alerts, tmp_path):
    """KNOWN BYPASS (asserted as the documented non-outcome).

    A victim stats the harmless path and then opens it while the racer swaps it
    for a symlink to /etc/shadow. The kernel follows the symlink, so the victim
    may genuinely read /etc/shadow -- but the monitor only ever sees the
    userspace pathname (the benign path), because the event model has no
    readlink / resolved-symlink-target field. Expected: NO cred_shadow_read
    alert for the victim pid.

    If this assertion ever fails, resolved-target resolution has landed (or a
    new rule keys on fd_name); flip this test to a positive.
    """
    if not os.path.exists("/etc/shadow"):
        pytest.skip("/etc/shadow not present")

    benign = str(tmp_path / ".check_me")
    racer = symlink_swap_race(
        benign_path=benign, sensitive_target="/etc/shadow", iterations=100
    )
    victim = toctou_victim_read(
        benign_path=benign, sensitive_target="/etc/shadow", iterations=100
    )
    racer.wait(timeout=20)
    victim.wait(timeout=20)
    assert racer.returncode == 0, "racer failed before swapping the path"
    assert victim.returncode == 0, "victim failed before the check->open loop"

    alerts.wait_for_no_alert(rule_id="cred_shadow_read", pid=victim.pid, window=3)


def test_cron_symlink_race_is_detected_at_create_time(alerts):
    """POSITIVE: persistence is caught by the name/op at create time.

    The racer drops a regular file into the cron directory (which satisfies
    persistence_cron_write) and then swaps it for a symlink to the payload.
    Expected: persistence_cron_write fires for the racer pid.

    KNOWN BYPASS (documented): after the swap the entry points at /tmp/evil.sh,
    but the final target is not part of the event model, so an attacker can hide
    the real payload behind a benign cron filename. The Go suite does not model
    the cron shape, so this gap is exercised by this Python test only.
    """
    cron_dir = _cron_dir()
    proc = cron_symlink_persistence_race(
        cron_dir=cron_dir, payload="/tmp/evil.sh", iterations=10
    )
    pid = proc.pid
    proc.wait(timeout=20)
    assert proc.returncode == 0, "cron race child failed before writing the probe"

    alert = alerts.wait_for_alert(
        rule_id="persistence_cron_write", pid=pid, timeout=5
    )
    assert alert.pid == pid


def test_non_symlink_benign_write_does_not_fire_symlink_rule(alerts):
    """NEAR-MISS NEGATIVE: a plain regular-file write in the same directory.

    Writing a normal file (no symlink syscall) must not satisfy the
    symlink-syscall rule, so the positive above is not vacuous. The file may
    still trip persistence_cron_write, which is ignored here; the assertion is
    scoped to the symlink rule and to this pid.
    """
    cron_dir = _cron_dir()
    probe = os.path.join(cron_dir, f".ebpf-guard-benign-{os.getpid()}")
    proc = benign_regular_write(path=probe)
    pid = proc.pid
    proc.wait(timeout=10)
    assert proc.returncode == 0, "benign write child failed unexpectedly"
    try:
        alerts.wait_for_no_alert(
            rule_id="persist_systemd_wants_symlink", pid=pid, window=2
        )
    finally:
        try:
            os.unlink(probe)
        except FileNotFoundError:
            pass
