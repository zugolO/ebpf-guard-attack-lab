"""
Integration tests: io_uring as a syscall-detection evasion channel (task D).

io_uring lets a process submit file/network I/O to a kernel-consumed ring, so
the application calls only io_uring_setup(2) / io_uring_enter(2) while the
actual read(2)/connect(2) never executes. These tests spawn real children that
use raw io_uring and ask what the live ebpf-guard daemon reports:

  * the ring submission IS visible (iouring_unexpected_setup / _enter fire), but
  * the operation behind it is NOT: the event model exposes only op/tosubmit/
    flags/fd, so a ring read of /etc/shadow and a ring connect to :3389 are
    indistinguishable from a bare io_uring_enter.

The last point is the documented KNOWN BYPASS. It is asserted as the documented
NON-outcome (no cred_shadow_read, no lateral_rdp_connection) next to a positive
that proves the ring activity really reached the daemon, so the gap cannot be
silently skipped. If such an assertion ever fails, the daemon has gained
ring-operation payload/path visibility -- flip that test to a positive.

Requirements: root + a running ebpf-guard daemon + a Linux eBPF kernel with
io_uring. The whole module skips otherwise (including on macOS), so it is safe
to collect on a developer machine. It is NOT executed on macOS.
"""

import os
from pathlib import Path

import pytest

from attacks.iouring_attacks import (
    EXIT_NO_TARGET,
    benign_no_iouring_wait,
    io_uring_setup_probe,
    io_uring_supported,
    ring_connect_loopback,
    ring_openat_and_read,
    ring_read_file,
)


def _daemon_available() -> bool:
    sock = os.getenv("EBPF_GUARD_ALERT_SOCKET", "/run/ebpf-guard/alerts.sock")
    return Path(sock).exists() or bool(os.getenv("EBPF_GUARD_ALERT_LOG"))


_HAS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
_IOURING = io_uring_supported()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not (_HAS_ROOT and _daemon_available()),
        reason="requires root + a running ebpf-guard daemon (see conftest.py)",
    ),
    pytest.mark.skipif(
        not _IOURING,
        reason="io_uring not available on this kernel",
    ),
]


def _reap(proc, what: str) -> None:
    """Reap a generator child and assert its ring operation really executed.

    The generators communicate through their exit code (see
    ``attacks.iouring_attacks``): ``EXIT_NO_TARGET`` means the environment lacked
    the target, which is a clean skip. Any other non-zero exit means the ring op
    did not execute, so a following "no alert" assertion would pass vacuously --
    fail loudly instead.
    """
    proc.wait(timeout=10)
    if proc.returncode == EXIT_NO_TARGET:
        pytest.skip(f"{what}: target missing/unreadable in this environment")
    assert proc.returncode == 0, (
        f"{what}: ring operation did not execute (exit {proc.returncode}), so "
        "the documented non-outcome would be vacuous"
    )


def _assert_positive_not_bypass(
    alerts, pid: int, positive_rule: str, bypass_rule: str
) -> None:
    """Assert `positive_rule` fires for `pid` while `bypass_rule` does not.

    ``AlertCollector.wait_for_alert`` consumes and discards non-matching alerts,
    so waiting for the positive alert first would silently swallow a
    ``bypass_rule`` alert the daemon emitted before -- or in the same processing
    burst as -- the positive one (emission order within a burst is arbitrary).
    Matching BOTH rules in the predicate makes the first of the two alerts the
    return value, so a file/network alert winning that race fails loudly instead
    of disappearing; ``wait_for_no_alert`` then covers an alert emitted after
    the positive one. (conftest.py is shared, so this stays local.)
    """
    first = alerts.wait_for_alert(
        pid=pid,
        predicate=lambda a: a.rule_id in (positive_rule, bypass_rule),
        timeout=5,
    )
    assert first.rule_id == positive_rule, (
        f"documented io_uring bypass no longer holds: {bypass_rule} fired for "
        f"pid={pid} before {positive_rule}"
    )
    alerts.wait_for_no_alert(rule_id=bypass_rule, pid=pid, window=3)


def test_iouring_setup_fires_setup_rule(alerts):
    """POSITIVE: a process calling io_uring_setup(2) is reported.

    python3 is not in the rule's allowlist, so iouring_unexpected_setup fires.
    This is the non-vacuous baseline for the bypass tests below: it proves the
    daemon actually sees io_uring activity at all.
    """
    proc = io_uring_setup_probe()
    pid = proc.pid
    _reap(proc, "io_uring_setup probe")

    alert = alerts.wait_for_alert(
        rule_id="iouring_unexpected_setup", pid=pid, timeout=5
    )
    assert alert.pid == pid
    assert alert.severity == "warning"


def test_ring_read_fires_enter_rule(alerts, tmp_path):
    """POSITIVE: a read submitted through the ring is reported.

    The file is opened normally, but the read(2) itself is replaced by an
    IORING_OP_READ submitted via io_uring_enter(2); python3 is not in the enter
    rule's allowlist, so iouring_unexpected_enter fires.
    """
    benign = tmp_path / "ring-read.txt"
    benign.write_bytes(b"ebpf-guard io_uring probe\n")

    proc = ring_read_file(path=str(benign), iterations=4)
    pid = proc.pid
    _reap(proc, "ring read child")

    alert = alerts.wait_for_alert(
        rule_id="iouring_unexpected_enter", pid=pid, timeout=5
    )
    assert alert.pid == pid
    assert alert.severity == "critical"


def test_high_volume_ring_submit_fires_high_volume_rule(alerts, tmp_path):
    """POSITIVE: one io_uring_enter with >32 SQEs is flagged.

    Submits 64 IORING_OP_READ SQEs in a single enter (python3 is not
    allowlisted), which trips iouring_high_volume_submit (to_submit > 32).
    """
    benign = tmp_path / "ring-batch.txt"
    benign.write_bytes(b"x" * 4096)

    proc = ring_read_file(path=str(benign), iterations=64)
    pid = proc.pid
    _reap(proc, "ring batch child")

    alert = alerts.wait_for_alert(
        rule_id="iouring_high_volume_submit", pid=pid, timeout=5
    )
    assert alert.pid == pid
    assert alert.severity == "warning"


def test_ring_openat_read_of_shadow_is_a_documented_known_bypass(alerts):
    """KNOWN BYPASS (asserted as the documented non-outcome).

    The child opens /etc/shadow *through the ring* (IORING_OP_OPENAT) and reads
    it with IORING_OP_READ, so neither open(2) nor read(2) ever executes.
    ebpf-guard's io_uring event model exposes only op/to_submit/flags/fd -- no
    target path -- so no file rule (cred_shadow_read) can match: the ring read
    is indistinguishable from a bare io_uring_enter. Expected: no
    cred_shadow_read alert for this pid.

    The positive half asserts the generic iouring_unexpected_enter DOES fire, so
    the non-outcome is not vacuous and the ring read really reached the daemon.
    The child additionally exits non-zero if the ring OPENAT/READ did not
    execute, so a failed op can never stand in for the documented miss.
    """
    if not (os.path.exists("/etc/shadow") and os.access("/etc/shadow", os.R_OK)):
        pytest.skip("/etc/shadow not present or unreadable")

    proc = ring_openat_and_read(path="/etc/shadow", reads=2)
    pid = proc.pid
    _reap(proc, "ring openat child")

    _assert_positive_not_bypass(
        alerts, pid, "iouring_unexpected_enter", "cred_shadow_read"
    )


def test_ring_connect_is_a_documented_known_bypass(alerts):
    """KNOWN BYPASS: a TCP connect issued through the ring is not a connect(2).

    socket(2) creates the socket normally, but the connect(2) is replaced by
    IORING_OP_CONNECT submitted through io_uring, so a connect/dport-based rule
    keyed on the network event (lateral_rdp_connection, port 3389) never sees
    the target. Expected: no lateral_rdp_connection for this pid, while the
    generic iouring_unexpected_enter still fires.

    The connection targets loopback only and is dropped immediately (the
    generator refuses any non-loopback host). The child exits non-zero if the
    ring CONNECT never ran, so the miss cannot be asserted vacuously.
    """
    proc = ring_connect_loopback(port=3389, iterations=2)
    pid = proc.pid
    _reap(proc, "ring connect child")

    _assert_positive_not_bypass(
        alerts, pid, "iouring_unexpected_enter", "lateral_rdp_connection"
    )


def test_benign_process_without_io_uring_does_not_fire(alerts):
    """NEAR-MISS NEGATIVE: a process that never touches io_uring.

    Keeps the io_uring positives non-vacuous: a child doing nothing must not
    produce any alert for its pid.
    """
    proc = benign_no_iouring_wait(seconds=0.3)
    pid = proc.pid
    proc.wait(timeout=10)
    assert proc.returncode == 0, "benign control child failed unexpectedly"

    alerts.wait_for_no_alert(pid=pid, window=2)
