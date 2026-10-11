"""
Integration tests: namespace / mount evasion (PLAN.md task E).

Key question: does ebpf-guard resolve paths in the host namespace, or can an
attacker blind it by switching namespace?

Answer documented by these tests: ebpf-guard observes the *userspace pathname*
handed to ``open(2)`` (the lab event model, internal/ruletest/types.go
``FileSpec``, carries only ``filename``/``fd_name``/``op``/``flags`` and has no
namespace or resolved-path field). Consequently:

  * POSITIVE -- a reader in a brand-new mount namespace
    (``unshare(CLONE_NEWNS)``) or PID namespace (``unshare(CLONE_NEWPID)`` +
    ``fork``) still opens "/etc/shadow" by that name, so cred_shadow_read still
    fires. A namespace switch alone does not blind the agent.
  * POSITIVE -- a plain read of /etc/shadow fires cred_shadow_read (control, so
    the namespace tests below cannot pass vacuously).
  * KNOWN BYPASS -- the same inode reached through the host-root escape
    ``/proc/1/root/etc/shadow``, or through a bind mount presented under a
    benign pathname, is NOT matched: cred_shadow_read compares
    ``filename == "/etc/shadow"`` exactly. These are asserted as the documented
    NON-outcome; if the daemon ever gains namespace/mount-aware path resolution
    the assertions flip and fail loudly, which is the intended early warning.
  * NEGATIVE CONTROL -- a harmless read raises no alert at all.

The same pathname-equality gap is asserted on the Go/YAML side as ``known_bypass``
mutants in tests/rules/credential_access_test.yaml (cred_shadow_read) and
tests/rules/lateral_movement_test.yaml (lateral_ssh_agent_socket_access, whose
"/tmp/ssh-" prefix also misses /proc/1/root/... and bind-mounted paths).

Requirements: root + a running ebpf-guard daemon + Linux. The whole module skips
otherwise, so it collects safely on a developer machine (e.g. macOS). It is NOT
executed on macOS; only ``py_compile`` / ``pytest --collect-only`` can be checked
there.
"""

import os
from pathlib import Path

import pytest

from attacks.namespace_attacks import (
    READ_FAILED,
    SETUP_FAILED,
    bind_mount_shadow_read,
    direct_shadow_read,
    mount_ns_shadow_read,
    pid_ns_shadow_read,
    proc1root_shadow_read,
    read_benign_file,
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


def _require_shadow():
    if not os.path.exists("/etc/shadow"):
        pytest.skip("/etc/shadow not present")


def test_direct_shadow_read_fires(alerts):
    """POSITIVE CONTROL: a plain read of /etc/shadow fires cred_shadow_read.

    This is the baseline the namespace probes are compared against; without it a
    "no alert" result elsewhere could just mean the rule was never loaded.
    """
    _require_shadow()
    proc = direct_shadow_read()
    pid = proc.pid
    proc.wait(timeout=10)
    assert proc.returncode == 0, "direct shadow-read child failed"

    alert = alerts.wait_for_alert(rule_id="cred_shadow_read", pid=pid, timeout=5)
    assert alert.pid == pid


def test_mount_namespace_read_still_fires(alerts):
    """POSITIVE / NAMESPACE-AGNOSTIC: unshare(CLONE_NEWNS) + read /etc/shadow.

    The reader still hands "/etc/shadow" to open(2), so the pathname rule fires
    even though the process runs in a fresh mount namespace. Expected: alert.
    """
    _require_shadow()
    proc = mount_ns_shadow_read()
    pid = proc.pid
    proc.wait(timeout=10)
    if proc.returncode == SETUP_FAILED:
        pytest.skip("unshare(CLONE_NEWNS) not permitted (no CAP_SYS_ADMIN?)")
    assert proc.returncode == 0, "mount-namespace reader failed unexpectedly"

    alert = alerts.wait_for_alert(rule_id="cred_shadow_read", pid=pid, timeout=5)
    assert alert.pid == pid


def test_pid_namespace_read_still_fires(alerts):
    """POSITIVE / NAMESPACE-AGNOSTIC: unshare(CLONE_NEWPID) + fork + read.

    The forked reader is pid 1 of the new PID namespace and opens "/etc/shadow"
    by name, so the pathname rule fires. Matched on comm because the reader is a
    grandchild whose host pid the test cannot know. Expected: alert.
    """
    _require_shadow()
    proc = pid_ns_shadow_read()
    proc.wait(timeout=10)
    if proc.returncode == SETUP_FAILED:
        pytest.skip("unshare(CLONE_NEWPID)/fork not permitted")
    assert proc.returncode == 0, "pid-namespace reader failed unexpectedly"

    alert = alerts.wait_for_alert(
        rule_id="cred_shadow_read", comm="nspid", timeout=5
    )
    assert alert.comm == "nspid"


def test_proc1root_read_is_a_documented_known_bypass(alerts):
    """KNOWN BYPASS (asserted as the documented non-outcome).

    /proc/1/root/etc/shadow reaches the same sensitive inode through pid 1's
    root (the host root when read from inside a namespace). open(2) receives
    "/proc/1/root/etc/shadow", and cred_shadow_read requires
    filename == "/etc/shadow", so no alert fires. Skips when the escape path is
    unavailable. If this ever fails, root/namespace-aware path resolution has
    landed; flip it to a positive.
    """
    _require_shadow()
    if not os.access("/proc/1/root/etc/shadow", os.R_OK):
        pytest.skip("/proc/1/root/etc/shadow not readable")
    proc = proc1root_shadow_read()
    pid = proc.pid
    proc.wait(timeout=10)
    if proc.returncode == READ_FAILED:
        pytest.skip("read via /proc/1/root did not happen; bypass unproven")
    assert proc.returncode == 0, "proc1root reader failed unexpectedly"

    alerts.wait_for_no_alert(rule_id="cred_shadow_read", pid=pid, window=3)


def test_bind_mount_read_is_a_documented_known_bypass(alerts, tmp_path):
    """KNOWN BYPASS (asserted as the documented non-outcome).

    The child bind-mounts /etc/shadow onto a benign path inside its own private
    mount namespace and reads the benign path, so the sensitive content is
    reached while open(2) only ever sees the benign pathname. cred_shadow_read
    compares filename == "/etc/shadow" exactly, so no alert fires. The mount is
    local to the throwaway namespace and never touches the host mount table.

    Non-destructive: only reads. Skips when unshare/bind mount is not permitted.
    """
    _require_shadow()
    benign = str(tmp_path / "ebpf-guard-bind-probe")
    proc = bind_mount_shadow_read(benign_path=benign)
    pid = proc.pid
    proc.wait(timeout=10)
    if proc.returncode == SETUP_FAILED:
        pytest.skip("unshare(CLONE_NEWNS)/bind mount not permitted")
    if proc.returncode == READ_FAILED:
        pytest.skip("read through the bind mount did not happen; bypass unproven")
    assert proc.returncode == 0, "bind-mount reader failed unexpectedly"

    alerts.wait_for_no_alert(rule_id="cred_shadow_read", pid=pid, window=3)


def test_benign_read_does_not_fire(alerts):
    """NEGATIVE CONTROL: a harmless read raises no alert for this pid.

    Keeps the namespace assertions honest: a pid doing nothing sensitive must
    stay silent even with the same reader setup and a recognisable comm.
    """
    proc = read_benign_file()
    pid = proc.pid
    proc.wait(timeout=10)
    assert proc.returncode == 0, "benign reader failed unexpectedly"

    alerts.wait_for_no_alert(pid=pid, window=2)
