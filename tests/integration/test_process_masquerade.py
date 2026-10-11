"""
Integration tests: comm / argv[0] masquerade (issue #31).

Bare comm is attacker-controlled: prctl(PR_SET_NAME) rewrites
task_struct->comm, and execve() derives comm from the path used to launch the
binary, so an attacker can make kernel events look like they came from a
legitimate process (logrotate, rsync, nginx, systemd, ...).

These tests spawn real processes and answer the key question for #31: does
ebpf-guard detect via parent_comm / /proc/[pid]/exe / lineage, or only via
bare comm? The two evasion tests below document the known gap (rules keyed on
a `comm not_in [...]` allowlist are defeated by PR_SET_NAME); the argv[0]
test shows that spoofing argv[0] alone is *not* enough, because execve sets
comm from the executable path. The negative control confirms that a legitimate
process rewriting its own comm raises no alert.

Requirements: root + a running ebpf-guard daemon. The whole module skips
otherwise, so it is safe to collect on a developer machine (e.g. macOS).
"""

import os
import shutil
from pathlib import Path

import pytest

from attacks.masquerade_attacks import (
    argv0_spoofed_exec,
    benign_prctl_setname,
    spoofed_comm_open_ssh_agent,
    spoofed_comm_unlink_log,
    symlink_masquerade_exec,
)


def _daemon_available() -> bool:
    sock = os.getenv("EBPF_GUARD_ALERT_SOCKET", "/run/ebpf-guard/alerts.sock")
    return Path(sock).exists() or bool(os.getenv("EBPF_GUARD_ALERT_LOG"))


_HAS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
_WGET = shutil.which("wget")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not (_HAS_ROOT and _daemon_available()),
        reason="requires root + a running ebpf-guard daemon (see conftest.py)",
    ),
]


def test_prctl_comm_spoof_evades_log_clear_rule(alerts):
    """PR_SET_NAME('logrotate') + unlink under /var/log/.

    Known gap: evasion_log_clear excludes `comm not_in [logrotate, syslog,
    rsyslog, journald]`, so an attacker who rewrites its own comm to the
    logger name is never reported. Expected: no alert (detection would need
    /proc/[pid]/exe or the process lineage).
    """
    if not os.access("/var/log", os.W_OK):
        pytest.skip("no write access to /var/log")
    proc = spoofed_comm_unlink_log(fake_name="logrotate")
    pid = proc.pid
    proc.wait(timeout=10)
    assert proc.returncode == 0, "masquerade child failed before the probe action"

    alerts.wait_for_no_alert(rule_id="evasion_log_clear", pid=pid, window=2)


def test_prctl_comm_spoof_evades_ssh_agent_socket_rule(alerts):
    """PR_SET_NAME('rsync') + open of /tmp/ssh-*/agent.*.

    Known gap: lateral_ssh_agent_socket_access excludes `comm not_in [ssh,
    scp, sftp, rsync, git]`, so a credential thief masquerading as rsync is
    not reported. Expected: no alert.
    """
    proc = spoofed_comm_open_ssh_agent(fake_name="rsync")
    pid = proc.pid
    proc.wait(timeout=10)
    assert proc.returncode == 0, "masquerade child failed before the probe action"

    alerts.wait_for_no_alert(
        rule_id="lateral_ssh_agent_socket_access", pid=pid, window=2
    )


@pytest.mark.skipif(_WGET is None, reason="wget not installed")
def test_argv0_spoof_alone_does_not_evade_tool_transfer(alerts):
    """execve real wget with argv[0]='nginx'.

    execve() sets comm from the executable path, not argv[0], so comm is still
    'wget' and the comm-based tool-transfer rule must still fire — spoofing
    argv[0] alone is insufficient.
    """
    proc = argv0_spoofed_exec(
        real_binary=_WGET,
        fake_argv0="nginx",
        args=["-q", "-O", "/dev/null", "--timeout=1", "http://127.0.0.1:9/"],
    )
    pid = proc.pid
    proc.wait(timeout=10)

    alert = alerts.wait_for_alert(
        rule_id="lateral_tool_transfer_wget", pid=pid, timeout=5
    )
    assert alert.pid == pid


@pytest.mark.skipif(_WGET is None, reason="wget not installed")
def test_symlink_comm_spoof_evades_tool_transfer(alerts):
    """execve a symlink named 'nginx' that points at the real wget binary.

    The kernel derives comm from the exec path basename ('nginx'), so the real
    download tool is hidden from a bare-comm rule. Expected: no alert
    (detection would need /proc/[pid]/exe or the process lineage).
    """
    proc = symlink_masquerade_exec(
        real_binary=_WGET,
        fake_name="nginx",
        args=["-q", "-O", "/dev/null", "--timeout=1", "http://127.0.0.1:9/"],
    )
    pid = proc.pid
    proc.wait(timeout=10)

    alerts.wait_for_no_alert(
        rule_id="lateral_tool_transfer_wget", pid=pid, window=2
    )


def test_benign_prctl_setname_does_not_fire(alerts):
    """Negative control: a legitimate process rewrites its own comm but does
    nothing malicious — no rule may fire for its pid."""
    proc = benign_prctl_setname(fake_name="logrotate")
    pid = proc.pid
    proc.wait(timeout=10)
    assert proc.returncode == 0, "benign control child failed unexpectedly"

    alerts.wait_for_no_alert(pid=pid, window=2)
