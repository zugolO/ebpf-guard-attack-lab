"""Multi-stage attack chain generators (issue #32).

A "chain" is two or more individually-detectable steps that a correlator ties
into one unifying alert keyed on a single process lineage. The generators
below produce real kernel-visible activity for the two variants the
integration suite needs:

  * same-PID  – one process performs both steps itself, so a lineage-aware
                correlator can attribute both events to the same process and
                raise a unifying chain alert.
  * two-PID   – two independent processes each perform one step; no single
                process exhibits both steps, so no chain alert may fire (the
                individual per-event rule alerts may still fire).

Both steps are real file operations, so a live eBPF file-access monitor
observes them without requiring any external tool to be installed:

  * credential theft (step 1) – read of a fake SSH private key. The path
    contains "/.ssh/id_", which is what the cred_ssh_private_key_read rule
    matches; the file content is fake and lives under a temporary directory.
  * lateral movement (step 2) – open of a fake SSH agent socket under
    /tmp/ssh-*, which is what lateral_ssh_agent_socket_access matches.

Nothing under the real user's ~/.ssh is read or written: every path used here
is created inside a private temp directory (the agent-socket path is created
under /tmp/ssh-chain-* so it satisfies the rule's "/tmp/ssh-" prefix).
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path


_PYTHON = sys.executable or "/usr/bin/python3"

# Child snippets. {key} is an existing fake SSH key path; {agent} is a path
# under /tmp/ssh-* that does not exist yet.
_READ_KEY = "import os\n" "os.close(os.open({key!r}, os.O_RDONLY))\n"

_OPEN_AGENT = (
    "import os\n"
    "open({agent!r}, 'w').close()\n"
    "os.close(os.open({agent!r}, os.O_RDONLY))\n"
)

_TWO_STEPS = _READ_KEY + _OPEN_AGENT


def _make_fake_private_key() -> str:
    """Create a fake SSH private key under a private temp dir and return its
    path. The path contains "/.ssh/id_" so it near-matches a real key without
    ever touching the user's ~/.ssh."""
    workdir = Path(tempfile.mkdtemp(prefix="ebpf-guard-chain-"))
    ssh_dir = workdir / ".ssh"
    ssh_dir.mkdir()
    key = ssh_dir / "id_rsa"
    key.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "ebpf-guard chain probe (fake, not a real key)\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    return str(key)


def _new_agent_path() -> str:
    """Return a not-yet-created path under /tmp/ssh-chain-*, so the opened
    filename satisfies lateral_ssh_agent_socket_access's "/tmp/ssh-" prefix."""
    workdir = Path(tempfile.mkdtemp(prefix="ssh-chain-", dir="/tmp"))
    return str(workdir / f"agent.{os.getpid()}")


def _spawn(code: str, **fmt) -> subprocess.Popen:
    """Run ``code.format(**fmt)`` in a fresh, independent python process.

    start_new_session=True detaches each child into its own session so the two
    negative-case processes are genuinely independent rather than sharing a
    shell/job-control lineage.
    """
    return subprocess.Popen(
        [_PYTHON, "-c", code.format(**fmt)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def run_chain_same_pid() -> subprocess.Popen:
    """Positive case: one process performs both chain steps in the SAME pid.

    The returned Popen's pid is the lineage the correlator should attribute the
    whole chain to.
    """
    key = _make_fake_private_key()
    agent = _new_agent_path()
    return _spawn(_TWO_STEPS, key=key, agent=agent)


def run_chain_two_pids() -> "tuple[subprocess.Popen, subprocess.Popen]":
    """Negative case: the same two steps executed by two unrelated pids.

    Returns (credential_step, lateral_step) — two independent processes, each
    performing exactly one step, neither an ancestor of the other.
    """
    key = _make_fake_private_key()
    agent = _new_agent_path()
    credential = _spawn(_READ_KEY, key=key)
    lateral = _spawn(_OPEN_AGENT, agent=agent)
    return credential, lateral
