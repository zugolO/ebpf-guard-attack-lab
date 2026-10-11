"""Comm / argv[0] masquerade attack generators (issue #31).

`comm` (task_struct->comm, 16 bytes) is attacker-controlled. Two independent
ways to forge it:

  1. prctl(PR_SET_NAME) rewrites comm at any time, so every kernel event the
     process emits *after* the call carries the forged name.
  2. execve() derives comm from the basename of the path used to launch the
     binary — not from argv[0] — so exec'ing a symlink alias named after a
     legitimate tool forges comm while /proc/[pid]/exe still resolves to the
     real, offensive binary.

The generators below spawn real subprocesses that combine a spoofed argv[0]
with prctl(PR_SET_NAME), or exec a symlink alias, so the integration suite can
observe whether ebpf-guard's comm-based rules are evaded — i.e. whether
detection actually relies on parent_comm / /proc/[pid]/exe / lineage instead
of bare comm.
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PR_SET_NAME = 15  # from <linux/prctl.h>

_PYTHON = sys.executable or "/usr/bin/python3"


def _resolve_binary(name_or_path: str) -> str:
    """Resolve a bare tool name (e.g. "wget") to an absolute path for use as
    Popen(executable=...) / symlink target; absolute paths pass through."""
    if os.path.sep in name_or_path:
        return name_or_path
    return shutil.which(name_or_path) or name_or_path


# Python source executed by the masquerading child. It rewrites comm with
# prctl() and then performs the probe action *in the same process*, so the
# resulting kernel events (not the execve itself) carry the forged comm.
_ACTIONS = {
    "unlink_log": (
        "open({path!r}, 'w').write('ebpf-guard masquerade probe\\n')\n"
        "os.unlink({path!r})\n"
    ),
    "open_ssh_agent": (
        "open({path!r}, 'w').close()\n"
        "os.close(os.open({path!r}, os.O_RDONLY))\n"
    ),
    "benign": "time.sleep(0.2)\n",
}

_PREAMBLE = (
    "import ctypes, os, time\n"
    "_libc = ctypes.CDLL(None, use_errno=True)\n"
    "_libc.prctl.argtypes = [ctypes.c_int, ctypes.c_char_p,\n"
    "                         ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]\n"
    "_libc.prctl.restype = ctypes.c_int\n"
    "if _libc.prctl({prctl}, {name!r}.encode(), 0, 0, 0) != 0:\n"
    "    raise OSError(ctypes.get_errno(), 'prctl(PR_SET_NAME) failed')\n"
)


def _spawn(action: str, fake_name: str, **fmt) -> subprocess.Popen:
    """execve python3 with argv[0]=fake_name, then prctl(PR_SET_NAME, fake_name)."""
    code = _PREAMBLE.format(prctl=PR_SET_NAME, name=fake_name) + _ACTIONS[action].format(**fmt)
    return subprocess.Popen(
        [fake_name, "-c", code],  # argv[0] is forged; the executed file is python3
        executable=_PYTHON,
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )


def spoofed_comm_unlink_log(
    fake_name: str = "logrotate", path: str = ""
) -> subprocess.Popen:
    """prctl(PR_SET_NAME, fake_name) then create+unlink a file under /var/log/.

    Targets evasion_log_clear, whose `comm not_in [logrotate, ...]` exclusion
    means a process masquerading as the logger is not reported.
    """
    path = path or f"/var/log/ebpf-guard-masq-{os.getpid()}.log"
    return _spawn("unlink_log", fake_name, path=path)


def spoofed_comm_open_ssh_agent(
    fake_name: str = "rsync", path: str = ""
) -> subprocess.Popen:
    """prctl(PR_SET_NAME, fake_name) then open a fake SSH agent socket.

    Targets lateral_ssh_agent_socket_access, whose `comm not_in [ssh, scp,
    sftp, rsync, git]` exclusion lets a masquerader read it silently.
    """
    path = path or f"/tmp/ssh-ebpf-masq-{os.getpid()}/agent.{os.getpid()}"
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    return _spawn("open_ssh_agent", fake_name, path=path)


def benign_prctl_setname(fake_name: str = "logrotate") -> subprocess.Popen:
    """Negative control: a legitimate process rewrites its own comm but does
    nothing malicious — no rule may fire for its pid."""
    return _spawn("benign", fake_name)


def argv0_spoofed_exec(
    real_binary: str, fake_argv0: str, args=()
) -> subprocess.Popen:
    """execve real_binary with a forged argv[0].

    execve() sets comm from the *executable path*, not argv[0], so this does
    not by itself hide the real tool from a comm-based rule — it isolates the
    argv[0] half of the masquerade from the prctl/symlink halves.
    """
    return subprocess.Popen(
        [fake_argv0, *args],
        executable=_resolve_binary(real_binary),
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )


def symlink_masquerade_exec(
    real_binary: str, fake_name: str, args=()
) -> subprocess.Popen:
    """execve a symlink named after a legitimate tool that points at real_binary.

    The kernel derives comm from the basename of the path passed to execve, so
    comm and argv[0] both say fake_name while /proc/[pid]/exe resolves to
    real_binary.
    """
    workdir = Path(tempfile.mkdtemp(prefix="ebpf-guard-masq-"))
    link = workdir / fake_name
    link.symlink_to(_resolve_binary(real_binary))
    return subprocess.Popen(
        [str(link), *args],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
    )
