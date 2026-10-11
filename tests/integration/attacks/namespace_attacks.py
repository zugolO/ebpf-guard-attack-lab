"""Namespace/mount evasion attack generators (PLAN.md task E).

An attacker with root can move its file accesses into a fresh mount or PID
namespace, hide a sensitive file behind a bind mount, or reach it through the
magic ``/proc/<pid>/root`` host-root escape. The key question for ebpf-guard is
whether it resolves the path as the attacker's process actually opens it (the
userspace pathname handed to ``open(2)``) or as a host-namespace path.

The generators below produce the shapes the integration suite needs:

  * mount_ns_shadow_read   -- ``unshare(CLONE_NEWNS)`` then read /etc/shadow.
                              The pathname is still "/etc/shadow"; this isolates
                              "did switching namespace alone blind the rule?".
  * pid_ns_shadow_read     -- ``unshare(CLONE_NEWPID)`` + fork (the forked
                              child is pid 1 of the new namespace) then read
                              /etc/shadow.
  * bind_mount_shadow_read -- in a *private* mount namespace, bind-mount the
                              sensitive file onto a benign-looking path and read
                              the benign path, so ``open(2)`` only sees the
                              benign name.
  * proc1root_shadow_read  -- read ``/proc/1/root/etc/shadow``, the classic
                              host-root escape (pid 1's root is the host root
                              when read from inside a namespace/container).
  * direct_shadow_read     -- positive control: a plain read of /etc/shadow.
  * read_benign_file       -- negative control: a harmless read.

SAFETY: non-destructive. A sensitive target is only ever *read*, never written.
The bind mount is created inside a throwaway, private mount namespace
(``unshare(CLONE_NEWNS)`` + ``mount --make-rprivate /``) that the kernel tears
down when the child exits, so the host mount table is never modified. The only
path a generator creates is a caller-supplied probe file under a temp dir.

GRACEFUL DEGRADATION: a child that cannot create the namespace or the bind
mount exits with ``SETUP_FAILED`` (77) instead of raising; the test skips on
that code so a missing capability is never reported as a detection success. A
child that set up the namespace but finds the target missing/unreadable exits 0
(there is nothing to observe).

WHAT THE MONITOR CAN SEE: the lab event model (internal/ruletest/types.go)
carries no namespace/mount field and no resolved-path field -- ``FileSpec``
exposes only the userspace pathname (``filename``, ``fd_name``, ``op``,
``flags``). So namespace/mount evasion reduces to a pathname-string problem:
mount/PID namespace switches do NOT blind a pathname rule (the reader still
opens "/etc/shadow"), but the same inode reached through
``/proc/<pid>/root/...`` or a bind mount under a different pathname is a
documented known bypass. The Go/YAML side asserts that gap as ``known_bypass``
mutants in tests/rules/credential_access_test.yaml (cred_shadow_read) and
tests/rules/lateral_movement_test.yaml (lateral_ssh_agent_socket_access).

Consumed by tests/integration/test_namespace_evasion.py; needs root + a running
ebpf-guard daemon + Linux, and skips otherwise.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

# Exit status of a child that could not create the namespace / bind mount (e.g.
# EPERM under a capability-restricted container). The test skips on this code
# rather than reading the missing attack as "no alert = evasion".
SETUP_FAILED = 77

# Exit status of a child whose namespace setup succeeded but whose sensitive
# read did not (LSM denial, race, missing escape path). Without it a known-bypass
# test would see exit 0 + "no alert" and pass vacuously, because the read it
# claims went undetected never actually happened.
READ_FAILED = 78

_PYTHON = sys.executable or "python3"

# ctypes preamble shared by the namespace children: bind libc's unshare(2) and
# mount(2) so the generators do not depend on the unshare(1)/mount(8) binaries.
# ``_set_comm`` names the reader so the PID-namespace case (a forked grandchild
# whose host pid the test cannot know) can still be matched on comm.
_LIBC_PREAMBLE = f"""\
import ctypes, os, sys

READ_FAILED = {READ_FAILED}

_libc = ctypes.CDLL(None, use_errno=True)
_libc.unshare.argtypes = [ctypes.c_int]
_libc.unshare.restype = ctypes.c_int
_libc.mount.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
    ctypes.c_ulong, ctypes.c_void_p,
]
_libc.mount.restype = ctypes.c_int
_libc.prctl.argtypes = [
    ctypes.c_int, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong,
    ctypes.c_ulong,
]
_libc.prctl.restype = ctypes.c_int

CLONE_NEWNS = 0x00020000
CLONE_NEWPID = 0x20000000
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1 << 18


def _set_comm(name):
    # PR_SET_NAME = 15.
    _libc.prctl(15, name.encode(), 0, 0, 0)


def _read(path):
    try:
        with open(path) as f:
            f.read()
    except OSError:
        sys.exit(READ_FAILED)
"""


def _spawn(code: str) -> subprocess.Popen:
    """Run a child ``python3 -c`` snippet with its stderr suppressed."""
    return subprocess.Popen([_PYTHON, "-c", code], stderr=subprocess.DEVNULL)


def mount_ns_shadow_read(
    target: str = "/etc/shadow",
    comm: str = "nsevade",
) -> subprocess.Popen:
    """``unshare(CLONE_NEWNS)`` then read ``target`` from inside the new mount
    namespace.

    The userspace pathname handed to ``open(2)`` is unchanged ("/etc/shadow"),
    so this isolates whether a namespace switch alone can blind a pathname rule.
    The new namespace is a copy of the parent's mounts; propagation is forced
    private so nothing done here can reach the host mount table. Exits
    ``SETUP_FAILED`` when unshare/mount is not permitted.
    """
    code = _LIBC_PREAMBLE + f"""\
_set_comm({comm!r})
if _libc.unshare(CLONE_NEWNS) != 0:
    sys.exit({SETUP_FAILED})
if _libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None) != 0:
    sys.exit({SETUP_FAILED})
_read({target!r})
"""
    return _spawn(code)


def pid_ns_shadow_read(
    target: str = "/etc/shadow",
    comm: str = "nspid",
) -> subprocess.Popen:
    """``unshare(CLONE_NEWPID)`` + ``fork()`` then read ``target``.

    After ``unshare(CLONE_NEWPID)`` the caller is still in the old PID
    namespace; only the forked child becomes pid 1 of the new one, which is why
    the read runs there. The pathname is unchanged, so a pathname rule should
    still fire. Exits ``SETUP_FAILED`` when unshare/fork is not permitted.
    """
    code = _LIBC_PREAMBLE + f"""\
if _libc.unshare(CLONE_NEWPID) != 0:
    sys.exit({SETUP_FAILED})
try:
    pid = os.fork()
except OSError:
    sys.exit({SETUP_FAILED})
if pid == 0:
    try:
        _set_comm({comm!r})
        _read({target!r})
    except SystemExit as e:
        os._exit(e.code if isinstance(e.code, int) else 1)
    os._exit(0)
_, status = os.waitpid(pid, 0)
# Propagate the grandchild's real status: only unshare/fork failures mean
# SETUP_FAILED (skip); a read failure or a snippet bug must not turn into a skip.
sys.exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)
"""
    return _spawn(code)


def bind_mount_shadow_read(
    benign_path: str | None = None,
    source: str = "/etc/shadow",
    comm: str = "nsbind",
) -> subprocess.Popen:
    """Bind-mount the sensitive ``source`` onto ``benign_path`` inside a private
    mount namespace, then read ``benign_path``.

    The sensitive inode is reached, but ``open(2)`` only ever sees the benign
    pathname, so a rule that compares the filename to "/etc/shadow" exactly
    misses it. ``benign_path`` defaults to a per-process name in the system temp
    dir; the parent creates an empty probe file as the bind target (the child
    replaces it only inside its own namespace). Exits ``SETUP_FAILED`` when
    unshare/bind mount is not permitted. Reads only -- never writes the source.
    """
    if benign_path is None:
        benign_path = os.path.join(
            tempfile.gettempdir(), f".ebpf-guard-ns-{os.getpid()}"
        )
    # The bind target must exist; a plain empty file is enough and is never
    # populated with sensitive content outside the child's private namespace.
    try:
        fd = os.open(benign_path, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
    except OSError:
        pass
    code = _LIBC_PREAMBLE + f"""\
_set_comm({comm!r})
if _libc.unshare(CLONE_NEWNS) != 0:
    sys.exit({SETUP_FAILED})
if _libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None) != 0:
    sys.exit({SETUP_FAILED})
if _libc.mount({source!r}.encode(), {benign_path!r}.encode(), None, MS_BIND, None) != 0:
    sys.exit({SETUP_FAILED})
_read({benign_path!r})
"""
    return _spawn(code)


def proc1root_shadow_read(
    target: str = "/etc/shadow",
    comm: str = "nsroot",
) -> subprocess.Popen:
    """Read ``target`` through ``/proc/1/root/<target>``.

    ``/proc/1/root`` is pid 1's root directory; from inside a namespace or
    container it resolves to the host root, so this is the classic host-root
    escape. ``open(2)`` receives "/proc/1/root/etc/shadow", not "/etc/shadow",
    so a filename-equality rule misses it. Exits ``READ_FAILED`` when the escape
    path is missing or unreadable, so "no alert" is never read as a bypass.
    """
    code = _LIBC_PREAMBLE + f"""\
_set_comm({comm!r})
_read({("/proc/1/root" + target)!r})
"""
    return _spawn(code)


def direct_shadow_read(
    target: str = "/etc/shadow",
    comm: str = "nsdirect",
) -> subprocess.Popen:
    """Positive control: a plain read of the sensitive ``target``.

    Same read as the namespace probes but without any namespace trickery, so it
    proves the rule can fire and keeps the namespace assertions non-vacuous.
    """
    code = _LIBC_PREAMBLE + f"""\
_set_comm({comm!r})
_read({target!r})
"""
    return _spawn(code)


def read_benign_file(
    path: str = "/etc/hostname",
    comm: str = "nsbenign",
) -> subprocess.Popen:
    """Negative control: a harmless read that must raise no alert.

    The child uses the same reader setup (and a recognisable comm) as the
    namespace probes but touches nothing sensitive, so a 'no alert' result
    cannot be blamed on the harness.
    """
    code = _LIBC_PREAMBLE + f"""\
_set_comm({comm!r})
_read({path!r})
"""
    return _spawn(code)
