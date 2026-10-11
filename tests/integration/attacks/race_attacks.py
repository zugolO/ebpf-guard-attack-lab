"""TOCTOU / symlink-race attack generators (issue #33).

A time-of-check-to-time-of-use (TOCTOU) bug lets an attacker swap a
harmless-looking path for a symlink between the moment a checker inspects it and
the moment it is used. The generators below produce the shapes the integration
suite needs:

  * symlink_swap_race            -- repeatedly (re)creates a benign regular file,
                                   then replaces it with a symlink to a
                                   sensitive target, so a checker racing this
                                   loop can be tricked into using /etc/shadow.
  * toctou_victim_read           -- the naive victim: it stats the
                                   harmless-looking path and then opens it,
                                   leaving the check->use window open for the
                                   racer to fill.
  * cron_symlink_persistence_race -- the persistence shape: a regular file is
                                   dropped into a cron directory (passing any
                                   name/op-based "create" check), then swapped
                                   for a symlink to the attacker payload. It
                                   asks whether detection keys on the final
                                   resolved target (readlink) or only on the
                                   name observed at create time.

SAFETY: the generators are non-destructive by construction. The only paths they
ever create/remove are the caller-supplied `benign_path` and a unique
`.ebpf-guard-race-<pid>` probe inside `cron_dir`; every child degrades
gracefully (exits 0) when its target directory/file is missing or unreadable
instead of raising. A sensitive target is only ever *read*, never written.

WHAT THE MONITOR CAN SEE: a syscall/file monitor observes the *userspace*
pathname handed to open(2)/symlink(2), not the inode the kernel resolves a
symlink to. The event model therefore has no readlink / resolved-symlink-target
field (`EventSpec.FileSpec` exposes only `filename`, `fd_name`, `op`), so the
final-target half of the race is a documented detection gap -- the integration
suite asserts that known-bypass non-outcome, and
`tests/rules/toctou_watchdog_test.yaml` asserts the rename shape as an alert
(ransomware_mass_rename independently fires), not as a whole-engine bypass.

Consumed by tests/integration/test_toctou_race.py; needs root + a running
ebpf-guard daemon and skips otherwise.
"""

from __future__ import annotations

import os
import subprocess
import tempfile


def _default_benign_path() -> str:
    """A benign probe path private to this process.

    A fixed, world-writable default (e.g. ``/tmp/.check_me``) is a footgun: a
    planted symlink there would be followed and its target truncated. Use a
    per-process name in the system temp dir instead.
    """
    return os.path.join(tempfile.gettempdir(), f".ebpf-guard-check-{os.getpid()}")


def _spawn(code: str) -> subprocess.Popen:
    """Run a child ``python3 -c`` snippet with its stderr suppressed."""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def symlink_swap_race(
    benign_path: str | None = None,
    sensitive_target: str = "/etc/shadow",
    iterations: int = 200,
) -> subprocess.Popen:
    """Classic TOCTOU: repeatedly create `benign_path` as a regular file, then
    swap it to a symlink to `sensitive_target`, racing any checker/user.

    Each iteration first materialises a harmless-looking regular file (which
    passes an existence/size/permission check) and then replaces it with a
    symlink to the sensitive target. `os.unlink` removes the symlink itself,
    never the target, and the child restores the path to "absent" before it
    exits, so the loop leaves no artifact behind and never writes the target.

    The default `benign_path` is a per-process name in the system temp dir; a
    caller-supplied path that already exists as a symlink is unlinked, never
    followed (the create uses O_NOFOLLOW).
    """
    if benign_path is None:
        benign_path = _default_benign_path()
    code = f"""\
import os

benign = {benign_path!r}
target = {sensitive_target!r}

# Graceful degradation: with nothing sensitive to race toward there is no
# attack to run, so exit successfully rather than raising in the child.
if not os.path.exists(target) or not os.access(target, os.R_OK):
    raise SystemExit(0)

for _ in range({iterations}):
    try:
        # Drop the symlink left by the previous iteration BEFORE recreating the
        # regular file. Without this the O_NOFOLLOW create below would stall
        # the loop (ELOOP), and without O_NOFOLLOW it would follow the symlink
        # and truncate the sensitive target.
        try:
            os.unlink(benign)
        except FileNotFoundError:
            pass
        fd = os.open(
            benign,
            os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW,
            0o600,
        )
        os.close(fd)
        # Swap the regular file for a symlink; unlink never touches the target.
        os.unlink(benign)
        os.symlink(target, benign)
    except OSError:
        pass

# Clean up our own probe so the loop leaves no artifact behind.
try:
    os.unlink(benign)
except OSError:
    pass
"""
    return _spawn(code)


def cron_symlink_persistence_race(
    cron_dir: str = "/etc/cron.d",
    payload: str = "/tmp/evil.sh",
    iterations: int = 100,
) -> subprocess.Popen:
    """Writes a regular file into `cron_dir` (passes name-based 'create'
    checks), then replaces it with a symlink to `payload` -- testing whether
    persistence detection keys on the final resolved target (readlink) or only
    the name at create time.

    The probe is written under a unique `.ebpf-guard-race-<pid>` name so an
    existing cron file is never overwritten, and it is removed again before the
    child exits. The leading dot also keeps the name outside cron's
    `[A-Za-z0-9_-]+` convention, so the symlinked payload is never executed by
    cron: the activation half of the persistence race is deliberately not shown.
    A non-existent, unwritable or unreadable `cron_dir` makes the child exit 0
    instead of raising. `payload` is only ever used as a symlink target and is
    never written or read.
    """
    code = f"""\
import os

cron_dir = {cron_dir!r}
payload = {payload!r}

if not os.path.isdir(cron_dir) or not os.access(cron_dir, os.W_OK):
    raise SystemExit(0)

name = os.path.join(cron_dir, ".ebpf-guard-race-%d" % os.getpid())
for _ in range({iterations}):
    try:
        # Name-based "create" check sees a regular, harmless cron file.
        fd = os.open(name, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
        os.close(fd)
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass
        # The final target now resolves to the attacker payload (readlink-only).
        os.symlink(payload, name)
    except OSError:
        pass

# Never leave a persistence artifact behind.
try:
    os.unlink(name)
except OSError:
    pass
"""
    return _spawn(code)


def toctou_victim_read(
    benign_path: str = "/tmp/.check_me",
    sensitive_target: str = "/etc/shadow",
    iterations: int = 200,
) -> subprocess.Popen:
    """A 'victim' that repeatedly stats the harmless-looking path then opens
    it; the racer swaps the path to a symlink to `sensitive_target` between the
    check and the open, so the victim may read the sensitive target.

    The child only ever opens `benign_path`; when the racer has swapped it the
    kernel follows the symlink and the read lands on `sensitive_target`. It
    degrades gracefully (exit 0) when the sensitive target is missing or
    unreadable, and it never writes anything.
    """
    code = f"""\
import os

benign = {benign_path!r}
target = {sensitive_target!r}

# Graceful degradation: without a readable sensitive target there is no race
# worth running; exit 0 rather than raising in the child.
if not os.path.exists(target) or not os.access(target, os.R_OK):
    raise SystemExit(0)

for _ in range({iterations}):
    # CHECK: the victim inspects the harmless-looking path...
    try:
        os.stat(benign)
    except OSError:
        continue
    # ...USE: and then opens it. A racer can swap benign -> symlink(target) in
    # this window; the open follows the symlink and reads the target.
    try:
        fd = os.open(benign, os.O_RDONLY)
        try:
            os.read(fd, 1)
        finally:
            os.close(fd)
    except OSError:
        pass
"""
    return _spawn(code)


def benign_regular_write(
    path: str = "/tmp/.benign_check",
    payload: str = "ebpf-guard benign probe\n",
) -> subprocess.Popen:
    """Negative control for the symlink probes: a plain regular-file write.

    Writing a normal (non-symlink) file in the same directory must not satisfy
    a symlink-syscall rule, which is what keeps the symlink-race positive from
    passing vacuously. The child silently ignores an unwritable path.
    """
    code = f"""\
import os

path = {path!r}
payload = {payload!r}
# O_NOFOLLOW: never follow a planted symlink and truncate its target. This is
# the negative control for the very race the other generators exploit.
try:
    fd = os.open(
        path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600
    )
    try:
        os.write(fd, payload.encode())
    finally:
        os.close(fd)
except OSError:
    pass
"""
    return _spawn(code)
