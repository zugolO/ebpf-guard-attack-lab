"""Watchdog / self-tamper evasion attack generators (issue #33).

The strongest way to defeat a runtime-security agent is to attack the agent
itself: kill its process, detach its BPF programs out from under it, or starve
the ring buffer so the watchdog/attestation tick never runs. These generators
produce that activity *from outside* the agent so the integration suite can
assert on externally observable signals (the heartbeat metric and the alert
stream) instead of the agent's own unit tests:

  * find_ebpf_guard_pid            -- locate the live daemon.
  * kill_ebpf_guard_daemon         -- SIGTERM/SIGKILL the daemon (DESTRUCTIVE).
  * detach_bpf_program_via_bpftool -- detach the ebpf-guard bpf_link(s) via
                                      bpftool (DESTRUCTIVE; no-op when bpftool
                                      or the link is absent).
  * flood_ring_buffer_to_starve_watchdog
                                   -- DoS the ring buffer with a burst of
                                      file-access events to delay/lose the
                                      watchdog/attestation tick.
  * read_heartbeat_metric          -- scrape
                                      ebpf_guard_heartbeat_timestamp_seconds
                                      from the external /metrics endpoint.

DESTRUCTIVE GENERATORS: killing the daemon or detaching its programs invalidates
the pytest session's `alerts` fixture for the remainder of the run. They must
only be invoked from tests gated behind EBPF_GUARD_ALLOW_DESTRUCTIVE=1 on an
isolated VM against a disposable daemon -- never during an ordinary developer
run (see tests/integration/test_watchdog_evasion.py).

Only the standard library is used (urllib for the scrape); no new dependency.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import urllib.request

DEFAULT_METRICS_URL = "http://127.0.0.1:9090/metrics"
HEARTBEAT_METRIC = "ebpf_guard_heartbeat_timestamp_seconds"


def find_ebpf_guard_pid() -> int | None:
    """Locate the running ebpf-guard daemon pid (env EBPF_GUARD_PID override,
    else scan /proc/*/comm or pgrep). Returns None when absent."""
    override = os.getenv("EBPF_GUARD_PID", "")
    if override:
        try:
            return int(override)
        except ValueError:
            return None

    # Preferred: read /proc/<pid>/comm directly (Linux, exact match).
    try:
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                with open(f"/proc/{entry}/comm", "r") as f:
                    comm = f.read().strip()
            except OSError:
                continue
            if comm in ("ebpf-guard", "ebpf_guard"):
                return int(entry)
    except OSError:
        pass

    # Fallback: pgrep (also covers non-Linux or a restricted /proc).
    pgrep = shutil.which("pgrep")
    if pgrep:
        for name in ("ebpf-guard", "ebpf_guard"):
            try:
                out = subprocess.check_output(
                    [pgrep, "-x", name], text=True, stderr=subprocess.DEVNULL
                )
            except (subprocess.CalledProcessError, OSError):
                continue
            pids = [int(tok) for tok in out.split() if tok.strip().isdigit()]
            if pids:
                return pids[0]
    return None


def kill_ebpf_guard_daemon(pid: int, sig: int = 15) -> None:
    """Send `sig` (default SIGTERM) to the daemon.

    DESTRUCTIVE: this stops the very detector under test. The caller must run
    on a disposable daemon (EBPF_GUARD_ALLOW_DESTRUCTIVE=1) because the
    session-scoped `alerts` fixture cannot be recovered afterwards.
    """
    os.kill(pid, sig)


def _ebpf_guard_link_ids(bpftool: str, prog_name: str) -> list[int]:
    """Return the bpf_link ids whose program is `prog_name` (best-effort).

    Parses `bpftool link show --json`; an unparseable or unsupported output
    yields an empty list so the caller degrades to a skip instead of raising.
    """
    try:
        out = subprocess.check_output(
            [bpftool, "link", "show", "--json"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, OSError):
        return []
    try:
        links = json.loads(out)
    except ValueError:
        return []
    if not isinstance(links, list):
        return []
    ids: list[int] = []
    for link in links:
        if isinstance(link, dict) and link.get("prog_name") == prog_name:
            link_id = link.get("id")
            if isinstance(link_id, int):
                ids.append(link_id)
    return ids


def detach_bpf_program_via_bpftool(
    prog_name: str = "ebpf_guard",
) -> subprocess.Popen | None:
    """Detach the bpf_link(s) that hold `prog_name` attached.

    `bpftool prog detach PROG ATTACH_TYPE [ATTACH_TARGET]` needs an attach type
    (and usually a target such as an interface) that cannot be discovered
    generically, so a bare `prog detach <name>` is a usage error that detaches
    nothing. libbpf-based daemons attach via bpf_link on modern kernels, and
    those are detachable without a target by link id:
    `bpftool link detach id ID`. We resolve the ids from
    `bpftool link show --json` (matching `prog_name`) and detach them in turn.

    Returns a Popen running the last detach; the caller MUST assert a zero
    returncode so a detach that bpftool rejects fails loudly. Returns None when
    bpftool is absent or no bpf_link is attached to `prog_name` (e.g. a legacy
    perf_event attach, which bpftool cannot detach by program name) -- the
    caller skips rather than reporting a false positive.

    DESTRUCTIVE: detaching the program blinds the agent. The exact attach point
    depends on how ebpf-guard attaches its programs and MUST be confirmed on the
    stand; the test verifies the result externally (tamper alert or heartbeat
    freeze), not via this return value.
    """
    bpftool = shutil.which("bpftool")
    if bpftool is None:
        return None

    link_ids = _ebpf_guard_link_ids(bpftool, prog_name)
    if not link_ids:
        return None

    proc = None
    for link_id in link_ids:
        proc = subprocess.Popen(
            [bpftool, "link", "detach", "id", str(link_id)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        proc.wait(timeout=10)
        if proc.returncode != 0:
            break
    return proc


def flood_ring_buffer_to_starve_watchdog(
    events_per_sec: int = 100000,
) -> subprocess.Popen:
    """DoS the 256KB ring buffer hard enough to delay/lose the watchdog/
    attestation tick.

    Emits a bounded (default ~5s) burst of real file-access syscalls -- open,
    read and close on a small file -- from a child process. The burst is paced
    towards `events_per_sec` (<=0 means "as fast as possible") and stops on its
    own so a developer cannot accidentally leave it running forever. This is the
    negative-side generator: liveness (the heartbeat advancing) must survive the
    flood.
    """
    code = f"""\
import os, time

path = "/etc/passwd"
target = {events_per_sec}
duration = 5.0
t0 = time.monotonic()
end = t0 + duration
count = 0
while time.monotonic() < end:
    try:
        fd = os.open(path, os.O_RDONLY)
        try:
            os.read(fd, 1)
        finally:
            os.close(fd)
    except OSError:
        pass
    count += 1
    if target > 0:
        expected = count / float(target)
        elapsed = time.monotonic() - t0
        if elapsed < expected:
            time.sleep(expected - elapsed)
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def read_heartbeat_metric(metrics_url: str | None = None) -> float | None:
    """Scrape ebpf_guard_heartbeat_timestamp_seconds from the external /metrics
    endpoint (env EBPF_GUARD_METRICS_URL, default http://127.0.0.1:9090/metrics).
    Return None when unreachable. Use urllib only (no new dependency)."""
    url = metrics_url or os.getenv("EBPF_GUARD_METRICS_URL", DEFAULT_METRICS_URL)
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except (OSError, ValueError):
        return None

    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith(HEARTBEAT_METRIC):
            continue
        # Prometheus line is "<name>{labels} <value>"; take the last token.
        try:
            return float(line.rsplit(None, 1)[1])
        except (IndexError, ValueError):
            return None
    return None
