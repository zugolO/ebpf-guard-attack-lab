"""Threshold-evasion / low-and-slow attack generators (issue #29).

An attacker can stay just under a detection threshold -- a rate limit, a burst
counter, or the profiler's EWMA anomaly boundary -- and still accomplish its
objective. The generators below produce:

  * sub-threshold behaviour that a *signature* rule MUST still catch
    (no-silent-suppression: a rule-level rate limit must never drop the 2nd..Nth
    credential read),
  * repetitive-but-benign periodic behaviour that MUST NOT be scored as an EWMA
    anomaly, and
  * a post-learning behaviour burst that MUST be scored as one (positive
    control, so the negative cannot pass vacuously).

They are consumed by tests/integration/test_threshold_evasion.py, which needs
root + a running ebpf-guard daemon; the test module skips otherwise.
"""

import subprocess


def low_and_slow_shadow_reads(
    path: str = "/etc/shadow",
    count: int = 5,
    interval: float = 1.0,
) -> subprocess.Popen:
    """Read a sensitive file a few times, slowly, from a recognisable comm.

    This is the low-and-slow credential-theft shape: enough accesses to be
    useful, spread out enough to slip under any naive rate limit. The
    per-access rule (cred_shadow_read) is a signature with no threshold, so the
    engine must alert on EVERY read; the integration test asserts exactly
    `count` distinct alerts, i.e. no access is silently suppressed.
    """
    code = f"""\
import time
for _ in range({count}):
    try:
        with open({path!r}) as f:
            f.read()
    except OSError:
        pass
    time.sleep({interval})
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def slow_jittered_beacon(
    host: str = "127.0.0.1",
    port: int = 4455,
    count: int = 3,
    base_interval: float = 3.0,
    jitter: float = 0.5,
) -> subprocess.Popen:
    """Slow, jittered TCP beacon kept BELOW the periodic-connection threshold.

    beacon_fixed_interval fires only when conn_periodic_count_5m > 2 AND the
    inter-connection coefficient of variation < 0.35. Sending `count` = 3
    connections inside the 5-minute window *satisfies* the count condition, so
    the evasion has to come from timing: the two inter-connection gaps
    alternate by +/- `jitter`, i.e. 4.5s and 1.5s with the defaults. Their
    coefficient of variation is 0.5 (population) / 0.71 (sample) -- both well
    above 0.35 -- so the periodicity condition fails and the rule does not fire.
    Expected: NO alert (demonstrates EVASION against a fixed-interval
    rate/periodicity detector). `port` is deliberately a rare, non-standard
    dport (4455) so this beacon neither pollutes nor is polluted by other
    suites' 4444 traffic if the daemon's 5-minute counter is keyed on
    dst:dport rather than pid.
    """
    code = f"""\
import socket, time
for i in range({count}):
    s = socket.socket()
    s.settimeout(0.5)
    s.connect_ex(('{host}', {port}))
    s.close()
    if i < {count} - 1:
        factor = 1.0 + ({jitter} if i % 2 == 0 else -{jitter})
        time.sleep({base_interval} * factor)
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def benign_healthcheck(
    count: int = 8,
    interval: float = 2.0,
    port: int = 80,
) -> subprocess.Popen:
    """Predictable benign healthcheck: periodic local connect on a standard
    port plus a harmless hostname read.

    In production this pattern runs roughly every 30s; the test-only profile
    (hack/ebpf-guard.test.yaml) shortens the profiler learning_period from
    3600s to 10s and min_learning_samples from 100 to 10. Each iteration emits
    TWO events (one connect, one file read), so the default `count` = 8
    produces ~16 events over ~16s -- at least min_learning_samples and
    comfortably past learning_period. That margin matters: if the pid never
    left the learning phase the negative would pass vacuously. Expected: NO
    anomaly_detection alert (negative control for the profiler's false-positive
    behaviour). See test_threshold_evasion.py for the timing caveat.
    """
    code = f"""\
import socket, time
for _ in range({count}):
    s = socket.socket()
    s.settimeout(0.5)
    s.connect_ex(('127.0.0.1', {port}))
    s.close()
    try:
        open('/etc/hostname').read()
    except OSError:
        pass
    time.sleep({interval})
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def behavior_burst(
    host: str = "127.0.0.1",
    port: int = 4456,
    baseline_count: int = 12,
    baseline_interval: float = 1.0,
    burst_count: int = 100,
    burst_interval: float = 0.02,
) -> subprocess.Popen:
    """Positive control for anomaly_detection: a pid whose behaviour suddenly
    changes after the profiler has had time to learn it.

    Phase 1 (baseline) emits `baseline_count` low-rate, repetitive file reads
    spaced `baseline_interval` apart, so the pid leaves the profiler's learning
    phase (> learning_period 10s and >= min_learning_samples 10) with a quiet,
    predictable profile. Phase 2 (drift) then floods the same pid with
    `burst_count` rapid TCP connects -- a sharp rate/type change that the EWMA
    profiler (`anomaly_threshold` 0.7, `ewma.weight` 0.7 in the test profile)
    should score as an anomaly. Expected: an anomaly_detection alert; this is
    what makes the benign_healthcheck negative non-vacuous.

    CAVEAT: the real profiler lives in the ebpf-guard daemon, not this lab, so
    its exact feature vector and alert rule id cannot be validated on macOS. If
    the daemon reports anomaly alerts under a different rule id, update both
    this control and test_benign_healthcheck_does_not_trigger_anomaly.
    """
    code = f"""\
import socket, time
for _ in range({baseline_count}):
    try:
        open('/etc/hostname').read()
    except OSError:
        pass
    time.sleep({baseline_interval})
for _ in range({burst_count}):
    s = socket.socket()
    s.settimeout(0.05)
    s.connect_ex(('{host}', {port}))
    s.close()
    time.sleep({burst_interval})
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)
