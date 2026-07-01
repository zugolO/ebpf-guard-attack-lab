"""Low-and-slow attack generators (issue #29).

Unlike mass_port_scan() / c2_beacon_fixed_interval() with their short,
CI-friendly intervals, these generators intentionally keep the action rate
below whatever threshold a rate limiter or EWMA anomaly profiler is assumed
to be watching, to test whether spreading activity out over time lets an
attacker evade detection.
"""

import subprocess


def low_and_slow_file_scan(
    target_dir: str,
    count: int = 20,
    interval_sec: float = 5.0,
) -> subprocess.Popen:
    """Read one sensitive file every interval_sec — under any per-second rate
    threshold, but statistically anomalous for the process's profile over a
    full learning_period window."""
    code = f"""\
import os, time
for i in range({count}):
    try:
        open(os.path.join({target_dir!r}, "secret_%d" % i), "rb").read(1)
    except OSError:
        pass
    time.sleep({interval_sec})
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def low_and_slow_port_scan(
    target_ip: str = "127.0.0.1",
    ports: tuple = (22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017),
    interval_sec: float = 6.0,
) -> subprocess.Popen:
    """One connection attempt per interval_sec against a distinct port —
    the same target/port set as mass_port_scan() but spread far below any
    per-second connection-rate threshold."""
    ports_repr = repr(list(ports))
    code = f"""\
import socket, time
for p in {ports_repr}:
    s = socket.socket()
    s.settimeout(0.5)
    s.connect_ex(({target_ip!r}, p))
    s.close()
    time.sleep({interval_sec})
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def beacon_just_under_interval_threshold(
    host: str = "127.0.0.1",
    port: int = 4444,
    interval: float = 45.0,
    count: int = 6,
) -> subprocess.Popen:
    """Beacon with an interval longer than a typical short-window 'suspicious
    burst' detector, to probe the lower bound of interval-based profiling."""
    code = f"""\
import socket, time
for _ in range({count}):
    s = socket.socket()
    s.settimeout(0.5)
    s.connect_ex(({host!r}, {port}))
    s.close()
    time.sleep({interval})
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def benign_periodic_healthcheck(
    host: str = "127.0.0.1",
    port: int = 8080,
    interval: float = 5.0,
    count: int = 6,
) -> subprocess.Popen:
    """Negative case: a legitimate process with rare but perfectly regular
    connections (healthcheck pattern) — must not be flagged as anomalous
    once the profiler has learned this as the process's baseline."""
    code = f"""\
import socket, time
for _ in range({count}):
    s = socket.socket()
    s.settimeout(0.5)
    s.connect_ex(({host!r}, {port}))
    s.close()
    time.sleep({interval})
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)
