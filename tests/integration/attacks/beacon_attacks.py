"""C2 beaconing and long-lived connection attack generators."""

import subprocess


def c2_beacon_fixed_interval(
    host: str = "127.0.0.1",
    port: int = 4444,
    interval: float = 5.0,
    count: int = 5,
) -> subprocess.Popen:
    """Repeated TCP connects with a fixed interval — classic C2 beacon pattern."""
    code = f"""\
import socket, time
for _ in range({count}):
    s = socket.socket()
    s.settimeout(0.5)
    s.connect_ex(('{host}', {port}))
    time.sleep(0.1)
    s.close()
    time.sleep({interval})
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def long_lived_tcp_connection(duration_sec: int = 30) -> subprocess.Popen:
    """Single TCP connection held open for an extended period — reverse-shell / tunnel pattern."""
    code = f"""\
import socket, time
s = socket.socket()
s.settimeout(1)
s.connect_ex(('127.0.0.1', 4444))
time.sleep({duration_sec})
s.close()
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def c2_beacon_jitter(
    base_interval: float = 10.0,
    jitter: float = 0.3,
    count: int = 5,
) -> subprocess.Popen:
    """Beacon with randomised interval (±jitter) — mimics Cobalt Strike default."""
    code = f"""\
import socket, time, random
for _ in range({count}):
    s = socket.socket()
    s.settimeout(0.5)
    s.connect_ex(('127.0.0.1', 4444))
    s.close()
    jitter_factor = 1.0 + random.uniform(-{jitter}, {jitter})
    time.sleep({base_interval} * jitter_factor)
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def dns_beacon(
    domain: str = "beacon.evil.io",
    interval: float = 30.0,
    count: int = 10,
) -> subprocess.Popen:
    """Periodic DNS queries to a single domain — DNS C2 channel."""
    code = f"""\
import socket, time
for _ in range({count}):
    try:
        socket.getaddrinfo('{domain}', None)
    except Exception:
        pass
    time.sleep({interval})
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def database_connection_pool() -> subprocess.Popen:
    """Negative: long-lived connection on a well-known DB port — should not fire."""
    code = """\
import socket, time
s = socket.socket()
s.settimeout(1)
s.connect_ex(('127.0.0.1', 5432))  # PostgreSQL
time.sleep(5)
s.close()
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)
