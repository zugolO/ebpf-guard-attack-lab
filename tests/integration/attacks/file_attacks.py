"""File-access attack generators."""

import subprocess
import tempfile
from pathlib import Path


def read_sensitive_file(path: str = "/etc/shadow") -> subprocess.Popen:
    """Open a sensitive file for reading using a recognisable comm."""
    return subprocess.Popen(
        ["python3", "-c", f"open('{path}').read()"],
        stderr=subprocess.DEVNULL,
    )


def write_to_tmpfs(filename: str = ".implant") -> subprocess.Popen:
    """Write a suspicious file to /tmp (tmpfs write by non-package-manager)."""
    path = f"/tmp/{filename}"
    return subprocess.Popen(
        ["python3", "-c", f"open('{path}', 'w').write('payload')"],
        stderr=subprocess.DEVNULL,
    )


def write_executable_to_tmp() -> subprocess.Popen:
    """Drop an executable into /tmp — triggers dropper/drift rules."""
    return subprocess.Popen(
        ["python3", "-c",
         "import os; f=open('/tmp/.x','wb'); f.write(b'\\x7fELF'); f.close(); "
         "os.chmod('/tmp/.x', 0o755)"],
        stderr=subprocess.DEVNULL,
    )


def modify_cron(path: str = "/etc/cron.d/test_persist") -> subprocess.Popen:
    """Write to a cron directory — triggers persistence rules."""
    return subprocess.Popen(
        ["python3", "-c",
         f"open('{path}', 'w').write('* * * * * root /tmp/.x\\n')"],
        stderr=subprocess.DEVNULL,
    )


def read_proc_keys() -> subprocess.Popen:
    """Read /proc/keys — credential access via proc filesystem."""
    return subprocess.Popen(
        ["python3", "-c", "open('/proc/keys').read()"],
        stderr=subprocess.DEVNULL,
    )


def overwrite_ld_preload() -> subprocess.Popen:
    """Write to /etc/ld.so.preload — classic persistence / hijack."""
    return subprocess.Popen(
        ["python3", "-c", "open('/etc/ld.so.preload','w').write('/tmp/evil.so')"],
        stderr=subprocess.DEVNULL,
    )
