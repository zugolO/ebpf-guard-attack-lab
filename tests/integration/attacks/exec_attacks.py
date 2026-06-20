"""Execution / process-launch attack generators."""

import subprocess


def exec_interpreter_from_server(comm: str = "nginx") -> subprocess.Popen:
    """
    Exec a shell from a process masquerading as a web server.
    Simulates webshell / post-exploitation: web process spawns sh.
    """
    return subprocess.Popen(
        ["python3", "-c",
         "import subprocess; subprocess.run(['sh','-c','id'], capture_output=True)"],
        stderr=subprocess.DEVNULL,
    )


def exec_memory_only_binary() -> subprocess.Popen:
    """Execute a binary that was never on disk (memfd_create path)."""
    code = (
        "import ctypes, os\n"
        "libc = ctypes.CDLL(None)\n"
        "fd = libc.memfd_create(b'payload', 1)\n"
        # write a minimal valid ELF or just close it — trigger is memfd_create
        "os.close(fd)\n"
    )
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def ptrace_attach(target_pid: int) -> subprocess.Popen:
    """Attach ptrace to a target PID — triggers anti-debug / credential-dump rules."""
    code = (
        "import ctypes, sys\n"
        "PTRACE_ATTACH = 16\n"
        "libc = ctypes.CDLL(None)\n"
        f"libc.ptrace(PTRACE_ATTACH, {target_pid}, 0, 0)\n"
    )
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def exec_suspicious_tool(tool: str = "nmap") -> subprocess.Popen:
    """Run a known recon tool (living-off-the-land / recon rules)."""
    return subprocess.Popen(
        [tool, "--version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def exec_from_tmp() -> subprocess.Popen:
    """Execute a binary from /tmp — triggers drift / exec-from-tmpfs rules."""
    import os, shutil
    shutil.copy("/bin/true", "/tmp/.guard_test_exec")
    os.chmod("/tmp/.guard_test_exec", 0o755)
    return subprocess.Popen(
        ["/tmp/.guard_test_exec"],
        stderr=subprocess.DEVNULL,
    )


def spawn_shell_from_python() -> subprocess.Popen:
    """Python interpreter spawning a shell — webshell-like pattern."""
    return subprocess.Popen(
        ["python3", "-c", "import subprocess; subprocess.run(['bash','-c','exit'])"],
        stderr=subprocess.DEVNULL,
    )
