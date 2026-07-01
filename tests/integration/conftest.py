"""
Integration test fixtures for ebpf-guard single-machine testing.

Setup:
  - ebpf-guard daemon must be running on this machine (or started via EBPF_GUARD_BINARY)
  - Tests require root privileges (eBPF needs CAP_BPF / CAP_SYS_ADMIN)
  - Alert delivery via unix socket (default: /run/ebpf-guard/alerts.sock)

Environment variables:
  EBPF_GUARD_BINARY       path to ebpf-guard binary (starts daemon if set)
  EBPF_GUARD_CONFIG       path to config file for the daemon
  EBPF_GUARD_ALERT_SOCKET path to unix socket for JSON-line alerts
                          (default: /run/ebpf-guard/alerts.sock)
  EBPF_GUARD_ALERT_LOG    fallback: path to log file with JSON alerts
  EBPF_GUARD_TIMEOUT      seconds to wait for an alert (default: 5)
"""

import json
import os
import queue
import select
import signal
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import pytest


ALERT_SOCKET = os.getenv("EBPF_GUARD_ALERT_SOCKET", "/run/ebpf-guard/alerts.sock")
ALERT_LOG    = os.getenv("EBPF_GUARD_ALERT_LOG", "")
DEFAULT_TIMEOUT = float(os.getenv("EBPF_GUARD_TIMEOUT", "5"))


@dataclass
class Alert:
    rule_id:   str
    severity:  str
    pid:       int
    comm:      str
    action:    str
    rule_name: str = ""
    message:   str = ""
    timestamp: str = ""

    @staticmethod
    def from_dict(d: dict) -> "Alert":
        return Alert(
            rule_id=d.get("rule_id", ""),
            severity=d.get("severity", ""),
            pid=d.get("pid", 0),
            comm=d.get("comm", ""),
            action=d.get("action", "alert"),
            rule_name=d.get("rule_name", ""),
            message=d.get("message", ""),
            timestamp=d.get("timestamp", ""),
        )


class AlertCollector:
    """Reads JSON-line alerts from ebpf-guard and queues them for tests."""

    def __init__(self):
        self._q: queue.Queue[Alert] = queue.Queue()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if Path(ALERT_SOCKET).exists():
            self._thread = threading.Thread(target=self._read_socket, daemon=True)
        elif ALERT_LOG:
            self._thread = threading.Thread(target=self._tail_log, daemon=True)
        else:
            raise RuntimeError(
                f"No alert source found. Set EBPF_GUARD_ALERT_SOCKET or "
                f"EBPF_GUARD_ALERT_LOG. Socket path checked: {ALERT_SOCKET}"
            )
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def wait_for_alert(
        self,
        *,
        rule_id: Optional[str] = None,
        comm: Optional[str] = None,
        pid: Optional[int] = None,
        severity: Optional[str] = None,
        predicate: Optional[Callable[[Alert], bool]] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> Alert:
        """
        Block until a matching alert arrives or timeout expires.
        Raises AssertionError on timeout — test fails with a clear message.
        """
        deadline = time.monotonic() + timeout
        collected = []

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                alert = self._q.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                continue

            collected.append(alert)
            if self._matches(alert, rule_id=rule_id, comm=comm, pid=pid,
                             severity=severity, predicate=predicate):
                return alert

        criteria = dict(rule_id=rule_id, comm=comm, pid=pid, severity=severity)
        criteria = {k: v for k, v in criteria.items() if v is not None}
        raise AssertionError(
            f"No matching alert within {timeout}s. Criteria: {criteria}. "
            f"Received {len(collected)} non-matching alert(s): "
            + ", ".join(f"{a.rule_id}(pid={a.pid},comm={a.comm})" for a in collected[-5:])
        )

    def wait_for_no_alert(
        self,
        *,
        rule_id: Optional[str] = None,
        comm: Optional[str] = None,
        pid: Optional[int] = None,
        predicate: Optional[Callable[[Alert], bool]] = None,
        window: float = 1.0,
    ):
        """Assert that no matching alert arrives within the window."""
        deadline = time.monotonic() + window
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            try:
                alert = self._q.get(timeout=min(remaining, 0.05))
            except queue.Empty:
                continue
            if self._matches(alert, rule_id=rule_id, comm=comm, pid=pid, predicate=predicate):
                raise AssertionError(
                    f"Unexpected alert fired: rule_id={alert.rule_id} "
                    f"pid={alert.pid} comm={alert.comm}"
                )

    @staticmethod
    def _matches(alert: Alert, *, rule_id, comm, pid, severity=None,
                 predicate=None) -> bool:
        if rule_id  and alert.rule_id  != rule_id:  return False
        if comm     and alert.comm     != comm:      return False
        if pid      and alert.pid      != pid:       return False
        if severity and alert.severity != severity:  return False
        if predicate and not predicate(alert):       return False
        return True

    def _read_socket(self):
        while not self._stop.is_set():
            try:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.connect(ALERT_SOCKET)
                buf = b""
                while not self._stop.is_set():
                    r, _, _ = select.select([sock], [], [], 0.1)
                    if not r:
                        continue
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        self._enqueue(line)
                sock.close()
            except (ConnectionRefusedError, FileNotFoundError):
                time.sleep(0.5)

    def _tail_log(self):
        with open(ALERT_LOG, "r") as f:
            f.seek(0, 2)  # seek to end
            while not self._stop.is_set():
                line = f.readline()
                if line:
                    self._enqueue(line.encode())
                else:
                    time.sleep(0.05)

    def _enqueue(self, raw: bytes):
        try:
            d = json.loads(raw.decode("utf-8", errors="replace").strip())
            self._q.put(Alert.from_dict(d))
        except json.JSONDecodeError:
            pass


class DaemonManager:
    """Optionally starts/stops the ebpf-guard daemon for the test session."""

    def __init__(self):
        self._proc: Optional[subprocess.Popen] = None

    def start(self):
        binary = os.getenv("EBPF_GUARD_BINARY", "")
        if not binary:
            return  # assume daemon is already running externally
        config = os.getenv("EBPF_GUARD_CONFIG", "")
        cmd = [binary]
        if config:
            cmd += ["--config", config]
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # give daemon time to load eBPF programs
        time.sleep(2)

    def stop(self):
        if self._proc:
            self._proc.send_signal(signal.SIGTERM)
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None


# ── Session-scoped fixtures ────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def daemon():
    mgr = DaemonManager()
    mgr.start()
    yield mgr
    mgr.stop()


@pytest.fixture(scope="session")
def alerts(daemon):
    collector = AlertCollector()
    collector.start()
    yield collector
    collector.stop()


# ── Per-test temp directory ────────────────────────────────────────────────────

@pytest.fixture
def tmp(tmp_path):
    return tmp_path
