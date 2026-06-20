"""
K8s integration test fixtures.

Requires:
  - kubectl configured and pointing at a test cluster
  - ebpf-guard DaemonSet running (or will be deployed by EBPF_GUARD_DEPLOY=1)
  - python packages: kubernetes, pytest

Environment variables:
  KUBECONFIG              path to kubeconfig (default: ~/.kube/config)
  EBPF_GUARD_IMAGE        ebpf-guard container image to deploy
  EBPF_GUARD_DEPLOY       set to "1" to deploy DaemonSet before tests
  EBPF_GUARD_NS           namespace (default: ebpf-guard-test)
  EBPF_GUARD_K8S_TIMEOUT  seconds to wait for pods/alerts (default: 30)
  EBPF_GUARD_ALERT_SOCKET path to alert socket on the node (mounted via hostPath)
"""

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Iterator, Optional

import pytest

try:
    from kubernetes import client as k8s_client
    from kubernetes import config as k8s_config
    from kubernetes.client import CoreV1Api, AppsV1Api
    HAS_K8S_SDK = True
except ImportError:
    HAS_K8S_SDK = False

NAMESPACE     = os.getenv("EBPF_GUARD_NS", "ebpf-guard-test")
TIMEOUT       = int(os.getenv("EBPF_GUARD_K8S_TIMEOUT", "30"))
MANIFESTS_DIR = Path(__file__).parent / "manifests"
DEPLOY        = os.getenv("EBPF_GUARD_DEPLOY", "0") == "1"


# ── kubectl helper ─────────────────────────────────────────────────────────────

def kubectl(*args, check=True, capture=True) -> subprocess.CompletedProcess:
    cmd = ["kubectl", *args]
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
    )


def kubectl_exec(pod: str, *cmd, namespace: str = NAMESPACE) -> str:
    result = kubectl(
        "exec", pod, "-n", namespace, "--", *cmd,
        capture=True,
    )
    return result.stdout


def wait_pod_ready(name: str, namespace: str = NAMESPACE, timeout: int = TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = kubectl(
            "get", "pod", name, "-n", namespace,
            "-o", "jsonpath={.status.phase}",
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip() == "Running":
            return
        time.sleep(2)
    raise TimeoutError(f"Pod {name} not Running after {timeout}s")


def wait_daemonset_ready(name: str, namespace: str = NAMESPACE, timeout: int = TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = kubectl(
            "get", "daemonset", name, "-n", namespace,
            "-o", "jsonpath={.status.numberReady}",
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip() not in ("", "0"):
            return
        time.sleep(3)
    raise TimeoutError(f"DaemonSet {name} not ready after {timeout}s")


# ── Alert collection from K8s (read via kubectl exec into ebpf-guard pod) ─────

class K8sAlertCollector:
    """
    Reads JSON-line alerts from the ebpf-guard pod running on the same node
    as the test workloads.  Uses `kubectl exec` into the guard pod to tail
    the alert socket output.
    """

    def __init__(self, guard_pod: str):
        self._guard_pod = guard_pod
        self._alerts: list = []

    def collect_for(self, seconds: float = 3.0):
        """Collect all alerts emitted during a window of `seconds`."""
        try:
            result = kubectl(
                "exec", self._guard_pod, "-n", NAMESPACE,
                "--", "timeout", str(int(seconds)),
                "cat", "/run/ebpf-guard/alerts.fifo",
                check=False,
            )
            for line in result.stdout.splitlines():
                try:
                    self._alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        except subprocess.SubprocessError:
            pass
        return self._alerts

    def find(self, *, rule_id: Optional[str] = None, comm: Optional[str] = None,
             pid: Optional[int] = None) -> list:
        return [
            a for a in self._alerts
            if (rule_id is None or a.get("rule_id") == rule_id)
            and (comm   is None or a.get("comm")    == comm)
            and (pid    is None or a.get("pid")      == pid)
        ]

    def assert_fired(self, *, rule_id: str, **kwargs):
        matches = self.find(rule_id=rule_id, **kwargs)
        assert matches, (
            f"Expected alert rule_id={rule_id!r} but got: "
            + str([a.get("rule_id") for a in self._alerts[-10:]])
        )
        return matches[0]

    def assert_not_fired(self, *, rule_id: str, **kwargs):
        matches = self.find(rule_id=rule_id, **kwargs)
        assert not matches, f"Unexpected alert fired: {rule_id!r} — {matches}"


# ── Session fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def k8s_namespace():
    kubectl("apply", "-f", str(MANIFESTS_DIR / "namespace.yaml"))
    yield NAMESPACE


@pytest.fixture(scope="session")
def ebpf_guard_ready(k8s_namespace):
    if DEPLOY:
        kubectl("apply", "-f", str(MANIFESTS_DIR / "ebpf-guard-daemonset.yaml"))
    wait_daemonset_ready("ebpf-guard", namespace=k8s_namespace, timeout=120)

    # Return the name of one guard pod on the default node
    result = kubectl(
        "get", "pods", "-n", k8s_namespace,
        "-l", "app=ebpf-guard",
        "-o", "jsonpath={.items[0].metadata.name}",
    )
    guard_pod = result.stdout.strip()
    assert guard_pod, "No ebpf-guard pod found"
    yield guard_pod


@pytest.fixture(scope="session")
def victim_pod(k8s_namespace, ebpf_guard_ready):
    kubectl("apply", "-f", str(MANIFESTS_DIR / "victim-deployment.yaml"))
    # Wait for victim pod
    result = kubectl(
        "get", "pods", "-n", k8s_namespace,
        "-l", "role=victim",
        "-o", "jsonpath={.items[0].metadata.name}",
    )
    pod_name = result.stdout.strip()
    wait_pod_ready(pod_name, namespace=k8s_namespace)
    yield pod_name


@pytest.fixture(scope="session")
def attacker_pod(k8s_namespace, ebpf_guard_ready):
    kubectl("apply", "-f", str(MANIFESTS_DIR / "attacker-pod.yaml"))
    wait_pod_ready("attacker", namespace=k8s_namespace)
    yield "attacker"


@pytest.fixture(scope="session")
def attacker_privileged_pod(k8s_namespace, ebpf_guard_ready):
    kubectl("apply", "-f", str(MANIFESTS_DIR / "attacker-privileged-pod.yaml"))
    wait_pod_ready("attacker-privileged", namespace=k8s_namespace)
    yield "attacker-privileged"


@pytest.fixture
def alert_collector(ebpf_guard_ready):
    return K8sAlertCollector(guard_pod=ebpf_guard_ready)


# ── Session teardown ───────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def cleanup_namespace(k8s_namespace):
    yield
    if os.getenv("EBPF_GUARD_KEEP_NS", "0") != "1":
        kubectl("delete", "namespace", k8s_namespace, "--ignore-not-found", check=False)
