"""
K8s integration tests: cluster-level attack detection.

Each test:
  1. Runs an attack command inside the attacker pod (kubectl exec)
  2. Waits for ebpf-guard alert via K8sAlertCollector
  3. Asserts expected rule fired (or did not fire)
"""

import pytest
from conftest import kubectl_exec


pytestmark = pytest.mark.k8s


def test_kubectl_exec_into_victim_fires_drift_alert(
    attacker_pod, victim_pod, alert_collector
):
    """kubectl exec from attacker → victim triggers drift/exec detection."""
    kubectl_exec(victim_pod, "id")
    alerts = alert_collector.collect_for(seconds=5)
    alert_collector.assert_fired(rule_id="k8s_kubectl_exec")


def test_read_service_account_token_fires_alert(attacker_pod, alert_collector):
    """Reading the SA token is a common K8s privilege escalation step."""
    kubectl_exec(
        attacker_pod,
        "cat", "/var/run/secrets/kubernetes.io/serviceaccount/token",
    )
    alert_collector.collect_for(seconds=3)
    alert_collector.assert_fired(rule_id="k8s_sa_token_read")


def test_write_to_host_path_fires_alert(
    attacker_privileged_pod, alert_collector
):
    """Writing to a hostPath mount (host filesystem) — container escape step."""
    kubectl_exec(
        attacker_privileged_pod,
        "sh", "-c", "echo test > /host/tmp/ebpf_guard_test_escape",
    )
    alert_collector.collect_for(seconds=5)
    alert_collector.assert_fired(rule_id="container_host_path_write")


def test_nsenter_to_host_fires_alert(attacker_privileged_pod, alert_collector):
    """nsenter into the host PID namespace — full container escape."""
    kubectl_exec(attacker_privileged_pod, "nsenter", "--target", "1", "--pid", "--", "id")
    alert_collector.collect_for(seconds=5)
    alert_collector.assert_fired(
        rule_id="container_escape_nsenter",
    )


def test_cryptominer_dns_query_fires_alert(attacker_pod, alert_collector):
    """DNS query to a known mining pool domain."""
    kubectl_exec(
        attacker_pod,
        "python3", "-c",
        "import socket; socket.getaddrinfo('pool.minexmr.com', None)",
    )
    alert_collector.collect_for(seconds=5)
    alert_collector.assert_fired(
        predicate=lambda a: "miner" in a.get("rule_id", "").lower()
                            or "crypto" in a.get("rule_id", "").lower(),
    )


def test_lateral_move_internal_port_scan_fires_alert(attacker_pod, alert_collector):
    """Port scan of internal ClusterIP range — lateral movement recon."""
    kubectl_exec(
        attacker_pod,
        "python3", "-c",
        "import socket\n"
        "for p in range(1,30):\n"
        "    s=socket.socket(); s.settimeout(0.01); s.connect_ex(('10.96.0.1',p)); s.close()\n",
    )
    alert_collector.collect_for(seconds=10)
    alert_collector.assert_fired(
        predicate=lambda a: "scan" in a.get("rule_id","").lower()
                            or "recon" in a.get("rule_id","").lower(),
    )


def test_normal_pod_http_request_does_not_fire(attacker_pod, alert_collector):
    """Normal HTTP request on port 80 must not trigger reverse-shell rules."""
    kubectl_exec(
        attacker_pod,
        "python3", "-c",
        "import socket; s=socket.socket(); s.settimeout(0.5); "
        "s.connect_ex(('victim', 80)); s.close()",
    )
    alert_collector.collect_for(seconds=2)
    alert_collector.assert_not_fired(rule_id="reverse_shell_connect")
