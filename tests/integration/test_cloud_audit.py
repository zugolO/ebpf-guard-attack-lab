"""
Integration tests: cloud credential theft and lateral movement (EventCloudAudit).

Covers AWS IMDS exfiltration, credentials file reads, IAM enumeration,
and GCP metadata token theft. EventCloudAudit is Python-layer only — see #6.
"""

import pytest
from attacks.cloud_attacks import (
    steal_imds_credentials,
    read_aws_credentials,
    aws_iam_enumerate,
    steal_gcp_service_account_token,
    aws_s3_deploy_artifact,
)


pytestmark = pytest.mark.integration


def test_imds_credential_theft_fires_alert(alerts):
    proc = steal_imds_credentials()
    pid = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        rule_id="aws_imds_credential_access",
        pid=pid,
        timeout=5,
    )
    assert alert.severity in ("warning", "critical")


def test_aws_credentials_file_read_fires_alert(alerts):
    proc = read_aws_credentials()
    pid = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "credential" in a.rule_id.lower() or "cloud" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.pid == pid


def test_aws_iam_enumeration_fires_alert(alerts):
    proc = aws_iam_enumerate()
    pid = proc.pid
    proc.wait(timeout=10)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "iam" in a.rule_id.lower() or "enumerat" in a.rule_id.lower(),
        pid=pid,
        timeout=10,
    )
    assert alert.pid == pid


def test_gcp_metadata_token_theft_fires_alert(alerts):
    proc = steal_gcp_service_account_token()
    pid = proc.pid
    proc.wait(timeout=5)

    alert = alerts.wait_for_alert(
        predicate=lambda a: "cloud" in a.rule_id.lower() or "metadata" in a.rule_id.lower(),
        pid=pid,
        timeout=5,
    )
    assert alert.severity in ("warning", "critical")


def test_legitimate_cicd_aws_call_does_not_fire(alerts):
    proc = aws_s3_deploy_artifact()
    pid = proc.pid
    proc.wait(timeout=10)

    alerts.wait_for_no_alert(pid=pid, window=3)
