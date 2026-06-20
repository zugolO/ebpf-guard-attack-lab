"""Cloud credential theft and lateral movement attack generators."""

import subprocess


def steal_imds_credentials() -> subprocess.Popen:
    """HTTP GET to AWS EC2 IMDS IAM credentials endpoint."""
    return subprocess.Popen(
        ["python3", "-c", """\
import urllib.request
try:
    req = urllib.request.urlopen(
        'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        timeout=2,
    )
except Exception:
    pass
"""],
        stderr=subprocess.DEVNULL,
    )


def read_aws_credentials() -> subprocess.Popen:
    """Direct read of ~/.aws/credentials — plaintext key theft."""
    return subprocess.Popen(
        ["python3", "-c", "open('/root/.aws/credentials').read()"],
        stderr=subprocess.DEVNULL,
    )


def aws_iam_enumerate() -> subprocess.Popen:
    """Run aws iam list-users — lateral movement reconnaissance."""
    return subprocess.Popen(
        ["aws", "iam", "list-users", "--output", "json"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def steal_gcp_service_account_token() -> subprocess.Popen:
    """HTTP GET to GCP metadata server for a service-account token."""
    return subprocess.Popen(
        ["python3", "-c", """\
import urllib.request
try:
    req = urllib.request.Request(
        'http://metadata.google.internal/computeMetadata/v1/instance/'
        'service-accounts/default/token',
        headers={'Metadata-Flavor': 'Google'},
    )
    urllib.request.urlopen(req, timeout=2)
except Exception:
    pass
"""],
        stderr=subprocess.DEVNULL,
    )


def aws_s3_deploy_artifact() -> subprocess.Popen:
    """Negative: legitimate CI/CD aws s3 cp — should not trigger cloud audit alert."""
    return subprocess.Popen(
        ["aws", "s3", "cp", "/dev/null", "s3://ci-artifacts/placeholder"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
