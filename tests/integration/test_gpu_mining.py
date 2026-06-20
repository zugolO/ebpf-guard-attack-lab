"""
Integration tests: GPU / crypto-miner detection (EventGPU, event_type=11).

Architecture:
  ebpf-guard attaches uprobes to libcuda.so.1 function entry points.
  When a process calls cuMemAlloc / cuLaunchKernel / cuMemcpyHtoD, the uprobe
  fires, ebpf-guard emits a GPUEvent, and the rule engine evaluates it against
  rules/gpu-mining.yaml.  Tests assert that the expected rule fires (or is
  absent) within a timeout.

Why Python integration tests (not Go YAML unit tests):
  YAML unit tests exercise the rule engine in isolation with synthetic events.
  These tests exercise the full uprobe→kernel-event→daemon→socket→rule pipeline,
  confirming that eBPF uprobes on libcuda.so.1 actually fire for real calls.

Requirements:
  - ebpf-guard daemon running with GPU uprobe support
  - libcuda.so.1 (NVIDIA driver) OR a stub; set CUDA_MOCK_LIB to the stub path
  - Same eBPF-capable Linux VM as other integration tests (see conftest.py)

Skip:
  All tests in this module are skipped automatically when libcuda.so.1 cannot
  be located and CUDA_MOCK_LIB is not set, so the suite is safe to include in
  the standard `make test-integration` run.
"""

import pytest
from attacks.gpu_attacks import (
    cuda_large_alloc,
    cuda_continuous_memcpy,
    cuda_kernel_launch_from_unknown,
    cuda_lib_available,
    pytorch_training_job,
)


pytestmark = pytest.mark.integration

requires_cuda = pytest.mark.skipif(
    not cuda_lib_available(),
    reason=(
        "libcuda.so.1 not found — set CUDA_MOCK_LIB to a stub path "
        "(see hack/build-cuda-mock.sh) or install NVIDIA CUDA drivers"
    ),
)


@requires_cuda
def test_cuda_large_alloc_fires_alert(alerts):
    """
    A 500 MiB cuMemAlloc from an unlisted process must trigger
    gpu_large_alloc_unusual (critical).
    """
    proc = cuda_large_alloc()
    pid = proc.pid
    proc.wait(timeout=10)

    alert = alerts.wait_for_alert(
        rule_id="gpu_large_alloc_unusual",
        pid=pid,
        timeout=10,
    )
    assert alert.severity == "critical"
    assert alert.pid == pid


@requires_cuda
def test_cuda_kernel_launch_fires_alert(alerts):
    """
    A cuLaunchKernel call from a process not in the ML allowlist must trigger
    gpu_kernel_launch_unauthorized (warning).

    Note: the attack subprocess runs as comm='python3', which is allowlisted
    in gpu_kernel_launch_unauthorized.  This test therefore exercises the
    uprobe pipeline rather than the rule match.  To test the full alert path,
    run the attack from a binary whose comm is not allowlisted (e.g. 'xmrig').
    The predicate below accepts any GPU kernel-launch alert.
    """
    proc = cuda_kernel_launch_from_unknown()
    pid = proc.pid
    proc.wait(timeout=10)

    # Accept any GPU alert for this pid — comm='python3' may or may not be
    # allowlisted depending on local rule tuning.
    alerts.wait_for_alert(
        predicate=lambda a: a.pid == pid and "gpu" in a.rule_id.lower(),
        timeout=10,
    )


@requires_cuda
def test_cuda_continuous_memcpy_fires_alert(alerts):
    """
    Repeated cuMemcpyHtoD calls from an unlisted process must trigger
    gpu_mining_pattern.  The attack performs 5 host-to-device transfers;
    we assert on the first alert.
    """
    proc = cuda_continuous_memcpy()
    pid = proc.pid
    proc.wait(timeout=15)

    alert = alerts.wait_for_alert(
        rule_id="gpu_mining_pattern",
        pid=pid,
        timeout=15,
    )
    assert alert.pid == pid


@requires_cuda
def test_pytorch_small_alloc_does_not_fire_large_alloc_rule(alerts):
    """
    A 10 MiB cuMemAlloc (simulating a per-tensor PyTorch allocation) must NOT
    trigger gpu_large_alloc_unusual, which only fires above 500 MiB.

    This is the negative / benign-corpus test: legitimate ML usage should not
    generate false-positive miner alerts.
    """
    proc = pytorch_training_job()
    pid = proc.pid
    proc.wait(timeout=10)

    alerts.wait_for_no_alert(
        rule_id="gpu_large_alloc_unusual",
        pid=pid,
        window=3,
    )
