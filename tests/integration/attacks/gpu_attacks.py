"""GPU / crypto-miner attack generators.

All functions return a subprocess.Popen whose PID can be correlated with
AlertCollector.wait_for_alert() in the test suite.

Environment variables:
  CUDA_MOCK_LIB   path to a stub libcuda.so.1 for CI environments without a
                  real NVIDIA GPU.  The stub must export cuInit, cuDeviceGet,
                  cuCtxCreate, cuCtxDestroy, cuMemAlloc, cuMemFree,
                  cuLaunchKernel, and cuMemcpyHtoD with the real signatures
                  but is allowed to return CUDA_ERROR_NO_DEVICE for GPU ops.
                  ebpf-guard attaches uprobes to these symbols at the shared
                  library level, so the uprobe fires regardless of the return
                  value — making the stub sufficient for alert generation.

GPU op codes understood by ebpf-guard (GPUEvent.Op):
  0 = alloc         cuMemAlloc
  1 = free          cuMemFree
  2 = memcpy_htod   cuMemcpyHtoD  ← upload (mining loop)
  3 = memcpy_dtoh   cuMemcpyDtoH
  4 = memcpy_dtod   cuMemcpyDtoD
  5 = kernel_launch cuLaunchKernel
"""

import ctypes
import ctypes.util
import os
import subprocess


def _cuda_lib_path() -> str:
    """Return a usable path to libcuda.so.1 or an empty string if not found."""
    env_mock = os.getenv("CUDA_MOCK_LIB", "")
    if env_mock and os.path.exists(env_mock):
        return env_mock

    found = ctypes.util.find_library("cuda")
    if found:
        return found

    for candidate in (
        "/usr/lib/x86_64-linux-gnu/libcuda.so.1",
        "/usr/lib64/libcuda.so.1",
        "/usr/local/cuda/lib64/libcuda.so.1",
        "/usr/local/cuda/lib/libcuda.so.1",
    ):
        if os.path.exists(candidate):
            return candidate

    return ""


def cuda_lib_available() -> bool:
    """Return True if libcuda.so.1 (or a mock stub) can be located."""
    return bool(_cuda_lib_path())


def cuda_large_alloc() -> subprocess.Popen:
    """
    Spawn a subprocess that calls cuMemAlloc(500 MiB).

    ebpf-guard intercepts the cuMemAlloc uprobe and emits a GPUEvent with
    op=alloc, size=524288000, triggering the gpu_large_alloc_unusual rule.
    The subprocess comm is 'python3' which is not in the rule's allowlist.
    """
    lib = _cuda_lib_path()
    code = f"""
import ctypes
try:
    libcuda = ctypes.CDLL("{lib}")
    libcuda.cuInit(0)
    dev = ctypes.c_int()
    libcuda.cuDeviceGet(ctypes.byref(dev), 0)
    ctx = ctypes.c_void_p()
    libcuda.cuCtxCreate(ctypes.byref(ctx), 0, dev)
    ptr = ctypes.c_void_p()
    # 500 MiB — above the gpu_large_alloc_unusual threshold
    libcuda.cuMemAlloc(ctypes.byref(ptr), 500 * 1024 * 1024)
    if ctx.value:
        libcuda.cuCtxDestroy(ctx)
except Exception:
    pass
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def cuda_kernel_launch_from_unknown() -> subprocess.Popen:
    """
    Spawn a subprocess that calls cuLaunchKernel with a null function pointer.

    The call will return an error, but ebpf-guard intercepts the uprobe entry
    before the error check, emitting a GPUEvent with op=kernel_launch.
    The subprocess comm is 'python3'; the rule gpu_kernel_launch_unauthorized
    allowlists 'python3', so tests for this scenario should use a non-allowlisted
    executable (e.g. a compiled wrapper renamed to 'xmrig') in practice.
    This function is provided for completeness and exercises the uprobe path.
    """
    lib = _cuda_lib_path()
    code = f"""
import ctypes
try:
    libcuda = ctypes.CDLL("{lib}")
    libcuda.cuInit(0)
    dev = ctypes.c_int()
    libcuda.cuDeviceGet(ctypes.byref(dev), 0)
    ctx = ctypes.c_void_p()
    libcuda.cuCtxCreate(ctypes.byref(ctx), 0, dev)
    # cuLaunchKernel with null hf — uprobe fires before error propagation
    libcuda.cuLaunchKernel(None, 1, 1, 1, 1, 1, 1, 0, None, None, None)
    if ctx.value:
        libcuda.cuCtxDestroy(ctx)
except Exception:
    pass
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def cuda_continuous_memcpy() -> subprocess.Popen:
    """
    Spawn a subprocess that calls cuMemcpyHtoD in a tight loop (5 iterations).

    Each cuMemcpyHtoD call triggers a GPUEvent with op=memcpy_htod.
    The subprocess comm 'python3' is not in the gpu_mining_pattern allowlist,
    so each iteration fires an alert.  Tests should wait for at least one alert.
    """
    lib = _cuda_lib_path()
    code = f"""
import ctypes
try:
    libcuda = ctypes.CDLL("{lib}")
    libcuda.cuInit(0)
    dev = ctypes.c_int()
    libcuda.cuDeviceGet(ctypes.byref(dev), 0)
    ctx = ctypes.c_void_p()
    libcuda.cuCtxCreate(ctypes.byref(ctx), 0, dev)
    dev_ptr = ctypes.c_void_p()
    staging = 4 * 1024 * 1024  # 4 MiB
    libcuda.cuMemAlloc(ctypes.byref(dev_ptr), staging)
    host_buf = ctypes.create_string_buffer(staging)
    for _ in range(5):
        libcuda.cuMemcpyHtoD(dev_ptr, host_buf, staging)
    if dev_ptr.value:
        libcuda.cuMemFree(dev_ptr)
    if ctx.value:
        libcuda.cuCtxDestroy(ctx)
except Exception:
    pass
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)


def pytorch_training_job() -> subprocess.Popen:
    """
    Simulate a legitimate ML training job with a small GPU allocation (10 MiB).

    This must NOT trigger gpu_large_alloc_unusual (threshold: 500 MiB).

    In practice, PyTorch builds a CUDA context and allocates memory
    incrementally as tensors are created — individual allocations stay well
    below the large single-shot reservation made by a crypto miner.
    """
    lib = _cuda_lib_path()
    code = f"""
import ctypes
try:
    libcuda = ctypes.CDLL("{lib}")
    libcuda.cuInit(0)
    dev = ctypes.c_int()
    libcuda.cuDeviceGet(ctypes.byref(dev), 0)
    ctx = ctypes.c_void_p()
    libcuda.cuCtxCreate(ctypes.byref(ctx), 0, dev)
    ptr = ctypes.c_void_p()
    # 10 MiB — typical per-tensor allocation, well below 500 MiB threshold
    libcuda.cuMemAlloc(ctypes.byref(ptr), 10 * 1024 * 1024)
    if ptr.value:
        libcuda.cuMemFree(ptr)
    if ctx.value:
        libcuda.cuCtxDestroy(ctx)
except Exception:
    pass
"""
    return subprocess.Popen(["python3", "-c", code], stderr=subprocess.DEVNULL)
