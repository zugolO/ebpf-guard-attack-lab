"""
Attack generators for single-machine integration tests.

Each function spawns a real subprocess that performs the attack syscall/action
and returns the subprocess object (with .pid).  Using subprocess keeps the
attacking process separate from the test runner so ebpf-guard sees a realistic
comm / pid pair.
"""
