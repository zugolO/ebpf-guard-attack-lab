"""io_uring syscall-detection evasion attack generators (PLAN.md §3 task D).

io_uring lets a process hand file and network I/O to a shared ring that the
*kernel* executes: the application calls ``io_uring_setup(2)`` once and then
only ``io_uring_enter(2)``, while the actual ``read(2)``/``connect(2)`` never
runs. A monitor built on classic syscall hooks therefore sees the ring
submission but not the operation behind it. The generators below drive that
shape with raw io_uring (ctypes) so ``tests/integration/test_iouring_evasion.py``
can ask what the live ebpf-guard daemon reports:

  * io_uring_setup_probe  -- setup only; should fire iouring_unexpected_setup.
  * ring_read_file        -- open a benign file normally, then read it with
                             IORING_OP_READ through the ring (no read(2));
                             should fire iouring_unexpected_enter.
  * ring_openat_and_read  -- open *and* read a file entirely through the ring
                             (IORING_OP_OPENAT + IORING_OP_READ), so neither
                             open(2) nor read(2) runs; the KNOWN BYPASS case.
  * ring_connect_loopback -- replace connect(2) with IORING_OP_CONNECT to a
                             loopback port.
  * benign_no_iouring_wait-- negative control: no io_uring at all.

SAFETY: every generator is non-destructive. Files are only ever opened
read-only (``O_RDONLY``; ``ring_read_file`` adds ``O_NOFOLLOW``); no data is
written, printed or exported; the network generator refuses any non-loopback
host and connects to a port on 127.0.0.1 that is dropped/unused.

CHILD EXIT CODES: a missing/unreadable target (``EXIT_NO_TARGET``) is
environmental absence and stays a clean skip, but every other failure --
io_uring unavailable at runtime, a negative completion result, or no completion
at all -- exits non-zero. Without that, a ring op that never actually executed
would be indistinguishable from one the daemon missed, and the known-bypass
"no alert" assertions would pass vacuously. The integration suite reaps the
child and asserts on its exit code before believing the non-outcome (see
``_reap`` in tests/integration/test_iouring_evasion.py).

WHAT THE MONITOR CAN SEE (documented KNOWN BYPASS): the lab's ruletest event
model exposes only ``op`` (setup/enter), ``to_submit``, ``flags`` and ``fd`` on
an io_uring event (``IOUringSpec`` in internal/ruletest/types.go; the daemon's
``types.IOUringEvent`` carries the same four fields). There is no target path,
no file payload and no network address/dport. A ring-based read or connect is
therefore indistinguishable from a bare ``io_uring_enter`` by the Go rule
engine: the only signal is that *some* process submitted *some* work. The
integration suite asserts this known-bypass non-outcome (no ``cred_shadow_read``
for a ring read of /etc/shadow; no ``lateral_rdp_connection`` for a ring connect
to :3389) while asserting the generic ``iouring_unexpected_enter`` still fires,
so the gap is exercised rather than silently skipped.

``io_uring_supported()`` runs a real ``io_uring_setup`` probe via ctypes and
returns False on kernels that lack it (including every non-Linux platform), so
the suite skips instead of failing on a macOS developer machine. The whole
module is only executed on the root + daemon + eBPF-kernel stand.

Consumed by tests/integration/test_iouring_evasion.py; needs root + a running
ebpf-guard daemon and skips otherwise.
"""

from __future__ import annotations

import subprocess
import sys

_PYTHON = sys.executable or "/usr/bin/python3"

_LOOPBACK = "127.0.0.1"

# Child exit-code protocol: 0 means the ring operation really executed (a
# negative errno that still proves execution, e.g. ECONNREFUSED on a closed
# loopback port, also counts as 0); anything else is reported to the test.
EXIT_NO_TARGET = 3
EXIT_RING_UNAVAILABLE = 4
EXIT_OP_FAILED = 5
EXIT_NO_CQE = 6


def _spawn(code: str) -> subprocess.Popen:
    """Run a child ``python3 -c`` snippet with its output suppressed."""
    return subprocess.Popen(
        [_PYTHON, "-c", code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


_SUPPORT_PROBE = r'''
import ctypes, os

SYS_IO_URING_SETUP = 425

libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long

params = ctypes.create_string_buffer(256)
fd = libc.syscall(SYS_IO_URING_SETUP, 8, ctypes.byref(params))
if fd < 0:
    raise SystemExit(1)
os.close(fd)
raise SystemExit(0)
'''


def io_uring_supported() -> bool:
    """True when the running kernel can create an io_uring (ctypes probe).

    Spawns a short-lived child that calls ``io_uring_setup(2)`` and exits 0 on
    success. Non-Linux platforms short-circuit to False without ever attempting
    the raw syscall (that number means something else there).
    """
    if not sys.platform.startswith("linux"):
        return False
    try:
        proc = subprocess.run(
            [_PYTHON, "-c", _SUPPORT_PROBE],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


# Raw io_uring plumbing shared by every ring generator. Loaded into the child
# via `python3 -c`; it never runs on the host. Struct layouts follow
# <linux/io_uring.h>: io_uring_params (with its sq/cq offsets) and the 64-byte
# io_uring_sqe / 16-byte io_uring_cqe. Fields beyond `user_data` are left
# zeroed, which is all a NOP/READ/OPENAT/CONNECT SQE needs.
_RING_HELPERS = (
    f"EXIT_NO_TARGET = {EXIT_NO_TARGET}\n"
    f"EXIT_RING_UNAVAILABLE = {EXIT_RING_UNAVAILABLE}\n"
    f"EXIT_OP_FAILED = {EXIT_OP_FAILED}\n"
    f"EXIT_NO_CQE = {EXIT_NO_CQE}\n"
    + r'''
import ctypes, errno, mmap, os, socket, struct, time

SYS_IO_URING_SETUP = 425
SYS_IO_URING_ENTER = 426

IORING_OFF_SQ_RING = 0x00000000
IORING_OFF_CQ_RING = 0x08000000
IORING_OFF_SQES = 0x10000000

IORING_OP_NOP = 0
IORING_OP_CONNECT = 16
IORING_OP_OPENAT = 18
IORING_OP_READ = 22

AT_FDCWD = -100
O_RDONLY = 0

SQE_SIZE = 64
CQE_SIZE = 16

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long

# liburing publishes the SQ tail with smp_store_release; mirror it best-effort.
# __sync_synchronize lives in libgcc/compiler-rt and is not guaranteed to be
# reachable via ctypes everywhere, so fall back to the enter syscall boundary.
try:
    _sync_synchronize = _libc.__sync_synchronize
except AttributeError:
    _sync_synchronize = None


class _SQRingOffsets(ctypes.Structure):
    _fields_ = [
        ("head", ctypes.c_uint32), ("tail", ctypes.c_uint32),
        ("ring_mask", ctypes.c_uint32), ("ring_entries", ctypes.c_uint32),
        ("flags", ctypes.c_uint32), ("dropped", ctypes.c_uint32),
        ("array", ctypes.c_uint32), ("resv1", ctypes.c_uint32),
        ("resv2", ctypes.c_uint64),
    ]


class _CQRingOffsets(ctypes.Structure):
    _fields_ = [
        ("head", ctypes.c_uint32), ("tail", ctypes.c_uint32),
        ("ring_mask", ctypes.c_uint32), ("ring_entries", ctypes.c_uint32),
        ("overflow", ctypes.c_uint32), ("cqes", ctypes.c_uint32),
        ("flags", ctypes.c_uint32), ("resv1", ctypes.c_uint32),
        ("resv2", ctypes.c_uint64),
    ]


class _URingParams(ctypes.Structure):
    _fields_ = [
        ("sq_entries", ctypes.c_uint32), ("cq_entries", ctypes.c_uint32),
        ("flags", ctypes.c_uint32), ("sq_thread_cpu", ctypes.c_uint32),
        ("sq_thread_idle", ctypes.c_uint32), ("features", ctypes.c_uint32),
        ("wq_fd", ctypes.c_uint32), ("resv", ctypes.c_uint32 * 3),
        ("sq_off", _SQRingOffsets), ("cq_off", _CQRingOffsets),
    ]


class Ring:
    def __init__(self, entries):
        self.params = _URingParams()
        fd = _libc.syscall(
            SYS_IO_URING_SETUP, int(entries), ctypes.byref(self.params)
        )
        if fd < 0:
            raise OSError(ctypes.get_errno(), "io_uring_setup")
        self.fd = fd
        p = self.params
        self.sq_ring = mmap.mmap(
            fileno=self.fd, length=p.sq_off.array + p.sq_entries * 4,
            flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE,
            offset=IORING_OFF_SQ_RING,
        )
        self.cq_ring = mmap.mmap(
            fileno=self.fd, length=p.cq_off.cqes + p.cq_entries * CQE_SIZE,
            flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE,
            offset=IORING_OFF_CQ_RING,
        )
        self.sqes = mmap.mmap(
            fileno=self.fd, length=p.sq_entries * SQE_SIZE,
            flags=mmap.MAP_SHARED, prot=mmap.PROT_READ | mmap.PROT_WRITE,
            offset=IORING_OFF_SQES,
        )

    def _u32(self, mm, off):
        return struct.unpack_from("=I", mm, off)[0]

    def _put32(self, mm, off, value):
        struct.pack_into("=I", mm, off, value)

    def submit(self, opcode, fd, addr=0, length=0, off=0, flags28=0, count=1):
        """Fill `count` SQEs with the same operation and enter the ring once.

        Layout written (little-endian, no padding): opcode/flags/ioprio/fd at
        0..7, off at 8, addr at 16, len at 24, open_flags/rw_flags at 28,
        user_data at 32. Everything after is left zeroed. `off` holds the file
        offset for READ and the sockaddr length for CONNECT; `length` holds len
        for READ and the mode for OPENAT; `flags28` holds open_flags for OPENAT.
        """
        sq_off = self.params.sq_off
        mask = self._u32(self.sq_ring, sq_off.ring_mask)
        tail = self._u32(self.sq_ring, sq_off.tail)
        for i in range(count):
            idx = (tail + i) & mask
            base = idx * SQE_SIZE
            self.sqes[base:base + SQE_SIZE] = b"\x00" * SQE_SIZE
            struct.pack_into(
                "=BBHiQQIIQ", self.sqes, base,
                opcode & 0xFF, 0, 0, int(fd),
                off & 0xFFFFFFFFFFFFFFFF, addr & 0xFFFFFFFFFFFFFFFF,
                length & 0xFFFFFFFF, flags28 & 0xFFFFFFFF,
                (i + 1) & 0xFFFFFFFFFFFFFFFF,
            )
            self._put32(self.sq_ring, sq_off.array + idx * 4, idx)
        # smp_store_release-equivalent before publishing the new tail, so the
        # SQE bytes above are visible to the kernel (liburing uses the same
        # barrier; aarch64 otherwise allows the tail store to land first).
        if _sync_synchronize is not None:
            _sync_synchronize()
        self._put32(self.sq_ring, sq_off.tail, (tail + count) & 0xFFFFFFFF)
        # min_complete=0: submit and return; never block the child on a CQE.
        ret = _libc.syscall(SYS_IO_URING_ENTER, self.fd, count, 0, 0, 0)
        if ret < 0:
            raise OSError(ctypes.get_errno(), "io_uring_enter")

    def drain(self, count, timeout=2.0):
        """Poll up to `count` completion results (cqe.res); [] on timeout."""
        results = []
        deadline = time.monotonic() + timeout
        while len(results) < count and time.monotonic() < deadline:
            cq_off = self.params.cq_off
            head = self._u32(self.cq_ring, cq_off.head)
            tail = self._u32(self.cq_ring, cq_off.tail)
            while head != tail and len(results) < count:
                mask = self._u32(self.cq_ring, cq_off.ring_mask)
                base = cq_off.cqes + (head & mask) * CQE_SIZE
                results.append(
                    struct.unpack_from("=i", self.cq_ring, base + 8)[0]
                )
                head = (head + 1) & 0xFFFFFFFF
                self._put32(self.cq_ring, cq_off.head, head)
                tail = self._u32(self.cq_ring, cq_off.tail)
            if len(results) < count:
                time.sleep(0.002)
        return results
'''
)


def io_uring_setup_probe(entries: int = 8) -> subprocess.Popen:
    """Call io_uring_setup(2) once (no submission) and exit.

    Fires ``iouring_unexpected_setup`` for a process whose comm is not in the
    rule's allowlist (the child is ``python3``). Exits non-zero when the kernel
    rejects ``io_uring_setup`` at runtime (the module-level probe normally skips
    such a kernel first).
    """
    body = (
        f"entries = {entries!r}\n"
        "try:\n"
        "    ring = Ring(entries)\n"
        "except OSError:\n"
        "    raise SystemExit(EXIT_RING_UNAVAILABLE)\n"
        "os.close(ring.fd)\n"
    )
    return _spawn(_RING_HELPERS + body)


def ring_read_file(
    path: str = "/etc/hostname", iterations: int = 4, entries: int = 64
) -> subprocess.Popen:
    """Open `path` read-only with open(2), then read it via IORING_OP_READ.

    The read is submitted to the ring, so no read(2) syscall occurs -- the shape
    a syscall-hook monitor can miss. The open is still a normal syscall; use
    ``ring_openat_and_read`` for the fully-ring variant. The child never writes,
    never prints the content and uses ``O_NOFOLLOW``; it exits
    ``EXIT_NO_TARGET`` when `path` is missing/unreadable and non-zero when the
    ring read itself fails, so a positive alert can never rest on a read that
    never happened.
    """
    body = (
        f"path = {path!r}\n"
        f"iterations = {iterations!r}\n"
        f"entries = {entries!r}\n"
        "buf = ctypes.create_string_buffer(64)\n"
        "try:\n"
        "    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)\n"
        "except OSError:\n"
        "    raise SystemExit(EXIT_NO_TARGET)\n"
        "try:\n"
        "    ring = Ring(entries)\n"
        "except OSError:\n"
        "    os.close(fd)\n"
        "    raise SystemExit(EXIT_RING_UNAVAILABLE)\n"
        "try:\n"
        "    ring.submit(\n"
        "        IORING_OP_READ, fd, ctypes.addressof(buf), 64, 0, 0, iterations\n"
        "    )\n"
        "except OSError:\n"
        "    os.close(fd)\n"
        "    raise SystemExit(EXIT_RING_UNAVAILABLE)\n"
        "res = ring.drain(iterations)\n"
        "os.close(fd)\n"
        "if len(res) != iterations:\n"
        "    raise SystemExit(EXIT_NO_CQE)\n"
        "if any(r < 0 for r in res):\n"
        "    raise SystemExit(EXIT_OP_FAILED)\n"
    )
    return _spawn(_RING_HELPERS + body)


def ring_openat_and_read(
    path: str = "/etc/shadow", reads: int = 2, entries: int = 64
) -> subprocess.Popen:
    """Open *and* read `path` entirely through the ring.

    Submits IORING_OP_OPENAT (no open(2) syscall) and then IORING_OP_READ on the
    fd the kernel returns (no read(2) syscall). This is the strongest form of
    the io_uring bypass: the file access produces no file/syscall event at all,
    only the ring submission. Read-only by construction; the data is discarded
    and never printed. The child exits ``EXIT_NO_TARGET`` when the path is
    missing or permission is denied, and non-zero when the ring op was submitted
    but did not execute (negative CQE ``res``, including EACCES/EPERM), so the
    known-bypass non-outcome cannot rest on an op that never ran.
    """
    body = (
        f"path = {path!r}\n"
        f"reads = {reads!r}\n"
        f"entries = {entries!r}\n"
        "pathbuf = ctypes.create_string_buffer(path.encode() + b'\\x00')\n"
        "buf = ctypes.create_string_buffer(64)\n"
        "# Environmental absence (no target / no permission) is a clean skip.\n"
        "if not os.path.exists(path) or not os.access(path, os.R_OK):\n"
        "    raise SystemExit(EXIT_NO_TARGET)\n"
        "try:\n"
        "    ring = Ring(entries)\n"
        "except OSError:\n"
        "    raise SystemExit(EXIT_RING_UNAVAILABLE)\n"
        "try:\n"
        "    ring.submit(\n"
        "        IORING_OP_OPENAT, AT_FDCWD, ctypes.addressof(pathbuf),\n"
        "        0, 0, O_RDONLY, 1\n"
        "    )\n"
        "except OSError:\n"
        "    raise SystemExit(EXIT_RING_UNAVAILABLE)\n"
        "res = ring.drain(1)\n"
        "if not res:\n"
        "    raise SystemExit(EXIT_NO_CQE)\n"
        "if res[0] < 0:\n"
        "    # The op ran but the kernel denied access: environmental, not a bypass.\n"
        "    if -res[0] in (errno.EACCES, errno.EPERM):\n"
        "        raise SystemExit(EXIT_NO_TARGET)\n"
        "    raise SystemExit(EXIT_OP_FAILED)\n"
        "fd = res[0]\n"
        "try:\n"
        "    ring.submit(\n"
        "        IORING_OP_READ, fd, ctypes.addressof(buf), 64, 0, 0, reads\n"
        "    )\n"
        "except OSError:\n"
        "    os.close(fd)\n"
        "    raise SystemExit(EXIT_RING_UNAVAILABLE)\n"
        "rres = ring.drain(reads)\n"
        "os.close(fd)\n"
        "if len(rres) != reads:\n"
        "    raise SystemExit(EXIT_NO_CQE)\n"
        "if any(r < 0 for r in rres):\n"
        "    raise SystemExit(EXIT_OP_FAILED)\n"
    )
    return _spawn(_RING_HELPERS + body)


def ring_connect_loopback(
    host: str = _LOOPBACK,
    port: int = 3389,
    iterations: int = 2,
    entries: int = 64,
) -> subprocess.Popen:
    """Replace connect(2) with IORING_OP_CONNECT to a loopback address.

    The socket is created with the normal socket(2), but the connect is
    submitted through the ring, so a connect/dport-based rule (e.g.
    ``lateral_rdp_connection`` for port 3389) never sees it. Only loopback is
    accepted (any other host raises ValueError) and the target port is expected
    to be closed, so the connect completes with a network-level errno
    (ECONNREFUSED/EINPROGRESS) -- which still proves the op executed. The
    sockaddr is a real 16-byte ``sockaddr_in`` (AF_INET + port + 4-byte address
    + 8 zero bytes) and its length 16 is passed as the CONNECT SQE's ``off``
    field (the kernel's addrlen convention for IORING_OP_CONNECT), so the
    kernel's ``addr_len < sizeof(struct sockaddr_in)`` guard accepts it. The
    child exits non-zero when no completion arrives or the op never ran
    (ENOSYS/EINVAL/EOPNOTSUPP), so the known-bypass non-outcome cannot rest on a
    connect that never happened.
    """
    if host != _LOOPBACK:
        raise ValueError(
            f"ring_connect_loopback only targets {_LOOPBACK} (got {host!r})"
        )
    body = (
        f"host = {host!r}\n"
        f"port = {port!r}\n"
        f"iterations = {iterations!r}\n"
        f"entries = {entries!r}\n"
        "try:\n"
        "    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "except OSError:\n"
        "    # No usable network stack: environmental, so skip rather than fail.\n"
        "    raise SystemExit(EXIT_NO_TARGET)\n"
        "try:\n"
        "    sock.setblocking(False)\n"
        "    # Real 16-byte sockaddr_in: family, port in network order, 4-byte\n"
        "    # address, 8 bytes of zero padding. A shorter buffer with no family\n"
        "    # field is rejected by the kernel with -EINVAL before the connect.\n"
        "    sa = struct.pack('!HH4s8x', socket.AF_INET, port,\n"
        "                     socket.inet_aton(host))\n"
        "    sabuf = ctypes.create_string_buffer(sa, len(sa))\n"
        "    try:\n"
        "        ring = Ring(entries)\n"
        "    except OSError:\n"
        "        raise SystemExit(EXIT_RING_UNAVAILABLE)\n"
        "    try:\n"
        "        ring.submit(\n"
        "            IORING_OP_CONNECT, sock.fileno(), ctypes.addressof(sabuf),\n"
        "            0, len(sa), 0, iterations\n"
        "        )\n"
        "    except OSError:\n"
        "        raise SystemExit(EXIT_RING_UNAVAILABLE)\n"
        "    res = ring.drain(iterations)\n"
        "finally:\n"
        "    sock.close()\n"
        "if len(res) != iterations:\n"
        "    raise SystemExit(EXIT_NO_CQE)\n"
        "# A negative CQE from a closed loopback port (ECONNREFUSED/EINPROGRESS)\n"
        "# proves the kernel ran the connect; these errnos mean it never did.\n"
        "if any(r < 0 and -r in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP)\n"
        "       for r in res):\n"
        "    raise SystemExit(EXIT_OP_FAILED)\n"
    )
    return _spawn(_RING_HELPERS + body)


def benign_no_iouring_wait(seconds: float = 0.3) -> subprocess.Popen:
    """Negative control: a process that never touches io_uring.

    Keeps the io_uring positives from passing vacuously: a child doing nothing
    must not produce any iouring alert.
    """
    return _spawn("import time\n" + f"time.sleep({seconds!r})\n")
