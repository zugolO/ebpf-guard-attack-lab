#!/usr/bin/env bash
# setup-test-vm.sh
# Prepares a Linux VM for ebpf-guard single-machine integration tests.
# Run as root on Ubuntu 22.04+ / Debian 12+ / Fedora 38+.

set -euo pipefail

KERNEL_MIN="5.8"

log()  { echo "[setup] $*"; }
die()  { echo "[setup] ERROR: $*" >&2; exit 1; }

# ── Kernel version check ──────────────────────────────────────────────────────
KERNEL=$(uname -r | cut -d. -f1-2)
log "Kernel: $KERNEL (min required: $KERNEL_MIN)"
python3 -c "
import sys
cur  = tuple(int(x) for x in '${KERNEL}'.split('.'))
need = tuple(int(x) for x in '${KERNEL_MIN}'.split('.'))
if cur < need:
    sys.exit(1)
" || die "Kernel ${KERNEL} too old. Upgrade to ${KERNEL_MIN}+."

# ── Check BPF is available ────────────────────────────────────────────────────
if [[ ! -d /sys/fs/bpf ]]; then
    mount -t bpf bpf /sys/fs/bpf || die "Cannot mount bpffs"
fi
log "bpffs: OK"

# ── Detect distro and install deps ───────────────────────────────────────────
if command -v apt-get &>/dev/null; then
    log "Detected Debian/Ubuntu"
    apt-get update -qq
    apt-get install -y -qq \
        python3 python3-pip \
        linux-headers-$(uname -r) \
        bpftool \
        clang llvm \
        iproute2 \
        netcat-openbsd \
        nmap \
        curl wget \
        nsenter \
        ca-certificates
elif command -v dnf &>/dev/null; then
    log "Detected Fedora/RHEL"
    dnf install -y -q \
        python3 python3-pip \
        kernel-devel \
        bpftool \
        clang llvm \
        iproute \
        nmap \
        nmap-ncat \
        curl wget \
        util-linux \
        ca-certificates
else
    die "Unsupported distro (need apt or dnf)"
fi

# ── Python test dependencies ──────────────────────────────────────────────────
log "Installing Python test dependencies"
pip3 install -q pytest pytest-timeout pytest-xdist

# ── Ensure /run/ebpf-guard socket dir exists ─────────────────────────────────
mkdir -p /run/ebpf-guard
chmod 0750 /run/ebpf-guard
log "Alert socket dir: /run/ebpf-guard"

# ── Sysctl: allow unprivileged BPF for testing ───────────────────────────────
# (ebpf-guard itself needs root; this allows the attack subprocess to attempt
#  BPF loads so the rule engine can detect them)
sysctl -qw kernel.unprivileged_bpf_disabled=0 || true
log "kernel.unprivileged_bpf_disabled=0"

# ── Summary ──────────────────────────────────────────────────────────────────
log ""
log "Setup complete. Next steps:"
log "  1. Copy ebpf-guard binary to this machine and start it:"
log "       EBPF_GUARD_ALERT_SOCKET=/run/ebpf-guard/alerts.sock \\"
log "       ./ebpf-guard --config /etc/ebpf-guard/config.yaml &"
log ""
log "  2. Run integration tests:"
log "       cd ebpf-guard-attack-lab"
log "       EBPF_GUARD_ALERT_SOCKET=/run/ebpf-guard/alerts.sock \\"
log "       make test-integration"
