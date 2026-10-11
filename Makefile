# ebpf-guard-attack-lab test runner
#
# Usage:
#   make test-unit          run Go unit + rule-engine tests (no kernel needed)
#   make test-integration   run Python single-machine integration tests (needs root + daemon)
#   make test-k8s           run Python K8s integration tests (needs cluster)
#   make test-all           run all test layers
#
# Required env vars for integration:
#   EBPF_GUARD_BINARY       path to ebpf-guard binary (optional, auto-starts daemon)
#   EBPF_GUARD_CONFIG       daemon config file (default: hack/ebpf-guard.test.yaml,
#                           a TEST-ONLY shortened-profiler profile; override to skip it)
#   EBPF_GUARD_ALERT_SOCKET unix socket path for alerts (default: /run/ebpf-guard/alerts.sock)
#   CUDA_MOCK_LIB           path to stub libcuda.so.1 for GPU tests without real GPU
#                           (GPU tests skip automatically when unset and libcuda not found)
#
# Required env vars for k8s:
#   KUBECONFIG              path to kubeconfig
#   EBPF_GUARD_IMAGE        ebpf-guard container image

GOTEST  := go test -v -count=1 -timeout 120s
PYTEST  := python3 -m pytest -v --timeout=30
INT_DIR := tests/integration
K8S_DIR := tests/k8s

.PHONY: test-unit test-integration test-k8s test-all \
        install-python-deps setup-vm lint

# ── Unit tests (Go: ./internal/... + ./tests/...) ──────────────────────────────
# ./tests/... holds the rule-engine suites (TestRuleSuites, TestCoverageMatrix,
# TestSnapshot, TestReplayTraces, TestBenignCorpus); ./internal/... currently has
# no test files. tests/integration and tests/k8s are Python-only, not Go packages.
test-unit:
	$(GOTEST) ./internal/... ./tests/...

# ── Single-machine integration tests (Python, needs root + running daemon) ─────
# EBPF_GUARD_CONFIG defaults to the CI profile (hack/ebpf-guard.test.yaml, a
# 10s learning_period instead of 3600s) so EWMA/profiler tests don't stall.
# It only takes effect when EBPF_GUARD_BINARY makes conftest.py start the daemon;
# set EBPF_GUARD_CONFIG yourself to use a different profile.
test-integration: install-python-deps
	@echo "==> Integration tests require: root, ebpf-guard daemon, eBPF-capable kernel"
	cd $(INT_DIR) && EBPF_GUARD_CONFIG="$${EBPF_GUARD_CONFIG:-$(CURDIR)/hack/ebpf-guard.test.yaml}" $(PYTEST) . -m integration $(PYTEST_ARGS)

# ── K8s integration tests ─────────────────────────────────────────────────────
test-k8s: install-python-deps
	@echo "==> K8s tests require: kubectl configured, ebpf-guard DaemonSet"
	cd $(K8S_DIR) && $(PYTEST) . -m k8s $(PYTEST_ARGS)

# ── Run all layers ─────────────────────────────────────────────────────────────
test-all: test-unit test-integration test-k8s

# ── Python dependency install ─────────────────────────────────────────────────
install-python-deps:
	pip3 install -q -r $(INT_DIR)/requirements.txt

install-k8s-deps:
	pip3 install -q -r $(K8S_DIR)/requirements.txt

# ── VM setup ─────────────────────────────────────────────────────────────────
setup-vm:
	bash hack/setup-test-vm.sh

# ── Lint / static checks ─────────────────────────────────────────────────────
lint:
	go vet ./...
	python3 -m py_compile $(INT_DIR)/conftest.py $(INT_DIR)/attacks/*.py $(INT_DIR)/test_*.py
	python3 -m py_compile $(K8S_DIR)/conftest.py $(K8S_DIR)/test_*.py
