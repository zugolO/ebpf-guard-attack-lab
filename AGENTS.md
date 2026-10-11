# ebpf-guard-attack-lab

Тестовая лаборатория атак для детектора ebpf-guard (апстрим: ветка `testing`, не `main`).
Дефолтная ветка этого репо — `main`. Трекер работ и открытые хвосты: `PLAN.md`.

## Структура
- `rules/` — правила детектора (YAML), 74 шт.
- `tests/rules/*_test.yaml` — Go-сьюты правил (`alert` / `no_alert`, `chains:`).
- `internal/ruletest/` — локальный движок прогона сьютов.
- `tests/*_test.go` — TestRuleSuites, TestCoverageMatrix (gate 100%/100%), snapshot, replay, benign.
- `tests/integration/` — Python live-тесты (`attacks/*.py` + `test_*.py`), нужны root, eBPF-ядро, демон.
- `tests/k8s/` — тесты кластера. `tests/fuzz`, `tests/bench` — fuzz и бенчмарки.

## Команды
- `make test-unit` — Go-тесты, ядро не нужно. Запускать после любой правки правил/сьютов.
- `go vet ./...`
- `make test-integration` — только на стенде с root и демоном.

## Правила работы
- У каждого правила должен быть ≥1 `alert` и ≥1 `no_alert` кейс, иначе coverage-gate падает.
- Python-тесты на хосте разработки можно лишь проверить через `python3 -m py_compile` и
  `pytest --collect-only`; без стенда они skip. Не заявлять их как «проверено».
- Локальный движок `chains:` не коррелятор: не моделирует lineage и chain-alert.
- Новый alert/no_alert кейс добавлять в тот же `*_test.yaml`, что и соседние кейсы правила.
