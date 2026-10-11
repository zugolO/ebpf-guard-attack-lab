# PLAN — attack-lab как грозная машина для ebpf-guard

Единый трекер работ. Цель: attack-lab должен уметь проверить **каждую** подсистему
ebpf-guard — не только «правило стреляет на одно событие», но и обход, подавление,
корреляцию цепочек и атаку на сам детектор.

Статус-легенда: ✅ сделано · 🟡 в работе (есть PR) · ⬜ не начато

---

## 0. Снимок состояния (на 2026-10-11)

- Сборка зелёная: `go vet ./...` чистый, `go test ./...` → 312 PASS.
- 73 правила, **100% позитивное покрытие** (у каждого ≥1 тест на срабатывание).
- Слои тестов: Go unit (`internal/ruletest`), Python single-machine integration
  (`tests/integration`), K8s integration (`tests/k8s`), fuzz (`tests/fuzz`),
  benchmarks (`tests/bench`), snapshot/replay/coverage матрица.

---

## 1. Зависшие PR — разобраны (2026-10-11)

| PR | Что | Итог |
|----|-----|------|
| ✅ [#34](https://github.com/zugolO/ebpf-guard-attack-lab/pull/34) | Encoding/obfuscation bypass tests (закрывает #30) | **смёржен в main** (go vet/go test/py_compile зелёные, ревью-тредов нет) |
| ❌ [#28](https://github.com/zugolO/ebpf-guard-attack-lab/pull/28) | Фикс CI + sync ветки | **закрыт** — чужая база, падающий bench-CI, устаревший дифф. Полезный фикс вынесен в задачу F ниже |

---

## 2. Открытые задачи-сценарии (issues)

### ⬜ #29 — Threshold evasion (low-and-slow против rate-limit / EWMA)
<https://github.com/zugolO/ebpf-guard-attack-lab/issues/29>
Держать частоту/объём чуть ниже порога, чтобы не потревожить rate-limit
(`internal/correlator`) и EWMA anomaly scoring (`internal/profiler`).
- `tests/rules/threshold_evasion_test.yaml` — через `throttle_tests:` проверить,
  что алерт **не** подавляется молча на всём диапазоне (`expect_first_n` = `repeat`).
- `tests/integration/attacks/threshold_attacks.py` + `test_threshold_evasion.py` —
  low-and-slow чтение файлов и beacon под порогом интервала.
- Негатив: предсказуемый healthcheck раз в 30с не уходит в anomaly.
- **Блокер:** `learning_period: 3600` непрактичен в CI → нужен укороченный тестовый
  профиль (см. задачу B ниже).

### ⬜ #31 — Comm-спуфинг под легитимные бинари (systematic known_bypass)
<https://github.com/zugolO/ebpf-guard-attack-lab/issues/31>
Механизм `MutantSpec.Patch["comm"]` + `known_bypass` уже есть, но используется
только в `persistence_test.yaml` (2 кейса).
- Пройти по `tests/rules/*_test.yaml`, где `expect: alert` зависит от `comm` вне
  allowlist, и добавить mutant со спуфингом под ближайший allowlisted процесс
  (`mysqld`, `systemd`, `dpkg`, `rsync`, `nginx`...).
  Файлы-кандидаты: `collection_evasion_gaps`, `defense_evasion`,
  `living_off_the_land`, `webshell_detection`, `lateral_movement`,
  `persistence_extended`.
- `tests/integration/attacks/masquerade_attacks.py` + `test_process_masquerade.py` —
  `execve` с поддельным `argv[0]` и **`prctl(PR_SET_NAME)`** (реально переписывает
  `task_struct->comm`). Ключ: ловит ли ebpf-guard до спуфинга через `parent_comm` /
  `/proc/[pid]/exe` / lineage, а не голый `comm`.
- **Рекомендую начать отсюда** — механизм готов, быстрый результат.

### ⬜ #32 — Multi-stage attack chains → покрытие LineageTracker
<https://github.com/zugolO/ebpf-guard-attack-lab/issues/32>
`chains:` используется только в `chain_test.yaml` (одна цепочка), а в ebpf-guard
есть выделенный `internal/profiler/lineage.go`.
- Дополнить `tests/rules/chain_test.yaml` минимум 3 цепочками:
  container-escape→persistence, credential-theft→lateral-movement,
  recon→exfiltration (`expect_chain: all_fire`).
- `tests/integration/attacks/chain_attacks.py` + `test_attack_chains.py` — живой
  lineage: один родитель делает 2 шага, ожидается объединяющий chain-alert.
- Негатив: те же 2 правила из разных несвязанных PID → chain-alert **не** поднимается.

### ⬜ #33 — TOCTOU/symlink-race + watchdog/self-tamper evasion
<https://github.com/zugolO/ebpf-guard-attack-lab/issues/33>
Два непокрытых класса:
1. **TOCTOU / symlink race** — подмена benign-файла на symlink к `/etc/shadow`,
   `/etc/cron.d/` между проверкой и использованием.
   `tests/integration/attacks/race_attacks.py` + `test_toctou_race.py`. Проверить,
   матчит ли правило финальный разрешённый путь (`readlink`) или только имя на
   момент `create` → задокументировать `known_bypass` где применимо.
2. **Watchdog / self-tamper** — атака на сам демон: kill процесса, `bpftool prog
   detach`, флуд ring buffer. Проверить, что heartbeat
   (`ebpf_guard_heartbeat_timestamp_seconds`) / BPF attestation
   (`internal/watchdog`) детектируется **снаружи** (метрика/алерт), а не только
   unit-тестами. `tests/integration/attacks/watchdog_attacks.py` +
   `test_watchdog_evasion.py`.
   Негатив: штатный `SIGHUP` (reload) не трактуется как tamper.

### ✅ #30 — Encoding/obfuscation bypass → **сделано**, PR #34 смёржен в main.
Добавлено: правило `exfil_dns_high_entropy_qname`, позитив/негатив по DNS-энтропии,
`mutants` с `known_bypass` на case-sensitive `contains` в `lolbin_socat_shell`,
Python-атаки (base64/hex/env-split/fragmented-DNS). Найден сопутствующий баг
`qname_is_dga` getter (`internal/correlator/rules.go:1171`) — обходит guard
`len(label) >= 8`; задокументирован как follow-up (см. задачу G ниже).

---

## 3. Слепые зоны (новые задачи — завести как issues)

Выявлены анализом; инструментарий частично рапортует их сам.

### ⬜ A. Негативное покрытие правил — закрыть WARN «0% negative»
`tests/coverage_test.go` печатает `rules with ≥1 negative test: 0 (0.0%)` для всех
73 правил. Проверяется только срабатывание, но не отсутствие срабатывания на
легитимном похожем событии — это и есть измерение false-positive на уровне правил.
- Добавить `expect: no_alert` кейсы к каждому правилу (похожий, но легитимный ввод).
- Приоритет: высокий, самый дешёвый и важный пробел.

### ⬜ B. Ускоренный тест-профиль для EWMA/профилировщика (предусловие для #29)
`learning_period: 3600` нельзя ждать в CI. Вынести отдельный тестовый `config.yaml`
с укороченными `learning_period`/`ewma_weight` + прокинуть в `docker-compose.test.yml`.
Без этого #29 нереализуем.

### ⬜ C. Coverage-gate в CI (регресс-защита покрытия)
Сейчас `coverage_test.go` только **логирует** пробелы, не фейлит сборку. Сделать
пороговым: падать, если позитивное покрытие < 100% или негативное < целевого N%.
Так регресс покрытия ловится автоматически, а не глазами.

### ⬜ D. io_uring как канал обхода syscall-детекции
Правила `iouring.yaml` есть, но интеграционного теста, который реально выполняет
операции через `io_uring` (чтение файла / сеть в обход классических syscall-хуков),
нет. Проверить, видит ли ebpf-guard действия, выполненные через ring, а не syscall.

### ⬜ E. Namespace/mount evasion
Действия из нового mount/PID namespace, bind-mount поверх чувствительных путей,
чтение `/proc/1/root/...`. Проверить, резолвит ли ebpf-guard пути в host-namespace
или его можно ослепить сменой namespace.

### ⬜ F. `make test-unit` должен гонять реальные тесты движка (из закрытого PR #28)
Сейчас `test-unit:` в `Makefile` запускает только `$(GOTEST) ./internal/...`, а там
**нет** тестовых файлов — все rule-engine тесты (`TestRuleSuites`,
`TestCoverageMatrix`, `TestSnapshot`, `TestReplayTraces`, `TestBenignCorpus`) лежат
в `./tests/...`. Значит CI-джоб «Unit Tests (Go)» зелёный вхолостую и не ловит
регресс правил. Фикс: `test-unit` должен покрывать и `./internal/...`, и `./tests/...`.
Приоритет: высокий — это маскирует реальные падения. (Был в PR #28, но тот целил в
неправильную базу и устарел; берём только этот фикс отдельным маленьким PR.)

### ⬜ G. Фикс `qname_is_dga` field getter (follow-up из #30)
`internal/correlator/rules.go:1171` — getter возвращает `"true"` при
`NgramScore >= threshold`, обходя guard `len(label) >= 8`, который соблюдает сам
`NgramDGADetector.IsDGA()`. Короткие обычные слова (`example`) ложно детектятся
как DGA через это поле. Правило из #30 обходит баг (использует `qname_entropy` /
`qname_digit_ratio` напрямую), но сам getter стоит починить. Относится к коду
движка ebpf-guard, не к attack-lab — возможно, заводить в основном репозитории.

---

## 4. Порядок работ (рекомендуемый)

1. ~~Разобрать зависшие PR~~ — сделано: #34 смёржен, #28 закрыт.
2. Задача **F** (`make test-unit` гоняет реальные тесты) — срочно, маскирует регресс CI.
3. Задача A (негативное покрытие) + C (gate) — фундамент качества.
4. #31 (comm-спуфинг) — механизм готов, быстрый результат.
5. #32 (chains / lineage) — корреляция, высокая ценность.
6. B → #29 (EWMA threshold evasion) — требует тест-профиля.
7. #33 (TOCTOU + watchdog) — самый сложный слой (атака на сам детектор).
8. D, E — добить каналы обхода (io_uring, namespace).
9. G — фикс `qname_is_dga` (в основном репо ebpf-guard).

---

## Принцип

Для каждого обхода — **явный, задокументированный результат**: либо ebpf-guard ловит
(позитивный тест), либо пробел помечен `known_bypass: true` и виден в отчёте. Никаких
тихо пропущенных дыр.
