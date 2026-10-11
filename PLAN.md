# PLAN — attack-lab как грозная машина для ebpf-guard

Единый трекер работ. Цель: attack-lab должен уметь проверить **каждую** подсистему
ebpf-guard — не только «правило стреляет на одно событие», но и обход, подавление,
корреляцию цепочек и атаку на сам детектор.

Статус-легенда: ✅ сделано · 🟡 в работе (есть PR) · ⬜ не начато

---

> **Важно про апстрим.** Ведущая ветка в репозитории **ebpf-guard** — это
> **`testing`** (не `main`/`master`). Любая сверка правил/типов событий, миграция
> фикстур и задачи, заводимые в основном репо (напр. G), должны целиться в
> `testing`. Пути вроде `internal/correlator/rules.go`, `internal/profiler/`,
> `internal/watchdog/` в этом файле ссылаются на код ebpf-guard@`testing`.
> (Дефолтная ветка самого **attack-lab** остаётся `main` — PR тут идут в `main`.)

## 0. Снимок состояния (на 2026-10-11)

- Сборка зелёная: `go vet ./...` чистый, `go test ./...` → 409 PASS.
- 74 правила, **100% позитивное** и **100% негативное** покрытие (у каждого
  правила ≥1 `alert` и ≥1 `no_alert` кейс; coverage-gate требует 100%/100%).
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

### ✅ ~~#29 — Threshold evasion (low-and-slow против rate-limit / EWMA)~~
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
Сделано: `tests/rules/threshold_evasion_test.yaml` (12× `/etc/shadow` read → `expect_first_n: 12`, near-miss negative `persistence_cron_write`/crontab); `tests/integration/attacks/threshold_attacks.py` + `tests/integration/test_threshold_evasion.py` (5 тестов: no-silent-suppression, jittered-beacon evasion + fixed-interval positive control, benign healthcheck negative + post-learning burst positive control).
Проверка: `go test -run 'TestRuleSuites/threshold_evasion_test.yaml' ./tests/ -v` — PASS (не skip); `go test ./tests/... ./internal/...` и `go vet ./...` — чисто; `python3 -m py_compile` + `pytest --collect-only -k threshold` — 5 тестов собираются и скипаются без root/демона.

**Особенности решения / открытые вопросы (#29):**
- В скопированном `internal/correlator` есть только статический `sampling` (`sample_rate`/`sampling.rate`, режимы random/hash_pid); счётного `threshold:`/burst и EWMA-профилировщика нет, и ни одно правило в `rules/` не задаёт rule-level rate-limit. Поэтому реального порога в Go-слое нет: `threshold_evasion_test.yaml` — это **регресс-гард на «не подавлять молча»** (always-fire signature-правило должно алертить на каждом из N событий), а не проверка обхода порога. Реальный EWMA/rate-limit проверяется только Python-слоем против живого демона.
- Python-часть **не прогнана на стенде** (нужен root + eBPF-ядро + запущенный ebpf-guard) — только `py_compile` + сбор. Открытые вопросы к стендовому прогону: (а) подтвердить rule_id `beacon_fixed_interval` и `anomaly_detection` и их пороги по фактическому ruleset образа; (б) окна `wait_for_no_alert(window=3)` могут быть коротки, если профилировщик скоррит по тику, а не на событие (ревьюер советует 5–8с); (в) негатив-healthcheck ограничен `pytest --timeout=30`, поэтому продовые 30с не воспроизводятся буквально — тест держится на укороченном профиле B.

### ✅ ~~#31 — Comm-спуфинг под легитимные бинари (systematic known_bypass)~~
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

Сделано: 31 comm-спуфинг mutant в 6 файлах (`collection_evasion_gaps` ×1,
`defense_evasion` ×5, `living_off_the_land` ×5, `webshell_detection` ×6,
`lateral_movement` ×9, `persistence_extended` ×5) + Python-слой
`tests/integration/attacks/masquerade_attacks.py` и
`tests/integration/test_process_masquerade.py` (5 тестов: 2 prctl-обхода,
1 argv[0]-без-обхода, 1 symlink-обход, 1 негативный контроль).
Проверка: `go vet ./...` чисто, `go test ./tests/...` PASS, `py_compile` чисто,
pytest collect → 5 тестов (чисто skip без root/daemon). Открытые особенности и
follow-up → **I**.

### ✅ #32 — Multi-stage attack chains → покрытие LineageTracker
<https://github.com/zugolO/ebpf-guard-attack-lab/issues/32>
`chains:` используется только в `chain_test.yaml` (одна цепочка), а в ebpf-guard
есть выделенный `internal/profiler/lineage.go`.
- Дополнить `tests/rules/chain_test.yaml` минимум 3 цепочками:
  container-escape→persistence, credential-theft→lateral-movement,
  recon→exfiltration (`expect_chain: all_fire`).
- `tests/integration/attacks/chain_attacks.py` + `test_attack_chains.py` — живой
  lineage: один родитель делает 2 шага, ожидается объединяющий chain-alert.
- Негатив: те же 2 правила из разных несвязанных PID → chain-alert **не** поднимается.

Сделано: +3 цепочки `all_fire` и негативная `none_fire`-цепочка в
`tests/rules/chain_test.yaml` (container-escape→persistence, credential-theft→
lateral-movement, recon→exfiltration) + `tests/integration/attacks/chain_attacks.py`
и `tests/integration/test_attack_chains.py` (2 pytest: same-pid chain-alert,
two-unrelated-pids negative). `rules_path` теперь указывает на каталог
`../../rules`; для этого `internal/ruletest/runner.go::loadRuleSet` реализует уже
задокументированный контракт «файл или каталог» (каталог → слияние всех `*.yaml`
в отсортированном порядке). Проверка: `go vet ./...` чисто,
`go test -count=1 ./internal/... ./tests/...` PASS,
`go test -count=1 -run 'TestRuleSuites/chain_test.yaml' -v ./tests/` PASS
(9/9 подтестов реально выполнены, не skip), `py_compile` + `pytest --collect-only` (2 теста).

Особенности / открытые вопросы:
- Локальный движок `chains:` — последовательный инжектор событий с агрегатной
  проверкой (`all_fire`/`any_fire`/`none_fire`), а не коррелятор: parent/child
  lineage и объединяющий chain-alert он не моделирует. `expect_chain: all_fire`
  доказывает лишь, что каждое правило срабатывает на своём событии по порядку,
  а **не** существование единого chain-alert.
- Реальный lineage наблюдаем только в Python-слое
  (`chain_attacks.py`/`test_attack_chains.py`): ему нужны root + eBPF-ядро +
  запущенный демон, поэтому локально эти 2 теста только компилируются и
  collect-ятся — **stand verification pending** (ревьюер: «correct on static
  reading + compiles», не verified).
- Точная сигнатура chain-alert (rule_id/JSON) в этом репозитории отсутствует:
  `_is_chain_alert` матчит "chain"/"lineage"/"correlat" в rule_id/rule_name/
  message, и это нужно подтвердить на стенде. В `internal/correlator/` понятия
  chain/lineage нет вовсе, так что если демон такого alert не эмитит — позитивный
  pytest упадёт громко (это не обязательно баг лаборатории).
- В `rules/` нет правила container-escape: escape-фаза смоделирована прокси
  `lateral_ssh_from_container` (прокомментировано в YAML).
- Негатив в YAML (`none_fire`, near-miss шаги с разными pid) сам по себе lineage
  не проверяет — движок не коррелирует по pid; реальная проверка «2 правила из
  разных несвязанных PID → нет chain-alert» живёт в Python-слое.
- Known warnings ревьюера: ~~поздний дубликат chain-alert от позитивного теста
  может дать ложный фейл негативного (нет фильтра по pid)~~ **исправлено
  (2026-10-11):** негативный тест теперь скоупит предикат на `{credential_step.pid,
  lateral_step.pid, os.getpid()}` — поздний chain-alert от позитивного теста (другой
  pid) больше не фейлит негатив. Открытым остаётся лишь stand-вопрос: оба
  «несвязанных» ребёнка имеют общего родителя (pytest), поэтому коррелятор,
  ключующийся на дерево процессов, а не на acting pid, теоретически мог бы их
  объединить — подтверждать на стенде.

### ✅ ~~#33 — TOCTOU/symlink-race + watchdog/self-tamper evasion~~
<https://github.com/zugolO/ebpf-guard-attack-lab/issues/33>
Создано: `tests/integration/attacks/race_attacks.py`,
`tests/integration/attacks/watchdog_attacks.py`,
`tests/integration/test_toctou_race.py`,
`tests/integration/test_watchdog_evasion.py`, `tests/rules/toctou_watchdog_test.yaml`.

**Особенности решения / открытые вопросы (#33):**
- **Go/YAML-часть проверена локально:** `toctou_watchdog_test.yaml`
  (`rules_path: ../../rules`) — 6 базовых кейсов + 2 мутанта, все PASS;
  `TestCoverageMatrix` остаётся на 100% positive/negative (74/74), dead rule_id нет.
- **Python-часть НЕ прогнана на стенде** (нужен root + eBPF-ядро + запущенный
  демон): локально только `py_compile` + `pytest --collect-only` (9 тестов) +
  полный прогон → 9 skip. Закрыть на VM: `make test-integration` и подтвердить
  реальные имена/пороги ниже.
- **TOCTOU known-bypass — граница тоньше, чем в issue.** В `EventSpec.FileSpec`
  вообще нет поля разрешённого symlink-target (`readlink`); есть только
  `filename`/`fd_name`/`op`. При этом rename-форма обхода — **не** сквозной bypass:
  `integrity_lib_replaced` (`op in [write,create]`) его пропускает, но
  `ransomware_mass_rename` независимо срабатывает на rename-shape (в YAML это
  честный `expect: alert`, без `known_bypass`). Реально невидима только
  разрешённая цель symlink — она ассертится как задокументированный NON-outcome
  в `test_toctou_race.py` и описана в шапке YAML, а не через `known_bypass`.
  Закрытие требует dentry/readlink-резолвинга в движке, не YAML-правки.
- **Watchdog/self-tamper — comm-спуфинг как известный bypass:**
  `ebpf_subversion_unauthorized_caller` доверяет bare `comm`
  (`prctl(PR_SET_NAME)`); мутант `comm: ebpf-guard` → `no_alert` +
  `known_bypass: true`. Это и есть rationale для out-of-band BPF
  attestation/heartbeat (`internal/watchdog` в реальном агенте).
- **Открытые вопросы к стенду:** (а) подтвердить, что демон вообще отдаёт
  внешний `/metrics` и что метрика называется именно
  `ebpf_guard_heartbeat_timestamp_seconds` (по умолчанию
  `EBPF_GUARD_METRICS_URL=http://127.0.0.1:9090/metrics`); (б) pid демона
  ищется как `EBPF_GUARD_PID` → скан `/proc/*/comm` → `pgrep`; (в) `bpftool`
  опционален (`shutil.which`): detach идёт по bpf_link (`bpftool link detach id`),
  legacy perf_event/kprobe attach без bpf_link → тест **skip**, не fail;
  заметить, что `BPF_LINK_DETACH` (34) не входит в список arg0 правила
  `ebpf_subversion_unauthorized_caller` (`[3,6,9,33]`); (г) эффективность
  флуда ring buffer на macOS не измерима — негатив ассертит только выживание
  liveness (heartbeat продолжает расти); (д) точная сигнатура tamper-алерта
  неизвестна, `_is_tamper_alert` — best-effort текстовый предикат
  (`tamper/detach/attest/subversion`), подтвердить на стенде.
- **Destructive-тесты гейтятся** `EBPF_GUARD_ALLOW_DESTRUCTIVE=1` (kill/detach
  иначе skip): убийство демона инвалидирует session-scoped фикстуру `alerts`,
  запускать только на изолированной VM с одноразовым демоном.
- **Ревью:** 2 раунда; раунд 1 — CHANGES REQUESTED (3 critical: TypeError
  `wait_for_no_alert(predicate=…)`, неверный `bpftool prog detach` без
  ATTACH_TYPE, `known_bypass` маскировал постоянно срабатывающий
  `ransomware_mass_rename`) — исправлено; раунд 2 — APPROVE. Один
  не-блокирующий совет (symlink-follow в `benign_regular_write`) применён
  вызывающим: `open(path,"w")` → `os.open(..., O_NOFOLLOW)`.

Два непокрытых класса (исходная постановка):
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

### ✅ ~~A. Негативное покрытие правил — закрыть WARN «0% negative»~~
`tests/coverage_test.go` печатает `rules with ≥1 negative test: 0 (0.0%)` для всех
73 правил. Проверяется только срабатывание, но не отсутствие срабатывания на
легитимном похожем событии — это и есть измерение false-positive на уровне правил.
- Добавить `expect: no_alert` кейсы к каждому правилу (похожий, но легитимный ввод).
- Приоритет: высокий, самый дешёвый и важный пробел.
Сделано: добавлены `expect: no_alert` near-miss кейсы (с `rule_id` там, где его не
было) во все 24 `tests/rules/*_test.yaml`; негативное покрытие 0% → 100% (74/74
правил, exclusions пуст). Файлы: `tests/coverage_test.go`, `tests/rules/*_test.yaml`.
Проверка: `go test ./tests/...` — ok, `go vet ./...` — чисто.

### ✅ ~~B. Ускоренный тест-профиль для EWMA/профилировщика (предусловие для #29)~~
`learning_period: 3600` нельзя ждать в CI. Вынести отдельный тестовый `config.yaml`
с укороченными `learning_period`/`ewma_weight` + прокинуть в `docker-compose.test.yml`.
Без этого #29 нереализуем.
Сделано: `hack/ebpf-guard.test.yaml` (test-профиль: learning_period 10s, min_learning_samples 10, ewma.weight 0.7, anomaly_threshold 0.7, watchdog pressure off), примонтирован в `docker-compose.test.yml`, `Makefile` даёт дефолтный `EBPF_GUARD_CONFIG`, регресс-гард `tests/config_profile_test.go`.
Проверка: ebpf-guard `config validate --config .../hack/ebpf-guard.test.yaml` → `0 issues found.`; `go vet ./...` и `go test -count=1 ./internal/... ./tests/...` — PASS.

**Особенности решения / открытые вопросы (B):**
- Профиль намеренно **частичный**: viper мержит файл поверх встроенных дефолтов, поэтому перечислены только укороченные ручки. Значения: `learning_period: 10`, `min_learning_samples: 10`, `ewma.weight: 0.7`, `anomaly_threshold: 0.7`, `watchdog.memory_pressure/cpu_pressure.enabled: false`. Trade-off: короткое окно → шумный baseline и больше FP; отключённый watchdog — детерминизм коллекторов в CI важнее продовой грациозной деградации. Профиль строго TEST-ONLY.
- `ebpf-guard config validate` не отвергает неизвестные ключи (проверяет только парсинг/валидность), поэтому ключи дополнительно сверены с `internal/config/config.go` и закрыты регресс-гардом `tests/config_profile_test.go` (держится `learning_period ∈ (0,60]`, `min_learning_samples ∈ (0,50]`, `ewma.weight ∈ (0,1]`).
- `EBPF_GUARD_CONFIG` в `Makefile` действует только когда `EBPF_GUARD_BINARY` сам стартует демон; при внешнем/докерном демоне профиль прокидывается через `--config` в `docker-compose.test.yml`.
- `docker compose config`/`docker compose up` на dev-машине не запускались (docker не установлен) — валидность compose проверена Go-тестом `TestDockerComposeUsesTestConfigProfile`; реальный `docker compose up` и тайминги (learning 10с vs `EBPF_GUARD_TIMEOUT: 5`) подтверждать на стенде вместе с #29.

### ✅ ~~C. Coverage-gate в CI (регресс-защита покрытия)~~
Сейчас `coverage_test.go` только **логирует** пробелы, не фейлит сборку. Сделать
пороговым: падать, если позитивное покрытие < 100% или негативное < целевого N%.
Так регресс покрытия ловится автоматически, а не глазами.
Сделано: `minPositiveCoverage`/`minNegativeCoverage` = 100.0, пороги печатаются в
отчёте; `TestCoverageMatrix` фейлит сборку при потере positive/negative-теста.
Проверка: `go test -run TestCoverageMatrix ./tests/` — PASS с «positive ≥ 100.0%
negative ≥ 100.0%»; с намеренно сломанным кейсом — FAIL с внятным сообщением.

### ✅ ~~D. io_uring как канал обхода syscall-детекции~~
Правила `iouring.yaml` есть, но интеграционного теста, который реально выполняет
операции через `io_uring` (чтение файла / сеть в обход классических syscall-хуков),
нет. Проверить, видит ли ebpf-guard действия, выполненные через ring, а не syscall.
Сделано: `tests/integration/attacks/iouring_attacks.py` (raw `io_uring_setup`/`io_uring_enter`
через ctypes — реальный SQ/CQ ring, `IORING_OP_READ`/`OPENAT`+`READ` по `/etc/shadow`,
`IORING_OP_CONNECT` на loopback; без fallback на `read(2)`/`open(2)`/`connect(2)`; дети
различают «окружение без цели» (`EXIT_NO_TARGET=3` → skip) и «операция не выполнилась»)
+ `tests/integration/test_iouring_evasion.py` (pytestmark root+daemon+io_uring как в #31/#33;
позитив `iouring_unexpected_enter` доказывает, что ring-активность дошла до демона, рядом —
позитивный/негативный контроли) + `known_bypass`-мутант (`comm: nginx`) и проставленные
`rule_id` в `tests/rules/iouring_test.yaml` (негативное покрытие трёх iouring-правил).
Вывод: **сама ring-активность видна** (`iouring_unexpected_setup`/`_enter` срабатывают), но
**операция за ней — нет**: модель событий отдаёт только `op`/`to_submit`/`flags`/`fd`, поэтому
ring-чтение `/etc/shadow` и ring-connect на `:3389` неотличимы от «голого» `io_uring_enter`
(нет `cred_shadow_read`/`lateral_rdp_connection`). Это задокументированный `known_bypass`,
записанный как явный NON-outcome рядом с позитивом — если демон однажды получит видимость
payload/path ring-операций, тест упадёт громко.
Файлы: `tests/integration/attacks/iouring_attacks.py`, `tests/integration/test_iouring_evasion.py`,
`tests/rules/iouring_test.yaml`.
Проверка: `make test-unit` (exit 0, 0 FAIL, coverage-gate 74/74 positive+negative,
`TestRuleSuites/iouring_test.yaml` реально прогнан вместе с mutant-сабтестом) и
`go vet ./...` — PASS; `python3 -m py_compile` обоих модулей и
`pytest --collect-only tests/integration/` — OK. Python-часть на стенде НЕ прогонялась.

**Особенности решения / открытые вопросы (D):**
- **Python-часть НЕ stand-verified** (macOS, нет root/eBPF-ядра с io_uring/демона): локально
  только `py_compile`, `pytest --collect-only` и skip при прогоне. Закрывать на VM
  `make test-integration` (в контейнере возможен отказ `io_uring_setup` из-за seccomp — тогда
  сработает skip по `io_uring_supported()`, а не fail).
- ~~Go-мутант `known_bypass` демотит mismatch в warning~~ **изменено (2026-10-11):**
  теперь `runMutant` **фейлит** mismatch как «stale known_bypass» (см. H). Если
  демон/движок получит видимость payload/path ring-операций и позитив начнёт
  срабатывать, Go-мутант тоже упадёт громко, а не промолчит.
- ~~Частичное принятие CQE~~ **исправлено (2026-10-11):** `ring_read_file`,
  `ring_openat_and_read` (read-фаза) и `ring_connect_loopback` теперь требуют
  `len(res) != iterations → EXIT_NO_CQE` вместо «1 из N» (`if not res`). Контракт
  exit-кода строгий: ребёнок рапортует успех только при полном наборе завершений.
- `__sync_synchronize` — не экспортируется glibc, поэтому на практике работает fallback
  (plain tail store); на x86_64 TSO безопасно, на aarch64 стенде теоретически возможно spurious
  падение (не ложный pass) — ревью, suggestion.
- Окно `wait_for_no_alert(..., window=3)` может не увидеть bypass-алерт, пришедший позже 3 с
  после позитивного (низкий риск — оба события от одного ребёнка) — ревью, suggestion.
- Набор полей `types.IOUringEvent` в реальном демоне в этом репо не проверяем; на стенде
  позитивы фальсифицируют docstring-утверждение, если набор шире `op`/`to_submit`/`flags`/`fd`.

### ✅ ~~E. Namespace/mount evasion~~
Действия из нового mount/PID namespace, bind-mount поверх чувствительных путей,
чтение `/proc/1/root/...`. Проверить, резолвит ли ebpf-guard пути в host-namespace
или его можно ослепить сменой namespace.
Сделано: `tests/integration/attacks/namespace_attacks.py` (чтение `/etc/shadow` из
`unshare(CLONE_NEWNS)`, из `unshare(CLONE_NEWPID)`+fork, через bind-mount в приватном
mount-ns и через `/proc/1/root/etc/shadow`; позитивный/негативный контроли; только
чтение, неразрешённый setup → `SETUP_FAILED=77` → skip) + `tests/integration/test_namespace_evasion.py`
(pytestmark root+daemon как в #31/#33) + `known_bypass`-мутанты в `tests/rules/credential_access_test.yaml`
(`cred_shadow_read`) и `tests/rules/lateral_movement_test.yaml` (`lateral_ssh_agent_socket_access`).
Вывод: смена namespace сама по себе НЕ ослепляет pathname-правила (читатель всё ещё
передаёт `open(2)` имя `/etc/shadow` и алерт срабатывает), но тот же inode через
`/proc/1/root/...` или bind-mount под другим именем не матчится — движок не резолвит
путь в host-namespace (`internal/ruletest/types.go` не имеет полей namespace/mount/resolved-path).
Файлы: `tests/integration/attacks/namespace_attacks.py`, `tests/integration/test_namespace_evasion.py`,
`tests/rules/credential_access_test.yaml`, `tests/rules/lateral_movement_test.yaml`.
Проверка: `make test-unit` (exit 0, 0 FAIL, coverage-gate 74/74 positive/negative) и
`go vet ./...` — PASS; `go test -run 'TestRuleSuites/(credential_access_test|lateral_movement_test)\.yaml' -v ./tests/`
— 4 новых мутанта PASS, demote-warning нет; `python3 -m py_compile` обоих модулей и
`pytest --collect-only tests/integration/` (81 тест) — OK. Python-часть на стенде НЕ прогонялась.

**Особенности решения / открытые вопросы (E):**
- **Python-часть НЕ stand-verified** (macOS, нет root/eBPF-ядра/демона): локально только
  `py_compile`, `pytest --collect-only` и skip при прогоне. Закрывать на VM `make test-integration`.
- ~~`_read` в детях глотает `OSError` → вакуумный pass~~ **исправлено (2026-10-11):**
  `_read` теперь `sys.exit(READ_FAILED=78)` при `OSError`, а оба known-bypass теста
  (`/proc/1/root/...`, bind-mount) при `READ_FAILED` делают `pytest.skip("bypass
  unproven")`, а не ассертят «no alert». Теперь «нет алерта» засчитывается как bypass
  только если чувствительное чтение реально состоялось.
- ~~`pid_ns_shadow_read` мапит ЛЮБОЙ ненулевой exit внука в `SETUP_FAILED`~~
  **исправлено (2026-10-11):** снепшот внука пробрасывает его реальный `WEXITSTATUS`;
  `SETUP_FAILED` теперь только при провале `unshare`/`fork`, а `READ_FAILED` / баг
  сниппета больше не маскируются под skip.
- Читатель в PID-ns — форкнутый внук, его host-pid тесту неизвестен, поэтому матч идёт по
  `comm="nspid"`; фактический `comm` в алерте подтвердить на стенде.
- Литеральная инверсия bind-mount (benign поверх sensitive) правила НЕ обманывает (в `open(2)`
  уходит `/etc/shadow`) — задокументировано в docstring, отдельным тестом не покрыто.
- ~~Go-слой `known_bypass` демотит mismatch в warning~~ **изменено (2026-10-11):**
  теперь mismatch мутанта фейлит (см. H), поэтому если движок получит
  namespace/mount-aware резолвинг, упадут **и** Go-сьют (`credential_access`/
  `lateral_movement` мутанты), **и** Python-тесты — пробел не останется молча
  помеченным.

### ✅ ~~F. `make test-unit` должен гонять реальные тесты движка (из закрытого PR #28)~~
Сделано (из закрытого PR #28, взят только этот фикс): `test-unit:` в `Makefile`
теперь `$(GOTEST) ./internal/... ./tests/...` — покрывает rule-engine тесты
(`TestRuleSuites`, `TestCoverageMatrix`, `TestSnapshot`, `TestReplayTraces`,
`TestBenignCorpus`), которые лежат в `./tests/...`, а не в `./internal/...`.
Проверка: `make test-unit` — exit 0, 391 RUN, 0 FAIL.

### ⬜ G. Фикс `qname_is_dga` field getter (follow-up из #30)
`internal/correlator/rules.go:1171` — getter возвращает `"true"` при
`NgramScore >= threshold`, обходя guard `len(label) >= 8`, который соблюдает сам
`NgramDGADetector.IsDGA()`. Короткие обычные слова (`example`) ложно детектятся
как DGA через это поле. Правило из #30 обходит баг (использует `qname_entropy` /
`qname_digit_ratio` напрямую), но сам getter стоит починить. Относится к коду
движка ebpf-guard, не к attack-lab — заводить в основном репозитории ebpf-guard
против ветки **`testing`** (ведущая ветка там).

### ✅ ~~H. Хвосты ревью A/C — открытые особенности и follow-up~~

Гейт A/C работает и закрыт. Все edge-cases ревью исправлены (2026-10-11).

Особенности реализации — **исправлено**:
- **Дубликаты exclusion-ID** — `TestCoverageMatrix` теперь фейлит с «listed more
  than once», если ID встречается в `negativeCoverageExclusions` дважды;
  `countOfExclusionsPresentInRules = len(excluded)` считает уникальные записи,
  так что самопротиворечивый отчёт «73/72» больше невозможен.
- **Полное исключение всех правил** — при `negTotal == 0` негативное покрытие
  трактуется как vacuously-satisfied (`negPct = 100.0`), гейт не падает на «0/0».
- **Расхождение 73 vs 74** — разъяснено в комментарии: движок грузит 74, гейт =
  «100% от неисключённых» = 74/74; «73» было числом пробелов до задачи A.

Follow-up ревью — **исправлено**:
- **`tests/rules/reconnaissance_test.yaml`** — пробелы детекции `ethtool` /
  `tcpdump` в `recon_network_config` / `recon_active_connections` теперь помечены
  явными `known_bypass: true` мутантами (closed comm allowlist → реальный upstream
  fix в ebpf-guard@`testing`). Прежние no_alert near-miss кейсы (`ethtool`/
  `tcpdump` execve) заменены на честные near-miss по одной оси (тот же comm из
  allowlist, но `read`-syscall вместо execve), чтобы не прятать пробел под
  no_alert. `passwd`/user-enum near-miss оставлен как валидный negative.
- **`tests/rules/file_integrity_extended_test.yaml`** — слабый near-miss
  «`/etc/hostname` read» усилен до различия по одной оси: тот же путь
  `/etc/passwd`, но `op: read` вместо write/create.

Побочно усилен сам контракт `known_bypass` в движке (`internal/ruletest/runner.go`):
mismatch мутанта с `known_bypass` теперь **фейлит** с «stale known_bypass (gap
appears closed)», а не демотится в warning. Это закрывает дыру, из-за которой
закрытый пробел мог тихо оставаться помеченным как bypass (см. также D/E/#31 —
там отмечалось, что Go-слой демотит mismatch; теперь не демотит).

Не запускалось и не требуется для A/C: Python integration (`tests/integration`)
и K8s (`tests/k8s`) — нужен root + eBPF-ядро + запущенный демон.

### ⬜ I. Хвосты #31 — открытые особенности и follow-up

Комм-спуфинг-слой (#31) закрыт: 31 mutant эмпирически показывают, где детекция
держится на голом `comm`, а где нет. Но ревью вскрыло продуктовую особенность и
часть скоупа осталась намеренно не покрытой.

Особенности (записать, чтобы не потерять):
- **`collection_direct_db_file_access` вообще не смотрит на `comm`.** Правило
  заявлено как «non-db process reads DB files», но `comm`-условия в нём нет —
  поэтому спуфинг под `mysqld` **не** спасает атакующего (mutant с
  `expect: alert`), и одновременно правило ложно срабатывает на легитимном
  DB-процессе. Кандидат на фикс/уточнение в ebpf-guard (`testing`).
- **Что реально устойчиво к спуфингу.** Правила, клюющиеся на
  `filename`/op/`dport`/`uid`/path (`lolbin_strace_exec`, `lolbin_busybox_shell`,
  `webshell_*_in_web_root`, `lateral_rdp_connection`, `lateral_shared_volume_exec`,
  `persist_etc_environment_write`, `persist_etc_profile_write`), продолжают
  срабатывать при любом `comm`. Позитивные `comm in [...]` правила (например
  `webshell_script_write_via_web_process` c `nginx`) срабатывают, если спуфить
  **в** члена списка, и обходятся, если спуфить **в сторону** (`systemd`).
- **Механика Python-слоя.** `prctl(PR_SET_NAME)` реально переписывает
  `task_struct->comm` (обрезка до 15 байт); `execve` берёт `comm` из basename
  пути запуска, а не из `argv[0]`, поэтому symlink-алиас подделывает `comm`, но
  `/proc/[pid]/exe` всё ещё указывает на реальный бинарь. `argv[0]` сам по себе
  `comm` не подменяет — это отдельный вывод теста.

Follow-up (не в скоупе #31):
- **Другие suite'ы с `comm not_in` allowlist** не тронуты (покрыты только 6
  файлов, названных в задаче): `credential_access`, `initial_access`,
  `gpu_mining`, `iouring`, `runtime_integrity`, `bpf_rootkit`, `supply_chain`,
  `ebpf_subversion`, `kernel_integrity`, `persistence`. Возможен второй проход.
- **Python integration-пара #31 не проверена на стенде.** Локально возможно было
  только `py_compile` + pytest-collect (5 тестов, skip без root/daemon).
  Закрыть на VM с root + eBPF-ядром + демоном: `make test-integration`
  (`test_process_masquerade.py`) — и подтвердить/опровергнуть реальные ожидания
  `no_alert` для двух prctl/symlink-обходов.
- **Мелочи, исправленные ревью:** убран мёртвый `spoofed_comm_connect()`,
  добавлен `shutil.which("wget")`-guard, проверка `returncode` у evasion-детей,
  `argtypes` для `prctl`. Осталось: `returncode == 0` не доказывает, что probe-
  действие реально дошло до ядра, поэтому `wait_for_no_alert` — слабый
  позитивный контроль и на стенде его надо читать вместе с логом демона.

---

## 4. Порядок работ (рекомендуемый)

1. ~~Разобрать зависшие PR~~ — сделано: #34 смёржен, #28 закрыт.
2. ~~Задача **F** (`make test-unit` гоняет реальные тесты)~~ — сделано, вхолостую зелёный CI-джоб починен.
3. ~~Задача A (негативное покрытие) + C (gate)~~ — сделано; открытые хвосты → H.
4. ~~#31 (comm-спуфинг)~~ — сделано; открытые хвосты → I.
5. #32 (chains / lineage) — корреляция, высокая ценность.
6. ~~B → #29 (EWMA threshold evasion)~~ — сделано: Go/YAML-часть проверена, Python-часть ждёт прогона на стенде (§2 #29, §B).
7. ~~#33 (TOCTOU + watchdog)~~ — сделано: Go/YAML-часть проверена локально, Python-часть ждёт прогона на стенде (§2 #33).
8. D, E — добить каналы обхода (io_uring, namespace).
9. G — фикс `qname_is_dga` (в основном репо ebpf-guard).

---

## Принцип

Для каждого обхода — **явный, задокументированный результат**: либо ebpf-guard ловит
(позитивный тест), либо пробел помечен `known_bypass: true` и виден в отчёте. Никаких
тихо пропущенных дыр.
