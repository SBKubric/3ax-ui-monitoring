# mon-server

Спека и план реализации. Итог карты [Healthcheck-мониторинг inbound'ов: mon-server, mon-clients и контракт с панелью](https://github.com/SBKubric/3ax-ui-proxy/issues/20); решения приняты в её тикетах, здесь они только собраны. Термины по [CONTEXT.md](../../CONTEXT.md). Wire-формы: к панели — [Контракт API панели для mon-server](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/spec/monitoring-contract.md) (далее «контракт»), к mon-clients — [mon-protocol.md](mon-protocol.md) (далее «протокол»). Принцип: mon-server — реестр и единственный источник истины мониторинга, панель — пассивный приёмник ([ADR 0003](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/adr/0003-mon-server-single-source-panel-passive.md)).

## 1. Назначение и границы

mon-server — один Go-процесс на отдельном сервере с публичным IP. Он:

- раз в минуту poll'ит панель (`GET /state`, `POST /probe/ensure`), при смене ревизии панели забирает конфиги probe-набора (`GET /probe/configs` по обоим path) и пересобирает конфиг каждого mon-client;
- ведёт реестр mon-clients: registration requests с pairing code, одобрение и замена в admin UI, client tokens, paths и enable per-client;
- принимает heartbeat и tunnel probes, считает state machine targets и mon-clients, шлёт панели события и 5-минутные агрегаты;
- при недоступности панели (`PANEL_DOWN`) сам шлёт Telegram и копит события для досылки;
- отдаёт admin UI за логином.

Вне scope v1: несколько mon-server на панель и один mon-server на несколько панелей; пробы WireGuard и MTProto; мониторинг sub-сервера proxy front; показ состояния targets в admin UI (картина только в панели).

## 2. Процесс, bootstrap и CLI

- Один бинарник `mon-server`, Go, без внешних сервисов. Команды: `mon-server run` (сервис), `mon-server admin set <user>` (запрашивает пароль, пишет bcrypt-хэш в БД; повторный вызов меняет логин и пароль), `mon-server version`.
- **Bootstrap-конфиг** (файл `/etc/mon-server/config.json` или ENV `MON_*`) минимален: `listen` (`:443`), `publicIp` (обязателен в обоих режимах TLS, IP-литерал: из него строится `probeUrl` = `https://<publicIp>:<port>/v1/probe`, параметра `publicHost` нет — AWG-проба в netstack не резолвит имена), `dataDir` (`/var/lib/mon-server`), `tls.mode` (`acme-ip` | `files`, для `files` — `tls.cert`, `tls.key`), `tls.acmeCa` / `MON_TLS_ACME_CA` (`production` по умолчанию | `staging` | URL ACME directory, §2.1). Всё остальное — в настройках БД через admin UI (§9.4).
- **Права на `dataDir`.** В БД лежат `monToken` и `tgToken`, поэтому на каждом старте (и в `admin set`) mon-server создаёт `dataDir` с `0700` и выставляет `chmod` `dataDir` → `0700`, `mon-server.db` → `0600` — идемпотентно, чинит и существующую установку с более широкими правами. `dataDir/certs` certmagic сам держит в `0700`/`0600`. В systemd-юните дополнительно `StateDirectoryMode=0700` и `UMask=0077` (README).
- **Один листенер** HTTPS на `listen`: `/v1/*` для mon-clients (протокол), `/admin/*` для admin UI, `/healthz` без auth (только `200`). Heartbeat, регистрация и конфиг идут мимо туннелей, tunnel probe — через туннель target'а; различаются путями, не портами.
- Graceful shutdown: дождаться текущих обработчиков, буферы в SQLite (§3) уже durable.

### 2.1 TLS

`tls.mode = acme-ip` (default): встроенный certmagic — сертификат Let's Encrypt для IP-адреса, профиль `shortlived` (160 ч), challenge `tls-alpn-01` на том же `:443`, `DisableHTTPChallenge: true` (`:80` не нужен), `RenewalWindowRatio ≈ 0.5` (продление каждые ~3 дня), `FileStorage` в `dataDir/certs`. Требования к коробке: `:443` открыт всему интернету (валидаторы LE), NTP.

CA задаёт `tls.acmeCa` / `MON_TLS_ACME_CA`: `production` (default) — боевой Let's Encrypt; `staging` — staging Let's Encrypt (стенды, которые пересобираются чаще, чем позволяют лимиты боевого LE на один IP: 5 сертификатов на набор идентификаторов за 7 дней); любое другое значение — URL ACME directory (Pebble в e2e/CI). Профиль `shortlived`, IP-SAN и `tls-alpn-01` со staging совместимы. Storage certmagic разделён по host CA, staging и production не пересекаются. С `production` certmagic повторные попытки сначала валидирует на staging (неявный `TestCA`) — в логах ретраев виден staging-host. Admin UI показывает CA на табе «TLS & admin» (§9.4).

`tls.mode = files` — свой cert/key (домен или тесты), без ACME. Лист сертификата обязан содержать IP-SAN, равный `publicIp` (mon-clients ходят на `probeUrl` по IP); иначе старт падает с ошибкой `cert has no IP SAN for publicIp`.

mon-client проверяет сертификат системными CA, пиннинга нет и CA-флага нет. Сертификат от staging-CA mon-client доверяет только через окружение: `SSL_CERT_FILE` с корнями staging LE (Go при этом продолжает читать `/etc/ssl/certs`) — см. README.

## 3. Хранилище

SQLite одним файлом `dataDir/mon-server.db` (GORM, как у панели; `foreign_keys=ON`, busy timeout 5 с, одно соединение на запись). Времена — ms UTC. Индексы с префиксом `idx_ms_`.

| таблица | ключ | поля | назначение |
|---|---|---|---|
| `settings` | `key` PK | `value` | настройки §9.4 (kv, как у панели) |
| `admin` | одна строка | `username`, `password_hash` (bcrypt), `updated_at` | администратор |
| `admin_sessions` | `id` (случайные 32 байта, cookie) | `created_at`, `expires_at` (24 ч), `ip` | cookie-сессии |
| `login_attempts` | `ip` PK | `failures`, `locked_until` | 5 неудач → 15 мин |
| `registration_requests` | `request_id` PK (128 бит base64url) | `pairing_code`, `hostname`, `version`, `public_ip`, `remote_ip`, `status` (`pending`/`approved`/`rejected`/`expired`), `created_at`, `expires_at` (+5 мин), `approved_token` (одноразовая выдача), `mon_client_id` | заявки §6 |
| `mon_clients` | `id` (slug ≤ 64 `[A-Za-z0-9_.-]`) PK | `name`, `region`, `paths` (JSON `["proxy","direct"]`), `token_hash` (SHA-256), `enabled`, `state` (`ONLINE`/`OFFLINE`/`NEVER`), `last_heartbeat`, `version`, `xray_version`, `applied_revision`, `config_error`, `config_error_at`, `remote_ip`, `approved_at`, `missed_heartbeats` | реестр |
| `targets` | unique `(mon_client_id, inbound_kind, inbound_id, path)` | `state` (`UP`/`DOWN`/`FLAPPING`/`UNKNOWN`/`PAUSED`), `since`, `reason`, `consecutive_fail`, `consecutive_ok`, `transitions` (JSON последних времён переходов для FLAPPING), `flapping_until`, `last_result_at` | state machine §7 |
| `panel_inbounds` | `(inbound_kind, inbound_id)` | `protocol`, `port`, `remark`, `enable`, `seen_revision` | последний `GET /state` |
| `client_configs` | `mon_client_id` PK | `revision`, `document` (JSON §5), `built_at` | собранный конфиг per-client |
| `events_outbox` | `id` UUID v7 PK | `ts`, `payload` (JSON события контракта §4.6), `notified`, `sent_at` (NULL пока не подтверждено панелью), `dropped` (панель отвергла, см. §4 шаг 4) | очередь событий, в `PANEL_DOWN` — буфер до 24 ч |
| `stats_buckets` | unique `(mon_client_id, inbound_kind, inbound_id, path, bucket_start)` | `n_ok`, `n_fail`, `lat_min`, `lat_avg`, `lat_max`, `handshake_ms`, `sent_at`, `dropped` | 5-мин агрегаты до отправки и на случай повтора |
| `probe_seen` | `id` autoinc | `mon_client_id`, `inbound_kind`, `inbound_id`, `path`, `egress_ip`, `seen_at` | лог приходов tunnel probe (диагностика), ретеншн 24 ч |

Ретеншн (job раз в час): `events_outbox` с `sent_at` старше 7 дней, `stats_buckets` с `sent_at` старше 7 дней, `probe_seen` старше 24 ч, `registration_requests` не-pending старше 7 дней, `admin_sessions` истёкшие.

## 4. Цикл с панелью

Клиент панели: base URL из настроек (§9.4), `Authorization: Bearer <monToken>`, таймаут 10 с, ретраи только на сеть/5xx/таймаут с экспоненциальной задержкой (1 → 2 → 4 с, не дольше минуты цикла); `4xx` на батч целиком — лог и дроп батча (`dropped`). Голый `404` на `GET /state` = «неверный токен, путь или мониторинг выключен» → Telegram от mon-server (§10), состояние `PANEL_DOWN` не объявляется (панель отвечает).

Раз в минуту (`panel poll`):

1. `GET /state` → сохранить `panel_inbounds`, override, `probe.subId`, `revision`. Ревизия отличается от последней виденной → шаг 3.
2. `POST /probe/ensure` с полным снимком реестра: `{id, name, region, state, lastHeartbeat}` по всем mon-clients с `enabled=true` (выключенные и `NEVER` тоже входят: панель показывает их как есть). Ответ несёт `subId` и `revision`; `503 xray_unavailable` — повторить в следующем цикле.
3. При смене ревизии, при смене `realHost` (он не входит в ревизию панели, но в direct-ссылки входит) и после Save `realHost`/`panelUrl` в Settings (§9.4; решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 4): `GET /probe/configs?host=<realHost>` (path `direct`) и, если `override.enabled`, `GET /probe/configs` (path `proxy`); ответ с `revision` ≠ текущей отбросить и повторить в следующем цикле. Пересобрать `client_configs` всех mon-clients (§5). Inbound'ы, исчезнувшие из `/state`, — снять их targets (`PAUSED` → удалить строки после подтверждения следующим heartbeat без этих targets); inbound'ы с `enable=false` есть в `/state`, но не в `items` → их targets `PAUSED` с событием `config_disabled`.
4. Отправка очереди: `POST /events` батчами ≤ 1000 из `events_outbox` с `sent_at IS NULL` (по `ts`), `POST /stats` для закрытых бакетов с `sent_at IS NULL` (≤ 2000). Панель отвечает поэлементно: `200 {accepted, rejected: [{index, id?, error}]}` (`id` — только у событий; решение [#50](https://github.com/SBKubric/3ax-ui-monitoring/issues/50)). Принятые → `sent_at = now`; отвергнутые → лог `WARN` с `error` панели, `sent_at = now` и `dropped = true`, без повторов (повтор был бы отвергнут так же). Пустое тело `200` (панель до поэлементной валидации) = «все приняты». Дубликаты и `ignored` панели — лог, не ошибка. `400 invalid_body` на батч целиком остаётся для нечитаемого тела — дроп батча, как любой `4xx`.

### 4.1 `PANEL_DOWN`

3 неудачных подряд запроса к панели (любых) → режим `PANEL_DOWN`: событие `{kind: panel, from: PANEL_UP, to: PANEL_DOWN, reason: http_timeout|http_5xx|conn_refused, notified: true}` в outbox, одно сообщение «panel unreachable» в Telegram от mon-server. В режиме: переходы targets и mon-clients mon-server **сам** шлёт в Telegram с пометкой «via mon-server» и помечает `notified=true`; события копятся в outbox (ограничение 24 ч — старше отбрасываются с логом), бакеты копятся без ограничения ретеншном 7 дней. Poll `GET /state` продолжается раз в минуту — он и есть детектор возврата. Первый успешный запрос → `PANEL_UP` (событие с `notified: true`), досылка outbox батчами с исходными `ts`, сообщение «panel back, N событий дослано».

## 5. Конфиг mon-client и config revision

Для каждого mon-client документ протокола §4.2:

- `targets` = `items` из `/probe/configs` для каждого path из `paths` этого mon-client (default `["proxy","direct"]`); `proxy` только при `override.enabled`; `link`/`conf` отдаются **как есть** (панель уже подставила адрес по path). Все inbound'ы — всем mon-clients; фильтра по inbound'ам в v1 нет.
- `probe` — глобальные параметры из настроек (§9.4): `intervalMs 60000`, `budgetMs 20000`, `connectMs 5000`, `tlsMs 10000`, `headersMs 10000`, `startJitterMs 5000`, `heartbeatTimeoutMs 10000`.
- `probeUrl` = `https://<publicIp>:<port>/v1/probe`.
- **`configRevision`** = первые 16 hex SHA-256 канонического JSON документа без поля `configRevision`. Меняется при смене ревизии панели, `paths` mon-client, `probe`-параметров или `probeUrl`. Пороги state machine в конфиг не входят.

Документ хранится в `client_configs`; `GET /v1/config` отдаёт его, ответ heartbeat несёт только `configRevision`.

## 6. Регистрация, токены, реестр

Протокол §2–3, admin UI §9.

- `POST /v1/register`: rate limit **1 заявка/мин на IP**, ≤ **3 pending с IP**, ≤ **20 pending глобально** (`429` + `Retry-After`); pairing code `[A-Z2-9]{6}` от mon-client; ответ `202 {requestId, pollAfter: 10000, expiresAt}`; заявка живёт 5 мин, потом `status=expired` и `410` на опрос. Неверный `requestId` — `404` без деталей.
- Одобрение (admin UI): администратор сверяет код с логом коробки, вводит `name`, `region`, выбирает paths → `monClientId` = slug имени (уникальный, ≤ 64), client token = 32 случайных байта (base64url), в БД только SHA-256; `approved_token` хранится в заявке до первого `GET /v1/register/<id>` со статусом `approved`, затем стирается. **Approve as replacement**: выбранный существующий mon-client сохраняет id, историю, paths, name и region; его `token_hash` заменяется (старый токен отозван), `state=NEVER` до первого heartbeat. **Seq привязан к поколению токена** (решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 1): при каждой выдаче токена — Approve и Approve as replacement (в том числе после Revoke) — `last_ack_seq = 0`; новая регистрация mon-client начинает с `seq=1`, и её циклы не отбрасываются как дубликаты циклов прежнего токена. Подсказка: при совпадении `hostname` или `public_ip` заявки с существующим mon-client admin UI предлагает замену, режим выбирает администратор явно. Reject → `status=rejected`, mon-client ждёт 1 ч.
- Аутентификация `/v1/config`, `/v1/heartbeat`, `/v1/probe`: `Bearer <token>` → SHA-256 → поиск по `token_hash` (constant-time сравнение). Неизвестен/отозван → `401 token_revoked`; известен, но `enabled=false` → `403 disabled`.
- **Revoke** (admin UI): `token_hash` очищается, mon-client остаётся в реестре со `state=OFFLINE` до новой заявки (одобрить её как replacement, чтобы вернуть id). Revoke идёт через state machine (§7.3, решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 2): в той же транзакции — событие `mon_client` `→ OFFLINE` с `reason: token_revoked` (если клиент ещё не `OFFLINE`; из `NEVER` — с пустым `from`), targets → `UNKNOWN` с `reason: mon_client_revoked`, Telegram — как у `OFFLINE` по таймауту. **Delete** mon-client: строка и его targets удаляются, панель чистит по следующему снимку. **Disable**: `enabled=false`, targets → `UNKNOWN` (событие `reason: mon_client_disabled`), из снимка реестра не исключается.

## 7. Heartbeat, state machine, статистика

Протокол §5; пороги из [State machine target'а](https://github.com/SBKubric/3ax-ui-proxy/issues/22).

### 7.1 Приём heartbeat

1. `received_at = now` (время mon-server — авторитет для состояния); `ts` циклов клампится к `received_at` при расхождении > 5 мин и используется только для раскладки по бакетам.
2. mon-client: `last_heartbeat = now`, `state=ONLINE` (из `OFFLINE`/`NEVER` — событие `mon_client ONLINE`; первый переход, из `NEVER`, уходит панели с пустым `from` — `NEVER` внутреннее состояние реестра и наружу не отдаётся, словарь панели для `mon_client` — `ONLINE`/`OFFLINE`), `version`, `xrayVersion`, `configError` (появился → событие в лог реестра + Telegram от mon-server §10; исчез → очистить). `configRevision` в heartbeat ≠ актуальной → `applied_revision` в реестре помечается как отстающая (видно в admin UI).
3. Циклы с `seq ≤ ackSeq` предыдущего ответа (`last_ack_seq`, сбрасывается при выдаче токена, §6) игнорируются. Из новых: **живой цикл** (последний, пришедший своим heartbeat, `unverified=false`) применяется к state machine; **досланные** (`seq` ниже последнего) и **unverified** идут только в статистику; из unverified берутся только успехи, провалы — пропуск. Результаты по targets, которых нет в текущем конфиге mon-client, отбрасываются.
4. Ответ `{configRevision, serverTs, ackSeq: max seq}`.

### 7.2 State machine target (считает mon-server)

| состояние | вход | выход | событие панели / Telegram |
|---|---|---|---|
| `UNKNOWN` | новый target; mon-client `OFFLINE`/disabled | в `UP` — с первого успеха живого цикла; в `DOWN` — только после `downAfter` провалов подряд (провалы до порога оставляют `UNKNOWN`) | событие; Telegram нет |
| `UP` | `upAfter` (2) успехов подряд из `DOWN`; из `UNKNOWN` — первый успех | — | «UP» с длительностью простоя (только из `DOWN`) |
| `DOWN` | `downAfter` (3) провала подряд при живом heartbeat — из `UP` и из `UNKNOWN` одинаково | — | «DOWN» с `reason` из результата |
| `FLAPPING` | ≥ `flapN` (4) переходов UP↔DOWN за `flapMin` (30 мин) | `flapHoldMin` (15) без переходов → фактическое состояние; выход проверяется только при приходе результата живого цикла (таймера нет: без результатов target остаётся `FLAPPING`, первый результат после истечения выводит его и применяется уже к фактическому состоянию) | одно сообщение при входе и выходе; переходы внутри — только события |
| `PAUSED` | inbound `enable=false` или пропал из `/probe/configs` (`config_disabled`); target выпал из собранного конфига mon-client по не-inbound причине (решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 3): `override_disabled` (выключен host override, path `proxy`), `path_removed` (у mon-client убран path), `no_probe_link` (inbound включён, но панель не выдала на этот path probe-ссылку); строка не удаляется | inbound снова активен → `UNKNOWN` (`config_enabled`, только для `config_disabled`); target снова в конфиге mon-client → `UNKNOWN` (`config_enabled`, для не-inbound причин; проверяется при каждом heartbeat), затем первый результат | событие с `reason` причины / `config_enabled`; Telegram нет |

Пороги глобальные в настройках (§9.4). Каждый переход → событие контракта §4.6 в outbox: `{id: UUID v7, ts: received_at, kind: target, monClientId, inboundKind, inboundId, path, from, to, reason, notified}`; `reason` из словаря (`tcp_refused` `tcp_timeout` `tls_timeout` `reality_real_cert` `awg_no_handshake` `http_error` `recovered` `flapping` `config_disabled` `config_enabled` `override_disabled` `path_removed` `no_probe_link` `mon_client_offline` `mon_client_disabled` `mon_client_revoked`; для `mon_client` — `heartbeat_missed`, `token_revoked`). Причины `PAUSED` у inbound (`config_disabled`) и у конфига mon-client (`override_disabled` `path_removed` `no_probe_link`) снимаются каждая своей стороной: включение inbound'а не снимает паузу `path_removed`.

### 7.3 mon-client

`OFFLINE` после `clientOfflineAfter` (3) пропущенных heartbeat подряд по времени приёма (проверяет job раз в 20 с: `now − last_heartbeat > 3 × intervalMs + heartbeatTimeoutMs`); все его targets → `UNKNOWN` (события с `reason: mon_client_offline`, без Telegram); событие `mon_client OFFLINE` (`reason: heartbeat_missed`) → Telegram через панель («mon-client <name> (<region>) OFFLINE»). `ONLINE` — первый heartbeat, все targets остаются `UNKNOWN` до результата.

**Revoke** — тот же переход по решению администратора (решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 2): событие `mon_client → OFFLINE` с `reason: token_revoked`, targets → `UNKNOWN` с `reason: mon_client_revoked`, Telegram по тем же правилам, что у `OFFLINE` по таймауту (через панель; в `PANEL_DOWN` — сам mon-server). Уже `OFFLINE` mon-client второго перехода не получает. `PAUSED` targets, как и при `OFFLINE`/Disable, остаются `PAUSED`.

### 7.4 Статистика

Бакет 5 мин по `(monClientId, inboundKind, inboundId, path, bucketStart = ts − ts % 300000)`: `n_ok`, `n_fail` (unverified-провалы не считаются), `lat_min/avg/max` по `tlsMs` успешных проб, `handshake_ms` — `handshakeMs` последнего успешного цикла бакета (только AWG), `NULL` при `n_ok=0`. Бакет закрывается через 1 мин после конца окна и уходит в `POST /stats` (§4 шаг 4); досланные циклы дописывают в бакет и, если он уже отправлен, отправляют повторно (upsert на панели).

### 7.5 Tunnel probe

`GET /v1/probe?target=<kind:inboundId:path>&n=<nonce>` с client token: ответ `200 {nonce, egressIp: <source IP запроса>, serverTs}`; запись в `probe_seen`. Состояние по этим запросам **не** считается: успех определяет mon-client в heartbeat. Неизвестный target для этого mon-client — `200` всё равно (диагностика), запись помечается `unknown_target`.

## 8. Telegram от mon-server

Бот и chat id — в настройках (§9.4), тот же бот, что у панели. mon-server шлёт сам только: «panel unreachable» / «panel back, N событий дослано»; переходы в режиме `PANEL_DOWN` с пометкой «via mon-server»; `configError` mon-client («mon-client <name>: config error <первая строка>»); `404` на `GET /state` («panel rejects monitoring token or monitoring is disabled»). Всё остальное — через панель (контракт §4.6, `notified=false`).

## 9. Admin UI

Решения тикета [Admin UI mon-server: страницы заявок, реестра и настроек](https://github.com/SBKubric/3ax-ui-proxy/issues/37): вариант A прототипа ([артефакт](https://claude.ai/code/artifact/4b51c48d-1c19-4acb-b7cc-798ac9816f31), [исходник](https://github.com/SBKubric/3ax-ui-proxy/blob/prototype/mon-admin-ui/docs/prototypes/mon-admin-ui.html)) — оболочка панели 3AX-UI: тёмный сайдбар, карточки, таблицы, по странице на задачу.

### 9.1 Стек и auth

- **Vue 3 + Ant Design Vue 4 без сборщика**: UMD-сборки `vue.global.prod.js`, `antd.min.js`, `antd.min.css` (+ `dayjs`) лежат в `web/assets/` и вшиваются в бинарник `go:embed`; страницы — `html/template`, по одному Vue-приложению на страницу, без роутера. Тема через `ConfigProvider` (`colorPrimary #008771`, `darkAlgorithm` по переключателю, хранится в `localStorage`). Node в сборке не нужен. Только английский в v1, строки в одном объекте `strings` на страницу.
- Логин: **логин + пароль**, bcrypt (`admin set`), cookie-сессия `mon_session` (HttpOnly, Secure, SameSite=Lax) на 24 ч; 5 неудачных логинов с IP → 15 мин блокировки (`login_attempts`); без 2FA. Все `/admin/*`, кроме `/admin/login`, требуют сессию; JSON-ручки admin UI живут под `/admin/api/*` и отдают `{success, msg, obj}` как панель.

### 9.2 Requests (`/admin/requests`)

Пункт меню с бейджем числа pending. Таблица: IP · hostname (+ версия, номер попытки) · pairing code крупным моноширинным · «expires mm:ss / received N ago» · Operate: **Approve**, **Approve as replacement ▾**, **Reject**; в шапке rate-limit'ы. Строка подсвечена, если hostname или IP совпадают с существующим mon-client («same hostname as msk-1: replacement?»).

**Approve** — модалка: код крупно + предупреждение «сверьте с логом коробки», переключатель «New mon-client / Replace an existing one», Name + Region (id = slug имени показан под полем, постоянный), чекбоксы paths с пояснением, что `direct` раскрывает адрес real server этой коробке. В режиме замены — выбор существующей записи (name/region/paths берутся из неё). Кнопка «Approve and issue token».

### 9.3 mon-clients (`/admin/clients`)

Таблица в стиле inbound'ов панели: Operate «⋯» (Edit, Revoke, Delete) · switch Enabled · Name с id·region · State (`ONLINE`/`OFFLINE`/`never seen`/`disabled`) · Last heartbeat («approved N ago» для never seen) · Paths тегами · Version (mon-client + xray) · Config (применённая ревизия или тег ⚠ config error с тултипом). **Edit** — модалка: name, region, paths правятся, id — нет; там же полный текст configError, применённая и серверная ревизии. **Revoke** — confirm с пояснением (401 → коробка стирает state и подаёт новую заявку; одобрить её как replacement). Состояние targets не показывается.

### 9.4 Settings (`/admin/settings`)

Одна кнопка **Save** сверху, строка статуса «Panel reachable · revision · N inbounds · override → host · checked N ago» (или последняя ошибка; если последний запрос упал на `x509: unknown authority` — отдельный текст с подсказкой про `panelCa`). Табы:

| таб | поля (ключ `settings`) |
|---|---|
| **Real server** | `panelUrl` (base URL панели с `webBasePath`), `monToken`, `panelCa` (textarea, PEM-цепочка; задана → запросы к панели доверяют **только** этому пулу вместо системного, самоподписанный лист панели годится как trust anchor; пусто → системный пул; невалидный PEM отклоняется при Save и Check), кнопка **Check** (`GET /state` и `GET /probe/configs` для введённого `realHost` по введённым значениям, включая `panelCa`, без Save; `x509: unknown authority` — отдельный текст с подсказкой про `panelCa`), `realHost` — адрес для path `direct`, по умолчанию host из `panelUrl`; **read-only блок Proxy front**: override вкл/выкл и host из последнего `GET /state` — своего поля proxy front у mon-server нет |
| **Telegram** | `tgToken`, `tgChatId`, кнопка **Send test** (без Save) |
| **Thresholds** | `downAfter 3`, `upAfter 2`, `flapN 4`, `flapMin 30`, `flapHoldMin 15`, `clientOfflineAfter 3`, `panelDownAfter 3` |
| **Probe** | `intervalMs 60000`, `budgetMs 20000`, `connectMs 5000`, `tlsMs 10000`, `headersMs 10000`, `startJitterMs 5000`, `heartbeatTimeoutMs 10000` |
| **TLS & admin** | read-only из bootstrap: `tls.mode`, в `acme-ip` — CA (`tls.acmeCa` и URL directory), срок сертификата и следующее продление, `dataDir`, `listen`; подсказка `mon-server admin set <user>` |

Save применяет всё разом; смена `probe`-параметров пересобирает `client_configs` всем mon-clients (новая config revision). Смена `realHost` или `panelUrl` (решение [#51](https://github.com/SBKubric/3ax-ui-monitoring/issues/51) п. 4) сбрасывает кэш probe-материала и сразу перечитывает `GET /state` + `GET /probe/configs` (§4 шаг 3) с сохранёнными значениями, затем пересобирает `client_configs` (ссылки входят в хэш — ревизия меняется); панель недоступна → Save всё равно сохраняет, кэш остаётся сброшенным, и материал перечитывает следующий poll. **Check** делает то же на лету без сохранения: после `GET /state` — `GET /probe/configs?host=<введённый realHost или host из panelUrl>` и, при включённом override, `GET /probe/configs`; показывает число probe-ссылок по path (или ошибку панели), кэш материала и `client_configs` не трогает.

## 10. Ручки (сводка)

| путь | кто | auth |
|---|---|---|
| `POST /v1/register`, `GET /v1/register/<requestId>` | mon-client | rate limit / `requestId` |
| `GET /v1/config`, `POST /v1/heartbeat` | mon-client | client token |
| `GET /v1/probe?target=&n=` | mon-client, через туннель | client token |
| `GET /healthz` | кто угодно | нет |
| `/admin/login`, `/admin/logout` | администратор | логин + пароль |
| `/admin/requests`, `/admin/clients`, `/admin/settings` (страницы) и `/admin/api/*` (JSON) | администратор | cookie-сессия |

Панель mon-server вызывает сам (§4); внешних входящих от панели нет.

## 11. Структура кода

```
cmd/mon-server/main.go        — CLI: run, admin set, version
internal/config/              — bootstrap-конфиг (файл/ENV)
internal/store/               — GORM-модели §3, миграции, ретеншн
internal/panel/               — клиент контракта, poll, outbox, PANEL_DOWN
internal/registry/            — заявки, токены, mon-clients, config revision
internal/state/               — state machine targets и mon-clients, бакеты
internal/api/                 — /v1/* хендлеры
internal/admin/               — /admin/* хендлеры, сессии, login_attempts
internal/tg/                  — Telegram
internal/tlsx/                — certmagic / files
web/assets/, web/html/        — admin UI (go:embed)
docs/spec/                    — эта спека, протокол, mon-client
```

## 12. План реализации

Каждый шаг — отдельный коммит; тесты `go test ./...`; интеграция с панелью — httptest-стаб контракта.

1. Bootstrap-конфиг, `store` с моделями §3, `admin set`; тесты миграции и bcrypt.
2. TLS (`certmagic` в `acme-ip`, `files`), листенер, `/healthz`.
3. Клиент панели §4: `GET /state`, ревизия, `POST /probe/ensure`, `GET /probe/configs`; тесты на стабе: смена ревизии перечитывает конфиги, `404` → Telegram, 3 неудачи → `PANEL_DOWN`, возврат досылает outbox.
4. Регистрация §6: `/v1/register*`, rate limit, TTL заявок, одобрение/замена/отклонение, токены; тесты на лимиты, одноразовую выдачу токена, replacement.
5. Конфиг per-client и config revision §5; тесты детерминированности хэша и его изменения от paths/probe/realHost.
6. Heartbeat §7.1 и state machine §7.2–7.3; таблица тестов на все переходы, unverified-правило, досылку, кламп времени, `ackSeq`.
7. Статистика §7.4 и отправка `POST /events`/`POST /stats` §4 шаг 4; тесты на закрытие бакетов и повторную отправку.
8. Tunnel probe §7.5 и `probe_seen`.
9. Telegram §8.
10. Admin UI §9: логин и сессии, Requests, mon-clients, Settings (Check, Send test, Save с пересборкой конфигов); embed-ассеты.
11. Ретеншн-job §3, `version`, README с установкой (упаковка mon-server — туман карты, не решалось).
12. Ручная проверка на стенде: панель на real server + proxy front + два mon-client → заявки, одобрение, `UP` по обоим path, `DOWN` при остановке inbound'а, `PANEL_DOWN` при остановке панели.
