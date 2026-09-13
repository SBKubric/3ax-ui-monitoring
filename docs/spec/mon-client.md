# mon-client

Спека и план реализации. Итог карты [Healthcheck-мониторинг inbound'ов: mon-server, mon-clients и контракт с панелью](https://github.com/SBKubric/3ax-ui-proxy/issues/20); решения приняты в её тикетах, здесь они только собраны. Термины по [CONTEXT.md](../../CONTEXT.md). Wire-форма — [mon-protocol.md](mon-protocol.md) (далее «протокол»); механика проб и её опытная проверка — [research: как mon-client гоняет пробу через xray-core и AWG в контейнерах](https://github.com/SBKubric/3ax-ui-proxy/blob/research/mon-client-probes/docs/research/mon-client-probes.md) (далее «research»).

## 1. Назначение и границы

mon-client — коробка в целевом регионе: **один контейнер, один Go-процесс без capabilities**. Для xray-targets он держит дочерний `xray` (бинарь из официального образа, конфиг в файл, stderr в pipe), для AWG-targets — встроенный `amneziawg-go/v3` с `tun/netstack` (gVisor, in-process, без `/dev/net/tun`, маршрутов и прав). Раз в минуту он гоняет tunnel probe к mon-server через каждый туннель и шлёт один heartbeat мимо туннелей. Успех пробы определяет mon-client; состояние targets считает mon-server.

Вне scope v1: пробы WireGuard и MTProto; `awg-quick`, netns и policy routing в контейнере (research §3.2, §4 — не работают без privileged или дают ложный UP); упаковка и инсталлер (туман карты).

## 2. Запуск, параметры, state-файл

- Единственный параметр — `serverUrl` (`https://<ip>:443`), через флаг `--server` или ENV `MON_SERVER_URL`. Опционально `--state-dir` (`/var/lib/mon-client`), `--xray-bin` (`/usr/local/bin/xray`), `--log-level`.
- **State-файл** `state.json` (0600): `{monClientId, token, serverUrl, appliedRevision}`. Пока его нет — регистрация (§3). Пропал или `401` — стереть и регистрироваться заново.
- Рабочие файлы в state-dir: `xray.json` (сгенерированный конфиг), `xray.log` не ведётся (stderr читается в pipe), `cycles.json` — буфер неподтверждённых циклов (§6).
- mon-client доверяет системным CA; пиннинга нет.

## 3. Регистрация

Протокол §2.

1. Сгенерировать pairing code `[A-Z2-9]{6}`, **напечатать в лог** (`registration request sent, pairing code 7K3F9Q`), `POST /v1/register {pairingCode, hostname, version, publicIp}` (`publicIp` — best effort, из первого исходящего соединения; пусто допустимо).
2. `202 {requestId, pollAfter, expiresAt}` → опрос `GET /v1/register/<requestId>` каждые `pollAfter` (10 с) до `approved` (сохранить `monClientId`, `token` в state-файл → §4), `rejected` (ждать 1 ч, новая заявка) или `410` (новая заявка с новым кодом; backoff 1 → 2 → 5 мин, дальше каждые 5 мин).
3. `429` → ждать `Retry-After`. Сетевые ошибки — тот же backoff.

## 4. Конфиг и его применение

Протокол §4.

1. `GET /v1/config` при старте, после регистрации и когда `configRevision` в ответе heartbeat отличается от `appliedRevision`.
2. **Сборка**: из `targets` документа
   - xray-targets (`link`) → один `xray.json` (research §2.1): на target socks-inbound `127.0.0.1:<port>` (`auth: noauth`, порты с 10801 по порядку, `tag in-<kind>-<inboundId>-<path>`), outbound из ссылки (`vless`/`vmess`/`trojan`/`shadowsocks`; для Reality — `security: reality`, `serverName/fingerprint/publicKey/shortId/spiderX[/mldsa65Verify]`, `flow`, `encryption: none`; `network tcp`≡`raw`), правило routing `inboundTag → outboundTag`, последним outbound `blackhole`; `log: {loglevel: info, access: none}`, `mux` выключен (свежий Reality-handshake на каждую пробу);
   - AWG-targets (`conf`) → разбор `.conf` в UAPI: ключи base64 → hex, `Jc/Jmin/Jmax/S1..S4/H1..H4/I1..I5` и прочие AWG-параметры в нижнем регистре; `Address` → `localAddresses` netstack, `MTU` (default 1420), `DNS` игнорируется; `Endpoint`, `AllowedIPs`, `PersistentKeepalive` не нужен.
3. **Применение между циклами**: дождаться проб в полёте, записать `xray.json`, `xray -test -c xray.json`; успех → перезапустить дочерний xray (SIGTERM, ждать, старт, дождаться готовности socks-портов), `appliedRevision = configRevision`. Ошибка (`-test` упал, ссылка не разобралась, `.conf` не разобрался) → остаться на старой ревизии, продолжить пробы по старому конфигу, `configError` в каждом heartbeat (первая строка ошибки, ≤ 256 символов), повторять `GET /v1/config` при каждой смене ревизии. Грейса нет: результаты по удалённым targets отбрасываются.
4. Первый старт без валидного конфига (нет targets) — цикл идёт пустым: heartbeat без результатов.

## 5. Цикл проб

Протокол §5; параметры из `probe` конфига (default 60 с цикл, бюджет 20 с, connect 5 с, TLS 10 с, заголовки 10 с, джиттер старта 0–5 с, heartbeat 10 с).

- Старт цикла по тикеру `intervalMs` со случайным джиттером `[0, startJitterMs]`; все targets **параллельно**, каждая проба под `context.WithTimeout(budgetMs)`.
- **Проба** — `GET <probeUrl>?target=<kind:inboundId:path>&n=<nonce>` с `Authorization: Bearer <token>`, `nonce` — 16 байт base64url на пробу. Клиент на пробу (`DisableKeepAlives: true`, свой `http.Transport`), `httptrace`:
  - xray: `Transport.Proxy = socks5://127.0.0.1:<port target'а>`; `tlsMs = TLSHandshakeStart→Done` (первая сквозная фаза: Reality-handshake + TCP real server→mon-server + TLS 1.3), `ttfbMs = WroteRequest→GotFirstResponseByte`, `connectMs` — к loopback (≈ 0), `handshakeMs = null`;
  - AWG: на пробу **пересоздать** netstack-device (`Close` → `NewDevice` + `IpcSet` + `Up`), `t0` перед `tnet.DialContext`; `connectMs` вручную вокруг dial; `handshakeMs = last_handshake_time − t0` из `IpcGet()` (опрос ~50 мс до изменения, максимум `connectMs`); `tlsMs`, `ttfbMs` — хуки работают.
- **Успех** = `200`, JSON с тем же `nonce`, в бюджете. `egressIp` из ответа кладётся в результат.
- **Провал и `reason`** (словарь контракта §4.6): `tcp_refused` (dial refused), `tcp_timeout` (connect не уложился), `tls_timeout` (TLS-handshake не уложился), `reality_real_cert` (строка `REALITY: received real certificate` в stderr xray за окно пробы с тем же `[session-id]`, что `dialing TCP to <addr>:<port>` target'а), `awg_no_handshake` (`last_handshake_time` не изменился за `connectMs`), `http_error` (не `200` или чужой `nonce`), `probe_timeout` (общий бюджет). `detail` ≤ 256 символов: последняя строка `failed to process outbound traffic` / `REALITY: …` из stderr xray или текст ошибки Go.
- Читатель stderr xray: кольцевой буфер последних 500 строк с временем; сопоставление с target по `dialing TCP to <addr>:<port>` (адрес и порт из ссылки target'а) и `[session-id]`.

## 6. Heartbeat и буфер

Протокол §5.3.

- После цикла — один `POST /v1/heartbeat` (свой Transport без прокси, таймаут `heartbeatTimeoutMs`): `{monClientId, configRevision: appliedRevision, client: {version, xrayVersion, uptimeMs, configError}, cycles: [...]}`. Цикл: `{seq (монотонный, в state), ts (начало цикла, ms), unverified, results[]}`.
- **Буфер** `cycles.json`: цикл добавляется до отправки; ответ `200 {ackSeq}` удаляет все `seq ≤ ackSeq`; не подтверждён (сеть, 5xx, таймаут) → цикл остаётся с `unverified: true` и досылается в следующем heartbeat вместе с новыми; ≤ 60 циклов, старые вытесняются. Пробы при этом **продолжаются**.
- Ответ: `configRevision` ≠ `appliedRevision` → §4 после текущего цикла.
- `401 token_revoked` → остановить пробы, стереть state-файл, §3. `403 disabled` → остановить пробы, heartbeat раз в 5 мин до `200`. `410` на регистрации — §3.

## 7. Логи и диагностика

Человекочитаемый лог в stdout: регистрация с pairing code, применение ревизий, результат каждой пробы одной строкой (`probe xray:12:proxy ok tls=47ms ttfb=39ms` / `probe awg:0:proxy FAIL awg_no_handshake …`), результат heartbeat (`ack 1441`, `buffered 3 cycles`), ошибки конфига. Уровень `info` по умолчанию; `debug` добавляет stderr xray целиком.

## 8. Структура кода

```
cmd/mon-client/main.go        — флаги, запуск
internal/state/               — state.json, cycles.json
internal/register/            — §3
internal/config/              — GET /v1/config, разбор ссылок и .conf, генератор xray.json, UAPI
internal/xray/                — дочерний процесс, -test, рестарт, читатель stderr
internal/awg/                 — netstack-device на target
internal/probe/               — цикл, httptrace, reason
internal/heartbeat/           — отправка, буфер, ackSeq
docs/spec/mon-client.md
```

Зависимости: `github.com/amnezia-vpn/amneziawg-go/v3` (device, conn, tun/netstack), `golang.org/x/net/proxy` (socks5 dialer не нужен: `Transport.Proxy` умеет `socks5://`), стандартная библиотека.

## 9. Открытое из research (UNVERIFIED, не блокирует)

- Живой прогон `tun/netstack` против AWG-сервера стенда.
- Отменяет ли xray фоновые ретраи dial при закрытии socks-соединения (влияет только на нагрузку).
- Вариант «xray как библиотека» (`core.New`/`core.Dial`) для точного замера Reality-handshake — возможная замена socks в v2.

## 10. План реализации

Каждый шаг — отдельный коммит; тесты `go test ./...`; mon-server — httptest-стаб протокола.

1. Флаги, state-файл, лог; тест round-trip state.
2. Регистрация §3 на стабе: код в логе, опрос, `approved` → state, `rejected`/`410`/`429`/backoff.
3. Разбор ссылок → outbound (таблица research §2.1: vless+reality обязательные поля, `tcp`≡`raw`, ошибки), разбор `.conf` → UAPI (base64→hex, нижний регистр, `Address`/`MTU`); golden-тесты; `xray -test` на сгенерированном конфиге в CI через образ `ghcr.io/xtls/xray-core`.
4. Дочерний xray: старт, `-test`, рестарт между циклами, читатель stderr с кольцевым буфером; тест сопоставления `dialing TCP` / `REALITY: received real certificate` с target.
5. Проба xray через socks5 + httptrace; тесты на стабе mon-server: `ok`, `http_error` (чужой nonce), `tls_timeout`, `tcp_refused`.
6. Проба AWG через netstack: пересоздание device, `handshakeMs`, `awg_no_handshake`; интеграционный тест с `amneziawg-go` сервером в контейнере (первый живой прогон netstack — закрывает UNVERIFIED research §8).
7. Цикл §5: параллельность, бюджеты, джиттер; heartbeat и буфер §6 с `ackSeq`, unverified, вытеснением; тесты.
8. Применение ревизии §4: между циклами, `configError`, отбрасывание результатов удалённых targets.
9. `401`/`403`/`410` ветки; `version`.
10. Dockerfile-набросок для ручной проверки на стенде (упаковка и инсталлер — отдельно, туман карты): один контейнер без capabilities, проверить регистрацию, `UP` по обоим path, `DOWN` при остановке inbound'а, `reality_real_cert` при подмене SNI-сайта.
