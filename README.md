# 3ax-ui-monitoring

Мониторинг inbound'ов панели [3AX-UI](https://github.com/SBKubric/3ax-ui-proxy): **mon-server** на отдельном сервере и коробки **mon-client** в целевых регионах, которые раз в минуту проверяют каждый inbound real server через proxy front и напрямую, а панель показывает картину и шлёт Telegram.

Статус: идёт реализация mon-server по плану §12 [его спеки](docs/spec/mon-server.md), mon-client — пока только спека. Решения приняты в карте [Healthcheck-мониторинг inbound'ов: mon-server, mon-clients и контракт с панелью](https://github.com/SBKubric/3ax-ui-proxy/issues/20).

## Документы

| документ | что |
|---|---|
| [CONTEXT.md](CONTEXT.md) | глоссарий: mon-server, mon-client, target, path, probe account, tunnel probe, heartbeat, registration request, pairing code, client token, config revision, unverified cycle, admin UI |
| [docs/spec/mon-server.md](docs/spec/mon-server.md) | mon-server: bootstrap и TLS, хранилище, цикл с панелью, реестр и регистрация, state machine, статистика, Telegram, admin UI, план реализации |
| [docs/spec/mon-client.md](docs/spec/mon-client.md) | mon-client: регистрация, конфиг и его применение, xray и AWG-netstack, цикл проб и измерения, heartbeat и буфер, план реализации |
| [docs/spec/mon-protocol.md](docs/spec/mon-protocol.md) | протокол mon-server ↔ mon-client v1 (wire-форма) |
| [Контракт API панели для mon-server](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/spec/monitoring-contract.md) | ручки панели `/mon/v1/*`, которые mon-server вызывает (репо панели) |
| [Панельная часть мониторинга](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/spec/monitoring-panel.md) | таблицы, probe accounts, job'ы, Telegram, UI панели (репо панели) |
| [ADR 0003](https://github.com/SBKubric/3ax-ui-proxy/blob/main/docs/adr/0003-mon-server-single-source-panel-passive.md) | mon-server — реестр и единственный источник истины, панель — пассивный приёмник |

## Как это устроено в двух словах

1. Панель (real server) открывает mon-server bearer-защищённые ручки и по его запросу заводит **probe accounts** — по служебному клиенту в каждом inbound'е под одним subId.
2. mon-server раз в минуту забирает у панели состояние и конфиги probe-набора, собирает каждому mon-client его **targets** (inbound × path `proxy`/`direct`) и раздаёт их по **config revision**.
3. mon-client поднимает туннель на каждый target (xray-core, AmneziaWG in-process) и раз в минуту шлёт **tunnel probe** через туннель и **heartbeat** мимо него.
4. mon-server считает UP/DOWN/FLAPPING/UNKNOWN/PAUSED и шлёт панели переходы и 5-минутные агрегаты; панель рисует страницу Monitoring, бейдж Health у inbound'ов и шлёт Telegram. Молчание mon-server панель показывает как STALE.

## Установка mon-server

### Что нужно на коробке

| требование | зачем |
|---|---|
| отдельный сервер с публичным IP | этот IP попадает в сертификат и в `probeUrl`, по нему mon-clients шлют heartbeat и tunnel probe |
| порт `443/tcp`, открытый **всему интернету** | один листенер отдаёт `/v1/*`, `/admin/*` и `/healthz`, и на нём же проходит ACME-challenge `tls-alpn-01`: валидаторы Let's Encrypt приходят с произвольных адресов, так что фильтр по IP ломает выпуск сертификата. Порт `80` не нужен — HTTP-challenge выключен |
| работающий NTP | сертификат для IP живёт 160 ч и продлевается каждые ~3 дня, а все времена в БД, протоколе и state machine — ms UTC: уехавшие часы ломают и TLS, и расчёт состояний |
| исходящий HTTPS | к панели (цикл §4) и к `api.telegram.org` (сообщения mon-server §8) |

### Сборка и запуск

```
make build                 # ./mon-server; нужен Go 1.26 и CGO — драйвер SQLite cgo'шный
make image                 # Docker-образ 3ax-mon-server:<version>
mon-server run [-config <path>] [-log-level debug|info|warn|error]
```

В образе уже выставлены `MON_DATA_DIR=/var/lib/mon-server` (том) и `MON_LISTEN=:443`, `EXPOSE 443`, команда по умолчанию — `run`. Живость проверяется без авторизации: `GET https://<publicIp>/healthz` → `200`.

### Bootstrap-конфиг

Файл `/etc/mon-server/config.json` (другой путь — флагом `-config`) плюс переменные `MON_*`; переменная перебивает файл, отсутствующий файл — не ошибка. В конфиге только то, что нужно до появления БД:

| ключ | ENV | default | что это |
|---|---|---|---|
| `listen` | `MON_LISTEN` | `:443` | адрес единственного HTTPS-листенера |
| `publicIp` | `MON_PUBLIC_IP` | — | публичный IP: на него выпускается сертификат, из него собирается `probeUrl`. Обязателен при `tls.mode=acme-ip` |
| `dataDir` | `MON_DATA_DIR` | `/var/lib/mon-server` | каталог данных: `mon-server.db` и `certs/` |
| `tls.mode` | `MON_TLS_MODE` | `acme-ip` | `acme-ip` — сертификат Let's Encrypt на IP (certmagic, `tls-alpn-01`); `files` — свой сертификат |
| `tls.cert` | `MON_TLS_CERT` | — | путь к файлу с PEM-цепочкой, обязателен при `tls.mode=files` |
| `tls.key` | `MON_TLS_KEY` | — | путь к файлу с PEM-ключом, обязателен при `tls.mode=files` |

```json
{
  "listen": ":443",
  "publicIp": "203.0.113.10",
  "dataDir": "/var/lib/mon-server",
  "tls": { "mode": "acme-ip" }
}
```

### Администратор и admin UI

```
mon-server admin set <user>        # спросит пароль дважды, положит bcrypt-хэш в БД
MON_ADMIN_PASSWORD=... mon-server admin set <user>   # без терминала: контейнер, инсталлер
```

Повторный вызов меняет и логин, и пароль. Дальше — admin UI на `https://<publicIp>/admin`. **Всё остальное настраивается там, а не в файле**: адрес панели и `monToken`, host real server для path `direct`, Telegram (токен бота и chat id), пороги state machine (`downAfter`, `upAfter`, `flapN`, `flapMin`, `flapHoldMin`, `clientOfflineAfter`, `panelDownAfter`) и параметры проб (`intervalMs`, `budgetMs`, `connectMs`, `tlsMs`, `headersMs`, `startJitterMs`, `heartbeatTimeoutMs`). Там же одобряются заявки mon-clients.

Версия бинарника — `mon-server version` (проставляется при сборке из `git describe`).

### Данные и бэкап

| путь | что |
|---|---|
| `<dataDir>/mon-server.db` | вся БД (§3), файл с правами `0600`: настройки, администратор, реестр mon-clients и хэши токенов, заявки, targets, очередь событий и 5-минутные бакеты |
| `<dataDir>/certs/` | хранилище certmagic: ACME-аккаунт и сертификаты |

Бэкапить нужно `mon-server.db` — в нём всё состояние; `certs/` восстановится сам перевыпуском. Размер БД держит ретеншн-job раз в час: он удаляет отправленные панели события и бакеты старше 7 дней, `probe_seen` старше 24 ч, отработавшие заявки и истёкшие сессии. Неотправленное не удаляется никогда — в `PANEL_DOWN` outbox единственная копия событий. `VACUUM` не делается: файл переиспользует освободившиеся страницы.

Упаковка (systemd-юнит, инсталлер, публикация образа) — отдельный тикет карты [SBKubric/3ax-ui-proxy#38](https://github.com/SBKubric/3ax-ui-proxy/issues/38), здесь сознательно не решается.
