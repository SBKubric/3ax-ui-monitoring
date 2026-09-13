# 3ax-ui-monitoring

Мониторинг inbound'ов панели [3AX-UI](https://github.com/SBKubric/3ax-ui-proxy): **mon-server** на отдельном сервере и коробки **mon-client** в целевых регионах, которые раз в минуту проверяют каждый inbound real server через proxy front и напрямую, а панель показывает картину и шлёт Telegram.

Статус: спека готова к реализации, кода пока нет. Решения приняты в карте [Healthcheck-мониторинг inbound'ов: mon-server, mon-clients и контракт с панелью](https://github.com/SBKubric/3ax-ui-proxy/issues/20).

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
