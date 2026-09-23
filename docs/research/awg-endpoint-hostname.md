# amneziawg-go: `endpoint=` по имени хоста и ошибки `IpcSet`/`Up`

Research-тикет [#60](https://github.com/SBKubric/3ax-ui-monitoring/issues/60) (карта #49). Дата: 2026-09-23.

## Версии источников

| Источник | Ревизия |
|---|---|
| amneziawg-go (как в `go.mod` mon-client: `github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260828`) | тег `v3.1.20260828` = `b5928efb6ca19f0153958460c3d141f04abc5c2e` |
| wireguard-go | `ecfc5a8d54462e18e13c72173e2623d16d8e25a0` (2026-05-22) |
| wireguard-tools (`wg`, `wg-quick`) | `a998407747005ea7e4e0258d96f105c97241e1d3` (2026-05-06) |
| amneziawg-tools (`awg`, `awg-quick`) | `ee0f0a9aa34ff0a0da4b3433b9512781cfe02843` (2026-08-13) |
| Спецификация UAPI | <https://www.wireguard.com/xplatform/#configuration-protocol> |

Ссылки ниже сокращены: `AWG` = `https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e`,
`WGT` = `https://git.zx2c4.com/wireguard-tools/tree`, `AWGT` = `https://github.com/amnezia-vpn/amneziawg-tools/blob/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843`.

## Краткие ответы

1. **`endpoint=` принимает только литерал `IP:port` / `[IPv6]:port`.** Имя хоста device не резолвит никогда: `IpcSet` падает с `IPC error -22 (EINVAL): failed to set endpoint …: ParseAddr("host"): unable to parse IP`. Смена IP за именем device не видна в принципе — имя в нём не хранится, хранится `netip.AddrPort`. Endpoint меняется только через новый `IpcSet` или через roaming (адрес источника последнего аутентифицированного пакета от пира).
2. **`IpcSet`** возвращает `*device.IPCError` с кодом (`ErrorCode()`): `-EINVAL` (невалидный ключ/значение, в т.ч. hostname в endpoint; для AWG — перекрытие H1..H4, S<nonce при header protection), `-EPROTO` (строка без `=`), `-EADDRINUSE` (`listen_port` на поднятом device), `-EIO` (ошибка чтения). Всё, кроме `EADDRINUSE`/`EIO`, — ошибка конфигурации, ретрай бессмысленен. Применение **не атомарно**: строки до ошибки уже применены. **`Up`** возвращает «голую» ошибку сокета (`bind.Open`: UDP listen, `EADDRINUSE` при фиксированном `ListenPort`, `EMFILE`, …) или netlink route socket (Linux); после неудачи device откатывается в Down, и `Up` можно повторить — это ошибки окружения, восстановимые. Handshake — **не** ошибка `Up`: `Up` не ждёт пира, неответ пира виден только в логе и в `last_handshake_time_*`.
3. **`wg`/`awg` (и через них `wg-quick`/`awg-quick`) резолвят имя один раз**, при разборе конфига (`getaddrinfo`, берётся первый результат, до 15 ретраев на временных ошибках, `WG_ENDPOINT_RESOLUTION_RETRIES`), и передают в ядро/UAPI уже IP. Повторного резолва ни по handshake, ни по таймеру нет; для динамического DNS есть отдельный contrib-скрипт `reresolve-dns.sh` под cron.

**Следствие для mon-client:** сейчас `.conf` с `Endpoint = host:port` проходит `ParseAWGConf` (валидатор не резолвит, а комментарий «the device does the resolving when it dials» — неверен), но каждый probe падает в `Open` → `IpcSet` и репортится как `awg_no_handshake`, хотя это ошибка конфигурации. Проверено эмпирически (см. §4).

## 1. Принимает ли `endpoint=` имя хоста

### Спецификация UAPI

> `endpoint`: The value for this key is either `IP:port` for IPv4 or `[IP]:port` for IPv6, indicating the endpoint of the previously added peer entry.
> — <https://www.wireguard.com/xplatform/#configuration-protocol>

Имя хоста протоколом не предусмотрено вовсе; в примерах спеки — только литералы (`[abcd:23::33%2]:51820`, `182.122.22.19:3233`).

### amneziawg-go

- Обработчик ключа: `device.net.bind.ParseEndpoint(value)`, при ошибке — `ipcErrorf(ipc.IpcErrorInvalid, "failed to set endpoint %v: %w", …)`; результат кладётся в `peer.endpoint.val` ([AWG/device/uapi.go#L653](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/uapi.go#L653)).
- mon-client использует `conn.NewDefaultBind()` = `NewStdNetBind()` на не-Windows ([AWG/conn/default.go](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/conn/default.go)). Её `ParseEndpoint` — это `netip.ParseAddrPort(s)` и больше ничего ([AWG/conn/bind_std.go#L90](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/conn/bind_std.go#L90)). `netip.ParseAddrPort` DNS не делает — только литерал.
- Windows-bind (`WinRingBind.ParseEndpoint`) зовёт `GetAddrInfoW` с `AI_NUMERICHOST` — тоже только литерал ([AWG/conn/bind_windows.go#L99](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/conn/bind_windows.go#L99)).
- Во всём дереве нет вызова резолвера для endpoint: единственный `net.ResolveUDPAddr` в `conn/` — для чтения локального адреса только что открытого listen-сокета ([bind_std.go#L122](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/conn/bind_std.go#L122)); `netstack.Net.LookupHost` — это DNS *внутри туннеля* для пользователя netstack, к endpoint отношения не имеет.
- netstack тут ни при чём: `CreateNetTUN` подменяет только TUN (трафик внутри туннеля), а UDP к пиру идёт через host-сокет `StdNetBind`.

### wireguard-go

Идентично: тот же `ParseEndpoint` → `netip.ParseAddrPort` (`conn/bind_std.go#n90` @ `ecfc5a8`) и тот же обработчик `endpoint` в `device/uapi.go` (`#n340`). AmneziaWG в этой части upstream не менял.

### Что происходит при смене IP за именем

Device имя не знает — после `IpcSet` у пира есть только `StdNetEndpoint{AddrPort}`. Endpoint меняется лишь:

- новым `IpcSet` с `endpoint=` (так работает `reresolve-dns.sh`, см. §3);
- roaming: `peer.SetEndpointFromPacket` при каждом аутентифицированном входящем пакете ([AWG/device/peer.go#L283](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/peer.go#L283); вызовы в `device/receive.go`), если не включён `disableRoaming` (только mobile-quirks). Для клиента, который сам инициирует, roaming бесполезен: сервер на новом IP не пришлёт пакет, пока клиент не постучится туда.

Если IP сменился, device просто ретраит initiation на старый адрес: каждые `RekeyTimeout` (5 с) пишет `Handshake did not complete after 5 seconds, retrying (try N)` и после `MaxTimerHandshakes` (90/5 = 18, переопределяется `max_handshake_attempts`) — `… giving up` ([AWG/device/timers.go#L80](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/timers.go#L80)). Ошибкой наружу это не всплывает.

## 2. Ошибки `IpcSet` и `Up`

### `IpcSet` → `IpcSetOperation`

[AWG/device/uapi.go#L234](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/uapi.go#L234). Тип ошибки — `*device.IPCError` (`Error()`: `"IPC error %d: %v"`, есть `Unwrap()` и `ErrorCode() int64`, [#L24–L43](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/uapi.go#L24-L43)); ловится `errors.As(err, &ipcErr)` с `var ipcErr *device.IPCError`. Коды на Unix ([AWG/ipc/uapi_unix.go#L20](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/ipc/uapi_unix.go#L20)):

| Код | Константа | Когда | Восстановима? |
|---|---|---|---|
| `-22` | `IpcErrorInvalid` (`-EINVAL`) | неизвестный ключ устройства/пира; невалидный hex ключа, число, CIDR; `endpoint` не IP-литерал; `protocol_version != 1`; AWG `mergeWithDevice`: перекрывающиеся диапазоны H1..H4, `S1..S4 < nonce` при `header_protection_key` ([#L824](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/uapi.go#L824)); `NewPeer` (например, >`MaxPeers`) | Нет — ошибка конфигурации |
| `-71` | `IpcErrorProtocol` (`-EPROTO`) | строка без `=` ([#L265](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/uapi.go#L265)) | Нет — ошибка генератора UAPI |
| `-98` | `IpcErrorPortInUse` (`-EADDRINUSE`) | `listen_port` → `BindUpdate()` ([#L316](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/uapi.go#L316)). **Только если device уже Up**: у device в состоянии Down `BindUpdate` закрывает сокеты и выходит без `Open` ([AWG/device/device.go#L525](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/device.go#L525)) | Да, окружение |
| `-5` | `IpcErrorIO` (`-EIO`) | ошибка `bufio.Scanner` (для `strings.Reader` практически недостижима; в т.ч. строка > 64 KiB) | Для `IpcSet(string)` — фактически нет |

Важные свойства:

- **Не атомарно.** Строки применяются по мере чтения; при ошибке всё, что было до неё (private key, созданные пиры, allowed IPs), уже в device. AWG-параметры H/S/HPK копятся в `ipcSetDevice` и сливаются в конце (`mergeWithDevice`) — но пиры к этому моменту уже созданы. Безопасная стратегия после ошибки — `Close()` и новый device (mon-client так и делает).
- Ошибка также логируется через `device.log.Errorf` (defer в `IpcSetOperation`).
- `IpcSet` не делает сетевых операций на Down-device и не ждёт пира.

### `Up` → `changeState(deviceStateUp)`

[AWG/device/device.go#L179](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/device.go#L179), `upLocked` [#L212](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/device.go#L212), `BindUpdate` [#L525](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/device.go#L525).

- Единственный источник ошибки — `BindUpdate`: `closeBindLocked` (закрытие старого bind), `bind.Open(port)` (UDP listen v4/v6; `EADDRINUSE` при фиксированном `ListenPort`, `EMFILE`/`ENOBUFS`, `EACCES` на привилегированном порту…), `startRouteListener` (Linux: netlink route socket для sticky sockets, [AWG/device/sticky_linux.go#L27](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/sticky_linux.go#L27) — может упасть в жёстко ограниченной песочнице), `bind.SetMark` при ненулевом `fwmark` (нужен `CAP_NET_ADMIN`).
- Ошибки «голые» (`*net.OpError`, `syscall.Errno`…), **не** `IPCError`.
- При ошибке `changeState` проваливается в `deviceStateDown` (`downLocked`), так что device остаётся консистентным в Down и `Up()` можно вызвать повторно — ошибки окружения, восстановимые.
- `Up()` на закрытом device возвращает `nil` и ничего не делает («once closed, always closed», [#L184](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/device.go#L184)).
- `Up` не ждёт handshake. Проблемы с пиром после `Up` — только лог: `Failed to send handshake initiation: …` (`Errorf`, [AWG/device/send.go#L179](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/send.go#L179); например, `no known endpoint for peer` из `SendBuffers`, если endpoint не задан — [peer.go#L120](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/device/peer.go#L120)) и `Handshake did not complete …` (`Verbosef`).

## 3. Как резолвят endpoint `wg`/`wg-quick` и `awg`/`awg-quick`

- `wg(8)`: «Endpoint — an endpoint IP or hostname, followed by a colon, and then a port number. This endpoint will be updated automatically to the most recent source IP address and port of correctly authenticated packets from the peer.» ([WGT/src/man/wg.8](https://git.zx2c4.com/wireguard-tools/tree/src/man/wg.8?id=a998407747005ea7e4e0258d96f105c97241e1d3#n165)). Имя принимает **CLI**, а не протокол.
- Резолв — в `parse_endpoint` при разборе конфига/аргументов: `getaddrinfo(host, port, AF_UNSPEC, SOCK_DGRAM)`; перманентные `EAI_NONAME`/`EAI_FAIL`/`EAI_NODATA` — сразу ошибка, остальные — ретраи с backoff 1 с ×1.2 до 20 с, по умолчанию 15 раз (`WG_ENDPOINT_RESOLUTION_RETRIES`, `infinity` — бесконечно); берётся **первый** адрес из результата ([WGT/src/config.c#n177–n280](https://git.zx2c4.com/wireguard-tools/tree/src/config.c?id=a998407747005ea7e4e0258d96f105c97241e1d3#n177)). В amneziawg-tools код тот же ([AWGT/src/config.c#L185–L290](https://github.com/amnezia-vpn/amneziawg-tools/blob/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843/src/config.c#L185)).
- В UAPI (userspace-реализации, в т.ч. amneziawg-go) `wg`/`awg` пишут уже числовой адрес: `getnameinfo(NI_NUMERICHOST)` → `endpoint=%s:%s` ([WGT/src/ipc-uapi.h#n66–n76](https://git.zx2c4.com/wireguard-tools/tree/src/ipc-uapi.h?id=a998407747005ea7e4e0258d96f105c97241e1d3#n66)). То есть «hostname в endpoint» у wg-стека — фича CLI, не device.
- `wg-quick up` → `set_config` → `wg addconf` ([WGT/src/wg-quick/linux.bash#n251](https://git.zx2c4.com/wireguard-tools/tree/src/wg-quick/linux.bash?id=a998407747005ea7e4e0258d96f105c97241e1d3#n251)); `awg-quick up` → `awg setconf` ([AWGT/src/wg-quick/linux.bash#L250](https://github.com/amnezia-vpn/amneziawg-tools/blob/ee0f0a9aa34ff0a0da4b3433b9512781cfe02843/src/wg-quick/linux.bash#L250)). Значит резолв **один раз при старте интерфейса**; ни по handshake, ни по таймеру повторного резолва нет.
- Для динамического DNS upstream предлагает внешний cron-скрипт: `contrib/reresolve-dns/reresolve-dns.sh` — раз в ~30 с перечитывает `.conf` и делает `wg set <if> peer <pk> endpoint <host:port>`, т.е. заново резолвит и заливает IP (README: «Run this script from cron every thirty seconds or so…»). Тот же скрипт лежит в amneziawg-tools.

## 4. Как это ложится на mon-client (origin/main `f436761`)

- `internal/client/config/awg.go`: `validateEndpoint` проверяет только наличие `:port`, hostname пропускает; комментарий «without resolving anything: the device does the resolving when it dials» — **неверен** (см. §1). `endpoint=<как в .conf>` уходит в UAPI дословно; `cfg.Endpoint` — тоже строка из `.conf`.
- `internal/client/awg/device.go` `Open`: `CreateNetTUN` → `NewDevice(tun, conn.NewDefaultBind(), …)` → `IpcSet(cfg.UAPI)` → `Up()`; при любой ошибке — `dev.Close()` и обёртка `awg: apply uapi config: %w` / `awg: bring device up: %w`. Коды `IPCError` не различаются.
- `internal/client/awg/probe.go`: любая ошибка `Open` → `ReasonAWGNoHandshake`. Для hostname-endpoint это систематическая ложная диагностика: каждый цикл «нет handshake», хотя это конфиг.
- `ListenPort` из `.conf` проходит в UAPI (`listen_port`). Т.к. `IpcSet` идёт до `Up`, `EADDRINUSE` проявится не в `IpcSet`, а в `Up()` — например, если два AWG-target'а с одинаковым `ListenPort` пробуются параллельно или порт занят локальным awg.
- Эмпирическая проверка (временный тест, не закоммичен; `golang:1.26-bookworm`): `.conf` с `Endpoint = localhost:51820` → `ParseAWGConf` = `nil`, `Open` = `awg: apply uapi config: IPC error -22: failed to set endpoint localhost:51820: ParseAddr("localhost"): unable to parse IP`, `errors.As(*device.IPCError).ErrorCode() == -22`.

### Выводы для runtime-тикета (рекомендации, не решение)

1. Резолвить имя **в mon-client**, перед `IpcSet`, на каждый probe (device и так пересоздаётся каждый цикл — это автоматически даёт «re-resolve per probe», чего wg-quick не умеет). Резолвер — хостовый (`net.DefaultResolver`), не netstack. Выбор адреса: как `wg` — первый из результата; либо предпочесть семейство, для которого у хоста есть маршрут.
2. Хранить в `AWGConfig` endpoint как `host:port` + отдельно отрисовывать строку `endpoint=` из резолвленного `netip.AddrPort` (UAPI сейчас — готовая строка; её придётся собирать в `Open` или оставлять плейсхолдер). В `Result`/detail полезно отдавать фактически использованный IP.
3. Классификация ошибок: DNS `IsNotFound` → ошибка конфигурации (аналог `EAI_NONAME`); `IsTemporary`/timeout → временная, повтор в следующем цикле; `IPCError` с `-EINVAL`/`-EPROTO` → ошибка конфигурации (не `awg_no_handshake`); ошибка `Up()` → ошибка окружения (сокет), восстановимая. Отсутствие handshake остаётся `awg_no_handshake`, оно определяется по `last_handshake_time_*`, а не по ошибкам `IpcSet`/`Up`.
4. Либо, как минимум, отвергать hostname на `ParseAWGConf` (`netip.ParseAddrPort`), чтобы ошибка стала `configError` на apply, а не ложным `awg_no_handshake` в каждом цикле.
