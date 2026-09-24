# 3AX-UI monitoring

Мониторинг inbound'ов панели 3AX-UI: один mon-server и коробки mon-client в целевых регионах, которые проверяют, что каждый inbound real server работает для реальных клиентов через proxy front и напрямую. Термины real server, proxy front, host override и tunnel subscription определены в [CONTEXT.md репо панели](https://github.com/SBKubric/3ax-ui-proxy/blob/main/CONTEXT.md) и здесь повторены для чтения без переключения.

## Language

**Real server**:
Сервер с панелью, inbound'ами, клиентами и историей трафика; его адрес никогда не попадает в клиентские конфиги.
_Avoid_: upstream, hidden server, panel box

**Proxy front**:
Одноразовый сервер, который клиенты видят вместо real server; при блокировке выбрасывается и заменяется.
_Avoid_: proxy box, relay server, relay панель, front

**Host override**:
Глобальная настройка панели, подменяющая адрес real server на адрес proxy front во всех выдаваемых конфигах и ссылках подписки.
_Avoid_: proxy override, address substitution

**Tunnel subscription**:
Публичный маршрут подписки панели, отдающий по subId клиентские конфиги AmneziaWG и WireGuard той же подписки; дополняет xray-подписку, не меняя её.
_Avoid_: AWG subscription, conf feed, tunnel feed

**mon-server**:
Единственный внешний сервис мониторинга на отдельном сервере: ведёт реестр mon-clients, получает у real server конфиги probe accounts и текущий host override, раздаёт mon-clients их targets, считает состояние каждого target и сообщает real server переходы и статистику.
_Avoid_: monitoring hub, collector, watchdog server

**mon-client**:
Коробка в целевом регионе, которой mon-server назначает набор targets; для каждого поднимает туннель (xray-core, awg) и раз в минуту шлёт mon-server tunnel probe через туннель и heartbeat мимо него.
_Avoid_: agent, probe node, sensor

**Target**:
Пара «inbound real server × path», которую проверяет один mon-client через probe account этого inbound'а. Единица состояния UP/DOWN и статистики.
_Avoid_: check, monitor, endpoint

**Path**:
Через какой адрес target достигает real server: `proxy` (адрес proxy front из host override) или `direct` (настоящий адрес real server).
_Avoid_: mode, route

**Probe account**:
Служебный клиент с именем `probe-…`, который панель заводит по запросу mon-server; все probe accounts панели живут под общим subId. В клиентском xray-inbound'е — один на inbound, общий для всех mon-clients и path. В туннельном сервере (AWG) — отдельный пир на каждую пару «mon-client × path», потому что у пира один endpoint и одна сессия и общий пир делят конкурирующие пробы. Отличается от пользовательских префиксом имени, не считается пользователем и чистится панелью по таймауту, когда mon-server перестаёт его подтверждать.
_Avoid_: monitoring client, service user, test client

**Tunnel probe**:
Ежеминутный запрос mon-client к mon-server, отправленный внутрь туннеля target'а; его успех означает, что inbound работает для реальных клиентов по этому path.
_Avoid_: ping, healthcheck

**Heartbeat**:
Ежеминутный запрос mon-client к mon-server мимо туннеля; несёт результаты tunnel probes и диагностику, а в ответ получает номер актуальной ревизии конфига. Отсутствие heartbeat означает, что мёртв сам mon-client, а не туннель.
_Avoid_: keepalive, ping

**Stale**:
Состояние target в панели, когда mon-server не присылал статистику дольше порога; отличается от DOWN тем, что молчит мониторинг, а не inbound.
_Avoid_: unknown, expired

**Registration request**:
Заявка mon-client на вход в реестр mon-server: подаётся без секрета, живёт пять минут в состоянии pending и превращается в запись реестра только после одобрения администратором в админке mon-server.
_Avoid_: enrollment, join request, handshake

**Pairing code**:
Короткий код, который mon-client печатает в свой лог и прикладывает к registration request; администратор сверяет его в админке, чтобы одобрить именно свою коробку.
_Avoid_: PIN, OTP, verification token

**Client token**:
Постоянный секрет mon-client, выданный mon-server при одобрении registration request; им подписаны heartbeat, tunnel probe и запрос конфига. Отзыв токена выкидывает mon-client из реестра до новой заявки.
_Avoid_: API key, bearer, credential

**Config revision**:
Хэш конфига, который mon-server собрал для конкретного mon-client (его targets, paths и параметры проб); возвращается в ответе на heartbeat, и его смена — единственный сигнал mon-client перечитать конфиг.
_Avoid_: version, generation, panel revision

**Unverified cycle**:
Цикл проб mon-client, за который heartbeat так и не был подтверждён mon-server; его провалы не считаются, потому что адресат tunnel probe — сам mon-server, и его недоступность нельзя отличить от падения туннеля.
_Avoid_: offline cycle, buffered cycle

**Admin UI**:
Веб-интерфейс mon-server за логином и паролем: одобрение registration requests, реестр mon-clients и все настройки mon-server; состояние targets он не показывает — это страница Monitoring панели.
_Avoid_: dashboard, console, mon-server panel
