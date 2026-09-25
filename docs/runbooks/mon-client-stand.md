# Ручная проверка mon-client на стенде

Чеклист для issue [SBKubric/3ax-ui-monitoring#23](https://github.com/SBKubric/3ax-ui-monitoring/issues/23):
запустить mon-client из `Dockerfile.mon-client` рядом с настоящим mon-server (эпик
[#1](https://github.com/SBKubric/3ax-ui-monitoring/issues/1)) и панелью
(эпик [SBKubric/3ax-ui-proxy#43](https://github.com/SBKubric/3ax-ui-proxy/issues/43)) и вручную
пройти сценарии из карты. Термины — [CONTEXT.md](../../CONTEXT.md); спека —
[mon-client.md](../spec/mon-client.md), протокол — [mon-protocol.md](../spec/mon-protocol.md).

Автоматическая часть этого уже покрыта: `make e2e` поднимает рядом с mon-server настоящий
mon-client-контейнер и прогоняет `e2e/tests/mon-client.spec.ts` — регистрация, одобрение через
админку, переход в ONLINE. Чеклист ниже — про то, что e2e не видит: реальную панель, xray- и
AWG-targets, перезапуски и стенд целиком.

Это не автотест: колонка «Результат» заполняется на стенде и итог переносится в комментарий к
issue #23. Расхождения со спекой — не правятся здесь, а заводятся отдельными тикетами эпика
#2 (см. итоговый раздел).

## Перед началом

Нужен работающий стенд:

- **mon-server** (эпик #1), доступный по `https://<ip>:443`, с админкой и одним админом
  (`mon-server admin set …`).
- **Панель** (эпик proxy#43) с настроенным **Real server**/`monToken` в mon-server (README
  §"4. Run") и хотя бы одним xray-inbound'ом (Reality) и одним AWG-сервером, у которых заведены
  probe accounts на оба path (`proxy`, `direct`). На панели с цепочкой вместо `proxy` — path
  каждого пробируемого звена (`edge:<name>`, `inner:<name>`, [mon-server.md](../spec/mon-server.md)
  §5.1): «оба path» ниже читать как «каждый path», а в логе — `probe xray:<inboundId>:edge:<name> ok …`.
- Собранный образ mon-client:

  ```sh
  make docker-client   # docker build -f Dockerfile.mon-client -t mon-client:dev .
  ```

## Чеклист

| № | Шаг | Команда / действие | Ожидаемо | Результат |
|---|---|---|---|---|
| 1 | Запуск контейнера | `docker run -d --name mon-client -v mon-client-state:/var/lib/mon-client -e MON_SERVER_URL=https://<mon-server-ip>:443 mon-client:dev` | контейнер стартует и остаётся `Up`; никаких `--cap-add`, `--privileged`, `--device=/dev/net/tun` или нестандартного `--network` не требуется (research §4, §7) | |
| 2 | Pairing code в логе | `docker logs mon-client` | строка `registration request sent, pairing code XXXXXX` (`[A-Z2-9]{6}`, спека §3, §7) | |
| 3 | Одобрение в админке | mon-server admin UI → **Requests**, найти заявку по коду из шага 2, одобрить | заявка переходит в реестр **mon-clients**; в логе контейнера — `registered as <monClientId>` | |
| 4 | Применение конфига | `docker logs -f mon-client` | строка о применении ревизии (`applied revision …`) вскоре после одобрения — конфиг с targets получен и `xray.json`/AWG UAPI применены | |
| 5 | Проба xray, оба path | `docker logs -f mon-client` | `probe xray:<inboundId>:proxy ok tls=…ms ttfb=…ms` и `probe xray:<inboundId>:direct ok …` — раз в минуту | |
| 6 | Проба AWG, оба path | `docker logs -f mon-client` | `probe awg:<inboundId>:proxy ok handshake=…ms …` и `…:direct ok …` | |
| 7 | Heartbeat подтверждён | `docker logs -f mon-client` | `ack <seq>` после каждого цикла, без `buffered N cycles` | |
| 8 | UP в панели, оба path | панель → Monitoring | оба target'а (xray и AWG) в состоянии **UP** по обоим path | |
| 9 | DOWN при остановке inbound'а | остановить inbound на real server (панель) | mon-client: `probe … FAIL tcp_refused …` (или `tcp_timeout`) несколько циклов подряд; панель: target переходит в **DOWN** после порога пропусков (default 3, спека §5) | |
| 10 | `reality_real_cert` при подмене SNI-сайта | подменить сайт-приманку Reality-inbound'а (`dest`/сертификат SNI на стороне real server) так, чтобы xray отдавал настоящий сертификат вместо Reality-ответа | mon-client: `probe xray:<id>:<path> FAIL reality_real_cert …`, `detail` со строкой `REALITY: received real certificate`; панель: target — **DOWN**/ошибка reality на этом path | |
| 11 | `awg_no_handshake` при неверном ключе | подменить приватный/публичный ключ в AWG probe account (панель выдаёт новый `.conf` с неверным ключом или испорчен вручную на стороне AWG-сервера) | mon-client: `probe awg:<id>:<path> FAIL awg_no_handshake …` (handshake не устанавливается); панель: target — **DOWN** | |
| 12 | Буфер и досылка при остановке mon-server | остановить контейнер/процесс mon-server на 2–3 минуты, затем снова запустить | пока mon-server лежит: mon-client продолжает пробы, лог показывает `buffered N cycles` вместо `ack`; после возврата mon-server: следующий heartbeat уходит со всеми накопленными циклами (`unverified: true`), лог — `ack <seq>` с ackSeq, покрывающим и старые, и новые seq; циклы за время простоя mon-server не считаются провалом (unverified cycle, CONTEXT.md) | |
| 13 | `401` после Revoke | в админке mon-server отозвать (Revoke) этот mon-client | mon-client: следующий heartbeat/запрос получает `401`, лог показывает ошибку токена, `state.json` стирается, дальше — новая заявка с новым pairing code (шаг 2 повторяется); `docker exec mon-client ls /var/lib/mon-client` — старого `state.json` больше нет | |

## Что смотреть при каждом шаге

- **На стороне mon-client**: `docker logs -f mon-client` (человекочитаемый лог, спека §7); при
  необходимости — `--log-level debug` (пересобрать контейнер с `-e` или добавить флаг в
  `docker run`, если понадобится stderr xray целиком).
- **На стороне панели**: страница **Monitoring** — состояние target'ов (UP/DOWN/stale) по path;
  админка mon-server — вкладки **Requests** и **mon-clients**.
- Состояние на диске (для отладки, не часть штатной проверки):
  `docker exec mon-client ls -la /var/lib/mon-client` — `state.json`, `cycles.json`, `xray.json`.

## Расхождения → отдельными тикетами эпика #2

Если фактическое поведение стенда расходится со спекой или с этим чеклистом — здесь оно не
правится. Каждое расхождение заводится отдельным тикетом в эпике
[SBKubric/3ax-ui-monitoring#2](https://github.com/SBKubric/3ax-ui-monitoring/issues/2) со ссылкой
на этот прогон и на соответствующий пункт таблицы; итог самого прогона (пройденные/непройденные
пункты) — в комментарии к issue #23.
