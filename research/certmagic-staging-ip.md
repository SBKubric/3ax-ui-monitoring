# certmagic + Let's Encrypt: staging CA, профиль `shortlived`, IP-сертификаты

Research для [#59](https://github.com/SBKubric/3ax-ui-monitoring/issues/59) (карта #49). Дата: 2026-09-23.
Версии: certmagic `v0.25.4` (go.mod), Go 1.26. Исходники certmagic цитируются по тегу `v0.25.4`.

## TL;DR

1. **Переключение на staging** — одно поле: `ACMEIssuer.CA = certmagic.LetsEncryptStagingCA`
   (`https://acme-staging-v02.api.letsencrypt.org/directory`). Staging **совместим** и с `Profile: "shortlived"`,
   и с IP-SAN, и с `tls-alpn-01` для IP: directory staging сейчас анонсирует `classic`/`shortlived`/`tlsserver`,
   IP-сертификаты в staging были раньше, чем в production. В mon-server сейчас CA захардкожен в production —
   нужен bootstrap-параметр (например `tls.acmeCA` / `MON_TLS_ACME_CA`).
2. **Лимиты production для одного IPv4**: 5 сертификатов на точный набор идентификаторов за 7 дней
   (refill 1 / 34 ч) — это жёсткий лимит для «одна коробка = один IP»; 50 / 7 дней на «registered domain» (для IPv4 —
   сам адрес, для IPv6 — /64), 5 authz-failures на идентификатор на аккаунт в час (refill 1 / 12 мин),
   300 заказов на аккаунт / 3 ч, 10 аккаунтов с одного IP / 3 ч. Продления через ARI от лимитов освобождены.
3. **Цепочка staging** выпущена от недоверенных корней `(STAGING) …`. mon-client флага CA сейчас **не имеет**
   (только `--server`, `--state-dir`, `--xray-bin`, `--log-level`), но все три его HTTP-пути (api, xray-проба, AWG-проба)
   используют системный пул Go, поэтому на стенде хватает `SSL_CERT_FILE`/`SSL_CERT_DIR` или
   `update-ca-certificates` в контейнере. Отдельный `MON_CA_FILE` не обязателен; если его вводить — только как
   удобство для стенда.

## 1. CA endpoint в certmagic и совместимость staging

### Как задаётся CA

- `ACMEIssuer.CA` — «The endpoint of the directory for the ACME CA we are to use»; `ACMEIssuer.TestCA` — endpoint для
  «тестовой» валидации, сертификаты с него отбрасываются
  ([acmeissuer.go L44–54](https://github.com/caddyserver/certmagic/blob/v0.25.4/acmeissuer.go#L44-L54)).
- Константы: `LetsEncryptStagingCA = "https://acme-staging-v02.api.letsencrypt.org/directory"`,
  `LetsEncryptProductionCA = "https://acme-v02.api.letsencrypt.org/directory"`
  ([acmeissuer.go L662–664](https://github.com/caddyserver/certmagic/blob/v0.25.4/acmeissuer.go#L662-L664)).
- `NewACMEIssuer`: если `TestCA == ""` **и** `CA == DefaultACME.CA` (production LE), то `TestCA` подставляется
  staging; если `CA` не production — `TestCA` остаётся пустым
  ([acmeissuer.go L190–200](https://github.com/caddyserver/certmagic/blob/v0.25.4/acmeissuer.go#L190-L200)).

### Неочевидное поведение текущего кода (production + неявный TestCA)

mon-server сейчас задаёт `CA: certmagic.LetsEncryptProductionCA` и не задаёт `TestCA`
(`internal/tlsx/tlsx.go`, `acmeSetup`) — значит, `TestCA` = staging автоматически. В certmagic:

- `doIssue`: `useTestCA := attempts > 0` — **первая** попытка идёт в production, все **повторные** — сначала в staging
  ([acmeissuer.go L447–460](https://github.com/caddyserver/certmagic/blob/v0.25.4/acmeissuer.go#L447-L460)).
- `Issue`: если повтор успешно прошёл на staging, сразу делается ещё одна попытка на production; при не-429 ошибке
  production ретраи прекращаются (`ErrNoRetry`), при 429 — продолжаются с backoff
  ([acmeissuer.go L391–441](https://github.com/caddyserver/certmagic/blob/v0.25.4/acmeissuer.go#L391-L441)).
- Сертификаты со staging в этом режиме **не сохраняются** (комментарий к `TestCA`).

Итог: ошибки валидации на повторах «сжигают» щедрые лимиты staging, а не production — это как раз защищает
production-лимиты при закрытом :443 или неверном `publicIp`. Менять не нужно, но это стоит знать при чтении логов
(`ca=https://acme-staging-v02…` на ретраях в production-режиме — норма).

Расписание ретраев `ManageAsync`: 1, 2, 2, 5, 10… мин, затем до 6 ч между попытками, максимум 30 дней
([async.go L167–200](https://github.com/caddyserver/certmagic/blob/v0.25.4/async.go#L167-L200)).

### Если CA = staging

- `TestCA` пустой → все попытки идут в staging, сертификат staging **сохраняется и отдаётся** листенером.
- `Profile` просто передаётся в заказ: `params.Profile = am.Profile`
  ([acmeissuer.go L473](https://github.com/caddyserver/certmagic/blob/v0.25.4/acmeissuer.go#L473)); certmagic
  не проверяет его против directory — проверяет сервер.
- `PreCheck` разрешает IP-сертификаты для CA, URL которых содержит `api.letsencrypt.org` — подстрока совпадает и
  с `acme-staging-v02.api.letsencrypt.org`
  ([acmeissuer.go L348–370](https://github.com/caddyserver/certmagic/blob/v0.25.4/acmeissuer.go#L348-L370)).
  Приватные/loopback IP отбрасываются `SubjectQualifiesForPublicCert`
  ([certificates.go L579–600](https://github.com/caddyserver/certmagic/blob/v0.25.4/certificates.go#L579-L600)) —
  на стенде нужен настоящий публичный IP в обоих режимах.
- `tls-alpn-01` для IP: certmagic хранит челлендж под reverse-DNS именем (`…in-addr.arpa`), которое валидатор
  шлёт в SNI по RFC 8738 ([solvers.go L853–863](https://github.com/caddyserver/certmagic/blob/v0.25.4/solvers.go#L853-L863)).
  От CA не зависит.
- Хранилище не конфликтует: ключ issuer'а строится из host+path directory URL
  ([acmeissuer.go L304–320](https://github.com/caddyserver/certmagic/blob/v0.25.4/acmeissuer.go#L304-L320)),
  так что staging и production сертификаты/аккаунты лежат в разных подкаталогах `dataDir/certs`. Переключение
  staging→production не требует чистки storage (но production-сертификат будет получен заново).
- ACME-аккаунты у LE отдельные для каждой среды
  ([staging-environment](https://letsencrypt.org/docs/staging-environment/): «ACME accounts are scoped to each
  environment») — certmagic создаёт аккаунт сам.

### Что говорит Let's Encrypt

- Живые directory (запрошено 2026-09-23) — и staging, и production анонсируют
  `meta.profiles = {classic, shortlived, tlsserver}`:
  `curl https://acme-staging-v02.api.letsencrypt.org/directory`.
- [Profiles](https://letsencrypt.org/docs/profiles/): `shortlived` — «Validity Period 160 hours», «Identifier Types
  DNS, IP»; `classic` и `tlsserver` — только DNS. То есть IP возможен **только** с `shortlived`.
- [6-day and IP Address Certificates are Generally Available (2026-01-15)](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability):
  «IP address certificates must be short-lived certificates».
- [We've Issued Our First IP Address Certificate (2025-07-01)](https://letsencrypt.org/2025/07/01/issuing-our-first-ip-address-certificate):
  «only the http-01 and tls-alpn-01 methods can be used» для IP; «IP address certificates are available right
  now in Staging».
- [Challenge types](https://letsencrypt.org/docs/challenge-types/): DNS-01 «cannot be used to validate IP Addresses».

### Что поменять в mon-server (для тикета про TLS)

`config.TLSConfig` сейчас `{Mode, Cert, Key}`, env `MON_TLS_MODE/CERT/KEY`; CA захардкожен. Минимально:
поле `tls.acmeCA` (`MON_TLS_ACME_CA`), default `certmagic.LetsEncryptProductionCA`, прокинутое в
`ACMEIssuer.CA`. Профиль, `DisableHTTPChallenge`, `RenewalWindowRatio`, storage менять не нужно. Опционально —
флаг-алиас `staging` → `LetsEncryptStagingCA`. Admin UI (§9.4 «TLS & admin») стоит показывать текущий CA,
чтобы staging-стенд было видно.

## 2. Лимиты production LE для IP-сертификатов

Источник: [Rate Limits](https://letsencrypt.org/docs/rate-limits/). Для IP: «For IPv4 addresses, we treat the
exact address as the registered domain. For IPv6 addresses, we treat the containing /64 range».

| Лимит | Значение | Refill | Что значит для mon-server (1 IP, 1 аккаунт) |
|---|---|---|---|
| New Certificates per Exact Set of Identifiers | 5 / 7 дней | 1 / 34 ч | **Главный.** 5 новых выпусков на `{publicIp}`, потом ≈1 в 34 ч. Потеря `dataDir/certs` (пересоздание контейнера без volume) несколько раз подряд = блок |
| New Certificates per Registered Domain (IPv4 = адрес, IPv6 = /64) | 50 / 7 дней | 1 / 202 мин | Глобальный, считаются все аккаунты; неактуален при одном клиенте |
| Authorization Failures per Identifier per Account | 5 / час | 1 / 12 мин | Закрытый :443, NAT, неверный `publicIp` → после 5 провалов пауза. В production-режиме certmagic ретраит через staging (см. §1), что смягчает |
| Consecutive Authorization Failures per Identifier per Account | 1152 | 1 / день | При ретраях certmagic (до 6 ч между попытками, 30 дней) недостижим |
| New Orders per Account | 300 / 3 ч | 1 / 36 с | Неактуален |
| New Registrations per IP Address | 10 / 3 ч | 1 / 18 мин | Каждый чистый `dataDir` = новый аккаунт |

Продления: «Renewals coordinated by ARI offer the unique benefit of being exempt from all rate limits»
([rate-limits](https://letsencrypt.org/docs/rate-limits/)). certmagic использует ARI по умолчанию (`DisableARI`
false; `Replaces` проставляется для не-test CA —
[acmeissuer.go L475–489](https://github.com/caddyserver/certmagic/blob/v0.25.4/acmeissuer.go#L475-L489)), так что
продления каждые ~80 ч лимиты не расходуют. Расходуют только **первичные** выпуски — т.е. потеря storage.
Вывод: `dataDir` обязан быть persistent volume; для отладки стенда — staging.

Лимиты staging ([staging-environment](https://letsencrypt.org/docs/staging-environment/)): 50 регистраций с IP / 3 ч,
1500 заказов / 3 ч, 30000 на точный набор идентификаторов в неделю, 200 authz-failures / час,
3600 consecutive / 6 ч — практически не ограничивает стенд.

## 3. Цепочка staging и доверие mon-client

### Цепочка

[Staging environment](https://letsencrypt.org/docs/staging-environment/): иерархия зеркалит production, имена с
префиксом `(STAGING)`. Корни «not present in browser/client trust stores»: `(STAGING) Pretend Pear X1` (RSA),
`(STAGING) Bogus Broccoli X2` (ECDSA), `(STAGING) Yearning Yucca Root YE`, `(STAGING) Yonder Yam Root YR`.
PEM: `https://letsencrypt.org/certs/staging/letsencrypt-stg-root-x1.pem`, `…/letsencrypt-stg-root-x2.pem`,
`…/gen-y/root-ye.pem`, `…/gen-y/root-yr.pem`. LE прямо предупреждает: добавлять только в тестовый trust store.
Какой корень окажется наверху цепочки shortlived-сертификата — зависит от текущих intermediates, поэтому
надёжнее доверять **всем четырём** (один bundle-файл).

### Текущий mon-client

- `cmd/mon-client/cli.go`: флаги `--server` (`MON_SERVER_URL`), `--state-dir`, `--xray-bin`, `--log-level`.
  Ни CA-флага, ни `MON_CA_FILE` нет; `hooks.HTTP` — только тестовый шов (комментарий: «without either a real
  mon-server or any CA-file flag»).
- Спека: «mon-client доверяет системным CA; пиннинга нет» (`docs/spec/mon-client.md`, `docs/spec/mon-server.md` §2.1).
- Все пути к mon-server идут через системный пул: api — `&http.Client{Transport: noProxyTransport()}`
  (`internal/client/api/client.go`), xray-проба — `TLSClientConfig: p.TLSConfig` (nil в production,
  `internal/client/probe/xray.go`), AWG-проба — `tlsConfig` (nil в production, `internal/client/awg/probe.go`).
  Важно: xray/AWG-пробы тоже делают TLS к mon-server (через туннель), так что при недоверенном сертификате
  упадут **и регистрация, и все пробы** (`tls`-ошибка → на панели ложные DOWN).

### Как доверять staging-серверу на стенде без изменений кода

Go на Linux читает системные корни так
([crypto/x509/root_unix.go](https://github.com/golang/go/blob/release-branch.go1.26/src/crypto/x509/root_unix.go),
[root_linux.go](https://github.com/golang/go/blob/release-branch.go1.26/src/crypto/x509/root_linux.go)):
`SSL_CERT_FILE` заменяет список bundle-файлов (читается первый существующий), `SSL_CERT_DIR` заменяет список
каталогов; каталоги по умолчанию (`/etc/ssl/certs`, `/etc/pki/tls/certs`) читаются **всегда**, если
`SSL_CERT_DIR` не задан.

Варианты (образ `Dockerfile.mon-client` — `debian:bookworm-slim` + `ca-certificates`):

1. `-e SSL_CERT_FILE=/etc/mon-client/le-staging-roots.pem -v ./le-staging-roots.pem:/etc/mon-client/le-staging-roots.pem:ro`
   — пул = staging-корни + всё из `/etc/ssl/certs` (Debian кладёт туда и отдельные PEM, и bundle), т.е. системные
   CA не теряются. Нулевые изменения кода.
2. Смонтировать PEM в `/usr/local/share/ca-certificates/*.crt` и выполнить `update-ca-certificates` на старте.
3. Ввести `--ca-file` / `MON_CA_FILE` (append к `x509.SystemCertPool()` и прокинуть в api, xray- и AWG-пробы) —
   явнее, но это новое поведение вне спеки; оправдано, только если стенд на staging станет штатным.

Рекомендация: для стенда — вариант 1 (документировать в `docs/runbooks/mon-client-stand.md`); `MON_CA_FILE` не
вводить, пока спека говорит «системные CA».

## Источники

- certmagic v0.25.4: [acmeissuer.go](https://github.com/caddyserver/certmagic/blob/v0.25.4/acmeissuer.go),
  [acmeclient.go](https://github.com/caddyserver/certmagic/blob/v0.25.4/acmeclient.go),
  [async.go](https://github.com/caddyserver/certmagic/blob/v0.25.4/async.go),
  [certificates.go](https://github.com/caddyserver/certmagic/blob/v0.25.4/certificates.go),
  [solvers.go](https://github.com/caddyserver/certmagic/blob/v0.25.4/solvers.go)
- Let's Encrypt: [Profiles](https://letsencrypt.org/docs/profiles/),
  [Rate Limits](https://letsencrypt.org/docs/rate-limits/),
  [Staging Environment](https://letsencrypt.org/docs/staging-environment/),
  [Challenge Types](https://letsencrypt.org/docs/challenge-types/),
  [IP certs GA 2026-01-15](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability),
  [First IP cert 2025-07-01](https://letsencrypt.org/2025/07/01/issuing-our-first-ip-address-certificate)
- ACME directory: `https://acme-staging-v02.api.letsencrypt.org/directory`,
  `https://acme-v02.api.letsencrypt.org/directory` (запрошены 2026-09-23)
- Go: [crypto/x509/root_unix.go](https://github.com/golang/go/blob/release-branch.go1.26/src/crypto/x509/root_unix.go)
- Код репо (origin/main `f436761`): `internal/tlsx/tlsx.go`, `internal/config/config.go`,
  `cmd/mon-client/cli.go`, `internal/client/{api/client.go,probe/xray.go,awg/probe.go}`
