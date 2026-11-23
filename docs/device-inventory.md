# Authorized device discovery

The console loads `configuration.devices.list` after sign-in and provides an
explicit refresh and next-page action. Clicking a device opens the existing
configuration card without copying an identifier. Manual lookup remains available
when discovery is unavailable. No mutation, policy publication or VPN connection
is triggered by listing or selecting a device.

The action accepts only an optional `after` device identifier. Each page contains
at most 32 devices in bytewise identifier order and an exclusive cursor. There
is no global device count. The ordinary, separate control audience and DPoP
verification remain mandatory. Metadata reads do not require another MFA prompt.
Every returned device must be active and approved, belong to an enabled,
unexpired account and have a live `configuration.drafts.read` device grant for
the actor, using the same explicit/wildcard ACL semantics as the existing card.
Discovery does not grant access to any configuration body or inherited layer.

Only the identifier, desired and issued revision, and bounded activation receipt
metadata are returned. The UI distinguishes an unissued policy, an awaited
receipt, a receipt for the issued policy and a historical receipt. A receipt is
never represented as proof of current online connectivity. Report timestamps
refer to server receipt time. The endpoint omits owners, keys, addresses,
configuration bodies, tokens and provider credentials.

The SQL transaction locks the selected grant, device and account rows and checks
monotonic authority and account/grant expiry after any lock wait. It has a five
second context deadline. The read is audited before commit. Missing audit
authority fails closed. No schema or runtime-role expansion is required.

The browser validates the complete closed page before rendering. Unexpected
members, duplicate/unsorted identifiers, oversized pages, incorrect cursors and
unsafe revisions discard the page. Session expiry, role withdrawal and logout
erase the entire list and current card; errors never retain a stale list.
Device metadata stays in tab memory. The PatternFly table uses a keyboard
accessible scroll region on narrow screens.

The initial discovery implementation passed all eight jobs and 52 browser
scenarios at `74bd3d720fefe920949d18479cc15f3dc0eb0612`,
[Actions 43649508396](https://github.com/nd4y/syn443-control-plane/actions/runs/43649508396).
The exact artifacts were verified and the live console SSO, authorized device
list, card selection and issued settings were checked separately. Private
device receipts remain outside the repository.

The subsequent keyboard correction focuses the selected card after collapsing
discovery. Tab then moves to the card actions. Algorithm metadata is a separate
secondary line, rather than another adjacent status badge. Two required browser
cases verify the real focus order and layout on desktop and narrow screens,
including erasure when another device has no algorithm metadata.

GitHub Actions must run the schema and BFF allowlist checks, actual PostgreSQL
ACL/isolation/pagination/report/audit/expiry-under-lock cases, and four mandatory
Chromium discovery scenarios. Acceptance of the two corrections requires their
exact subsequent build.
This contributes to web administration. Friendly names, user management, native
administrative screens, current online heartbeats and the full M2/M3 milestone
remain separate requirements.

### Issued route order

Open the issued settings in the device card and choose an outbound. For a
fixed chain the numbered list follows connection order from the device through
each configured detour to the selected outbound. Automatic selectors and
balancers list their configured choices. The device supplies live selection
evidence separately. Missing or circular references display an unknown order.
The view reads the existing credential-free policy projection and clears when
the operator changes devices or signs out.

## Срок отчёта в списке устройств

Панель запрашивает `includeReportExpiry: true` в `configuration.devices.list`. Сервер возвращает `reportExpiry: true` и `reportValidUntilMs` только для строк со статусом `reported`. В момент окончания срока выданной политики открытая строка становится архивной и выходит из фильтра проблем применения. Вкладка учитывает время ожидания ответа и проверяет срок при возвращении из фона. Для обновления состояния по новой политике администратор может обновить список.

Старая панель получает прежнюю форму ответа. Если прежняя версия каталога отвергла новый параметр как некорректный запрос (HTTP 400), панель один раз читает тот же список без параметра и указывает момент наблюдения рядом с отчётом. Отказ в доступе завершает просмотр. Отчёт о применении политики сам по себе не подтверждает доступность VPN.

### Проблемы применения по версиям

Разверните сводку в списке устройств. Сервер нумерует выдачи отдельно для каждого устройства. Состав конфигурации конкретной выдачи можно проверить в карточке устройства. Для каждого номера выдачи панель показывает число устройств, число действующих отчётов и сколько из этих отчётов сообщают о частичном применении или откате. Если действующих отчётов нет, результат остаётся неизвестным. Архивные отчёты, ожидание первого отчёта и ответы старого API с неизвестным сроком показаны отдельно.

В сводку входят загруженные страницы, соответствующие поиску, а в режиме избранного - только сохранённые в этой вкладке устройства. Фильтр проблем скрывает строки таблицы устройств, сохраняя полный знаменатель в сводке. Сведения о доступности VPN и причинах отказа конкретного прокси требуют собственных измерений.
