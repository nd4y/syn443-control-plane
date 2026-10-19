# Архитектурная оценка SYN443 и изменения ТЗ

19 октября 2026 года. Проверена версия 0.5, изменения включены в проект ТЗ 0.6. Это оценка проектных требований; новый продукт не реализован, пентест и физические приёмочные испытания не выполнены.

## Общая оценка

Цель обоснована: единый управляемый клиент уменьшает объём ручной поддержки друзей/коллег и решает личные задачи RU/NON_RU/INTERNAL маршрутизации. Сильные части 0.5: автономность телефона, разделение entry/exit, контекстная история сбоев, проверяемые профили health, scopes публикации и чёткий deferred scope.

Главный риск 0.5 - много правильных принципов без однозначных контрактов на границах. Одни только 237 требований не давали воспроизводимый comparator, понятное поведение при Android revoke, атомарную активацию и полный trust/lease контракт. Эту неопределённость нельзя компенсировать более сложным алгоритмом или микросервисами.

## Оценка с четырёх сторон

| Перспектива | Основной вывод | Изменение 0.6 |
| --- | --- | --- |
| Архитектор | Самый рискованный компонент - Android path binding/цепочки/supervisor, его нельзя оставлять после полной панели | Ранний вертикальный gate; фиксированные binary/TUN boundaries, activation generation, общий scheduler и bounded graph |
| Безопасность | Основные границы уже есть, но Wi-Fi trust, anti-replay/lease, signing authority и probe egress были недостаточно определены | SEC-01-12, DPoP/atomic enrollment, signed epoch/envelope, отдельный signer, scoped egress/consent |
| Разработчик | Разные команды могли реализовать разные rank/lifecycle/rollback и формально пройти старые описания | Reference classes/fixtures, transition/lifecycle tables, activation gates, схемы/API и исправленные SLO классы |
| Владелец и пользователи | Успех - доступ к нужным ресурсам без постоянного вмешательства и короткий путь к исправлению | Incident ID, частичная доступность без ложного Online, персональные шаблоны, безопасное mobile publish и migration/update flow |

## Приоритетные замечания и решения

| Приоритет | Проблема 0.5 | Требование 0.6 | Приёмка |
| --- | --- | --- | --- |
| P0 | Неоднозначные stability/energy classes и comparator | ARC-07, ALG, ENG-06: reference tuple/thresholds/aging/ties и одинаковые fixtures | AC66 |
| P0 | Взрыв пространства 500 профилей на 4 hops | ARC-05: templates/cardinality bounds, finite graph/cursor, ошибка превышения до публикации | AC67 |
| P0 | Гонки публикации, secret rotation, mode switch и stale probes | ARC-03/04, PROV-02/04: immutable snapshot/context и commit/rollback automaton | AC68/77 |
| P0 | Native hang может удерживать identity/TUN и заблокировать lifecycle | MOD-08/09: отдельный host, один runtime, supervisor без Go и bounded terminate/restart | AC68/75 |
| P0 | Ложное доверие home Wi-Fi по SSID/BSSID/endpoint | MODE-03/SEC-02/03: endpoint identity не равна доверенному физическому каналу | AC69 |
| P0 | Недостаточный anti-replay/QR atomicity/lease contract | SEC-04/05/06: DPoP, exact key-bound approval, epoch/floor, минимум expiry и anti-clock-extension | AC70/71 |
| P0 | SSRF/сканирование через диагностику и API-test | SEC-08/11: единая scoped egress policy и fleet quotas | AC72 |
| P0 | Недоверенный parser и подписант в одной worker role | SEC-07/SVC-03/08: отдельная signing authority | AC73 |
| P0 | Все checker components могут вместе превысить ресурсный budget | ARC-06: общий admission controller и priority/reserve | AC76 |
| P1 | Внешний offline NAS приводит к apply/rollback loop | ARC-04/PROV-04: intent gate и baseline, degraded activation | AC77 |
| P1 | Неоднозначная классификация CDN/IP literal/encrypted DNS | OWN-04: deterministic rule precedence и отдельный UNKNOWN action | AC78 |
| P1 | Ошибочное обещание всех запросов через 30 секунд в cold search | NFR-02/ENG-07/раздел 24: заранее разные классы сценариев и полный учёт failures | AC43-65 и AC67 |
| P1 | Не закончены force-stop/reboot/update/backup recovery | ENG-01-05: lifecycle table, штатный install, forward recovery | AC75/79 |
| P1 | Детальная telemetry может стать чрезмерным сбором | SEC-09/LOG-02/03: запрет секретов, separate consent и безопасный viewer/grants | AC74 |
| P1 | Нет короткого support workflow и fleet diagnosis | OWN-02/03/05: incident ID, связанные сбои/denominator/stale и пилотное исправление | AC74/77/80 |

## Что необходимо проверить раньше большой разработки

Выход этапа 0 - рабочий вертикальный Android прототип с реальным network binding и доступной цепочкой, а не только макеты панели. Он должен показать failure attribution по ingress/exit/DNS/target, bounded recovery, неизменность identity, применение/откат policy и измеримые resource costs.

Одновременно фиксируются normative schemas, reference fixtures, trust roots/rotation и auth contract. Должны быть испытаны собственный native-host boundary и совместимая сборка Go/proxy/NetBird. Если граница не работает, ADR и ТЗ меняются до масштабирования реализации.

Нормативные thresholds и limits0.6 - стартовый reference profile. Их проверяют на стенде и двух физических устройствах; новое значение выпускается как новая policy, а не задним числом меняет критерий уже выполненного теста.

## Что остаётся в scope и что отложено

Scope 1.0 сохранён: все указанные протоколы/NetBird, одна кнопка, четыре режима, provisioning, mobile administration, source imports, один Remnawave API-ресурс, telemetry и tests. Нельзя объявить 1.0 после одного happy-path demo.

Несколько Remnawave, x-ui/3x-ui, Tailscale/ZeroTier остаются только contracts/namespaces/capabilities. Также не добавлены обязательные Kubernetes, Kafka, отдельная БД на каждый сервис или hot-download binary plugins. Микросервисы оправданы изоляцией API, тяжёлых jobs, ingest и signer, а не числом контейнеров.

## Проверка результата документа

ТЗ 0.6 сохраняет привязку каждого дополнения к требованиям и приёмке. Результат ревью не означает отсутствие будущих багов или прохождение security certification. Осуществимость, расход батареи, длительные handover и recovery доказываются поставляемыми протоколами испытаний.
