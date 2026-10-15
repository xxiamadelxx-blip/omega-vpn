# Ω VPN: P2P, сопротивление блокировкам и проверяемая приватность (R&D)

**Дата:** 2026-10-15. **Статус:** RESTORED RESEARCH / PROPOSAL, **НЕ архитектурное решение и НЕ готовая функция**.
**Происхождение:** восстановленный пользователем текст отчёта Deep Research от 2026-10-14. Настоящий документ является сохранённым инженерным конспектом, проверкой части утверждений и программой исследований, а не побайтовой копией полного отчёта. Исходный полный текст доступен в разговоре, откуда пользователь передал его 2026-10-15. Ссылочные идентификаторы вида `turn17search0` из другого контекста непереносимы: ниже приведены прямые ссылки.

## 0. Зачем и как это связано с текущим продуктом

Текущий Ω VPN уже имеет **проверенный на облачном Android 15 x86_64** Kotlin VpnService/TUN + Xray/VLESS/REALITY и fail-closed HTTPS-пробу с включённым Android Always-on Lockdown ([E2E 38646622262](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38646622262)). **Это не проверка на физическом OnePlus Nord 3 ARM64**, не доказательство DNS/IPv6 packet-level безопасности, а узлы стороннего публичного каталога остаются недоверенными.

Это исследование — **возможное параллельное направление R&D** для снижения зависимости от анонимных коммерческих/публичных серверов. Не удалять и не переписывать работающий Xray-путь до инженерного интервью (Discovery), утверждения концепции и демонстрации отдельного прототипа. Существующие релизные M2→M5 gates остаются открытыми/неизменными.

## 1. Установленные принципы

1. **«Никаких серверов вообще» для выхода к произвольным интернет-сайтам не бывает.** Сеть должна обладать достижимой точкой интернет-выхода (exit). Если прямые P2P-сессии невозможны из-за NAT или политики сети, может потребоваться relay. Само устройство пользователя не обязано покупать VPS, но кто-то обеспечивает egress, полосу, электроэнергию и соединение. [RFC 8445 ICE](https://www.rfc-editor.org/rfc/rfc8445), [RFC 8656 TURN](https://www.rfc-editor.org/rfc/rfc8656).
2. **Анонимность не равна шифрованию.** Зашифрованный hop защищает содержимое на данном сегменте, но не скрывает время, объем, факт контакта с peer/exit. Недоверенный exit видит часть метаданных и может читать/менять незашифрованный HTTP; глобальный наблюдатель может коррелировать ingress/egress. `No logs` без доказательств и обязательств ничего не гарантирует.
3. **Direct-first плюс fallback — реалистично, чистый direct-only — нет.** [Tailscale NAT traversal](https://tailscale.com/blog/how-nat-traversal-works) объясняет необходимость rendezvous/relay. Связь двух телефонов за CGNAT может не пройти напрямую.
4. **Временные добровольные прокси работают, но не создают сами по себе безопасный exit.** Snowflake использует изменяющийся пул WebRTC proxy, брокер и централизованный Tor bridge. Это подтверждённая модель борьбы с блокировкой адресов, но не целиком «P2P VPN без инфраструктуры». [Snowflake, USENIX Security 2024](https://www.usenix.org/conference/usenixsecurity24/presentation/bocovich).
5. **Сменность транспортов — важнее собственного криптопротокола.** [Tor Pluggable Transport Specification](https://spec.torproject.org/pt-spec/) отделяет транспортные преобразования от приложения. [WireGuard Known Limitations](https://www.wireguard.com/known-limitations/) прямо не обещает обфускации, поэтому WireGuard сам по себе не является анти-DPI защитой. **Не писать новую криптографию, TLS/Noise или REALITY самостоятельно.**
6. **Mesh ≠ бесплатный полноценный Интернет.** [Yggdrasil](https://yggdrasil-network.github.io/) и [cjdns](https://github.com/cjdelisle/cjdns) интересны для адресации и оверлейной маршрутизации, но публичный выход всё равно требуется, как и защита от Sybil/eclipse.
7. **РКН/ТСПУ реальны, эффективность фильтров вариативна.** [OONI, 2024-12-09](https://ooni.org/post/2024-russia-report/) подтверждает массовые ограничения в наблюдавшихся сетях, TLS/SNI вмешательство, часть DNS блокировок, признаки распределённого развёртывания ТСПУ с централизованным управлением. Эти наблюдения не доказывают доступ к внутренней конфигурации DPI или точность классификации конкретного нового транспорта в 2026 году.

## 2. Концепт: Ω Horizon (рабочее название, не принято)

| Плоскость | Функция | Где располагается доверие | Открытый инженерный вопрос |
| --- | --- | --- | --- |
| Identity | Ключи устройства/peer, ротация, защита от подмены | Локальное устройство; pinned/verified keys | Получение и отзыв ключей без обязательного аккаунта, защита Sybil |
| Discovery | Познакомить пары peers с помощью сменных signed-bootstrap источников | Directory **не** имеет права выдавать себя за peer | Холодный старт без центра, poisoning/eclipsing, фильтрация |
| NAT path | ICE/STUN-like discovery и direct-first выбор пути | Peer identity не зависит от сети | Сочетания CGNAT/IPv6/NAT64, Android энергопотребление |
| Relay | Перенаправление **сквозь** добровольного peer, без расшифровки inner session | Аутентификация end-to-end вне relay | Доступность, DDoS, квоты/скорость, peer churn |
| Exit | Уполномоченный выход к обычным интернет-сайтам | Exit явно недоверен; пользователь информирован | Злоупотребления, права оператора, стоимость, HTTPS/DNS |
| Data plane | TUN, session management, packet routing, authentication | Хорошо проверенная crypto library | IPv4/IPv6, DNS, MTU, UDP/TCP, state/migration |
| Transport | Native UDP/TCP/WebRTC/другие адаптеры | Ни один transport не влияет на identity/политику DNS | DPI классификация, смена bearer, отсутствие утекающих fallback |
| Policy & UI | Согласие, предпочтения, kill-switch, оценка качества | Локальные решения; opt-in volunteer exits | Отделить индикатор «подключён» от «приватность доказана» |

Данные от Android TUN не должны попадать напрямую в внешнюю сеть при failed authentication/path/relay/exit. OS Always-on + «Блокировать соединения без VPN» остаётся обязательной рекомендованной внешней защитой для сценариев падения приложения. **Приложение не может молча включать Android system Lockdown от имени владельца телефона.**

### Почему «наш собственный протокол» не означает создание новых шифров

**Новизна может находиться в оркестрации**: политики выбора и смены путей, fault containment, многоисточниковом discovery, рейтинге неопределённости и математически проверяемых свойствах fail-closed. Изобретение собственного handshake или криптографии без независимого аудита наоборот снизит безопасность. Комбинации ICE/TURN + volunteer relays + transport adapters по отдельности известны; заявления об абсолютной уникальности **не обоснованы**.

## 3. Независимые архитектурные гипотезы

### H1. P2P-first с честной fallback-моделью (приоритет 1)

**Тезис:** для лабораторной матрицы traversable NAT direct P2P даёт меньший RTT/больший goodput, а добровольный relay сохраняет connectivity для hard NAT.

- Прототип: Linux peer A/B, тестовый volunteer relay R и полностью контролируемый exit E; позже Android TUN.
- Измерить: direct rate по заранее описанным NAT-классам, p50/p95 соединения, fallback success при гарантированно доступном R, энергозатраты Android.
- **FAIL:** direct путь признан «VPN работающим», но маршрутизируемые пакеты проходят напрямую вне ожидаемого encrypted tunnel; отказ relay вызывает clear-net leak.
- **Ограничение:** первый MVP **не** предполагает, что случайные телефоны автоматически становятся exit или что relay обязан бесплатно предоставлять безлимит.

### H2. Независимые bootstrap-источники (приоритет 2)

**Тезис:** клиент продолжит обнаруживать аутентифицированных peers после выключения одного discovery-сервиса без замены доверенных криптографических ключей.

- Прототип: три неидентичных локальных discovery backends, подписанные peer advertisements, модель злонамеренного каталога.
- Метрики: bootstrap success при потере одного источника, доля аутентифицированных маршрутов, rollback/key-revocation handling.
- **FAIL:** поддельное объявление позволяет заменить peer public key, создать произвольный root of trust или выполнить удалённый код.
- **Не обещать:** любая DHT устойчива к Sybil по умолчанию.

### H3. Транспортные адаптеры без изменения безопасности ядра (приоритет 3)

**Тезис:** отказ одного carrier не меняет правила идентификации, DNS/IPv6/egress и не выпускает исходящий трафик напрямую.

- Контракт: `connect(peerIdentity, policy, routeHint) → authenticatedLink`, `health`, `close`; отдельный transport должен предоставлять лишь соединение, не переключая policies.
- Первый adapter: обычный измеряемый UDP/TCP carrier в закрытой сети. Остальные, включая анти-DPI, только после сетевых инвариантов.
- **FAIL:** интерфейс требует передачи endpoint secrets в общую публичную telemetry или автоматически загружает исполняемые бинарные «плагины» с недоверенного directory.
- **Android 15 деталь:** Tor PT spec описывает дочерние процессы; на Android API потребуется собственный безопасный host/binding и проверка ограничений фоновых процессов. Не обещать drop-in поддержку PT subprocess.

### H4. Минимизация знания exit и control plane (приоритет 4)

**Тезис:** разделение identity/discovery/relay/exit может исключить ситуацию, когда один control-plane оператор знает всех peers и сайты посещения.

- Метрики: аудит observable metadata каждого компонента, моделирование злонамеренного exit, traffic-correlation baseline.
- **FAIL:** единственный backend одновременно хранит постоянный идентификатор пользователя, назначения и историю подключения; exit подменяет TLS проверки приложений.
- Ограничение: это не защита от глобального наблюдателя. При требовании сильной анонимности сравнить Tor с многоузловыми маршрутами и mixnets; высокая скорость и глобальная неотслеживаемость конфликтуют.

### H5. Воспроизводимый «анти-DPI» бенчмарк (приоритет 5, НЕ production deployment)

**Тезис:** несколько сменных transport classes повышают процент успешных подключений в собственном искусственном наборе сетевых фильтров относительно одного fixed transport.

- Стенд: netns/nftables/сетевой эмулятор; controlled TLS/HTTP/DNS endpoints, фиксированные policy наборы для UDP block, TCP impairment, packet loss, SNI filtering.
- Метрики: connection survival, false positive rate, PCAP fingerprint separability (ROC-AUC), overhead/latency.
- **FAIL:** бенчмарк объявляет защиту от реального РКН по результату тестов вымышленного классификатора.
- Не использовать чужую сеть, не сканировать DPI и не извлекать служебные/закрытые конфигурации без разрешения.

## 4. Стратегия продукта и безопасность

**Стратегия A: рабочий Ω VPN.** Текущий Android Xray-клиент — существующий проверенный в эмуляторе вертикальный срез. Он требует честного объяснения, что чужие бесплатные VLESS-выходы недоверенны. Завершить ARM64 физический тест, DNS/IPv6/сети, healthcheck и release gate по существующему [MILESTONES.md](../../MILESTONES.md).

**Стратегия B: R&D Ω Horizon.** Отдельная ветка/feature flag, без массового public-exit каталога, без production cloud setup и без переключения пользовательского трафика на экспериментальный маршрут. Переход между стратегиями только после Discovery, лицензий, P0 стенда и явно утверждённых критериев.

**Безопасность по умолчанию:** запрет автоматической роли exit на мобильном устройстве, запрет невидимого peer-to-exit, запрет хранения destination history, защита anti-Sybil bootstrap, verification подписей build/release, отдельный user-consent, неисполнение удалённого кода из каталога, ограничение добровольного relay по трафику и ресурсам, возможность мгновенно выйти из сети.

**Экономика:** волонтёрские exits не гарантируют доступность, unlimited throughput или стабильный международный трафик. Не основывать целевой SLA на бесконечном предложении чужой полосы. В стране мобильного оператора может запрещаться перепродажа/транзит чужого трафика. Юридический анализ — перед public-exit launch.

**Никакой абсолютной приватности.** Для каждого security-claim указывать атакующего, наблюдаемую область, измерение и оставшийся риск. «0 выявленных утечек в N тестах» допустимо. «Утечки невозможны» недопустимо.

## 5. Испытания: теория → воспроизведение → изменение

| Gate | Проверка | Минимальный PASS | При FAIL |
| --- | --- | --- | --- |
| G0 | Requirements & threat-model Discovery | утверждённая пользователем схема доверия, consent, метрики | не писать новый VPN core |
| G1 | Linux namespace P2P TCP+UDP | A↔B успешно, крипто-аутентификация, repeatability | исправить link/session |
| G2 | Матрица NAT/CGNAT | direct в подходящих случаях, relay fallback в blocked direct; 0 direct leaks в тестовых flows | проверить route/policy |
| G3 | Exit consent & security | exit только вручную разрешён тестовым оператором, TLS не перехватывается | запретить exit |
| G4 | Android 15 эмуль TUN | чужой UID HTTPS, route flags, traffic pcap, kill-switch | блок release |
| G5 | DNS/IPv6/MTU/mobility | DNS и IPv6 через предусмотренный маршрут или explicit block; split-brain запрещён | конфиг/маршрутизация |
| G6 | Перестройка путей | peer churn, bootstrap outage, relay interruption; no direct fallback | исправить failover |
| G7 | DPI lab classification | опубликованные синтетические policy, датасеты, ROC/FPR/TPR; сравнение с baseline | не объявлять «невидимость» |
| G8 | ARM64 owned device | Wi‑Fi/mobile handover, 30 min uptime, battery/CPU, тест безопасности | оставить M5 OPEN |
| G9 | Adversarial review | malicious relay/exit, Sybil simulation, license/dependency audit, secret scan | не публиковать |

**Целевые числа R&D** из восстановленного отчёта (`≥75% direct`, `≥99% relay fallback`, `p95 failover <15s`, `0 наблюдаемых утечек`) являются **гипотезами/порогами будущего стенда**, не замерами и не универсальными гарантиями. Обязательно определить sampling и NAT-class population, прежде чем сравнивать проекты.

## 6. 30/60/90 дней: исследовательский трек, не обещанный релиз

- **0–30 дней:** Discovery, юридические/exit границы; зафиксировать threat model, выполнить DNS/IPv6 тесты существующего Xray, спроектировать transport API; добавить isolated namespace peer mock / packet capture. Результат: ADR-кандидат и G0–G1 evidence.
- **31–60 дней:** прототип authenticated peer links + NAT traversal, тестовые STUN/relay в разрешённой облачной/локальной среде, сравнение direct vs relay; прототип пользовательского opt-in exit. Результат: воспроизводимая NAT матрица, G2–G3.
- **61–90 дней:** Android integration behind feature flag, multiple bootstrap candidates, peer churn; классификационный synthetic lab baseline; battery/ARM64 checks, external security review. Результат: доказательства G4–G9, **не автоматическое обещание публичной сети**.

## 7. Пробелы восстановленного Deep Research: НЕ СЧИТАТЬ ИЗУЧЕННЫМ

- **Переписка/«внутреннее общение» РКН:** в тексте нет проверенных публичных внутренних документов, журналов конфигураций ТСПУ или аутентифицированных источников. [OONI](https://ooni.org/post/2024-russia-report/) показывает сетевые измерения и обоснованные выводы, но не секретную переписку. Любое дальнейшее исследование ограничено **законно опубликованными материалами**, а не доступом к закрытым системам.
- **4chan, профильные форумы, GitHub issues:** упомянуты в задании, но восстановленный доклад не содержит проверяемых thread IDs, архивных цитат, дат и выводов по этим площадкам. Нужен отдельный source audit, форумные гипотезы не приравнивать к измерениям.
- **Nym/I2P/GNUnet/Lokinet:** в докладе перечислены или обозначены направления, но нет самостоятельного глубокого Android-интеграционного/лицензионного сравнения.
- **Репутация добровольных exit:** Sybil/routing abuse/noise attacks и юридическая сторона названы, но механизм устойчивого trust onboarding, стоимости и злоупотреблений **не придуман**.
- **Экономика масштабирования, нагрузка, стимулы волонтёров:** математическая ёмкость сети, incentive/griefing, liability insurance и self-hosted exit availability **не измерены**.
- **Реальная производительность и классификация в РФ в октябре 2026:** данных и разрешённых воспроизводимых испытаний из отчёта недостаточно для заявлений о % обхода или «на две головы выше».
- **Юридические выводы:** ссылки на КоАП в оригинальном отчёте требуют отдельной актуальной правовой сверки и юриста; не считать консультацией или установленным статусом конкретного разработчика.

## 8. Проверяемые первичные источники

1. [RFC 8445: ICE](https://www.rfc-editor.org/rfc/rfc8445)
2. [RFC 8656: TURN](https://www.rfc-editor.org/rfc/rfc8656)
3. [Tailscale: How NAT traversal works](https://tailscale.com/blog/how-nat-traversal-works)
4. [Tailscale: Peer Relays](https://tailscale.com/blog/peer-relays-beta)
5. [Tor: Pluggable Transport Specification](https://spec.torproject.org/pt-spec/)
6. [USENIX Security 2024: Snowflake](https://www.usenix.org/conference/usenixsecurity24/presentation/bocovich)
7. [WireGuard: Protocol](https://www.wireguard.com/protocol/)
8. [WireGuard: Known Limitations](https://www.wireguard.com/known-limitations/)
9. [Xray: VLESS](https://xtls.github.io/en/config/inbounds/vless.html)
10. [Xray: REALITY](https://xtls.github.io/en/config/transports/reality.html)
11. [Yggdrasil Network](https://yggdrasil-network.github.io/)
12. [cjdns](https://github.com/cjdelisle/cjdns)
13. [Tor WebTunnel](https://community.torproject.org/relay/setup/webtunnel/)
14. [USENIX Security 2017: Loopix](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/piotrowska)
15. [OONI 2024: internet censorship measurement in Russia](https://ooni.org/post/2024-russia-report/)
16. [AWS: Domain Fronting limitations](https://aws.amazon.com/blogs/networking-and-content-delivery/continually-enhancing-domain-security-on-amazon-cloudfront/)

**Приоритет доказательств:** измеренный собственный packet-level тест > peer-reviewed эксперимент > протокольный RFC/официальная документация > независимое наблюдение OONI > Github discussion > архив анонимного форума > непроверенный слух.

**Решение:** `PENDING_USER_DISCOVERY_APPROVAL`. Документ не изменяет M2/M5 статус существующего Android приложения. Только после явного одобрения концепции можно запускать Gauntlet Loop реализации прототипа.
