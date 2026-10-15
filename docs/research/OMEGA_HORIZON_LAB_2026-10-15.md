# Ω Horizon: контролируемая проверка прямого пути и relay

**Дата:** 2026-10-15. **Ветка:** research/omega-horizon-p2p-lab. **Статус:** TLS loopback 9/9 PASS, Linux NAT/UDP fallback E2E PASS; G1/G2 PARTIAL, NAT hole punching непредсказуем.

## Цель

Фальсифицируемая H1/H3-гипотеза: одна и та же сессия с взаимной аутентификацией TLS 1.3 может пройти непосредственно между двумя peers или через relay, который не владеет ключами сессии. Сбой прямого соединения не должен выключать TLS. Подмена peer, повреждение TLS и отказ обоих путей не должны возвращать передачу через незашифрованное соединение.

**Это НЕ** Android VPN, ICE/STUN/NAT traversal, выход в публичный Интернет, тест РКН или защита от глобального traffic correlation. Сокеты работают только на 127.0.0.1; внешний IP намеренно запрещён.

## Матрица

| Проверка | Критерий |
| --- | --- |
| Direct | TLS 1.3, peer CN подтверждён, синтетический ACK соответствует nonce |
| Relay fallback | При отказе прямого сокета работает тот же TLS 1.3 через relay |
| Blind relay | Relay пересылает TLS ciphertext; nonce не обнаружен в наблюдаемом лабораторном sample |
| Reuse | Два последовательных клиентских сеанса через relay |
| No path | Нет direct и relay: исключение, нет прямого fallback |
| Malicious directory | Неверная идентичность сертификата: отказ и отсутствие повтора через relay |
| Tamper | Изменение TLS handshake внутри relay отвергается |
| Client auth | Peer не принимает синтетический payload без клиентского сертификата |
| Safety | Нельзя задать нелокальный IP/некорректный порт |

## Воспроизведение

Python >= 3.11, OpenSSL CLI. Эфемерные тестовые сертификаты генерируются во временной папке, не коммитятся и не применяются на Android.

    python3 -m unittest discover -s research/horizon/tests -v

**Фактический локальный результат:** 9/9 PASS; три последовательных прогона PASS на Python 3.13.5, OpenSSL 3.5.5. **GitHub Actions [#38717504898](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38717504898): SUCCESS**, шаг `Controlled loopback TLS P2P and relay tests` = PASS; независимая Vercel Sandbox проверка точного коммита: **9/9 PASS**. Это отдельный лабораторный CI, а не Android E2E.

## Threat model и пределы результата

Одноразовый CA лаборатории не обеспечивает устойчивость к компрометации authority: злоумышленник с ключом CA способен выпустить другое имя. Production потребует pinned peer identity, журнал отзыва/ротации ключей и распределённый bootstrap с защитой от Sybil/eclipse. Relay может видеть адреса, тайминг и объём. Наблюдение о ciphertext не доказывает приватность трафика на уровне IP/DNS/IPv6.

**Следующий gate:** воспроизводимая матрица endpoint-independent / endpoint-dependent / CGNAT, UDP с подтверждением identity поверх стандартной криптобиблиотеки, затем Android feature-flag за закрытым тестовым peer без включения exit на реальных устройствах.

**G0 Discovery/релиз:** не пройден. Эта экспериментальная ветка не меняет существующий Android Xray и не закрывает M2/M5.


## Контрольные сетевые испытания G2: Linux namespaces, NAT, UDP (2026-10-15)

Файл [`research/horizon/netns_lab.py`](../../research/horizon/netns_lab.py). Шесть сетевых пространств имён: client, NAT клиента, peer, NAT peer, relay и WAN-маршрутизатор. Частная сеть `10.53.0.0/16`; наружного выхода из test WAN нет, host firewall не меняется. Требуется изолированный runner с `sudo`, `iproute2` и `iptables`.

Команды:
```bash
python3 research/horizon/netns_lab.py --self-test
sudo -E python3 research/horizon/netns_lab.py --orchestrate
```

**[CI #38720473502](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38720473502) SUCCESS:** 9/9 TLS-loopback, 3/3 integrity unit, privileged six-namespace UDP suite PASS. Сетевой сценарий проверяет: unmapped NAT → relay, direct при явном port forward, искусственную блокировку direct → relay, гибель relay + недоступный direct → `NO_PATH`, restart relay, отклонение повреждённого HMAC ответа → `AUTH_FAIL` без доверия relay к peer key, и восстановление подключения. Моделируемый отказ `NO_PATH` проверяет **только поведение пробного клиента**, не весь трафик ОС.

**Новый отрицательный результат важнее демонстрационного успеха:** в отдельной серии из шести свежих сетевых стендов на Vercel Sandbox попытка rendezvous + reciprocal UDP hole punching **0/6** достигла прямого authenticated probe; relay fallback оставался доступным **6/6**. В другом отдельном прогоне hole punching **один раз прошёл**, но его воспроизводимость не установлена. В PCAP одного неудачного случая peer направлял rendezvous-трафик с NAT source port `39001`, а затем к другому endpoint через NAT source port `44723`, поэтому выданный адрес/порт не был пригоден. Это **не доказательство причины каждого отказа**: могут влиять также фильтрация и гонки таймингов. В коде `hole_punch_status = DIRECT_PATH_NOT_CONFIRMED` явно запрещает приравнивать отсутствие прямого пути к PASS.

Номинальное RTT готового relay-пакета в Linux миллисекундное, но **конечное время подключения через fallback около 951,5 мс** с учётом 950-мс таймаута прямого пути. Это измерение локальной лаборатории без сетевой задержки Интернета, не прогноз для операторов РФ.

**Границы доказательства:** UDP payload в этом тесте синтетический, HMAC-SHA256 обеспечивает обнаружение подмены тестового ответа, но **не шифрует содержимое**. TLS 1.3 проверялся **отдельно на loopback** и не был соединён с этим UDP транспортом. Отсутствуют ICE/STUN/TURN production, сертифицированная peer identity, мобильный CGNAT, Android TUN, DNS/IPv6, внешний Интернет, добровольные exit и проверка блокировок РКН. Этот эксперимент не доказывает анонимность или безопасность VPN.

**R&D решение:** direct-only отвергнут в пользу условного direct-first и гарантированного резервного relay при его доступности. Следующее испытание должно **детерминированно** задавать NAT mapping/filtering классы и отдельно проверять TCP/TLS-дата-путь через NAT. **G2 PARTIAL**, не release gate. M2/M5 основного Xray APK не изменены.
