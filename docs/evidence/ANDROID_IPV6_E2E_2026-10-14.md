# Android 15: отдельный IPv6-only E2E-тест

**Дата:** 2026-10-14. **Статус:** RUNNING, не объявлять PASS до завершения CI и анализа журнала.

Изменения: [probe 572fd01](https://github.com/xxiamadelxx-blip/omega-vpn/commit/572fd01bba3100df5af8d92955265bca75a7f25b), [оркестратор E2E a4ba5f1](https://github.com/xxiamadelxx-blip/omega-vpn/commit/a4ba5f10194c6b984b29c65b12a970cdb9594281).

Запуск: [GitHub Actions #38624055231](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38624055231).

## Почему нужна отдельная проверка

Успешные HTTPS и проверка DNS из предыдущего E2E не доказывают работоспособность IPv6 или отсутствие прямого IPv6 fallback. Обычный URL api.ipify.org может быть доступен по IPv4 и ничего не говорит о IPv6.

Независимое Android-приложение `dev.omega.vpn.probe` получило режим `ipv6`. Он подключается по HTTPS к `api6.ipify.org` (IPv6-only DNS), проверяет, что ответ действительно содержит IPv6, и пишет только salted SHA-256 IP fingerprint. Перед потенциально блокирующим HTTPS фиксируется активный network transport через Android `ConnectivityManager`.

### Требования для подтверждения

1. Baseline без VPN: попытка IPv6-only HTTPS, отдельно зафиксировать поддержку IPv6 интернетом эмулятора. Ошибка baseline не даёт права объявлять IPv6 защищённым.
2. Во время успешно проверенного VLESS/Reality TUN: отдельная попытка IPv6-only HTTPS от независимого UID, Android transport должен быть `TRANSPORT_VPN`.
3. Если baseline IPv6 доступен, а VPN-ответ содержит тот же IP fingerprint: **FAIL / suspicious direct leak**. Любой успешный IPv6-only HTTPS без `TRANSPORT_VPN`: **FAIL / unprotected success**.
4. Если IPv6-only запрос проходит через VPN, а fingerprint не совпадает с заведомо прямым baseline: **PASS_TUNNELED для данного сценария**, но это не packet-level доказательство отсутствия всех утечек.
5. Если IPv6-only запрос не проходит, результат **INCONCLUSIVE_NO_IPV6_CONNECTIVITY**. Не делать из ошибки вывода, что весь IPv6-трафик блокируется или гарантированно защищён.
6. Существующий регрессионный тест после проверки IPv6 по-прежнему должен блокировать upstream VPN IPv4, подтвердить fail-closed, восстановление и штатный Disconnect.

### Открытые вопросы

DNS-пакеты на физическом сетевом интерфейсе эмулятора, аварийное завершение процесса, Android Always-on/lockdown, смена Wi-Fi/мобильной сети и устройство OnePlus Nord 3 / ARM64 остаются отдельными релизными gate. Нельзя считать неизвестного владельца бесплатного сервера безопасным по результатам этих сетевых тестов.
