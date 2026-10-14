# Android 15 E2E: VPN disconnect/TUN lifecycle regression

Дата исследования: 2026-10-14. Stage M2/M5, **полная приёмка всё ещё OPEN**.

## Проблема, воспроизведённая на Android-эмуляторе

[GitHub Actions run 38594961970](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38594961970), Android 15 API35, x86_64, отдельное приложение-пробник `dev.omega.vpn.probe`:

- Установка Ω VPN и пробника: PASS.
- Исходный HTTPS из второго UID: PASS (HTTP 200, IP отпечаток сохраняется локально как солёный hash).
- Разрешение Android VpnService: PASS.
- Системная VPN-сеть определялась: PASS.
- HTTPS `https://api.ipify.org` из другого UID **через VPN**: PASS.
- Публичный IP после подключения **отличался** от прямого: PASS.
- Проверка разрешения DNS-имени: PASS (только **факт разрешения**, это ещё не полноценный DNS-leak-test).
- Нажатие кнопки отключения: PASS.
- Возврат прежнего публичного IP после отключения: **FAIL**.
- Итого: Android E2E завершён с `RuntimeError: vpn_disconnect_failed`. Исходный результат сохранён в артефакте `omega-android-emulator-evidence` указанного run.

## Причина и исправление

В исходном `OmegaVpnService.onDestroy()` очистка TUN и вызов `CoreController.stopLoop()` были помещены в single-thread executor **после** `startLoop()`. Если native `startLoop()` блокирует поток до остановки, этот порядок препятствует своевременному прекращению VPN-сессии. По имеющимся логам это **инженерная гипотеза**, а не доказанная native stack trace причина.

Коммит [425d7c1](https://github.com/xxiamadelxx-blip/omega-vpn/commit/425d7c12e9ef4caf90062dc08c7e4e3ba3a9f65c):

- Закрывать TUN descriptor **синхронно** при `DISCONNECT`, до освобождения worker.
- Вызывать `stopLoop()` в другом потоке, не в очереди занятого `startLoop()`.
- Защищать передачу descriptor/controller под lock с флагом `stopping` и закрывать FD при отмене во время подготовки.
- Разделять status native engine и фактическое состояние сетевого маршрута; не делать обхода в `freedom`.
- Android E2E после отключения делает **до пяти проб** HTTPS/публичного IP из независимого Android UID, чтобы отличить отсутствие возврата маршрута от задержки сети.
- Android emulator workflow теперь запускается и при изменениях `app/src/main/**`, чтобы важные изменения сервиса не проходили без Android E2E.

## Проверки на этапе изменения

- Облачная команда: `./gradlew --no-daemon --console=plain :app:assembleDebug :app:testDebugUnitTest :app:lintDebug`.
- На исходниках commit `425d7c1`: **PASS**, 16/16 JVM unit tests, lint PASS, собран ARM64 debug APK.
- Локальный APK SHA-256: `0d79654d329af176589c58def38073e1e808155f17f8b7bd769a383504c93357`; это не хеш CI-артефакта и не Android-x86_64.
- Android x86_64 E2E повтор: [CI run 38607129477](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38607129477). **Статус в момент подготовки документа: RUNNING, итог ещё не подтверждён.** Не изменять на PASS без журнала.

## Неразрешённые пункты, важные для security gate

1. Конечный возврат публичного IP и окончательная остановка Android VPN после команды Disconnect.
2. Надёжное переключение между двумя серверами, reconnect и onRevoke.
3. Проверка DNS leak через независимые resolvers, не только `InetAddress.getByName()`.
4. Принудительная IPv6-маршрутизация / IPv6 leak через второй Android UID.
5. Android Always-on VPN + Block without VPN и режим отказа/обрыва узла.
6. Тестирование реального ARM64 OnePlus Nord 3 по Wi-Fi и мобильной сети. Проход на x86_64 Android эмуляторе не удостоверяет физическое ARM64 устройство.
