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


## Subsequent E2E iteration: split UI state and real default network

[Run 38607129477](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38607129477), after initial TUN close fix, **FAIL**:
- First node: separate UID HTTPS `PASS`; public IP **unchanged**; inherited `vpn_is_active` based on historical `dumpsys connectivity` returned `True`. **This does not prove an active default VPN network.**
- The emulator screenshot **03-attempt-1.png** from the run's evidence showed Ω VPN displaying **«VPN отключён»** at the time. The script incorrectly attempted to click «Попробовать другой сервер» while still assuming the previous node was connected and ended with `next_server_not_available`.
- A prior screenshot from [run 38594961970](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38594961970) showed **«Xray запущен»** and changed IP. The difference supports distinguishing native engine/runtime/UI and actual routing; **not** blanket confidence in VPN health.

The first recovery script change was [19fe460](https://github.com/xxiamadelxx-blip/omega-vpn/commit/19fe4602e17a01b47808bd21db24794b3e0e6671): failed nodes must restore the baseline before testing another. Next audit revealed the app sometimes auto-disconnects on a native failure; this must be treated as already stopped, not another broken Disconnect button.

Further changes:
- [69b2d79](https://github.com/xxiamadelxx-blip/omega-vpn/commit/69b2d79d0d962492b3e10441a857789462da30e7): independent Android UID uses `ConnectivityManager.getActiveNetwork()` + `NetworkCapabilities.TRANSPORT_VPN`. Report `vpn_default=1/0` directly in each probe and demand `vpn_default=true` **and changed public IP** for VPN-success. Require `vpn_default=false` **and original IP** after disconnect. Native startup failure state is preserved in UI rather than overwritten by `onDestroy`.
- [59f34f0](https://github.com/xxiamadelxx-blip/omega-vpn/commit/59f34f0fa820ae2fc9fa295bd10303b38651fb6f): Java probe import compilation fix.
- [6da35c0](https://github.com/xxiamadelxx-blip/omega-vpn/commit/6da35c0fdfe4a531279c0ffc4e56f9118a40c623): save ONLY sanitized `OMEGA_TUN` stage and exception type before `probe()` clears logcat; track whether UI displayed Connected as separate evidence. Never export raw server URI, UUID, real IP, full logcat or other private fields.

**Independent cloud build:** From `59f34f0` via `./gradlew --no-daemon --console=plain :app:assembleDebug :probe:assembleDebug :app:testDebugUnitTest`, PASS (73 actionable tasks; all successful, 16/16 unit tests). From `6da35c0` the Python script passes `python3 -m py_compile`. This is static/build verification only.

**Latest Android E2E (pending as of documenting):** [run 38609586941](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38609586941). An observed absence of IP changes or `vpn_default=0` still means FAIL, even if HTTPS=PASS. Existing issues: robust switch/reconnect, DNS/IPv6 leak tests, Android phone ARM64 acceptance, failure kill switch.
