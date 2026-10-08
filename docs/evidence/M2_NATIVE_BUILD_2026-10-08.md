# M2 Native VPN Implementation Evidence — 2026-10-08

**Status: PARTIAL PASS (static/build); M2 RELEASE GATE OPEN.** Приложение пока **не доказало VPN-соединение на Android**.

## Reproducible source and native build

- Omega VPN source implementation: [898017a](https://github.com/xxiamadelxx-blip/omega-vpn/commit/898017a1b4e2d6927bea74919540ac816e15fd22).
- CI/native script: [11f3317](https://github.com/xxiamadelxx-blip/omega-vpn/commit/11f3317e40c29846011d7ceba35885b64b8fedc9).
- Error retention, no-direct-route test, backup/privacy changes: [4b1827a](https://github.com/xxiamadelxx-blip/omega-vpn/commit/4b1827a24c691e19953a501ff9ce1f975e1f5f87).
- LGPL AndroidLibXrayLite exact commit: `ea96a7f9c33d6e18021386db96bf95680e853c93`.
- Module includes Xray-core via `v1.260327.1-0.20260930074004-b26a91de4f32`.
- Go `1.27.2`, gomobile/gobind `golang.org/x/mobile@v0.0.0-20260908204917-8b95e45f8d3e`, Android NDK `28.0.13004108`, Android SDK 35 and Gradle 8.13.
- Locally built `libv2ray.aar` SHA256 `a1671503af774f5e21c3c0cac9a756c35f45be97b48bb65daf33ac39bcd4c92d`. CI rebuilds from source independently; its binary hash may differ because of timestamps/toolchain.
- `javap` verified `CoreController.startLoop(String,int)`, `stopLoop()`, `Libv2ray.initCoreEnv(String,String)`.
- No closed-source Happ code/assets or private keys in build.

## M2 build / static checks

1. **PASS:** `bash scripts/build-xray-android.sh` produced native ARM64 `libgojni.so` and AAR in isolated Vercel workbench. Source SHA pinned by script.
2. **PASS:** `./gradlew --no-daemon :app:assembleDebug :app:testDebugUnitTest :app:lintDebug` from checked out code + AAR.
3. **PASS:** local unit tests 7/7: BuildStage guard 1, VlessProfile 5, XrayConfigFactory fail-closed route 1.
4. **PASS:** Android Lint compile/no errors; dependency-version warnings may remain (not a security audit).
5. **PASS:** APK `dev.omega.vpn`, `0.2.0-m2`, targetSdk 35, includes native ARM64 JNI `libgojni.so`; APK Signature Scheme v2 verified.
6. **PASS:** REA `inspect-android-package` read `OmegaVpnService` in final manifest with `android.permission.BIND_VPN_SERVICE` and foreground `specialUse`.
7. **PASS for prior M2 commit:** [GitHub Actions 37810047834](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/37810047834) built native AAR from pinned source, Android APK, unit tests and uploaded ZIP artifact.
8. **Latest corrected M2 source CI:** [GitHub Actions 37810677819](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/37810677819). Consult its live state; not assumed successful before completion.

Local final M2 check source commit: `4b1827a24c691e19953a501ff9ce1f975e1f5f87`. Local APK SHA-256: `3bca5f46966adf97ca4a29030f5e8d78ef7a370e1788ecedca115b0cc8e4556e`, around 51 MiB. This APK checksum is specific to this **local** build, not the GitHub Actions ZIP checksum.

## What is implemented

- `VpnService.prepare` consent flow; Android foreground `OmegaVpnService` with ongoing notification and disconnect action.
- Android TUN with IPv4 and IPv6 default routes, DNS address, app exclusion to avoid native core routing loops.
- Xray's native `tun` inbound receives TUN descriptor via `startLoop(json, fd)`.
- Parser for a restricted, standard `vless://` TCP/REALITY URI including UUID, SNI, pbk, shortId, TLS fingerprint and Vision flow.
- Only VLESS outbound in generated JSON, no fallback to direct `freedom` egress. Unit test checks this property.
- Stop/revoke/exception cleanup. No recording user profile to disk/analytics; masked input field.
- No subscription/automatic server discovery: this is **M3**.

## Real device acceptance needed (NOT RUN)

**Device:** OnePlus Nord 3, Android 15, without root. Have an authorized live VLESS/TCP/Reality profile, do not paste it into a public issue or screenshots.

1. Download debug ZIP `omega-vpn-m2-debug` from a **successful** [GitHub Actions run](https://github.com/xxiamadelxx-blip/omega-vpn/actions/workflows/android-ci.yml), extract `app-debug.apk`, install, open.
2. Before activation, open `https://www.cloudflare.com/cdn-cgi/trace` in the browser and record only whether/what egress IP appears, keeping the address private.
3. Paste the VLESS/Reality URI into Ω VPN and tap **Подключить**. Approve Android's VPN permission prompt. Verify Android VPN status/notification, then reload the same HTTPS page.
4. **M2 gate requires different public egress IP and HTTP response over the VPN**, not only an on-screen 'Xray запущен' status. Test browsing/HTTPS from an unrelated app.
5. Disconnect. Repeat on mobile data and Wi-Fi separately; test switching networks and rejecting/revoking VPN permission. Record any failure without private server credentials.
6. Check DNS and IPv6 paths (including whether IPv6 egress bypasses the VPN). If leaks or bypass occur, M2 remains **FAIL/OPEN** until resolved.
7. On failures gather sanitized Android logcat for `dev.omega.vpn` (remove endpoint, private key, UUID, and public IP). Do not submit unknown public-node traffic secrets.

**No device tests, no active Android emulator tests, no live VLESS handshake from this APK, no verified mobile-carrier compatibility, no guaranteed free nodes.** Cloud SOCKS proof from previous feasibility audit is independent of this Android APK.

## Open risks

- No Android system-level traffic/power-state validation. Native Xray TUN descriptor passing compiles, but end-to-end packet routing is unproven on the target device.
- Public free nodes have no SLA and expose traffic trust to their operators; this APK does not collect or validate free subscription sources yet.
- IPv6, DNS, kill-switch and network switching need device testing. Android VPN may revert to direct connectivity when service is stopped unless the user enables Android always-on/block-connections-without-VPN settings; do not claim an implicit kill switch.
- M2 artifact is **experimental** and may incur cloud CI usage quotas. Runtime app uses no proprietary backend or paid API.
