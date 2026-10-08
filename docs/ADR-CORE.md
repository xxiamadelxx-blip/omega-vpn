# ADR-CORE-001: Android VPN core selection (M1)

**Date:** 2026-10-08  
**Decision:** Xray-core via AndroidLibXrayLite *as the implementation target*.  
**Implementation status:** M2 ARM64 AAR is built from pinned `AndroidLibXrayLite` SHA `ea96a7f9c33d6e18021386db96bf95680e853c93` and integrated. Kotlin VpnService/Go JNI compile. **Actual connectivity and tunnel protection on a physical Android device: NOT RUN. M2 gate OPEN.**

## Alternatives considered

| Option | License checked | Android binding | Pros | Risks |
| --- | --- | --- | --- | --- |
| v2rayNG with Xray | v2rayNG GPL-3.0, Xray-core MPL-2.0 | Demonstrated by upstream's Android app, which uses AndroidLibXrayLite AAR | Existing `VpnService` implementation; supports VLESS and Reality | Full fork is larger than MVP, package/copyright obligations, upstream AAR may be outdated |
| AndroidLibXrayLite + Xray-core | AndroidLibXrayLite LGPL-3.0, Xray-core MPL-2.0 | Upstream README documents `gomobile bind -androidapi 24` producing an AAR | Compact interface; reuse proven engine without importing v2rayNG proprietary assets or full app | Needs Go/gomobile/Android NDK, verified ABI and bridge; M2 |
| sing-box for Android / libbox | sing-box + SFA GPL-3.0-or-later with name/association restriction notice | SFA app uses locally provided `libbox.aar`; implementation demonstrates Android TUN | Strong multi-protocol support | Own libbox build/NDK and integration, GPL obligations, larger API surface than initial VLESS MVP |
| Reuse Happ APK binaries | **Rejected**: third-party proprietary code | Existing app only | Quick inspection possible | No permission to copy its implementation, update/license risks |

## Decision rationale

The first required protocol is VLESS/TLS/Reality. Xray-core is the natural choice (MPL-2.0) with the open AndroidLibXrayLite (LGPL-3.0). v2rayNG is a **reference implementation**, not code to copy into a closed app. The current Ω VPN source is intentionally GPL-3.0 to permit future code reuse from compatible GPL implementations, subject to all attribution/source obligations.

A separate Android build-spike is allowed in M1 to prove Kotlin/Compose/Gradle/Android SDK compile and packaging. This does **not** prove engine integration; do not call it connected VPN. M2 must compile an exact pinned AndroidLibXrayLite AAR for arm64-v8a, package it lawfully with notices and verify actual TUN traffic on device. If go-mobile binding proves impractical, revisit SFA/libbox with evidence and an updated ADR.

## Source evidence

- [v2rayNG](https://github.com/2dust/v2rayNG): GPL-3.0 LICENSE, README includes Xray support and AAR build guidance; `V2rayNG/app/build.gradle.kts` uses local AAR.
- [AndroidLibXrayLite](https://github.com/2dust/AndroidLibXrayLite): LGPL-3.0 LICENSE; README states JDK, Android SDK, Go and gomobile are required.
- [Xray-core](https://github.com/XTLS/Xray-core): MPL-2.0 LICENSE.
- [SFA](https://github.com/SagerNet/sing-box-for-android): GPL-3.0-or-later LICENSE with association/name notice; `app/build.gradle.kts` binds local libbox AAR.
- [sing-box](https://github.com/SagerNet/sing-box): GPL-3.0-or-later LICENSE with name/association notice.

Exact versions of **core implementation** and their dependency NOTICE/SBOM must be pinned and audited before M2 integration. M1 versions of Gradle/Android build toolchain are pinned in the source. This is architectural evaluation, not legal advice.

## Go/no-go M1 gate

1. Clean `./gradlew :app:assembleDebug :app:testDebugUnitTest` passes in isolated cloud build (and GitHub Actions).
2. APK package ID `dev.omega.vpn`, `minSdk 26`, `targetSdk 35`, with **no** `VPN_SERVICE` permission or network behavior prematurely advertised.
3. M2 integration plan documented above, GPL/Apache/Kotlin dependencies acknowledged.
4. Build cannot be marked a functioning VPN. M5 device gate unchanged.

## M1 build-spike result (2026-10-08)

- **PASS:** Android Gradle Plugin 8.9.2, Kotlin+Compose 2.1.20, Gradle Wrapper 8.13, JDK 21, compile/target SDK 35.
- **PASS:** cloud `assembleDebug` and JUnit test 1/1; [GitHub Actions successful build](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/37804978821).
- **PASS:** `apksigner verify` with v2 debug signature; `aapt` identifies `dev.omega.vpn` (minSdk 26, targetSdk 35). APK has no `android.permission.INTERNET` or VPN service yet.
- **NOT RUN (M2):** actual gomobile `AndroidLibXrayLite` AAR build, ABI validation, VpnService TUN, device connectivity.
- Upstream AndroidLibXrayLite `go.mod` observed requiring Go 1.27 and Xray `v1.260327.1-0.20260930074004-b26a91de4f32`; before compiling AAR, pin exact commits and review their transitive licenses. `docs/THIRD_PARTY_NOTICES.md` records this.

## M2 API implementation (2026-10-08)

- Go 1.27.2, Android SDK 35, NDK 28.0.13004108, `gomobile` and `gobind` at `golang.org/x/mobile@v0.0.0-20260908204917-8b95e45f8d3e`.
- AndroidLibXrayLite pinned source commit `ea96a7f9c33d6e18021386db96bf95680e853c93` built with `gomobile bind -target=android/arm64 -androidapi 26`.
- Built AAR SHA256: `a1671503af774f5e21c3c0cac9a756c35f45be97b48bb65daf33ac39bcd4c92d`; includes `lib/arm64-v8a/libgojni.so` ~36 MB uncompressed. No upstream Happ assets.
- Verified generated Java signatures with `javap`: `Libv2ray.initCoreEnv(String,String)`, `Libv2ray.newCoreController(CoreCallbackHandler)`, `CoreController.startLoop(String,int)`, `stopLoop()`.
- Android `OmegaVpnService` builds TUN using `VpnService.Builder`, adds IPv4/IPv6 default routes, excludes its own package to avoid recursion, passes `ParcelFileDescriptor.fd` to native Xray `tun` inbound, and closes controller before FD on shutdown.
- First accepted profile subset: `vless://` URI, TCP+REALITY with UUID, SNI, publicKey, shortId, fingerprint, optional Vision flow. Routes from TUN go only to the VLESS proxy; a `freedom` outbound is absent.
- No end-to-end device test yet. Review Android foreground restrictions, DNS/IPv6 safety and packet forwarding in M2 device acceptance.
