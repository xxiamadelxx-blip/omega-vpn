# M1 third-party licensing inventory

**Date:** 2026-10-08. This is the M1 build provenance inventory, **not a complete dependency SBOM**. Re-evaluate exact transitive dependencies and their notices before any release.

## Included in the M1 build

| Component | Pinned version | Upstream | License / action |
| --- | --- | --- | --- |
| Ω VPN's original Kotlin application | 0.1.0-m1 | This repository | GPL-3.0, [LICENSE](../LICENSE), source provided |
| Android Gradle Plugin | 8.9.2 | https://developer.android.com/build | Apache-2.0 tooling (not app VPN engine) |
| Gradle Wrapper + distribution | 8.13 | https://github.com/gradle/gradle | Apache-2.0; wrapper scripts/JAR from official open-source Gradle wrapper bundled in SFA; no SFA app code imported |
| Kotlin Android + Compose compiler | 2.1.20 | https://github.com/JetBrains/kotlin | Apache-2.0 |
| AndroidX Compose BOM | 2025.03.01 | https://developer.android.com/jetpack/compose/bom | Version alignment only, individual AndroidX runtime dependencies generally Apache-2.0 |
| AndroidX Activity Compose | 1.10.1 | https://developer.android.com/jetpack/androidx/releases/activity | Apache-2.0 |
| AndroidX Compose foundation/material3/ui | BOM version | https://developer.android.com/jetpack | Apache-2.0 |
| JUnit | 4.13.2 (test only) | https://github.com/junit-team/junit4 | EPL-1.0 (test dependency, not distributed as part of production APK) |

No APK, Java source, or native library from Happ, v2rayNG, SFA or AndroidLibXrayLite is bundled in this **M1** build. No VPN tunnel can be initiated.

## Engine decision, not yet integrated

| Component | Upstream | License evidence | M2 action |
| --- | --- | --- | --- |
| AndroidLibXrayLite | https://github.com/2dust/AndroidLibXrayLite | LGPL-3.0 `LICENSE` | Build a pinned gomobile AAR, retain LGPL source/notice and relink rights when distributing |
| Xray-core | https://github.com/XTLS/Xray-core | MPL-2.0 `LICENSE` | Pin exact version, preserve covered source/code changes, include notices |
| v2rayNG reference app | https://github.com/2dust/v2rayNG | GPL-3.0 `LICENSE` | Reference only; no imported source or binaries in M1 |
| sing-box / SFA alternative | https://github.com/SagerNet/sing-box ; https://github.com/SagerNet/sing-box-for-android | GPL-3.0-or-later `LICENSE` with name/association notice | Alternative only, not shipped |

**Current upstream AndroidLibXrayLite go.mod observed on 2026-10-08:** Go 1.27, Xray dependency `v1.260327.1-0.20260930074004-b26a91de4f32`. This is upstream observation, **not a frozen commitment** of Ω VPN. M2 must pin the precise library and core commit to produce a reproducible AAR and audit its transitive dependency licenses.

## Pre-release obligations

- [ ] Generate a full dependency license inventory/SBOM at chosen production commit.
- [ ] Verify any linked LGPL library's relinking/replacement requirements and include the necessary corresponding source.
- [ ] Include exact MPL-2.0 source availability and notices for shipped Xray-core.
- [ ] Verify third-party native binaries and Gradle/JDK toolchain provenance.
- [ ] Confirm trademark/branding separation from Happ, v2rayNG and SFA.
- [ ] Check compatibility of any copied GPL source before integrating it.

This inventory is informational and is not legal advice.
