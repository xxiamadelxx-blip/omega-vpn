# Android 15: Always-on lockdown and forced VPN process death

**Date:** 2026-10-14/15. **Status:** Android 15 OS Lockdown independent-UID direct HTTPS block **PASS** on disposable emulator; VPN reconnect + SIGKILL under Lockdown **NOT YET VERIFIED**. Do not label the release kill-switch verified until the full sequence passes.

New script [scripts/android-lockdown-e2e.py](../../scripts/android-lockdown-e2e.py), added by commit [3706bfd](https://github.com/xxiamadelxx-blip/omega-vpn/commit/3706bfd8e67be58fcf6c28ea95868f0cba35d3ab). This is a separate, destructive **ephemeral rooted Android emulator** test; it must never apply settings on the user's physical phone automatically.

## Why this is separate from proxy-upstream outage

[Successful proxy outage test](ANDROID_UPSTREAM_OUTAGE_2026-10-14.md) proved that when the **remote server** is unreachable, an already-established Android VpnService TUN does not silently fail over to direct HTTPS in the tested conditions. It does **not** prove protection if the **VPN app process** itself is killed and Android closes its VPN interface. Without Android's system lockdown, ordinary direct internet access may be restored by design.

## Acceptance procedure: disconnected lockdown proven, crash pending

1. Run after the normal E2E passes and disconnects. From an independent Android UID, prove ordinary unproxied HTTPS works and Android has no default VPN.
2. Within **rooted disposable emulator only**, snapshot the system settings and use the real Android VPN Settings UI to enable Always-on VPN and “Block connections without VPN”. Merely writing `Settings.Secure` or using unsupported `cmd connectivity` commands did not activate the lockdown mechanism.
3. **Do not trust settings readback:** send a fresh HTTPS request from the independent UID while the VPN is disconnected. It **must fail**. Otherwise report `INCONCLUSIVE_LOCKDOWN_NOT_APPLIED` and do not attempt to claim kill-switch PASS.
4. Connect Omega through its regular UI. Independent UID must observe `TRANSPORT_VPN=true`, HTTPS 200, and outbound public IP different from original.
5. Kill Omega process with `SIGKILL`, preserving the rest of the Android emulator. A new independent-UID HTTPS request must fail, not return a direct baseline IP. Any unexpected success fails the security test.
6. In `finally`, restore original secure VPN settings even if the test failed; publish only anonymized connection status/error class.

## Known architectural risk to test

Omega's `VpnService.Builder.addDisallowedApplication(packageName)` excludes its own app from the VPN. Android lockdown may block excluded apps' networking while no VPN is working, potentially preventing Xray from reaching its upstream node. This is a hypothesis, **not a verified failure**. If the E2E cannot establish the VPN under lockdown, document it as a release blocker and examine protected socket design; do not disable lockdown silently.

The app cannot enable user-owned Android VPN lockdown by a normal unprivileged Android API. No automatic lockdown is implemented on a user's device.

**Remain open:** DNS packet captures, IPv6 scenario, switch between mobile and Wi-Fi, ARM64 physical phone and operator trust.

## First attempt and CI infrastructure repair

[Workflow #38625798012](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38625798012) **FAILED BEFORE STARTING EMULATOR**. Go/mobile build could not verify `github.com/libp2p/go-netroute@v0.2.1/go.mod` because `sum.golang.org` returned `stream error: ... HTTP/2 INTERNAL_ERROR`. This is a network/checksum-fetch failure, **not** evidence for or against lockdown safety.

[Commit 939f617](https://github.com/xxiamadelxx-blip/omega-vpn/commit/939f617841511355633512ca559b8b21a2e160bf) adds bounded retries to Go install, gomobile init and AAR build without disabling `GOSUMDB` or replacing pinned dependencies. Static `bash -n` and Python `py_compile`: PASS. Retest [#38626946358](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38626946358) in progress at documentation time.

## Latest device-level evidence (2026-10-14)

- [Run #38638200310](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38638200310): Android 15 normal TUN, IP change, HTTPS and blocked-upstream fail-closed PASS; Lockdown setup **INCONCLUSIVE** because `cmd connectivity` lacks the needed command on this AVD.
- [Run #38641427737](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38641427737): Android Settings UI successfully opened; script used wrongly double-escaped coordinate regex and aborted before toggling. Fixed in [1155c1a](https://github.com/xxiamadelxx-blip/omega-vpn/commit/1155c1adbf9f1f413927756a96f38d7cc87d9cb0).
- [Run #38645435207](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38645435207): **PASS for OS Lockdown enforcement with VPN disconnected**. The AVD exposed both VPN Settings switches; both were enabled through Android UI, keys read back, and the independent app's HTTPS failed while `vpn_default=false`, following a successful direct HTTPS baseline. Normal VPN HTTPS, IP change, server-outage fail-closed, recovery and disconnect all passed earlier in the *same run*. Full test remains **FAIL**: after leaving Settings via HOME, the test failed to relaunch Omega before searching for the Connect button (`lockdown_vpn_ui_reconnect_button_missing`). This is a test navigation error, not evidence of a crash leak.
- [Commit 3150eb4](https://github.com/xxiamadelxx-blip/omega-vpn/commit/3150eb48f86009e057550cdd765ea53ad5263df3) explicitly reopens Omega's Activity before reconnect and requires independent probe startup evidence after SIGKILL. [Run #38646622262](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38646622262) triggered; crash test result pending at documentation time.

**Scope limit:** Lockdown-offline PASS confirms Android OS blocked this particular probe's direct HTTPS in the AVD. It does not independently prove device-wide DNS packets cannot escape, IPv6 fail-closed, handling of mobile/Wi-Fi transitions, or crash protection before the SIGKILL case runs.
