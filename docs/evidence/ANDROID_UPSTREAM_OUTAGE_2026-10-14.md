# Android 15: upstream VPN server outage, direct traffic leak regression

**Date:** 2026-10-14. **Status:** Android E2E run still in progress at initial documentation time. Do not mark PASS until a completed workflow and logs demonstrate all conditions.

## Why

The earlier Android 15 emulator run [#38611503072](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38611503072) passed a real Android VPN connection, HTTPS through an independent-UID probe, public-IP change and clean disconnect. It did **not** demonstrate whether traffic might bypass the VPN when the upstream VLESS/Reality server becomes unreachable.

## New fault injection (commit 63f059ae)

Workflow: [run #38618701510](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38618701510) (`android-emulator-e2e.yml`).

1. The standalone probe app (`dev.omega.vpn.probe`, separate Android UID) performs an unproxied HTTPS request and records **only a salted one-run SHA-256 fingerprint** of the public IP plus `ConnectivityManager.TRANSPORT_VPN` status.
2. Ω VPN UI imports the public free catalogue, requires a user risk acknowledgement, requests standard system VpnService permission, connects, then the independent probe must confirm HTTPS 200, VPN default network and a changed IP hash.
3. Test reads the explicitly displayed public IPv4 of the selected node, validates global reachability, and uses root **inside the Android emulator only** to insert an `iptables OUTPUT -d <selected node> -j DROP` rule.
4. A fresh independent-UID HTTPS probe must **fail with VPN still the Android default network**. An HTTPS 200 response with the original unproxied IP hash is a **critical direct-traffic leak and immediate failure**. Any ambiguous status is a failed test, not proof of privacy.
5. The firewall rule is deleted in `finally`, including when a failure was observed; HTTPS must recover through the VPN, with the non-baseline egress IP and VPN transport intact.
6. Existing test then disconnects Ω VPN and verifies normal unproxied HTTPS and the original public-IP fingerprint are restored.

The probe logs only mode, status, anonymized IP hash, Android VPN transport status and exception *class*. It neither prints unredacted public IP addresses nor commits the VLESS URI.

## Environment and limitations

- GitHub Actions `ubuntu-24.04` with hardware-assisted Android emulator (`/dev/kvm`), Android 15 API 35, Google APIs system image, x86_64 AndroidLibXrayLite/Xray JNI.
- Host-runner network tests are not a substitute for the Android-side second UID.
- Emulator `adb root` and `iptables` capability is a **test prerequisite**; if unavailable, the workflow fails with a named blocker, rather than reporting false PASS.
- This test verifies an outage of the *selected upstream proxy IP*, **not** process crash, Android lockdown, IPv6 escape, packet-level DNS leakage, Wi-Fi/mobile switching, or behavior on the physical ARM64 OnePlus Nord 3. These remain release blockers.
- A certificate-valid HTTPS request and VPN IP change cannot verify that an anonymous node's operator is trustworthy or independent of surveillance.

## Results

### First Android run: INCONCLUSIVE (2026-10-14)

[Run #38618701510](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38618701510) was **FAIL** as a whole:

- **PASS:** Android 15 x86_64 started a real default VPN; separate UID HTTPS=200; public IP changed.
- **OBSERVED:** after emulator firewall blocked the selected VLESS server's egress IP, the probe timed out and did not report any successful direct HTTPS.
- **UNPROVEN:** `vpn_default_during_failure=false` was a **test harness default on probe timeout**, not a completed `ConnectivityManager` measurement. Therefore it cannot prove that the VPN dropped, nor can the timeout alone prove fail-closed.
- **BLOCKER:** `proxy_outage_fail_closed_not_demonstrated`. See [anonymized evidence](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38618701510/artifacts/11921277209). This failure must not be relabelled PASS.

### Instrumentation correction and re-test

[Commit afaaf5a](https://github.com/xxiamadelxx-blip/omega-vpn/commit/afaaf5ac59bc37204f0f864e4946b898fece5896) makes the separate-UID Android probe log a distinct `STATUS vpn=0/1` immediately after `ConnectivityManager` returns, **before** potentially blocking HTTPS. On timeout Python now reads that status and indicates whether it was observed, rather than silently defaulting unknown to false. A `blocked_no_direct_fallback` PASS requires `FAIL` HTTPS, affirmative VPN status and a real prior status record.

[Repeat GitHub Actions run #38620668096](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38620668096): **IN PROGRESS at documentation time; no outcome claimed.**

Remaining release gates: actual ARM64 phone, crash/kill switch, DNS packet-level leaks, IPv6 handling and Wi-Fi/mobile handoff.
