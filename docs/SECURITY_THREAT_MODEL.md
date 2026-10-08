# Security threat model: public free VPN catalogue

Date: **2026-10-08**. Classification: **HIGH RISK / UNTRUSTED INPUT**.
Source: [Au1rxx/free-vpn-subscriptions](https://github.com/Au1rxx/free-vpn-subscriptions). Code-hardening commit: [c6c56c5](https://github.com/xxiamadelxx-blip/omega-vpn/commit/c6c56c5ce344ca59ade4f7dbcb5545cd1d0587e5).

## Security answer

**We cannot verify who controls an anonymous proxy/VLESS server.** Neither GitHub-hosted lists, a working TLS/Reality handshake, a successful HTTP 200/204 probe, IP geolocation, a change of public egress IP, nor an "open-source" catalogue establish whether an operator is a criminal, a state agency (including the FSB), or an otherwise trustworthy organisation. No assertion of state affiliation has been established.

A third-party VPN operator can observe connection IPs, timestamps, traffic volume, and some destination metadata. It can potentially read or alter HTTP traffic, spoof DNS (if resolver trust is weak), redirect to phishing sites, selectively block traffic and correlate activity. Proper HTTPS certificate validation reduces plaintext interception but cannot hide all metadata, provider-side logs or account-linked activity. A REALITY public key authenticates a configured *proxy endpoint*, not the identity, legal accountability or privacy practices of its operator.

**High-risk use is explicitly unsupported for anonymous catalogue nodes.** Prefer an independently accountable service with published operator identity, policy and evidence of independent audits if sensitive identity protection is required. Even reputable VPN services do not guarantee anonymity.

## Findings from public catalogue review

- The publisher's README describes hourly refreshes and TCP/TLS/config/HTTP-204 checks. These are **availability** tests, not anonymity or ownership checks.
- The publisher's `SECURITY.md` explicitly treats untrusted third-party nodes as inherent to the aggregation model, not defects that the publisher can repair.
- In the examined public repository tree, generated `output/` files, documentation, policy and GitHub issue templates were present; **collector and active probe implementation/workflows were not available for independent reproduction**. This does not prove bad intent but means the published "verified" claim is **not an independent security audit**.
- One 2026-10-08 snapshot contained **1,819** decoded configurations; a metadata-only pass over **717** VLESS/TCP/Reality-looking entries found **692 IPv4/IPv6 address literals** and **25 hostname entries**. No obviously non-global literal IP was found in that sample. Counts change with hourly updates and do **not** indicate the servers are trusted.
- The list can change without Omega VPN approval: HTTPS protects transport to GitHub, not against a publisher intentionally adding a malicious but syntactically valid server.

## P0 risks and implemented controls

| Threat | Potential outcome | Protection in Omega VPN after c6c56c5 | Residual risk |
| --- | --- | --- | --- |
| Unknown VPN/FSB/criminal owner | Metadata logging, traffic correlation | Explicit HIGH-RISK disclosure, no silent connection | **CRITICAL: impossible to eliminate for anonymous nodes** |
| Malicious feed update | Redirect users to selected attacker IP | Host and protocol/Reality validation; explicit opt-in; no unrequested connect | **HIGH: feed publisher still controls candidate list** |
| Local network / metadata IP / CGNAT | Access to unintended internal endpoints | Reject loopback, private/reserved/metadata/benchmark addresses, reject DNS hostnames and noncanonical IPs | Residual IP ownership cannot be verified |
| DNS rebinding by feed-controlled name | Name resolves to internal device/LAN address | Strict public catalogue accepts only literal globally routable **IPv4** hosts; no DNS lookup or hostname on input | Some legitimate hostname/IPv6 servers will be skipped; routing elsewhere requires physical tests |
| Malformed or oversized subscription | Memory exhaustion/unsafe configs | HTTP timeouts, size cap, Base64 decode validation, parse limit 5000 lines/120 candidates, fixed permitted transports | Future parser changes must be tested |
| Unwanted first connection | User connects before understanding risk | Search downloads only; separate explicit checkbox and manual Connect, never auto-connect after selecting next IP | User can still accept significant risks |
| Cleartext or TLS bypass | Traffic/content tampering | Android `usesCleartextTraffic=false` for app network stack; no insecure TLS bypass code intentionally included | Does **not** force HTTPS on third-party apps inside the VPN |
| DNS/IPv6/route leaks, kill-switch | Direct identifying traffic escapes | Xray config has no `freedom` outbound; further device tests required | **OPEN: not verified on Android** |
| Publication of private URI/UUID | Credential compromise | No disk persistence/telemetry of loaded feed configs; no credentials in repo | Avoid screenshots/logcat dumps containing endpoints |

## Required before a "trusted" or production release

- [x] Do not auto-connect on feed download or on "next server" selection; require explicit session-only acknowledgement.
- [x] Reject non-global/reserved IPv4, hostnames and IPv6 destinations from the **anonymous catalogue**, without DNS lookup.
- [x] No unreviewed executables or scripts loaded from feed: data-only `vless://`, fixed protocol subset.
- [x] Disallow cleartext traffic for Omega's own Android app network stack (does not affect other apps).
- [ ] On physical OnePlus Nord 3, verify Android VPN TUN, HTTPS, IP, DNS, IPv6, reconnect, revoke and fail-closed behavior.
- [ ] Implement verified HTTPS tunnel healthcheck **without sending private browsing data**; distinguish core running from healthy VPN.
- [ ] Assess DNS and endpoint IP leakage when VPN tunnel goes down or switches networks; consider Android Always-on VPN and "Block connections without VPN" where compatible.
- [ ] Treat provider trust level separately from connectivity; support **audited, identifiable operators** as a different category rather than awarding "safe" labels from speed tests.
- [ ] Determine provenance at **node/operator** level, including AS ownership, legal policies, abuse history, and corroborating independent evidence. This still cannot prove the absence of intelligence agency control.
- [ ] Check updates to catalogue and Xray-core dependency tree on a recurring basis, verify signatures when genuinely available.
- [ ] Repeat tests with adversarial payloads, parser fuzzing, native-lib security review, and runtime analysis.
- [ ] If user needs protection from a state-level actor, disable anonymous nodes for that use case, not simply hide a warning.

## User privacy and consent

The first press of "Find free nodes" accesses `raw.githubusercontent.com` **outside the VPN**, which necessarily exposes the current public source IP to the CDN/GitHub service and local network operator. Once a node is selected, its operator sees the user's source IP. The app must disclose both facts. No third-party catalogue can make these network interactions fully anonymous by itself.

**Decision:** Keep the free catalogue **experimental only, clearly labelled untrusted**. The security restrictions make obvious bad inputs harder to exploit but do **not** certify it as safe or rule out state surveillance. MVP safety and device testing gates remain open.
