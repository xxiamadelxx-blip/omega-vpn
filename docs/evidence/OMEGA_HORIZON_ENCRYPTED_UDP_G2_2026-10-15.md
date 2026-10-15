# Ω Horizon G2: authenticated encryption over NAT and blind relay

**Date:** 2026-10-15. **Branch:** \`research/omega-horizon-p2p-lab\`. **Scope:** isolated private Linux network laboratory, not a production VPN or an anonymity guarantee.

## Verifiable evidence

- [GitHub Actions #38727443696](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38727443696): **SUCCESS**. Checked source at [commit 292f500](https://github.com/xxiamadelxx-blip/omega-vpn/commit/292f500475066ebf02873868ec99b40a5c92fb88).
- Existing loopback mTLS and newly added AEAD unit suite: **25/25 PASS** (9 TLS + 16 AEAD).
- Linux NAT fixture unit, private-namespace mapping/filtering tests, TCP mTLS-over-NAT, original UDP relay test, and new encrypted-UDP relay/netns E2E: **PASS** in the same independent run.
- Code: [record layer](../../research/horizon/secure_datagram.py), [record tests](../../research/horizon/tests/test_secure_datagram.py), [isolated NAT/relay test](../../research/horizon/secure_udp_netns.py), [CI workflow](../../.github/workflows/omega-horizon-p2p-lab.yml).
- Reproduction on authorized isolated Linux host with Python 3.13, iproute2, iptables and \`cryptography==46.0.4\`:
  \`\`\`bash
  python3 -m pip install 'cryptography==46.0.4'
  python3 -m unittest discover -s research/horizon/tests -v
  sudo -E python3 research/horizon/secure_udp_netns.py --orchestrate
  \`\`\`

## What the prototype demonstrates

The peers share a newly generated **32-byte test secret** out-of-band; **only client/peer receive it**. A fresh random 128-bit session ID and directional HKDF-SHA256 derivation produce distinct ChaCha20-Poly1305 keys for client→peer and peer→client. The full versioned record header is authenticated as AEAD associated data. A monotonic per-sender sequence and 128-record receive window reject exact duplicates, old records and corrupted ciphertext.

Network endpoints in the six namespaces are restricted to the isolated \`10.53.0.0/16\` laboratory. The relay has no test PSK, cannot decrypt or generate valid peer records, and forwarded 296 bytes of ciphertext during the checked normal route. No synthetic plaintext marker appeared in relay-observed datagrams. The network program deliberately uses **two distinct peer UDP sockets** (direct vs relay registration), and rebinds client transport sockets after each route change while retaining the *same record-layer session identity*. This avoids stale Linux conntrack entries from a previous failed direct candidate.

**Eight independent checked states in one crypto session:**

| Case | Expected and observed |
| --- | --- |
| Direct port unavailable, relay reachable | Encrypted relay exchange **PASS_AEAD** |
| Explicit NAT forwarding becomes available | Encrypted direct exchange with unchanged session **PASS_AEAD** |
| Identical ciphertext resent | Peer sends no response: **REPLAY_BLOCKED** |
| Direct UDP is blocked while relay remains reachable | Encrypted relay **PASS_AEAD** |
| Both usable paths unavailable | **NO_PATH**, no plaintext/different Internet fallback |
| Relay restarts | Encrypted relay reconnect, same session **PASS_AEAD** |
| Relay maliciously changes AEAD ciphertext | **AUTH_FAIL**, invalid record rejected |
| Direct UDP unblocked | Encrypted direct path, same session **PASS_AEAD** |

Lab metrics in the independent CI run: direct exchange **~0.26 ms**, encrypted relay fallback **~351 ms including 350 ms direct timeout**, no-path decision **~1251 ms including both configured timeouts**. These are *isolated LAN* numbers, not Internet VPN performance or achievable latency under a national firewall.

## Threat model, limitations and negative conclusions

**Do not deploy this record protocol.** This is a controlled interoperability/feasibility test using standard library primitives, **not a professionally reviewed secure channel protocol**.

1. The static out-of-band PSK and HKDF do **not provide forward secrecy**, authenticated online key agreement, peer enrollment, key revocation or post-compromise recovery. Compromise of the shared PSK can allow decryption of saved recordings. The first authenticated peer record pins a session only within the current process; there is **no durable replay protection across app/process restarts**.
2. A relay cannot read synthetic payload plaintext, but still observes reachable IPs, source/destination timing, packet lengths and volume. It may drop/reorder/delay traffic. There is no cover traffic, anonymity, Sybil/eclipsing defense or protection from global correlation.
3. **NAT hole punching remains UNCONFIRMED/UNRELIABLE** in the earlier study (0/6 direct in a separate sample, 6/6 relay fallback). This test uses a **deliberately added inbound NAT rule** for the direct case. Distinct peer sockets and rebinding fix the lab's stale conntrack behavior; they do not solve CGNAT or peer discovery in arbitrary networks.
4. There is **no Android VpnService**, actual IP/TUN, application traffic, DNS/IPv6 packet-level capture, Wi-Fi/mobile switching, Internet exit, or measured censorship resistance. No protection against RKN DPI has been measured here.
5. Only synthetic test probes are permitted. The relay, the discovery system and volunteers are not assumed trustworthy. No public volunteer egress was enabled; no user keys, subscriptions or private destinations were used.

**G2 result: PARTIAL**, security lab invariants PASS; all actual product/physical-device release gates remain OPEN. The working Android Xray implementation in \`main\` was not changed.

## Next falsifiable gate

Replace static test-PSK provisioning with **a vetted authenticated key agreement protocol** (e.g. a reviewed Noise construction or a maintained QUIC/TLS library), pinned and reproducibly integrated. Test identity binding, transcript authentication, restart/rekey behavior, simultaneous sessions and deliberate replay after restart *before* routing any Android traffic. Follow with bounded relay resource accounting and Android-only, opt-in isolated device-to-device tests. Do not invent new cryptography or advertise "absolute anonymity".
