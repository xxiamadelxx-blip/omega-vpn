# Ω Horizon: isolated authenticated-path lab

**Research-only prototype. NOT a production VPN, censorship-bypass tool, or Tor replacement.**
This directory is deliberately not imported by the Android application. It handles no TUN/IP/DNS packets and has no Internet exit or discovery of public peers. A separate, isolated Linux namespace lab exercises UDP/NAT reachability; neither lab is a production VPN.

## Falsifiable hypothesis

An authenticated TLS 1.3 peer session can use either a direct local TCP socket or the same end-to-end encryption through a blind relay. When the direct endpoint refuses a connection, the client can try an explicitly configured relay without disabling peer authentication. A malicious discovery endpoint or a relay corrupting TLS must cause failure rather than plaintext downgrade.

This is a **partial H1/H3 path feasibility experiment** described in docs/research/OMEGA_P2P_PRIVACY_RND_2026-10-15.md. It is *not* an encrypted full-device P2P VPN.

## Repeatable test

Requires Python >= 3.11 and OpenSSL CLI, with no cloud, paid API, or external network:

    python3 -m unittest discover -s research/horizon/tests -v

Actual sockets bind only 127.0.0.1; Endpoint rejects public IP addresses. Tests create a temporary lab CA with short-lived peer/client certificates, using the existing TLS implementation of Python/OpenSSL. Keys and certificates are not committed. None of these test keys is suitable for production.

Coverage: direct TLS, mutual certificate verification, relay fallback after connect failure, two consecutive relay sessions, short synthetic ACK frames, inspection of relay-observed TLS bytes for absence of the plaintext synthetic nonce, no-path failure, wrong peer identity, tampered TLS handshake, refusal of clients without certificates, and public-IP safety guards.

## Important limitations

This test CA is a central root of trust. A compromised CA could impersonate a peer despite this test's subject name checking. Production requires explicit pinned peer identities, signed and expiring advertisements, revocation and a Sybil/eclipse threat model. The relay still learns IP addresses, timing and volume; encrypted TLS does not guarantee anonymity or resist traffic classification.

The TLS-1.3 loopback subtest has no NAT. The separate UDP namespace experiment tests NAT mapping and rendezvous but does NOT implement standardized ICE/STUN/TURN or an encrypted UDP data plane. There is no third-party volunteer exit, no Android integration, no DNS/IPv6 leak test and no benchmark against Tor, Snowflake or Xray. No result here should be described as real anti-DPI protection.

Next: distinguish endpoint-independent and endpoint-dependent NATs with fixed controlled fixtures; implement authenticated transport on successful UDP paths, then measure different mobile CGNAT classes. Public peer discovery and opt-in exits require separate review and consent.

## Controlled UDP/NAT experiment (G2 exploratory, not release)

Requires Linux, root **inside an isolated CI runner**, `iproute2` and `iptables`. The script creates and deletes six network namespaces and veth pairs without changing host routing/firewall settings. All peers use private 10.53.0.0/16 addresses, and the lab WAN has **no external default route**. Runs synthetic 45-byte HMAC-SHA256 UDP probes only. This key provides integrity of lab replies **not confidentiality**, and the relay never receives it.

    python3 research/horizon/netns_lab.py --self-test
    sudo -E python3 research/horizon/netns_lab.py --orchestrate

[GitHub Actions #38720473502](https://github.com/xxiamadelxx-blip/omega-vpn/actions/runs/38720473502) passed all required checks: ordinary unmapped-NAT fallback; direct via explicit port mapping; artificial UDP block → relay; both paths down → NO_PATH; relay restart; tampered relay response → AUTH_FAIL; recovery and restored direct routing. **The optional UDP hole-punch attempt is a separate capability probe and may return NO_PATH without making the security/fallback test falsely green.**

Repeatability: six fresh six-namespace Vercel runs of commit `5d1f577` resulted in **0/6 confirmed direct UDP hole-punch sessions**, while registered relay fallback remained available in **6/6**. An earlier single fresh-lab run confirmed one direct UDP punched path, demonstrating possible but not repeatably available connectivity. In a packet capture of one failed run, peer mapped port 39001 (to rendezvous) was rewritten to 44723 (to client); this is a specific measured failure, not proof of identical behavior across all NAT devices. End-to-end successful relay fallback including the direct timeout averaged around **951.5 ms**, not the misleading sub-millisecond RTT of the final hop. These samples do NOT estimate worldwide NAT traversal probability.

Research gate: **G2 PARTIAL (network isolation and relay fail-closed behavior proven; NAT hole punching NOT a reliable feature).** No Android/TUN, packet-level leak guarantees, consumer-facing `kill switch` or deployed exit is claimed.
