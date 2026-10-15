# Ω Horizon: isolated authenticated-path lab

**Research-only prototype. NOT a production VPN, censorship-bypass tool, or Tor replacement.**
This directory is deliberately not imported by the Android application. It handles no TUN/IP/DNS packets, has no Internet exit, does not discover public peers, and cannot traverse NAT.

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

Neither NAT traversal nor UDP/ICE/STUN/TURN is implemented. There is no third-party volunteer exit, no Android integration, no DNS/IPv6 leak test and no benchmark against Tor, Snowflake or Xray. No result here should be described as real anti-DPI protection.

Next: separate Linux network namespaces with authorized NAT topologies, direct UDP path discovery and relay fallback, measured without allowing clear-net user traffic. Public peer discovery and opt-in exits require separate review and consent.
