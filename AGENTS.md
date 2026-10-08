# AGENTS.md — Omega VPN entry point

**Single source of truth for agent behavior:** [AGENT.md](AGENT.md). Read it **before** editing code or docs. Also read [CONTEXT.md](CONTEXT.md), [MILESTONES.md](MILESTONES.md) and [README.md](README.md).

Key constraints:
- Real Android VPN with **no mandatory user payment, registration, card, paid APIs, root or owned VPN servers**. Public free nodes are untrusted, ephemeral, and require source/permission review.
- No copying Happ's proprietary implementation or assets. REA is a **research tool** in an external Vercel workbench: [docs/REA_WORKBENCH.md](docs/REA_WORKBENCH.md).
- Never bypass Capybara/Panther paywalls, accounts, quotas or trial terms.
- Prefer a proven open-source VPN engine, verify dependencies' exact licences, and preserve notices/source obligations.
- Build and test **actual packets through Android VpnService**, not only a web mock or cloud SOCKS test.
- **MVP can only be marked PASS after all M5 acceptance checks pass on the real OnePlus Nord 3 (Wi-Fi + mobile)**.
- Commit work and reproducible evidence to this repository; no success claims without tests and commit SHAs.

If asked to «продолжай», take the next unmet gate from MILESTONES.md, work independently, run appropriate checks, then commit and report the exact result.
