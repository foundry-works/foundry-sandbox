# Foundry Security Gaps Assessment

## Bottom line

- No obvious critical gap for Foundry's stated threat model (protecting against accidental/malicious automation in sandboxed development).
- There are important caveats and non-goals that matter for risk posture.

## Major Caveats

1. Not a targeted-attacker boundary.
2. Credential isolation is optional; disabling it exposes real credentials to the sandbox.
3. In credential-isolation mode, the sandbox runs with `read_only: false` (accepted risk with mitigations).
4. `CAP_NET_ADMIN` is granted during setup for DNS firewalling (mitigated, but still additional capability).
5. Unified proxy remains a high-value trusted component with parser attack surface (mitigated via limits/timeouts/fail-closed behavior).

## If Comparing Against egg

- Foundry does not natively provide egg-style process governance controls:
1. Phase-gated SDLC operation permissions.
2. Role-based contract mutation ownership.
3. Built-in HITL phase-approval workflow.
