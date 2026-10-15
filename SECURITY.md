# Security Policy

Flipping Nero is a red team tool for **authorized** security testing. This policy covers
the software itself, not the networks you test with it.

## Authorized use only

Using Flipping Nero against networks you do not own or are not written-permission
authorized to test is illegal in most jurisdictions. The scope guard, approval chain and
audit log are there to keep authorized engagements disciplined and documented; they are
not a substitute for permission.

## Reporting a vulnerability

If you found a security issue in the app itself (a way to bypass the ScopeGuard, the risk
assessment or the approval flow, an injection that defeats the `Untrusted` fencing, a leak
of loot values or provider keys), please report it privately:

1. Open a GitHub security advisory on this repository ("Report a vulnerability"), or
2. Email the maintainer via the address on the GitHub profile.

Please do **not** open public issues for exploitable weaknesses. Include reproduction
steps and, if possible, the audit log lines. You can expect a response within a few days.

## Invariants we consider security-critical

- Risk is computed in code from the parsed call; the model never influences it.
- Without an armed scope, no network tool executes.
- Capability-gated tools (exploit modules, credential spray) refuse to run until the
  operator armed engagement.
- Loot values appear redacted everywhere except one approval dialog, and reach the
  Keychain only through an approval.
- The pivot relay is operator-only; there is deliberately no agent tool for it.
