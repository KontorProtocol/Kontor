# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability in Kontor, please report
it **privately**. Do not open a public issue, pull request, or discussion for
security-sensitive reports.

Use GitHub's private vulnerability reporting — the **"Report a vulnerability"**
button under this repository's **Security** tab.

Please include:

- a description of the issue and its security impact;
- steps to reproduce or a proof of concept;
- the affected component(s) and the version or commit; and
- any suggested remediation.

We aim to acknowledge reports within **3 business days** and to share a
remediation timeline after triage. Please give us a reasonable window to address
the issue before public disclosure; we are glad to coordinate a disclosure date
and to credit reporters who wish to be named.

## Scope

In scope:

- The Kontor indexer / consensus node (`core/`): the reactor, the WASM contract
  runtime, Bitcoin transaction parsing, and the HTTP/WS API.
- The native contracts (`native-contracts/`).
- **Consensus-safety and determinism** issues — anything that could fork the
  metaprotocol or cause honest nodes to derive divergent state.

Reported separately:

- The proof-of-retrievability proof system lives in
  **`KontorProtocol/Kontor-Crypto`**; report circuit/SNARK issues there.

Generally out of scope:

- Denial of service from validly-priced transactions or ordinary resource use,
  and theoretical issues with no practical attack path.
- Advisories in third-party dependencies that are not reachable from Kontor
  (see `core/.cargo/audit.toml` for the documented, non-reachable set).
- Findings that require a compromised operator host or already-leaked keys.

## Threat Model

The protocol-level threat models are documented in the specifications
(`KontorProtocol/Documentation`):

- **Optimistic consensus** — Byzantine adversary ≤ 1/3 stake, with safety,
  liveness, and accountability properties (Optimistic Consensus spec,
  §Threat Model).
- **Storage protocol** — adversary capabilities, trust assumptions, and
  out-of-scope items (Storage Protocol spec, §Threat Model and the Layer 1–7
  security analysis).
- **Bridge / kBTC** (post-v1) — trust assumptions and attack vectors (Economics
  / Bridge spec).

## Status

Kontor is **pre-mainnet** software under active development; do not use it to
secure funds at risk.
