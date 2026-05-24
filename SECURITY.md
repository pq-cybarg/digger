# Security policy

## Reporting a vulnerability in digger itself

If you find a security bug **in digger's code** (privesc, sandbox
escape, code execution from a malicious case bundle, signature-bypass,
PQC-key handling flaw, etc.), please report it privately so it can be
fixed before disclosure.

**Preferred channel:** GitHub's private vulnerability reporting flow at
https://github.com/pq-cybarg/digger/security/advisories/new

Or, if you prefer not to use GitHub: email `resistant@tuta.com` with
subject prefix `[digger-sec]`. PGP key on request.

### What to include

- digger version (commit hash or `digger --version`) and how it was installed
- Reproducer (minimal case-dir, command, expected vs actual)
- Impact assessment from your perspective
- Whether the bug is exploitable from a malicious **case bundle**
  (someone hands you a `.digger` archive), a malicious **intel-feed
  response**, a malicious **target file** (during collection), or
  another vector
- Whether the bug breaks any of the [10 ethical-contract
  principles](ETHICS.md) — those are load-bearing; a regression there
  is a higher-severity issue than a typical functional bug

### Response timeline

- Acknowledgement: within 72 hours
- Triage + severity assessment: within 7 days
- Patch + advisory: target 30 days for high-severity, 90 days for
  lower-severity
- Credit in the advisory unless you ask to remain anonymous

## What is *not* a digger vulnerability

The following are by-design behaviors, not security bugs:

- **The evidence DB contains sensitive data.** Process command lines,
  browser history, password-store counts, etc. — that's what a
  forensic capture is. Don't ship the DB anywhere unencrypted; use
  `digger opsec redact` or `digger opsec encrypt`.
- **digger detects itself.** When digger runs on a host, its own
  process shows up in the process collector and its own files in the
  filesystem walk. The self-id module surfaces this with a clear
  annotation rather than filtering — see P10 in [ETHICS.md](ETHICS.md).
- **A live-feed source goes down.** Detectors degrade gracefully when
  a feed is missing. If the feed has tampered content, the PQC
  integrity check on the intel cache will refuse to use it (when
  `DIGGER_INTEL_STRICT=1` is set).
- **macOS `com.apple.provenance` xattr survives.** That's a
  kernel-protected 3-byte marker; it contains no PII. Genuine
  provenance-stripping requires booting to recovery + disabling SIP.

## Reporting a vulnerability in a *downstream* host

If you found a security issue **on a host you scanned with digger**
(i.e., digger flagged a real vulnerability in some other product), the
right disclosure target is that product's vendor, not digger. Digger
is the detection tool; the vulnerability is theirs to fix.

## Cryptographic algorithms

digger uses NIST-finalized post-quantum algorithms via
[liboqs](https://github.com/open-quantum-safe/liboqs):

- **Signature:** ML-DSA-65 (FIPS 204)
- **KEM:** ML-KEM-768 (FIPS 203)
- **Classical:** SHA-256 + SHA3-256 (paired chain), AES-256-GCM
- **FIPS 140-3 mode:** KATs run on the above set at startup; non-FIPS
  algorithms refuse to bind in `--fips-mode`.

If you find a flaw in our **use** of these algorithms (key handling,
nonce reuse, signature-verification bypass), please report per the
process above. Issues in the algorithms themselves should go to
liboqs / NIST.
