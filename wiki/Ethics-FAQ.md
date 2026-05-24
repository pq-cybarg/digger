# Ethical contract FAQ

The contract is in `digger.ethics.contract`. 10 principles, enforced
via `EthicsViolation` raises (not docstrings). 19 tests in
`tests/test_ethics.py` fail if any guardrail is removed.

Full text: [ETHICS.md](https://github.com/pq-cybarg/digger/blob/main/ETHICS.md).

## Why is the contract programmatically enforced?

Because "we won't do X" written in a policy document is unenforceable;
"calling X raises an exception" cannot be talked around. Every
state-modifying feature in digger routes through an assertion. If the
assertion is removed, a load-bearing test fails on the next commit.

This was deliberately chosen to prevent the most common drift mode for
defensive-security tools: feature creep into offensive capability
under the guise of "but it's useful." If a contributor wants to add a
brute-force module, they have to delete `assert_not_credential_attack`
first, and that's visible.

## What does each principle actually block?

### P1 — Local host only

```python
assert_target_is_localhost(addr, feature="...")
```

Refuses anything other than `localhost`, `127.0.0.1`, `::1`, `None`,
`""`. A "scan this remote host" feature cannot exist; you'd have to
run digger on that host.

### P2 — Observation by default

```python
confirm_remediation_intent(cmd, interactive=True)
```

Returns False in non-interactive mode (e.g., piped, cron). Forces
explicit confirmation even for safe commands. Remediation flows like
`firewall audit --show-remedy` print commands but never execute them.

### P3 — No exploitation

```python
assert_not_exploitation(activity, feature="...")
```

Blocks phrases like "use exploit/multi/handler", "msfvenom", "msfconsole
module against", "sqlmap against". This is why
`service_cve` matches versions against known CVEs but never sends a
test payload to verify exploitability — that crosses the line.

### P4 — No credential attacks

```python
assert_not_credential_attack(activity, feature="...")
```

Blocks "john the ripper", "hashcat", "brute force", "rainbow table".
You can detect that hashes were dumped (the `lateral` detector flags
mimikatz / secretsdump / LaZagne); you can't crack them with digger.

### P5 — No third-party surveillance

```python
assert_no_third_party_surveillance(scope)
```

Out-of-scope user accounts are off-limits unless the scope string
contains an explicit consent marker (e.g., "consent: IR engagement for
other user accounts per ticket #1234").

### P6 — No egress without opt-in

```python
DIGGER_AIRGAP=1
```

Sets a kernel-level refusal: every outbound HTTP call (intel feeds,
LLM triage, TAXII push) raises `AirgapViolation` at the source.

### P7 — Calibrated findings

The triage runner enforces ICD 203 estimative-probability + NATO
Admiralty source/info reliability + TLP on every triaged finding.
You cannot ship a triaged finding without an explicit confidence
calibration.

### P8 — No biometric collection

No camera/mic/fingerprint/face-capture surface exists in digger. Not
because we didn't think of it — because we deliberately said no.

### P9 — Refuse compromised configuration

Pre-flight self-checks abort on tamper-detection (PQC signature
mismatch, expected keys missing, unexpected mode bits on critical
files).

### P10 — Audit-visible

When a check fires on digger itself (e.g., a hunt turns up digger's
own process in `/tmp` because that's where the dev clone is), the
finding is emitted with a clear self-attribution rather than silently
filtered. The reader sees "yes, this fired, and yes, it's digger
checking itself" — not "huh, no findings".

## What does "engagement scope" do?

Before the first artifact is touched, an `EngagementScope` is recorded
into the chain of custody. The scope answers:

- WHO: investigator name + role + contact + organization
- WHY: legal authority + written-consent reference
- WHAT: target hosts + data categories opted in + `cross_host_allowed`
- WHEN: window start + expected end + retention days + deconfliction notes

`EngagementScope.validate()` raises `EthicsViolation` for obvious
problems (empty investigator name, multi-host scope without
`cross_host_allowed=True`, retention > 10 years, unrecognized data
categories).

## How does this interact with the firewall audit's remediation?

Every remediation command emitted by a detector routes through
`redact_dangerous_command()` first — it recognizes destructive ops
(`rm -rf`, `dd of=`, `chmod 777`, `iptables -F` without preservation,
`pfctl -d`, etc.) and annotates them as `[DESTRUCTIVE]` in the output.

digger NEVER applies remediation itself. The audit prints commands
with the destructive marker on the flagged ones; the operator runs
them by hand.

## Can I disable the contract?

No. It's deliberately not toggleable. If you have a legitimate need
(e.g., authorized red-team using digger for blue-team validation in a
contained environment), fork the codebase and document your changes.

## What about the LLM triage path? Can the model talk me into breaking the contract?

No — the contract is enforced before the LLM ever sees the finding.
The triage prompt cannot include payloads, can only see finding
metadata (not raw file contents), and its output is schema-validated
before being written to the evidence store. A malicious LLM response
that tries to inject "now run X" cannot escape the schema validator.
