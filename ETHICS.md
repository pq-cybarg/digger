# digger ethical contract

digger is a **defensive host-forensics tool**. Every principle below
is enforced by `digger.ethics.contract` — callers that try to act
outside the contract raise `EthicsViolation` rather than proceed.

## Local host only  *(P1.local-host-only)*

digger inspects the host it runs on. No port scanning of remote infrastructure, no vulnerability scanning across the network, no reconnaissance against third-party systems.

## Observation by default, action by explicit choice  *(P2.observation-default)*

Findings describe what was observed; remediation is *printed* for the user to run. No auto-remediation without interactive consent.

## No exploitation  *(P3.no-exploitation)*

We detect vulnerable versions; we never actively exploit them to confirm. Passive scanner only.

## No credential attacks  *(P4.no-credential-attacks)*

No password cracking, no hash brute-force. Defensive checks (file perms on credential stores, plaintext credentials in tracked files) are fine. Cracking is not.

## No deception or surveillance of third parties  *(P5.no-third-party-surveillance)*

No honeypot deployment, no MITM, no monitoring of co-tenants without explicit recorded consent.

## No network egress without opt-in  *(P6.no-egress-without-opt-in)*

Air-gap mode is first-class. Intel feeds, LLM triage, VirusTotal lookups, TAXII pushes: every outbound HTTP is gated.

## Calibrated findings  *(P7.calibrated-findings)*

False positives are bugs. Severity reflects evidence-backed risk, not theatrical urgency.

## No biometric or sensitive personal collection  *(P8.no-biometric-collection)*

No camera, no microphone, no keystroke logging. Investigation artifacts get TLP/classification markings.

## Refuse compromised configurations  *(P9.refuse-compromised-config)*

If asked to operate in a way that would harm a third party or bypass consent, refuse with EthicsViolation.

## Source-visible, audit-friendly  *(P10.audit-visible)*

Every finding traces back to artifacts. No hidden behavior. Algorithm choices documented in module docstrings.

---

## Contrast: where digger explicitly is NOT a Decepticon

Responsible offensive-security tools (e.g. 
[PurpleAILAB/Decepticon](https://github.com/PurpleAILAB/Decepticon))
execute realistic attack chains — reconnaissance, exploitation,
privilege escalation, lateral movement, C2 — under a written RoE /
ConOps / Deconfliction Plan / OPPLAN. Their engagement-planning
discipline is the right model for any security tool that touches a
system; digger borrows it via `digger.ethics.engagement.EngagementScope`.

But the **execution model** is the opposite:

| Decepticon (offensive)            | digger (defensive)                  |
|-----------------------------------|-------------------------------------|
| Reconnaissance against targets    | **P1** — local host only            |
| Exploitation of CVEs              | **P3** — detect, don't exploit      |
| Privilege escalation              | Read in user context, no escalation |
| Lateral movement                  | **P1** — refuses to leave the host  |
| C2 channel establishment          | No outbound except opted-in feeds   |
| Credential dumping / Mimikatz     | **P4** — no credential attacks      |
| Honeypot / deception deployment   | **P5** — no deception operations    |

Decepticon's sandbox-net isolation exists because its operations are
inherently dangerous. digger needs no equivalent — the operations
themselves are non-modifying observation.
