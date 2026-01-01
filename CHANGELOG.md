# CHANGELOG

All notable changes to digger.

This repository was initialized without prior git history; the v0.1.0 tag
captures the consolidated baseline. Each entry below maps to the in-session
task that produced it; file paths point to the primary artifacts so future
archaeology has a starting point.

## [0.1.0] — 2026-05-23

### Ethical contract (load-bearing, not advisory)

- **digger.ethics.contract** — 10 codified principles (P1 local-host-only
  through P10 audit-visible) enforced via `EthicsViolation` raises rather
  than docstrings. `assert_target_is_localhost`, `assert_not_exploitation`,
  `assert_not_credential_attack`, `assert_no_third_party_surveillance`,
  `assert_user_consent_for_modification`, `confirm_remediation_intent`,
  `redact_dangerous_command`.
- **digger.ethics.engagement** — `EngagementScope` (WHO/WHY/WHAT/WHEN +
  deconfliction notes) validated at case-open, recorded into chain of
  custody.
- **ETHICS.md** — auto-generated principles + Decepticon-contrast table.
- **tests/test_ethics.py** — 19 load-bearing tests.

### Threat-intel integrity + live-first convention

- **digger.intel.integrity** — PQC-sign + verify the whole intel-feed
  cache (dual SHA-256 + SHA3-256 tree hash, ML-DSA-65 signature).
- **digger.detectors._rules_io.load_intel** — verifies the cache
  signature once per process; `DIGGER_INTEL_STRICT=1` to refuse
  unsigned/tampered, `DIGGER_INTEL_NO_VERIFY=1` to silence.
- **digger.intel.feeds.Feed.fetch_fn** — composite multi-URL feed hook
  for sources NVD / SigmaHQ / MITRE that need more than one GET.
- **tests/test_data_freshness.py** — AST guardrail: every detector
  calling `load_yaml(...)` must also call `load_intel(...)` first (or
  carry a `# live-first-ok: <reason>` opt-out marker).

### New / extended live feeds

- **nvd_service_cves** — NVD API 2.0 paginated across 30 service CPEs
  (`digger/intel/sources/nvd_cpe.py`), 24h cadence.
- **sigmahq_corpus** — SigmaHQ master tarball, filtered to 8 attack
  categories (`digger/intel/sources/sigma_corpus.py`); `SigmaLoader`
  auto-extends search path with the live cache.
- **mitre_attack_groups** — MITRE ATT&CK Enterprise STIX 2.1
  (`digger/intel/sources/mitre_attack.py`), normalizes groups → software
  → techniques into the ThreatActor schema; 7-day cadence.
- **shai_hulud_packages** — new parser
  (`digger/intel/sources/shai_hulud.py`) maps the Aikido IOC JSON across
  all marker tiers (packages / unambiguous / suggestive / webhooks /
  workflow filename / artifact repos), accepts upstream field-name
  variants.
- Detector ordering reversed: live feeds authoritative,
  bundled fallback only (`supply_chain`, `shai_hulud`, `threat_actor`,
  `service_cve`).

### New collectors

- **service_versions** (`digger/collectors/common/service_versions.py`)
  — probes `<binary> --version` for 30+ services from trusted system
  paths only (no user-bin exec).
- **macos.firewall** / **linux.firewall**
  (`digger/collectors/{macos,linux}/firewall.py`) — pf, nftables,
  iptables, ufw, firewalld, plus macOS Application Firewall state.
- **linux.privesc** / **macos.privesc**
  (`digger/collectors/{linux,macos}/privesc.py`) — walks system bin
  dirs + scratch dirs + user homes for setuid/setgid binaries; capabilities;
  kernel taint.
- **linux.systemd** extended to walk `/home/*/.config/systemd/user/`
  with full unit contents.
- **browsers** collector extended with 7 new Chromium artifact families:
  cookies (per-domain counts, no values), saved-passwords summary
  (counts only), IndexedDB origins+bytes, Local Storage origins+bytes,
  installed PWAs, profile defaults (search engine, homepage, startup
  URLs, Safe Browsing flag), service workers (origins extracted from
  the SW LevelDB).

### New detectors

- **service_cve** (`digger/detectors/service_cve.py`) — semver-aware
  CVE matching against `nvd_service_cves` feed.
- **firewall_audit** (`digger/detectors/firewall_audit.py` +
  `digger/firewall/{model,parsers,audit}.py`) — 8 checks (default-deny
  inbound missing, world-listening sensitive ports, any/any rules,
  permissive outbound, AppFW disabled, backend disabled, multi-backend
  drift) with platform-specific remediation commands routed through
  `redact_dangerous_command`.
- **recon** — host-targeted reconnaissance: connection-table portscan
  footprints, SSH brute-force / banner-grab / user-enumeration from
  auth logs (T1595.001, T1110.001, T1592.002, T1589.002).
- **exploitation** — listening-service-spawned shells, three-tier RCE
  chains, 11 shellcode-shape cmdline patterns, web-server log exploit
  patterns (Log4Shell, Spring4Shell, path traversal, inline PHP,
  Shellshock, Laravel Ignition, etc.). Memory-anomaly detector
  escalates RWX/anon-exec findings to critical when the affected
  process is parented by a listening service.
- **privesc** — world-writable setuid, setuid in scratch/home,
  GTFOBins-trivial setuid (cp/mv/perl/python/awk/bash…), sudoers
  NOPASSWD: ALL, Linux file capabilities (cap_setuid etc.) on shells,
  kernel taint bit decoding.
- **lateral** — SMB/SSH/WinRM/RDP/VNC outbound to RFC1918 from non-
  admin processes, credential-dumping tools (mimikatz / Rubeus /
  SafetyKatz / secretsdump / LaZagne / Certipy), Impacket / evil-winrm /
  CrackMapExec / Responder / mitm6 by name, SSH ProxyJump chains,
  pass-the-hash markers in Windows event 4624.
- **c2** detector extended: Nighthawk / Merlin / Covenant frameworks
  added; named-pipe patterns (Cobalt Strike `MSSE-*`, Sliver `sliver_*`,
  Havoc `demon_*`); injection-landing-pad heuristic (svchost / dllhost /
  explorer / rundll32 with non-Microsoft outbound).
- **ad_attacks** — Kerberoasting (4769 RC4-HMAC), AS-REP roast (4768
  PreAuthType 0), BloodHound / SharpHound / AzureHound by name,
  DCSync via cmdline or event 4662 with replication-rights GUID,
  AdminSDHolder modification (5136), DCShadow / golden+silver ticket
  markers.
- **cloud_attacks** — IMDS endpoint (169.254.169.254) from non-cloud-
  agent processes, cloud creds in shell env, world-readable
  `~/.aws/credentials`, container-escape primitives (release_agent,
  /var/run/docker.sock, nsenter PID-1), kubeconfig theft, cloud-CLI
  privesc commands.
- **counter_re** — debuggers / RE tools (gdb / lldb / dtrace /
  x64dbg / IDA / Ghidra / radare2 / frida / WindBg) with target-PID
  matching digger itself or a defender process. Self-attribution via
  `digger.opsec.self_id`.
- **persistent_sessions** — tmux/screen/zellij parented by network
  services (sshd excluded), detached processes (nohup/setsid) with
  INET sockets, user-systemd ExecStart pointing to user-writable
  shell scripts.
- **attacker_tooling** — running OR installed offensive-security
  toolkits across 10 categories (Metasploit, Sliver, Mythic, Havoc,
  Brute Ratel, Nighthawk, Empire, Covenant, Impacket family,
  CrackMapExec / NetExec, evil-winrm, BloodHound family, Certipy,
  Responder, mitm6, bettercap, LaZagne, mimipenguin, hashcat / john,
  nmap / masscan, sqlmap / burp / ZAP, chisel / ligolo / ngrok).
  Self-attribution downgrades severity for dev-clone / venv paths.
- **browser** extended: live URLhaus + ThreatFox cross-reference for
  service-worker / cookie / IndexedDB / Local Storage / PWA start-url
  origins; per-storage bloat thresholds; search-engine-hijack and
  startup-URL-bad-host checks; corpus-driven detection for unpatched-
  Chromium bugs.

### Auto-Sigma export

- **digger.detectors.base.Detector.to_sigma_template()** — classmethod
  hook for per-detector generic SIEM rules.
- **digger generate sigma --from-detectors** — emits one Sigma YAML per
  detector that implements the hook. All 9 Decepticon-countermeasure
  detectors ship templates.
- **digger.genrule.sigma._GENERATORS** — per-finding Sigma mappers for
  every new detector (process_creation / network_connection / file_event
  / windows.security log sources with proper ATT&CK tags).

### Curated rule corpora

- **digger/rules/browsers/chromium_unpatched.yaml** — class corpus for
  known-bug-the-vendor-won't-fix-but-affects-every-Chrome-user issues;
  first entry: crbug-40062121 (persistent service-worker / background-
  fetch botnet primitive, disclosed 2022, never patched). Adding new
  entries fires new findings with zero code changes.
- **digger/rules/c2/c2_signatures.yaml** doubled — Nighthawk, Merlin,
  Covenant added; `pipe_patterns`, `tls_ja3`, `injection_target_names`,
  `file_patterns` schema additions.
- **digger/rules/services/cves.yaml** removed in favor of pure live
  NVD feed (no hand-typed bundled snapshot).

### Bug fixes

- **Shai-Hulud FP storm** (#46) — 1742 critical false-positives reduced
  to 0 by tiering markers (`worm_unambiguous_markers` vs
  `worm_suggestive_markers`) and excluding Go module cache walks.
- **KEV vendor matcher** (#47) — bundle_id reverse-DNS prefix match +
  word-boundary product token; eliminates Microsoft Office → Apache
  OpenOffice false positives.
- **Cryptex allow-list** (#48) — Apple Cryptex paths (`/System/Volumes/
  Preboot/Cryptexes/`, `/System/Cryptexes/`, `/private/var/preboot/
  Cryptexes/`) recognized by the unsigned-binary detector.
- **Apple system LaunchAgent allow-list** (#49) — `/System/Library/
  Launch{Daemons,Agents}/` with `com.apple.*` labels excluded from
  persistence-outlier when they reference `/tmp/` (legitimate kdumpd /
  nfsconf socket paths).

### Tests

- 337 tests, all passing. Suite grew from 133 (entry point) → 337.
