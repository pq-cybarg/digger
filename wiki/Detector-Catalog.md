# Detector catalog

All 32 detectors registered in `digger/detectors/__init__.py:all_detectors()`.

Severity ladders: `info` · `low` · `medium` · `high` · `critical`.

## Foundational

| Detector | What it catches | MITRE |
|---|---|---|
| `suspicious_processes` | Shell parented by browser; interpreter in `/tmp`; no-exe processes; encoded PowerShell; pipe-to-shell | T1059 |
| `network_anomaly` | LISTEN on uncommon ports; established external connections | T1571 |
| `persistence_outlier` | Persistence entries pointing into writable / world-shared paths | T1547 |
| `lolbins` | LOLBAS / GTFOBins abuse of trusted binaries | T1218, T1059 |
| `ioc` | Plain-text IOC feed matching (SHA-256, MD5, IPv4, URL, domain) | T1071 |
| `yara` | YARA-rule matching against process exes + recent-file walks | T1027 |
| `env_hijack` | LD_PRELOAD, DYLD_INSERT_LIBRARIES, BASH_ENV, PROMPT_COMMAND, PATH-in-tmp | T1574.006 |
| `ssh_auth_keys` | authorized_keys with forced-command, oversize key lists | T1098.004 |
| `browser` | Risky extension permissions + comprehensive Chromium scanner (see [Browser scanner](https://pq-cybarg.github.io/digger/browser-scanner.html)) | T1176, T1539, T1185, T1555.003 |
| `memory_anomaly` | RWX / anonymous-exec / drop-loaded modules — escalates to critical when parented by a listening service | T1055 |
| `unsigned_binary` | codesign / dpkg -V / rpm -V failures on running binaries | T1565.001 |
| `shai_hulud` | npm worm package@version + workflow file + webhook exfil patterns | T1195.002 |
| `supply_chain` | Malicious-package matches + live CISA KEV against installed software | T1195.001, T1190 |
| `trapdoor` | TrapDoor crypto-stealer campaign (Socket Security 2026-05-24): 34 compromised packages across npm/PyPI/crates.io attributed to GitHub ddjidd564; per-ecosystem mitigation commands; campaign-marker scan (`P-2024-001`, `trap-core.js`, `ddjidd564.github.io`, `cargo-build-helper-2026`) across processes / recent files / persistence-file contents (`.cursorrules`, `CLAUDE.md`, shell rc, git hooks, systemd user units); DNS exfil-domain check. | T1195.001, T1059, T1546, T1041 |
| `c2` | Cobalt Strike / Sliver / Mythic / Brute Ratel / Havoc / Empire / Meterpreter / Nighthawk / Merlin / Covenant + named-pipe + TLS-JA3 + injection landing pad | T1071, T1573, T1095, T1055 |
| `threat_actor` | MITRE ATT&CK Enterprise groups (live STIX feed) + bundled supplemental | T1003, T1059 |
| `service_cve` | Service-version → CVE (NVD CPE-keyed live feed) | T1190 |
| `firewall_audit` | pf / nftables / iptables / ufw / firewalld / WFP audit with remediation | T1562.004 |
| `loki_style` | Bridge to Neo23x0/signature-base IOC + YARA corpus | T1027 |
| `sigma` | (Optional, run separately) match collected artifacts against Sigma rules | varies |
| `timeline` | Synthesize chronological event timeline (runs last) | — |

## Decepticon countermeasures (12)

One defensive detector per offensive kill-chain phase. All
observation-only.

| Detector | Phase | Key signals | MITRE |
|---|---|---|---|
| `recon` | Reconnaissance | Connection-table portscan footprint; SSH brute-force / banner-grab / user-enumeration | T1595.001, T1110.001, T1592.002, T1589.002 |
| `exploitation` | Exploitation | Service → shell parentage; RCE three-tier chain; 11 shellcode-shape cmdlines; web-server log exploit signatures (Log4Shell, Spring4Shell, etc.) | T1190, T1059, T1203 |
| `privesc` | Privilege escalation | World-writable setuid; setuid in scratch/home; GTFOBins-trivial setuid; sudoers NOPASSWD ALL; Linux capabilities on shells; kernel taint decoded | T1548, T1068, T1547.006 |
| `lateral` | Lateral movement | SMB/SSH/WinRM/RDP/VNC outbound to RFC1918; credential dumpers (mimikatz/Rubeus/SafetyKatz/secretsdump/LaZagne/Certipy); Impacket family by name; SSH ProxyJump; pass-the-hash 4624 markers | T1021, T1550, T1570 |
| `ad_attacks` | AD attacks | Kerberoasting (4769 RC4-HMAC); AS-REP roast (4768 PreAuthType 0); BloodHound family; DCSync via cmdline or 4662 replication-rights GUID; AdminSDHolder modification (5136) | T1558.003, T1558.004, T1003.006, T1484.001 |
| `cloud_attacks` | Cloud | IMDS endpoint hit from non-cloud-agent; cloud creds in shell env; world-readable creds files; container escape primitives; kubeconfig theft; cloud-CLI privesc commands | T1552.005, T1078.004, T1611, T1528 |
| `counter_re` | Counter-RE on us | Debuggers (gdb/lldb/dtrace/x64dbg/IDA/Ghidra/radare2/frida/WindBg) with target-PID matching digger or EDR processes | T1622, T1057 |
| `persistent_sessions` | Persistent sessions | tmux/screen/zellij parented by network service (sshd excluded); detached nohup/setsid with sockets; user-systemd ExecStart in user-writable shell scripts | T1546, T1543.002 |
| `attacker_tooling` | Tooling on host | 60+ red-team tools across 10 categories. Three detection modes: T1 running process, T2 installed package (brew/dpkg/rpm/snap/flatpak/Windows uninstall), T3 deployment artifact on disk — catches git-clone + docker-compose'd kits like Z3r0, Decepticon, Mythic, Sliver, Havoc, Empire, Metasploit even when nothing is running. Self-attribution downgrades severity for dev-clone / venv paths. | T1588.002 |
| `anti_forensics` | Covering tracks | Shell history wiping (history -c, HISTFILE=/dev/null, ~/.bash_history symlinked to /dev/null); Unix log truncation (truncate -s 0 /var/log/, journalctl --vacuum-time=1s, rm /var/log/auth.log); Windows event log clearing (wevtutil cl, Clear-EventLog); timestomping (touch -t / --reference, SetCreationTime); secure-deletion tooling (shred / srm / sdelete / wipe); tmpfs RAM-only pivots. 10th Decepticon countermeasure. | T1070, T1070.001-.006 |
| `exfiltration` | Exfiltration | Archive-then-exfil pipes (tar/zip/7z piped to curl/wget/nc); cloud-bucket cp/sync (aws s3 / gsutil / azcopy / rclone / b2 / mc); paste-bin and anonymous file-drop uploads (pastebin / transfer.sh / file.io / 0x0.st / anonfiles / bashupload); chat-webhook exfil (Slack / Discord / Telegram / webhook.site); GitHub gist creation (T1567.001); protocol-tunneling tools (dnscat2 / iodine / dns2tcp / dnsteal / chisel / ngrok / frp / cloudflared / stunnel / socat-LISTEN / serveo; ssh -R/-D/-L port-forward); sensitive-target read + network-upload primitive (SSH key / AWS creds / kubeconfig / Keychain / browser logins piped to curl/wget/nc/-Method POST/bash > /dev/tcp); DNS-tunnel-shaped labels (two adjacent 40+ char base32 labels). Self-attribution downgrades severity when tunnel binaries live in a user-local install path. 11th Decepticon countermeasure. | T1041, T1048, T1048.003, T1567, T1567.001, T1567.002, T1572 |
| `impact` | Impact (ransomware / destruction) | Ransomware encrypt-shapes (`find -exec openssl enc`, `gpg --batch --encrypt --recursive`, `7z -p -mhe -r`, `cipher /e`); known ransom-note filenames (HOW_TO_DECRYPT / _readme.txt / info.hta / lockbit-decryptor / akira_readme / ryukreadme / etc.); mass-rename footprint (≥50 files sharing a known ransomware extension `.encrypted` / `.locked` / `.wcry` / `.lockbit` / etc.); shadow-copy / system-restore deletion (vssadmin delete shadows, wmic shadowcopy delete, bcdedit recoveryenabled No, wbadmin delete catalog, Disable-ComputerRestore); security-service stop / EDR-tamper (systemctl/service stop on falcon-sensor/sentinelone/sophos/defender; net/sc/Stop-Service on WinDefend/Sense/CSFalconSvc/Sysmon; Set-MpPreference -DisableRealtimeMonitoring; Add-MpPreference -ExclusionPath; launchctl unload on macOS agents); disk wipe (`dd if=/dev/zero of=/dev/sdX`, `shred /dev/`, `wipefs -af`, `mkfs -F`, `parted mklabel`, `diskpart clean`, `format C: /q /y`); system shutdown/reboot (`shutdown -h now`, Stop-Computer -Force, halt/poweroff/init 0); cloud destruction (`aws ec2 terminate-instances`, `aws s3 rb --force`, `aws rds delete-db-instance --skip-final-snapshot`, `aws cloudtrail stop-logging`, `gcloud compute instances delete --quiet`, `az vm delete --yes`, `kubectl delete --all`, `terraform destroy -auto-approve`). 12th and final Decepticon countermeasure. | T1485, T1486, T1489, T1490, T1529, T1561, T1562.001, T1562.008 |

Full walkthrough: [docs/decepticon-counter](https://pq-cybarg.github.io/digger/decepticon-counter.html).

## Adding a new detector

See [CONTRIBUTING.md](https://github.com/pq-cybarg/digger/blob/main/CONTRIBUTING.md) — the critical
rule is **live-first**: every detector that loads bundled rule data
must also call `load_intel(...)` first. The AST-level CI test in
`tests/test_data_freshness.py` enforces this.
