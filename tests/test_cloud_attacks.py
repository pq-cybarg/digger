"""CloudAttackDetector — IMDS, cloud creds, kubeconfig, container escape."""

from __future__ import annotations

from digger.core.evidence import Artifact, EvidenceStore
from digger.detectors.cloud_attacks import CloudAttackDetector
from digger.genrule.sigma import finding_to_sigma


def _store(tmp_path):
    return EvidenceStore(tmp_path / "evidence.db")


def _proc(store, pid, name, exe=None, cmdline=None, connections=None,
          open_files=None, env_sample=None, username="user"):
    cm = cmdline if isinstance(cmdline, list) else [cmdline] if cmdline else []
    store.add_artifact(Artifact(
        collector="processes", category="process",
        subject=f"pid={pid} {name}",
        data={"pid": pid, "ppid": 1, "name": name,
              "exe": exe or f"/usr/bin/{name}",
              "cmdline": cm, "username": username,
              "connections": connections or [],
              "open_files": open_files or [],
              "env_sample": env_sample or {}},
    ))


def _suid(store, path, mode):
    store.add_artifact(Artifact(
        collector="linux.privesc", category="privesc_surface",
        subject=f"suid:{path}",
        data={"path": path, "mode": mode, "is_setuid": False,
              "is_setgid": False, "world_writable": False,
              "owner_uid": 1000, "owner_gid": 1000, "size": 100, "mtime": 0,
              "in_system_dir": False},
    ))


# ---- K1 IMDS ---- #


def test_curl_to_imds_flagged_critical(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "curl", exe="/usr/bin/curl",
          connections=[{"raddr": ["169.254.169.254", 80], "status": "ESTABLISHED"}])
    findings = list(CloudAttackDetector().detect(store))
    imds = [f for f in findings if "IMDS" in f.title]
    assert imds, [f.title for f in findings]
    assert imds[0].severity == "critical"
    assert imds[0].mitre == "T1552.005"
    store.close()


def test_cloud_init_to_imds_not_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "cloud-init", exe="/usr/bin/cloud-init",
          connections=[{"raddr": ["169.254.169.254", 80], "status": "ESTABLISHED"}])
    findings = list(CloudAttackDetector().detect(store))
    assert [f for f in findings if "IMDS" in f.title] == []
    store.close()


def test_imds_in_cmdline_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash",
          cmdline=["bash", "-c",
                   "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/"])
    findings = list(CloudAttackDetector().detect(store))
    imds = [f for f in findings if "IMDS" in f.title]
    assert imds
    store.close()


# ---- K2 cloud creds in shell env ---- #


def test_aws_creds_in_bash_env_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash", env_sample={
        "AWS_ACCESS_KEY_ID": "AKIA...",
        "AWS_SECRET_ACCESS_KEY": "redacted",
        "PATH": "/usr/bin",
    })
    findings = list(CloudAttackDetector().detect(store))
    cred = [f for f in findings if "Cloud credentials in shell env" in f.title]
    assert cred
    assert cred[0].mitre == "T1552.001"
    store.close()


def test_aws_creds_in_sdk_process_not_flagged(tmp_path):
    """A python AWS SDK process having AWS env vars is fine."""
    store = _store(tmp_path)
    _proc(store, 100, "python3", env_sample={"AWS_ACCESS_KEY_ID": "AKIA..."})
    findings = list(CloudAttackDetector().detect(store))
    assert [f for f in findings if "Cloud credentials in shell env" in f.title] == []
    store.close()


# ---- K4 container escape primitives ---- #


def test_release_agent_escape_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash",
          cmdline=["bash", "-c", "echo $$ > /tmp/cgrp/release_agent"])
    findings = list(CloudAttackDetector().detect(store))
    esc = [f for f in findings if "release_agent" in f.title.lower()]
    assert esc
    assert esc[0].severity == "critical"
    store.close()


def test_docker_sock_reference_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "curl",
          cmdline=["curl", "--unix-socket", "/var/run/docker.sock",
                   "http://localhost/containers/json"])
    findings = list(CloudAttackDetector().detect(store))
    esc = [f for f in findings if "docker.sock" in f.title.lower()]
    assert esc
    store.close()


def test_nsenter_pid1_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "sh",
          cmdline=["sh", "-c", "nsenter -t 1 -m -u -i -n -p sh"])
    findings = list(CloudAttackDetector().detect(store))
    esc = [f for f in findings if "nsenter" in f.title.lower()]
    assert esc
    store.close()


# ---- K5 kubeconfig theft ---- #


def test_kubeconfig_read_by_random_process_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "cat", exe="/usr/bin/cat",
          open_files=["/etc/kubernetes/admin.conf"])
    findings = list(CloudAttackDetector().detect(store))
    kc = [f for f in findings if "Kubeconfig" in f.title]
    assert kc
    assert kc[0].severity == "critical"
    store.close()


def test_kubeconfig_read_by_kubectl_not_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "kubectl", exe="/usr/local/bin/kubectl",
          open_files=["/etc/kubernetes/admin.conf"])
    findings = list(CloudAttackDetector().detect(store))
    assert [f for f in findings if "Kubeconfig" in f.title] == []
    store.close()


# ---- K6 cloud CLI ---- #


def test_aws_sts_assume_role_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "aws", exe="/usr/local/bin/aws",
          cmdline=["aws", "sts", "assume-role",
                   "--role-arn", "arn:aws:iam::123:role/Admin",
                   "--role-session-name", "x"])
    findings = list(CloudAttackDetector().detect(store))
    sts = [f for f in findings if "aws sts" in f.title.lower()]
    assert sts
    assert sts[0].severity == "medium"
    store.close()


def test_gcloud_sa_key_create_flagged(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "gcloud",
          cmdline=["gcloud", "iam", "service-accounts", "keys", "create",
                   "key.json", "--iam-account", "sa@project.iam"])
    findings = list(CloudAttackDetector().detect(store))
    gc = [f for f in findings if "gcloud" in f.title.lower()
          and "SA key" in f.title]
    assert gc
    store.close()


# ---- K3 world-readable cred files ---- #


def test_world_readable_aws_credentials_flagged(tmp_path):
    store = _store(tmp_path)
    _suid(store, "/home/alice/.aws/credentials", "0644")
    findings = list(CloudAttackDetector().detect(store))
    cf = [f for f in findings if "credentials file" in f.title.lower()]
    assert cf
    assert cf[0].severity == "high"
    store.close()


# ---- Sigma generation ---- #


def test_imds_sigma_emitted(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "curl",
          connections=[{"raddr": ["169.254.169.254", 80], "status": "ESTABLISHED"}])
    f = next(CloudAttackDetector().detect(store))
    fdict = {"detector": f.detector, "title": f.title, "summary": f.summary,
             "severity": f.severity, "evidence": f.evidence,
             "finding_uuid": "ca-1"}
    rule = finding_to_sigma(fdict, case_id="t")
    assert rule is not None
    assert "attack.t1552.005" in rule["tags"]
    store.close()


def test_container_escape_sigma_emitted(tmp_path):
    store = _store(tmp_path)
    _proc(store, 100, "bash",
          cmdline=["bash", "-c", "echo /tmp/x > /sys/fs/cgroup/release_agent"])
    f = next(CloudAttackDetector().detect(store))
    fdict = {"detector": f.detector, "title": f.title, "summary": f.summary,
             "severity": f.severity, "evidence": f.evidence,
             "finding_uuid": "ca-2"}
    rule = finding_to_sigma(fdict, case_id="t")
    assert rule is not None
    assert "attack.t1611" in rule["tags"]
    store.close()
