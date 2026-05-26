"""Detector registry."""

from __future__ import annotations

from digger.detectors.base import Detector


def all_detectors() -> list[Detector]:
    from digger.detectors.suspicious_processes import SuspiciousProcessDetector
    from digger.detectors.network_anomaly import NetworkAnomalyDetector
    from digger.detectors.persistence import PersistenceDetector
    from digger.detectors.lolbins import LolbinDetector
    from digger.detectors.ioc import IocDetector
    from digger.detectors.yara_scan import YaraDetector
    from digger.detectors.browser import BrowserDetector
    from digger.detectors.env_hijack import EnvHijackDetector
    from digger.detectors.ssh_auth_keys import SshAuthKeysDetector
    from digger.detectors.shai_hulud import ShaiHuludDetector
    from digger.detectors.supply_chain import SupplyChainDetector
    from digger.detectors.trapdoor import TrapDoorDetector
    from digger.detectors.c2 import C2Detector
    from digger.detectors.threat_actor import ThreatActorDetector
    from digger.detectors.service_cve import ServiceCVEDetector
    from digger.detectors.firewall_audit import FirewallAuditDetector
    from digger.detectors.recon import ReconDetector
    from digger.detectors.exploitation import ExploitationDetector
    from digger.detectors.privesc import PrivescDetector
    from digger.detectors.lateral import LateralMovementDetector
    from digger.detectors.ad_attacks import ADAttackDetector
    from digger.detectors.cloud_attacks import CloudAttackDetector
    from digger.detectors.counter_re import CounterREDetector
    from digger.detectors.persistent_sessions import PersistentSessionDetector
    from digger.detectors.attacker_tooling import AttackerToolingDetector
    from digger.detectors.anti_forensics import AntiForensicsDetector
    from digger.detectors.exfiltration import ExfiltrationDetector
    from digger.detectors.impact import ImpactDetector
    from digger.detectors.collection import CollectionDetector
    from digger.detectors.nightmare_eclipse import NightmareEclipseDetector
    from digger.detectors.telemetry_jammer import TelemetryJammerDetector
    from digger.detectors.warbird_blocker import WarbirdBlockerDetector
    from digger.detectors.macos_telemetry_jammer import MacOSTelemetryJammerDetector
    from digger.detectors.linux_telemetry_jammer import LinuxTelemetryJammerDetector
    from digger.detectors.browser_telemetry_jammer import BrowserTelemetryJammerDetector
    from digger.detectors.mini_shai_hulud import MiniShaiHuludDetector
    from digger.detectors.shai_hulud_blocker import ShaiHuludBlockerDetector
    from digger.detectors.discovery import DiscoveryDetector
    from digger.detectors.vect import VectDetector
    from digger.detectors.info_stealer import InfoStealerDetector
    from digger.detectors.k8s_security import K8sSecurityDetector
    from digger.detectors.idp_security import IdpSecurityDetector
    from digger.detectors.slsa_audit import SlsaAuditDetector
    from digger.detectors.android_security import AndroidSecurityDetector
    from digger.detectors.timeline import TimelineBuilder
    from digger.loki.detector import LokiStyleDetector
    from digger.memory.detector import MemoryAnomalyDetector
    from digger.signing.detector import UnsignedBinaryDetector
    return [
        SuspiciousProcessDetector(),
        NetworkAnomalyDetector(),
        PersistenceDetector(),
        LolbinDetector(),
        IocDetector(),
        YaraDetector(),
        BrowserDetector(),
        EnvHijackDetector(),
        SshAuthKeysDetector(),
        ShaiHuludDetector(),
        SupplyChainDetector(),
        TrapDoorDetector(),
        C2Detector(),
        ThreatActorDetector(),
        ServiceCVEDetector(),
        FirewallAuditDetector(),
        ReconDetector(),
        ExploitationDetector(),
        PrivescDetector(),
        LateralMovementDetector(),
        ADAttackDetector(),
        CloudAttackDetector(),
        CounterREDetector(),
        PersistentSessionDetector(),
        AttackerToolingDetector(),
        AntiForensicsDetector(),
        ExfiltrationDetector(),
        ImpactDetector(),
        CollectionDetector(),
        NightmareEclipseDetector(),
        TelemetryJammerDetector(),
        WarbirdBlockerDetector(),
        MacOSTelemetryJammerDetector(),
        LinuxTelemetryJammerDetector(),
        BrowserTelemetryJammerDetector(),
        MiniShaiHuludDetector(),
        ShaiHuludBlockerDetector(),
        DiscoveryDetector(),
        VectDetector(),
        InfoStealerDetector(),
        K8sSecurityDetector(),
        IdpSecurityDetector(),
        SlsaAuditDetector(),
        AndroidSecurityDetector(),
        LokiStyleDetector(),
        MemoryAnomalyDetector(),
        UnsignedBinaryDetector(),
        TimelineBuilder(),  # last — produces a synthetic timeline
    ]
