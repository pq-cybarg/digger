"""digger CLI."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path

from digger import __version__
from digger.assets import ascii_logo
from digger.collectors import all_collectors
from digger.core import EvidenceStore
from digger.core.runner import run_collection
from digger.detectors import all_detectors


def _print_banner() -> None:
    print(ascii_logo())
    print(f"  v{__version__}\n")


# ---- subcommands --------------------------------------------------------- #


def cmd_collect(args: argparse.Namespace) -> int:
    store = EvidenceStore(args.case_dir)
    collectors = all_collectors(include_admin=not args.no_admin)
    if args.only:
        wanted = set(args.only.split(","))
        collectors = [c for c in collectors if c.name in wanted]
    print(f"running {len(collectors)} collectors → {args.case_dir}")
    summary = run_collection(
        store, collectors,
        classification=getattr(args, "classification", "UNCLASSIFIED"),
        tlp=getattr(args, "tlp", "TLP:AMBER"),
    )
    print(f"\ndone. {summary.total_artifacts} artifacts.")
    for r in summary.collector_results:
        flag = "OK"
        if r.error:
            flag = f"ERR ({r.error[:80]})"
        elif r.skipped:
            flag = f"skip ({r.reason})"
        print(f"  [{flag:30.30}] {r.name:34}  {r.artifacts_collected:>4} artifacts  ({r.elapsed_s:.2f}s)")
    store.close()
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    store = EvidenceStore(args.case_dir)
    detectors = all_detectors()
    if args.only:
        wanted = set(args.only.split(","))
        detectors = [d for d in detectors if d.name in wanted]
    print(f"running {len(detectors)} detectors over {args.case_dir}")
    total = 0
    for d in detectors:
        n = d.run(store)
        total += n
        print(f"  [{d.name:24}] {n:>4} findings")
    print(f"\ndone. {total} findings.")
    store.close()
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    from digger.ai import LLMClient, LLMConfig, TriageRunner
    from digger.ai.triage import TriageOptions

    config = LLMConfig.from_env()
    if args.llm_base_url:
        config.base_url = args.llm_base_url
    if args.llm_model:
        config.model = args.llm_model
    if args.llm_api_key:
        config.api_key = args.llm_api_key
    client = LLMClient(config)
    print(f"checking LLM at {config.base_url} (model {config.model})...")
    h = client.health()
    if not h.get("ok"):
        print(f"WARNING: LLM health check failed: {h}", file=sys.stderr)
        if not args.force:
            return 2
    store = EvidenceStore(args.case_dir)
    options = TriageOptions(
        skip_below=args.skip_below,
        only_detectors=args.only.split(",") if args.only else None,
        max_findings=args.max,
        case_summary=not args.no_case_summary,
    )
    runner = TriageRunner(client, options)
    print(f"triaging findings in {args.case_dir}")
    result = runner.run(store)
    print(f"\ndone. triaged {result['triaged']}, skipped {result['skipped']}, errors {result['errors']}")
    if result.get("case_summary"):
        print("\nCase summary:")
        print(f"  severity: {result['case_summary'].get('overall_severity')}")
        print(f"  {result['case_summary'].get('one_paragraph')}")
    store.close()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from digger.report import render_html, render_json, render_markdown
    store = EvidenceStore(args.case_dir)
    renderers = {
        "json": render_json,
        "md": render_markdown,
        "markdown": render_markdown,
        "html": render_html,
    }
    fmt = args.format.lower()
    if fmt not in renderers:
        print(f"unknown format {fmt}", file=sys.stderr)
        return 2
    content = renderers[fmt](store)
    out = args.out
    if not out:
        ext = {"json": "json", "md": "md", "markdown": "md", "html": "html"}[fmt]
        out = Path(args.case_dir) / f"report.{ext}"
    Path(out).write_text(content, encoding="utf-8")
    print(f"wrote {out}")
    store.close()
    return 0


def cmd_investigate(args: argparse.Namespace) -> int:
    """Collect + scan + triage + report in one go."""
    rc = cmd_collect(args)
    if rc != 0:
        return rc
    rc = cmd_scan(args)
    if rc != 0:
        return rc
    if not args.no_triage:
        try:
            cmd_triage(args)
        except Exception as exc:
            print(f"triage failed (continuing without AI): {exc}", file=sys.stderr)
    args.format = args.report_format
    args.out = args.report
    return cmd_report(args)


def cmd_intel_update(args: argparse.Namespace) -> int:
    from digger.intel import update_all
    only = args.only.split(",") if args.only else None
    results = update_all(
        force=args.force, only=only,
        auto_sign_key=args.sign_key,
        sign_alg=args.sign_alg,
    )
    for r in results:
        print(f"  [{r['status']:>10}] {r['feed']}")
    return 0


def cmd_intel_status(args: argparse.Namespace) -> int:
    from digger.intel import cache_status, intel_quick_status
    for s in cache_status():
        age = s["age_s"]
        age_s = f"{age:.0f}s ago" if age is not None else "never"
        flag = "STALE" if s["stale"] else "fresh"
        print(f"  [{flag:>5}] {s['name']:34}  fetched {age_s:>14}  size={s.get('size','?')}")
    qs = intel_quick_status()
    print(f"\n  integrity:")
    if qs.get("signed"):
        ts = qs.get("signed_at")
        when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else "?"
        print(f"    signed: yes  algorithm={qs.get('algorithm')}  at={when}")
        print(f"    run `digger intel verify` for a cryptographic re-check")
    else:
        print(f"    signed: no — {qs.get('reason', '')}")
        print(f"    run `digger intel sign --key <secret>` to bind a PQC signature")
    return 0


def cmd_intel_sign(args: argparse.Namespace) -> int:
    from digger.intel import sign_intel
    target = Path(args.target).expanduser() if args.target else None
    sig_path = sign_intel(target, secret_key_path=args.key,
                          algorithm=args.algorithm,
                          note=args.note or "")
    print(f"signed intel cache")
    print(f"  algorithm: {args.algorithm}")
    print(f"  signature: {sig_path}")
    return 0


def cmd_intel_verify(args: argparse.Namespace) -> int:
    from digger.intel import verify_intel
    target = Path(args.target).expanduser() if args.target else None
    result = verify_intel(target)
    if not result.signed:
        print(f"  [UNSIGNED]")
        print(f"  {result.note}")
        return 2
    if result.verified:
        print(f"  [VERIFIED]")
        print(f"  algorithm: {result.algorithm}")
        if result.computed:
            print(f"  current sha256_root:   {result.computed.sha256_root}")
            print(f"  current sha3_256_root: {result.computed.sha3_256_root}")
            print(f"  files: {result.computed.file_count}  total bytes: {result.computed.total_bytes:,}")
        return 0
    print(f"  [TAMPERED]", file=sys.stderr)
    print(f"  {result.note}", file=sys.stderr)
    return 1


def cmd_intel_watch(args: argparse.Namespace) -> int:
    from digger.intel import IntelScheduler
    sched = IntelScheduler(
        on_update=lambda r: print(f"  [{r['status']:>10}] {r['feed']} @ {time.strftime('%H:%M:%S')}"),
        force_first=args.force_first,
    )
    sched.start()
    print("intel scheduler running. Ctrl-C to stop.")
    try:
        signal.pause()
    except (KeyboardInterrupt, AttributeError):
        # signal.pause() doesn't exist on Windows — busy-wait there
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    sched.stop()
    print("\nstopped.")
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    store = EvidenceStore(args.case_dir)
    result = store.verify_chain()
    print(json.dumps(result, indent=2))
    store.close()
    return 0 if (result["artifacts_ok"]["all"] and result["findings_ok"]["all"]) else 1


def cmd_sign(args: argparse.Namespace) -> int:
    from digger.crypto import sign_evidence
    store = EvidenceStore(args.case_dir)
    message = store.chain_tip_message()
    out_path = Path(args.case_dir) / "case_signature.json"
    bundle = sign_evidence(
        message=message,
        out_path=out_path,
        algorithm=args.algorithm,
        secret_key_path=args.key,
        note=args.note,
    )
    print(f"signed chain tip with {bundle.algorithm}")
    print(f"  signature → {out_path}")
    store.close()
    return 0


def cmd_pqc_verify(args: argparse.Namespace) -> int:
    from digger.crypto import verify_evidence
    store = EvidenceStore(args.case_dir)
    message = store.chain_tip_message()
    sig_path = args.signature or (Path(args.case_dir) / "case_signature.json")
    ok = verify_evidence(message, sig_path)
    print("OK" if ok else "FAILED")
    store.close()
    return 0 if ok else 1


def cmd_pqc_info(args: argparse.Namespace) -> int:
    from digger.crypto import available_kems, available_sigs
    from digger.crypto.pqc import report_coverage
    cov = report_coverage(args.mode)
    print(json.dumps({
        "available_kems": available_kems(),
        "available_sigs": available_sigs(),
        "coverage": cov,
    }, indent=2))
    return 0


def cmd_chain_verify(args: argparse.Namespace) -> int:
    return cmd_verify(args)


# ---- compliance subcommands -------------------------------------------- #


def cmd_compliance_list(args: argparse.Namespace) -> int:
    from digger.compliance import list_frameworks, load_framework
    for name in list_frameworks():
        try:
            f = load_framework(name)
            print(f"  {name:32} {f.title}")
        except Exception as exc:
            print(f"  {name:32} (failed to load: {exc})", file=sys.stderr)
    return 0


def cmd_compliance_assess(args: argparse.Namespace) -> int:
    from digger.compliance import assess_all, list_frameworks, load_framework
    from digger.compliance.report import (
        render_compliance_html, render_compliance_md, render_compliance_json,
    )
    store = EvidenceStore(args.case_dir)
    names = args.frameworks.split(",") if args.frameworks else list_frameworks()
    out_dir = Path(args.out_dir or args.case_dir) / "compliance"
    out_dir.mkdir(parents=True, exist_ok=True)
    all_results = assess_all(store, names)
    for name, assessments in all_results.items():
        framework = load_framework(name)
        summary = {}
        for a in assessments:
            summary[a.status] = summary.get(a.status, 0) + 1
        print(f"\n{framework.id} ({framework.version}) — {len(assessments)} controls")
        for s, c in summary.items():
            print(f"  {s:>8}: {c}")
        for fmt, renderer, ext in [
            ("json", render_compliance_json, "json"),
            ("md", render_compliance_md, "md"),
            ("html", render_compliance_html, "html"),
        ]:
            if args.format in (fmt, "all"):
                (out_dir / f"{name}.{ext}").write_text(
                    renderer(framework, assessments), encoding="utf-8"
                )
    print(f"\nreports written to {out_dir}")
    store.close()
    return 0


# ---- FIPS subcommands -------------------------------------------------- #


def cmd_fips_status(args: argparse.Namespace) -> int:
    from digger.fips.mode import current_state, fips_self_test, _detect_os_fips_marker
    results = fips_self_test()
    print(json.dumps({
        "in_fips_mode_process": current_state().enabled,
        "self_test": results,
        "os_fips_marker": _detect_os_fips_marker(),
    }, indent=2, default=str))
    return 0


def cmd_fips_enable(args: argparse.Namespace) -> int:
    from digger.fips.mode import enable_fips_mode
    try:
        state = enable_fips_mode(force=args.force)
    except Exception as exc:
        print(f"FAILED to enable FIPS mode: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "enabled": state.enabled,
        "self_test_passed": state.self_test_passed,
        "os_fips_marker": state.os_fips_marker,
        "notes": state.notes,
    }, indent=2))
    return 0


# ---- export subcommands ----------------------------------------------- #


def cmd_export_stix(args: argparse.Namespace) -> int:
    from digger.exchange import to_stix_bundle
    store = EvidenceStore(args.case_dir)
    case_meta = {
        "case_id": store.get_meta("case_id"),
        "host": store.get_meta("host"),
        "ai_case_summary": store.get_meta("ai_case_summary"),
    }
    bundle = to_stix_bundle(
        case_meta,
        list(store.iter_findings()),
        sharing_tlp=args.tlp,
    )
    out = args.out or Path(args.case_dir) / "case.stix.json"
    Path(out).write_text(json.dumps(bundle, indent=2, default=str), encoding="utf-8")
    print(f"wrote STIX 2.1 bundle: {out}  ({len(bundle['objects'])} objects)")
    store.close()
    return 0


def cmd_export_misp(args: argparse.Namespace) -> int:
    from digger.exchange import to_misp_event
    store = EvidenceStore(args.case_dir)
    case_meta = {
        "case_id": store.get_meta("case_id"),
        "host": store.get_meta("host"),
    }
    event = to_misp_event(
        case_meta,
        list(store.iter_findings()),
        sharing_tlp=args.tlp,
    )
    out = args.out or Path(args.case_dir) / "case.misp.json"
    Path(out).write_text(json.dumps(event, indent=2, default=str), encoding="utf-8")
    print(f"wrote MISP event: {out}")
    store.close()
    return 0


def cmd_export_elk(args: argparse.Namespace) -> int:
    from digger.exchange.elk import ElkExporter
    store = EvidenceStore(args.case_dir)
    try:
        case_id = str(store.get_meta("case_id") or "")
        host = store.get_meta("host") or {}
        host_name = args.host_name or (
            (host.get("node") if isinstance(host, dict) else "") or ""
        )
        out = args.out or (Path(args.case_dir) / "elk.ndjson")
        exporter = ElkExporter(
            findings_index=args.findings_index,
            artifacts_index=args.artifacts_index,
        )
        n = exporter.write_file(
            store, out,
            case_id=case_id, host_name=host_name,
            include_artifacts=not args.no_artifacts,
        )
        print(f"wrote {n} NDJSON lines: {out}")
        print(
            f"  ingest: curl -X POST '<es>:9200/_bulk' "
            f"-H 'Content-Type: application/x-ndjson' --data-binary @{out}"
        )
    finally:
        store.close()
    return 0


def cmd_export_attack(args: argparse.Namespace) -> int:
    from digger.exchange import to_navigator_layer
    store = EvidenceStore(args.case_dir)
    case_meta = {
        "case_id": store.get_meta("case_id"),
        "host": store.get_meta("host"),
    }
    layer = to_navigator_layer(case_meta, list(store.iter_findings()))
    out = args.out or Path(args.case_dir) / "case.attack-navigator.json"
    Path(out).write_text(json.dumps(layer, indent=2, default=str), encoding="utf-8")
    print(f"wrote ATT&CK Navigator layer: {out}")
    store.close()
    return 0


def cmd_export_taxii(args: argparse.Namespace) -> int:
    from digger.exchange import TaxiiClient, to_stix_bundle
    import os
    store = EvidenceStore(args.case_dir)
    case_meta = {
        "case_id": store.get_meta("case_id"),
        "host": store.get_meta("host"),
        "ai_case_summary": store.get_meta("ai_case_summary"),
    }
    bundle = to_stix_bundle(case_meta, list(store.iter_findings()), sharing_tlp=args.tlp)
    client = TaxiiClient(
        base_url=args.base_url,
        username=args.username,
        password=args.password or os.environ.get("DIGGER_TAXII_PASSWORD"),
        token=args.token or os.environ.get("DIGGER_TAXII_TOKEN"),
    )
    result = client.add_objects(args.api_root, args.collection, bundle)
    print(json.dumps(result, indent=2, default=str))
    store.close()
    return 0


def cmd_sigma_scan(args: argparse.Namespace) -> int:
    from digger.exchange.sigma import SigmaDetector
    store = EvidenceStore(args.case_dir)
    dirs = [Path(d) for d in (args.dirs or "").split(",") if d]
    n = SigmaDetector(dirs=dirs).run(store)
    print(f"sigma: {n} findings")
    store.close()
    return 0


# ---- loki / signature-base subcommands -------------------------------- #


def cmd_loki_update(args: argparse.Namespace) -> int:
    from digger.loki import update_signature_base
    target = Path(args.target).expanduser() if args.target else None
    print(f"updating signature-base at {target or '~/.cache/digger/signature-base'} ...")
    result = update_signature_base(
        target=target,
        auto_sign_key=args.sign_key,
        sign_alg=args.sign_alg,
    )
    flag = "OK" if result.ok else "FAIL"
    print(f"  [{flag}] {result.method} → {result.target}")
    if result.message:
        print(f"  {result.message}")
    return 0 if result.ok else 1


def cmd_loki_status(args: argparse.Namespace) -> int:
    from digger.loki import discover_signature_base, quick_status
    from digger.loki.signature_base import load_signature_base
    root = discover_signature_base()
    if root is None:
        print("signature-base not found. Run `digger loki update` to fetch it.")
        return 1
    sb = load_signature_base(root)
    print(f"signature-base at {root}")
    for k, v in sb.summary().items():
        print(f"  {k:30} {v}")
    qs = quick_status(root)
    print(f"\n  integrity:")
    if qs.get("signed"):
        ts = qs.get("signed_at")
        when = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts)) if ts else "?"
        print(f"    signed: yes  algorithm={qs.get('algorithm')}  at={when}")
        print(f"    run `digger loki verify` for a cryptographic re-check")
    else:
        print(f"    signed: no — {qs.get('reason', '')}")
        print(f"    run `digger loki sign --key <secret>` to bind a PQC signature")
    return 0


def cmd_loki_scan(args: argparse.Namespace) -> int:
    from digger.loki import LokiStyleDetector
    store = EvidenceStore(args.case_dir)
    n = LokiStyleDetector().run(store)
    print(f"loki: {n} findings")
    store.close()
    return 0


def cmd_loki_sign(args: argparse.Namespace) -> int:
    from digger.loki import discover_signature_base, sign_snapshot
    root = Path(args.target).expanduser() if args.target else discover_signature_base()
    if root is None:
        print("signature-base not found.", file=sys.stderr)
        return 1
    sig_path = sign_snapshot(root, secret_key_path=args.key,
                              algorithm=args.algorithm, note=args.note or "")
    print(f"signed {root}")
    print(f"  algorithm: {args.algorithm}")
    print(f"  signature: {sig_path}")
    return 0


def cmd_loki_verify(args: argparse.Namespace) -> int:
    from digger.loki import discover_signature_base, verify_snapshot
    root = Path(args.target).expanduser() if args.target else discover_signature_base()
    if root is None:
        print("signature-base not found.", file=sys.stderr)
        return 1
    result = verify_snapshot(root)
    if not result.signed:
        print(f"  [UNSIGNED] {root}")
        print(f"  {result.note}")
        return 2
    if result.verified:
        print(f"  [VERIFIED] {root}")
        print(f"  algorithm: {result.algorithm}")
        if result.computed:
            print(f"  current sha256_root:   {result.computed.sha256_root}")
            print(f"  current sha3_256_root: {result.computed.sha3_256_root}")
            print(f"  files: {result.computed.file_count}  total bytes: {result.computed.total_bytes:,}")
        return 0
    print(f"  [TAMPERED] {root}", file=sys.stderr)
    print(f"  {result.note}", file=sys.stderr)
    if result.computed:
        print(f"  current sha256_root:   {result.computed.sha256_root}", file=sys.stderr)
        print(f"  current sha3_256_root: {result.computed.sha3_256_root}", file=sys.stderr)
    return 1


# ---- case diff subcommand --------------------------------------------- #


# ---- detection-rule generation --------------------------------------- #


def cmd_generate_sigma(args: argparse.Namespace) -> int:
    from digger.genrule import (
        generate_detector_templates, generate_sigma_rules, write_sigma_rules,
    )
    # --from-detectors: per-detector class-level templates, no case required.
    if getattr(args, "from_detectors", False):
        rules = generate_detector_templates()
        if not rules:
            print("no detectors implement to_sigma_template()", file=sys.stderr)
            return 1
        out_dir = Path(args.out_dir or "out/sigma")
        written = write_sigma_rules(rules, out_dir)
        print(f"generated {len(rules)} per-detector Sigma template{'s' if len(rules) != 1 else ''}")
        print(f"out: {out_dir}")
        if args.verbose:
            for p in written[:20]:
                print(f"  {p.name}")
            if len(written) > 20:
                print(f"  …and {len(written) - 20} more")
        return 0
    if not args.case_dir:
        print("--case-dir is required unless --from-detectors is set",
              file=sys.stderr)
        return 2
    store = EvidenceStore(args.case_dir)
    case_id = str(store.get_meta("case_id", ""))
    findings = list(store.iter_findings())
    if args.finding:
        findings = [f for f in findings if f["finding_uuid"] == args.finding]
        if not findings:
            print(f"no finding with uuid {args.finding}", file=sys.stderr)
            store.close()
            return 2
    rules = generate_sigma_rules(findings, case_id=case_id)
    if not rules:
        print("no findings mapped to Sigma rules", file=sys.stderr)
        store.close()
        return 1
    out_dir = Path(args.out_dir or (Path(args.case_dir) / "sigma-out"))
    written = write_sigma_rules(rules, out_dir)
    print(f"generated {len(rules)} Sigma rule{'s' if len(rules) != 1 else ''} "
          f"from {len(findings)} finding{'s' if len(findings) != 1 else ''}")
    print(f"out: {out_dir}")
    if args.verbose:
        for p in written[:20]:
            print(f"  {p.name}")
        if len(written) > 20:
            print(f"  …and {len(written) - 20} more")
    store.close()
    return 0


def cmd_art_update(args: argparse.Namespace) -> int:
    from digger.art.harness import cache_dir, update_corpus
    dest = Path(args.target).expanduser() if args.target else cache_dir()
    print(f"[art] cloning / updating into {dest}", file=sys.stderr)
    r = update_corpus(dest=dest)
    if r["stdout"]:
        print(r["stdout"], file=sys.stderr)
    if r["returncode"] != 0:
        print(f"git failed (rc={r['returncode']}): {r['stderr']}", file=sys.stderr)
        return r["returncode"] or 1
    print(f"[art] OK · cache at {r['dest']}", file=sys.stderr)
    return 0


def cmd_art_coverage(args: argparse.Namespace) -> int:
    from digger.art.harness import (
        build_coverage_matrix, coverage_report_json, coverage_report_text,
    )
    matrix = build_coverage_matrix()
    if args.format == "json":
        print(coverage_report_json(matrix))
    else:
        print(coverage_report_text(matrix))
    return 0


def cmd_falco_ingest(args: argparse.Namespace) -> int:
    from digger.falco import FalcoError, ingest_file
    store = EvidenceStore(args.case_dir)
    try:
        prio = (args.priorities.split(",") if args.priorities else None)
        rules = (args.rules.split(",") if args.rules else None)
        try:
            summary = ingest_file(
                args.log, store,
                priorities=prio, rules=rules,
                after_ts=float(args.after) if args.after else None,
                before_ts=float(args.before) if args.before else None,
                limit=int(args.limit) if args.limit else None,
            )
        except FalcoError as exc:
            print(f"falco error: {exc}", file=sys.stderr)
            return 2
        print(f"[falco] events: {summary.events_total} total, "
              f"{summary.events_emitted} emitted, "
              f"{summary.events_skipped} skipped")
        print(f"[falco] elapsed: {summary.elapsed_s:.1f}s")
        if args.verbose and summary.rules_seen:
            print("\nTop rules:")
            for rule, n in sorted(summary.rules_seen.items(),
                                    key=lambda kv: -kv[1])[:20]:
                print(f"  {rule:48s} {n:>5}")
    finally:
        store.close()
    return 0


def cmd_falco_stream(args: argparse.Namespace) -> int:
    from digger.falco import FalcoError, stream_events
    store = EvidenceStore(args.case_dir)
    try:
        try:
            summary = stream_events(
                store,
                max_events=int(args.max_events) if args.max_events else None,
            )
        except FalcoError as exc:
            print(f"falco error: {exc}", file=sys.stderr)
            return 2
        print(f"[falco] streamed {summary.events_emitted} events "
              f"({summary.events_skipped} skipped, "
              f"{summary.elapsed_s:.1f}s)")
    finally:
        store.close()
    return 0


def cmd_k8s_collect(args: argparse.Namespace) -> int:
    from digger.k8s import KubectlError, collect_cluster, discover_binary
    binary = discover_binary()
    if not binary:
        print("no kubectl binary in PATH "
              "(install via your distro package manager)",
              file=sys.stderr)
        return 1
    try:
        summary = collect_cluster(
            args.case_dir,
            binary=binary,
            context=args.context,
            namespace=args.namespace,
        )
    except KubectlError as exc:
        print(f"kubectl error: {exc}", file=sys.stderr)
        return 2
    print(f"[k8s] binary: {summary.binary}")
    if summary.context:
        print(f"[k8s] context: {summary.context}")
    if summary.namespace:
        print(f"[k8s] namespace: {summary.namespace}")
    print(f"[k8s] resources attempted: {summary.resources_attempted}, "
          f"succeeded: {summary.resources_succeeded}")
    print(f"[k8s] items emitted: {summary.items_emitted}")
    print(f"[k8s] elapsed: {summary.elapsed_s:.1f}s")
    if summary.per_resource_errors:
        print("\n  Per-resource errors:")
        for resource, err in summary.per_resource_errors.items():
            print(f"    {resource:24s} {err[:200]}")
    if args.verbose and summary.per_resource:
        print("\n  Per-resource counts:")
        for resource, n in sorted(summary.per_resource.items()):
            print(f"    {resource:24s} {n:>6}")
    return 0


def cmd_ci_workflow_audit(args: argparse.Namespace) -> int:
    from digger.ci import audit_workflows, emit_records_to_store
    store = EvidenceStore(args.case_dir)
    try:
        roots = ([r.strip() for r in args.roots.split(",") if r.strip()]
                  if args.roots else None)
        records = audit_workflows(roots=roots)
        emitted = emit_records_to_store(records, store)
        pwn = sum(
            1 for r in records
            if r.has_pull_request_target_with_checkout_head
        )
        wf_run = sum(1 for r in records if r.has_workflow_run_trigger)
        inj = sum(1 for r in records if r.injectable_interpolations)
        unpinned = sum(
            1 for r in records
            if any(not a.sha_pinned and not a.is_trusted_owner
                   and not a.is_local
                   for a in r.actions)
        )
        selfmod = sum(1 for r in records if r.self_modifying)
        print(f"[ci] workflows audited: {len(records)}")
        print(f"[ci]   pwn-request pattern:        {pwn}")
        print(f"[ci]   workflow_run-triggered:     {wf_run}")
        print(f"[ci]   injectable interpolations:  {inj}")
        print(f"[ci]   unpinned 3rd-party actions: {unpinned}")
        print(f"[ci]   self-modifying:             {selfmod}")
        print(f"[ci] artifacts emitted: {emitted}")
    finally:
        store.close()
    return 0


def cmd_mcp_audit(args: argparse.Namespace) -> int:
    from digger.mcp import audit_mcp_configs, emit_records_to_store
    store = EvidenceStore(args.case_dir)
    try:
        roots = ([r.strip() for r in args.roots.split(",") if r.strip()]
                  if args.roots else None)
        records = audit_mcp_configs(roots=roots)
        emitted = emit_records_to_store(records, store)
        proj_scoped = sum(1 for r in records if r.project_scoped)
        with_env = sum(1 for r in records if r.env)
        raw_script = sum(
            1 for r in records
            if r.pkg_ecosystem in ("raw_node", "raw_python", "raw_shell")
        )
        net_transport = sum(
            1 for r in records
            if r.transport.lower() in ("sse", "http", "https", "ws", "wss")
        )
        print(f"[mcp] MCP servers audited: {len(records)}")
        print(f"[mcp]   project-scoped:    {proj_scoped}")
        print(f"[mcp]   with env vars:     {with_env}")
        print(f"[mcp]   raw-script:        {raw_script}")
        print(f"[mcp]   network-transport: {net_transport}")
        print(f"[mcp] artifacts emitted: {emitted}")
        if args.verbose:
            print("\n  Per-config breakdown:")
            by_kind: dict[str, int] = {}
            for r in records:
                by_kind[r.config_kind] = by_kind.get(r.config_kind, 0) + 1
            for k, n in sorted(by_kind.items()):
                print(f"    {k:20s} {n:>4}")
    finally:
        store.close()
    return 0


def cmd_android_collect(args: argparse.Namespace) -> int:
    from digger.android import AdbError, collect_device, discover_binary
    binary = discover_binary()
    if not binary:
        print("no adb binary in PATH "
              "(install android-platform-tools)",
              file=sys.stderr)
        return 1
    try:
        summary = collect_device(
            args.case_dir,
            serial=args.serial,
            binary=binary,
            max_packages=int(args.max_packages)
                if args.max_packages else 600,
        )
    except AdbError as exc:
        print(f"adb error: {exc}", file=sys.stderr)
        return 2
    print(f"[android] binary: {summary.binary}")
    print(f"[android] devices in 'device' state: "
          f"{summary.devices_seen}")
    if summary.serial:
        print(f"[android] selected serial: {summary.serial}")
    print(f"[android] packages listed: {summary.packages_listed}")
    print(f"[android] packages dumped: {summary.packages_dumped}")
    print(f"[android] artifacts emitted: {summary.artifacts_emitted}")
    print(f"[android] elapsed: {summary.elapsed_s:.1f}s")
    if summary.errors:
        print("\n  Errors:")
        for err in summary.errors:
            print(f"    {err[:240]}")
    return 0 if summary.artifacts_emitted else 1


def cmd_slsa_audit(args: argparse.Namespace) -> int:
    from digger.slsa import audit_local_packages, emit_records_to_store
    store = EvidenceStore(args.case_dir)
    try:
        roots = ([r.strip() for r in args.roots.split(",") if r.strip()]
                  if args.roots else None)
        records = audit_local_packages(roots=roots)
        emitted = emit_records_to_store(records, store)
        with_att = sum(1 for r in records if r.has_attestation)
        parse_errs = sum(1 for r in records if r.parse_error)
        builder_untrusted = sum(
            1 for r in records
            if r.builder_trusted is False
        )
        print(f"[slsa] packages audited: {len(records)}")
        print(f"[slsa]   with attestation: {with_att}")
        print(f"[slsa]   parse errors:     {parse_errs}")
        print(f"[slsa]   untrusted builder: {builder_untrusted}")
        print(f"[slsa] artifacts emitted: {emitted}")
        if args.verbose:
            print("\nPer-ecosystem breakdown:")
            eco: dict[str, int] = {}
            for r in records:
                eco[r.ecosystem] = eco.get(r.ecosystem, 0) + 1
            for k, n in sorted(eco.items()):
                print(f"  {k:12s} {n:>6}")
    finally:
        store.close()
    return 0


def cmd_idp_ingest(args: argparse.Namespace) -> int:
    from digger.idp import IdpError, ingest_file
    store = EvidenceStore(args.case_dir)
    try:
        actors = ([a.strip() for a in args.actors.split(",") if a.strip()]
                  if args.actors else None)
        try:
            summary = ingest_file(
                args.log, store,
                provider=args.provider,
                after_ts=float(args.after) if args.after else None,
                before_ts=float(args.before) if args.before else None,
                actors=actors,
                limit=int(args.limit) if args.limit else None,
            )
        except IdpError as exc:
            print(f"idp error: {exc}", file=sys.stderr)
            return 2
        print(f"[idp/{summary.provider}] events: "
              f"{summary.events_total} total, "
              f"{summary.events_emitted} emitted, "
              f"{summary.events_skipped} skipped")
        print(f"[idp/{summary.provider}] elapsed: "
              f"{summary.elapsed_s:.1f}s")
        if args.verbose and summary.by_event_type:
            print("\nEvent-type distribution:")
            for et, n in sorted(summary.by_event_type.items(),
                                key=lambda kv: -kv[1])[:20]:
                print(f"  {et:32s} {n:>6}")
    finally:
        store.close()
    return 0


def cmd_plaso_info(args: argparse.Namespace) -> int:
    from digger.plaso import PlasoError, discover_binary, info
    binary = discover_binary()
    if not binary:
        print("no psort/psteal/log2timeline binary in PATH "
              "(install via `pip install plaso`)",
              file=sys.stderr)
        return 1
    print(f"[plaso] binary: {binary}")
    try:
        summary = info(args.plaso, binary=binary,
                       limit=int(args.limit))
    except PlasoError as exc:
        print(f"plaso error: {exc}", file=sys.stderr)
        return 2
    print(f"[plaso] sampled {summary.events_total} events "
          f"({summary.elapsed_s:.1f}s)")
    print(f"\nTop parsers:")
    for parser, n in sorted(summary.parsers_seen.items(),
                              key=lambda kv: -kv[1])[:20]:
        print(f"  {parser:32s} {n:>6}")
    print(f"\nTop data types:")
    for dt, n in sorted(summary.data_types_seen.items(),
                          key=lambda kv: -kv[1])[:20]:
        print(f"  {dt:48s} {n:>6}")
    return 0


def cmd_plaso_ingest(args: argparse.Namespace) -> int:
    from digger.plaso import PlasoError, ingest
    store = EvidenceStore(args.case_dir)
    try:
        parsers = (args.parsers.split(",") if args.parsers else None)
        data_types = (args.data_types.split(",")
                       if args.data_types else None)
        try:
            summary = ingest(
                args.plaso, store,
                parsers=parsers,
                data_types=data_types,
                after_ts=float(args.after) if args.after else None,
                before_ts=float(args.before) if args.before else None,
                limit=int(args.limit) if args.limit else None,
            )
        except PlasoError as exc:
            print(f"plaso error: {exc}", file=sys.stderr)
            return 2
        print(f"[plaso] events: {summary.events_total} total, "
              f"{summary.events_emitted} emitted, "
              f"{summary.events_filtered} filtered out")
        print(f"[plaso] elapsed: {summary.elapsed_s:.1f}s")
    finally:
        store.close()
    return 0


def cmd_hindsight_scan(args: argparse.Namespace) -> int:
    from digger.hindsight import (
        DEFAULT_INCLUDE, HindsightError, SUPPORTED_INCLUDE, run_scan,
    )
    if args.list_kinds:
        print("Supported deep-parse data kinds:")
        for k in SUPPORTED_INCLUDE:
            tag = "default" if k in DEFAULT_INCLUDE else "explicit"
            print(f"  {k:12s} ({tag})")
        return 0
    if not args.case_dir:
        print("--case-dir required", file=sys.stderr)
        return 2
    include = (args.include.split(",")
               if args.include else list(DEFAULT_INCLUDE))
    profiles = None
    if args.profile:
        profiles = [Path(p) for p in args.profile.split(",")]
    store = EvidenceStore(args.case_dir)
    try:
        try:
            summary = run_scan(
                store,
                deep=bool(args.deep_browser_parse),
                include=include,
                profiles=profiles,
            )
        except HindsightError as exc:
            print(f"hindsight error: {exc}", file=sys.stderr)
            return 2
    finally:
        store.close()
    if not summary["proceeded"]:
        print(f"hindsight: SKIPPED — {summary['reason']}", file=sys.stderr)
        return 1
    print(f"hindsight: scanned {summary['profiles']} profile(s), "
          f"{summary['rows_emitted']} rows emitted "
          f"(include={','.join(summary['include'])})")
    return 0


def cmd_vol_info(args: argparse.Namespace) -> int:
    from digger.volatility import (
        DEFAULT_PLUGINS, VolatilityError, discover_binary, image_info,
    )
    binary = discover_binary()
    if not binary:
        print("no Volatility 3 binary found in PATH "
              "(install via `pip install volatility3` to get `vol`)",
              file=sys.stderr)
        return 1
    print(f"[vol] binary: {binary}")
    if not args.image:
        # No image — just list curated plugins per OS
        for os_name, plugins in DEFAULT_PLUGINS.items():
            print(f"\n=== {os_name} plugins ({len(plugins)}) ===")
            for plugin, desc in plugins:
                print(f"  {plugin:30s} {desc}")
        return 0
    try:
        os_name, _info = image_info(args.image, binary=binary)
    except VolatilityError as exc:
        print(f"vol error: {exc}", file=sys.stderr)
        return 2
    print(f"[vol] image OS: {os_name}")
    plugins = DEFAULT_PLUGINS.get(os_name, [])
    print(f"[vol] curated plugins for {os_name} ({len(plugins)}):")
    for plugin, desc in plugins:
        print(f"  {plugin:30s} {desc}")
    return 0


def cmd_vol_scan(args: argparse.Namespace) -> int:
    from digger.volatility import VolatilityError, scan_image
    store = EvidenceStore(args.case_dir)
    try:
        plugins = (args.plugins.split(",")
                   if args.plugins else None)
        try:
            summary = scan_image(
                args.image, store,
                plugins=plugins, os_name=args.os,
                plugin_timeout_s=int(args.plugin_timeout),
            )
        except VolatilityError as exc:
            print(f"vol error: {exc}", file=sys.stderr)
            return 2
        print(f"[vol] image OS: {summary.os_name}")
        print(f"[vol] plugins run: {summary.plugins_run} "
              f"({summary.plugins_failed} failed)")
        print(f"[vol] rows emitted: {summary.rows_emitted}")
        print(f"[vol] elapsed: {summary.elapsed_s:.1f}s")
        if args.verbose:
            for r in summary.per_plugin:
                tag = "OK" if r.returncode == 0 else f"FAIL rc={r.returncode}"
                print(f"  [{tag:>10}] {r.plugin:28s} {len(r.rows):>5} rows "
                      f"({r.elapsed_s:.1f}s)"
                      + (f"  truncated" if r.raw_truncated else ""))
    finally:
        store.close()
    return 0


def cmd_fa_update(args: argparse.Namespace) -> int:
    from digger.forensic_artifacts import cache_dir, update_corpus
    dest = Path(args.target).expanduser() if args.target else cache_dir()
    print(f"[fa] cloning / updating into {dest}", file=sys.stderr)
    r = update_corpus(dest=dest)
    if r["stdout"]:
        print(r["stdout"], file=sys.stderr)
    if r["returncode"] != 0:
        print(f"git failed (rc={r['returncode']}): {r['stderr']}",
              file=sys.stderr)
        return r["returncode"] or 1
    print(f"[fa] OK · cache at {r['dest']}", file=sys.stderr)
    return 0


def cmd_fa_list(args: argparse.Namespace) -> int:
    from digger.forensic_artifacts import load_artifacts
    arts = load_artifacts()
    if not arts:
        print("no ForensicArtifacts loaded — run `digger fa update`",
              file=sys.stderr)
        return 1
    if args.os:
        wanted_os = args.os.lower()
        arts = [a for a in arts if a.supports(wanted_os)]
    if args.tags:
        tags = [t.strip() for t in args.tags.split(",") if t.strip()]
        arts = [a for a in arts if a.matches_tags(tags)]
    for a in arts[: args.limit or len(arts)]:
        os_list = ",".join(a.supported_os) or "all"
        labels = ",".join(a.labels) or "-"
        print(f"  {a.name:42s} [{os_list:18s}] {labels}")
    print(f"\n({len(arts)} artifacts shown)", file=sys.stderr)
    return 0


def cmd_fa_run(args: argparse.Namespace) -> int:
    from digger.forensic_artifacts import (
        ArtifactResolver, load_artifacts, run_artifact,
    )
    arts = load_artifacts()
    if not arts:
        print("no ForensicArtifacts loaded — run `digger fa update`",
              file=sys.stderr)
        return 1
    name_map = {a.name: a for a in arts}

    chosen: list = []
    if args.name:
        for n in args.name.split(","):
            n = n.strip()
            if n in name_map:
                chosen.append(name_map[n])
            else:
                print(f"unknown artifact: {n}", file=sys.stderr)
                return 2
    elif args.tags:
        tags = [t.strip() for t in args.tags.split(",") if t.strip()]
        chosen = [a for a in arts if a.matches_tags(tags)]
    else:
        print("provide --name NAME[,NAME...] or --tags TAG[,TAG...]",
              file=sys.stderr)
        return 2

    if not chosen:
        print("no artifacts matched", file=sys.stderr)
        return 1

    store = EvidenceStore(args.case_dir)
    try:
        resolver = ArtifactResolver()
        total = 0
        for a in chosen:
            n = run_artifact(
                a, store, resolver=resolver,
                all_artifacts_by_name=name_map,
            )
            total += n
            print(f"  [{a.name:40s}] {n} digger-artifacts emitted")
        print(f"\ndone. {total} artifacts total.")
    finally:
        store.close()
    return 0


def cmd_query(args: argparse.Namespace) -> int:
    from digger.query import (
        QueryError, list_canned, run_canned, run_query,
    )
    if args.list_canned:
        for name, desc in list_canned():
            print(f"  {name:30s} {desc}")
        return 0
    if not args.case_dir:
        print("--case-dir required", file=sys.stderr)
        return 2
    try:
        if args.canned:
            result = run_canned(args.canned, args.case_dir)
        elif args.sql:
            result = run_query(args.sql, args.case_dir, limit=args.limit)
        else:
            print("provide either --canned NAME, --list-canned, "
                  "or 'SELECT ...' as positional sql",
                  file=sys.stderr)
            return 2
    except QueryError as exc:
        print(f"query error: {exc}", file=sys.stderr)
        return 2
    fmt = (args.format or "text").lower()
    if fmt == "json":
        print(result.to_json())
    elif fmt == "csv":
        print(result.to_csv(), end="")
    else:
        print(result.to_text())
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    from digger.watch import run_watch
    interval = float(args.interval)
    only_c = args.only_collectors.split(",") if args.only_collectors else None
    only_d = args.only_detectors.split(",") if args.only_detectors else None
    alert = args.alert_on.split(",") if args.alert_on else None
    return run_watch(
        case_dir=args.case_dir,
        interval_s=interval,
        only_collectors=only_c,
        only_detectors=only_d,
        alert_on=alert,
        webhook_url=args.webhook,
        verbose=args.verbose,
        include_admin=not args.no_admin,
    )


def cmd_storyline(args: argparse.Namespace) -> int:
    from digger.report.storyline import (
        build_storylines, render_storyline_text, render_storyline_markdown,
        storylines_to_json,
    )
    import json as _json
    store = EvidenceStore(args.case_dir)
    try:
        storylines = build_storylines(store=store)
    finally:
        store.close()
    fmt = (args.format or "text").lower()
    if fmt == "json":
        print(_json.dumps(storylines_to_json(storylines), indent=2, default=str))
    elif fmt in ("md", "markdown"):
        print(render_storyline_markdown(storylines, top_n=args.top))
    else:
        print(render_storyline_text(storylines, top_n=args.top))
    return 0


def cmd_generate_heatmap(args: argparse.Namespace) -> int:
    from digger.genrule.heatmap import (
        build_coverage, render_html, render_json, render_text, write_heatmap,
    )
    coverage = build_coverage()
    fmt = args.format
    if args.out:
        out_path = Path(args.out)
        written = write_heatmap(coverage, fmt=fmt, out_path=out_path)
        print(f"wrote {written}", file=sys.stderr)
        s = coverage["summary"]
        print(
            f"coverage: {s['detectors_total']} detectors · "
            f"{s['techniques_covered']} techniques · "
            f"{s['tactics_covered']} of 14 tactics",
            file=sys.stderr,
        )
        return 0
    if fmt == "html":
        print("--out is required for --format html", file=sys.stderr)
        return 2
    if fmt == "json":
        print(render_json(coverage))
    else:
        print(render_text(coverage))
    return 0


# ---- memory subcommands ----------------------------------------------- #


def cmd_memory_scan(args: argparse.Namespace) -> int:
    from digger.memory.maps import list_regions_for_pid, list_regions_for_all_pids
    from digger.memory.scanner import _compile_rules, yara_scan_region

    if args.pid:
        targets = {args.pid: list_regions_for_pid(args.pid)}
    else:
        targets = list_regions_for_all_pids()

    rules = _compile_rules() if args.yara else None
    if args.yara and rules is None:
        print("(yara-python not installed or no rules found — running without YARA)", file=sys.stderr)

    flagged = 0
    total_pids = len(targets)
    total_regions = 0
    for pid, regions in targets.items():
        suspect = [r for r in regions if r.is_anonymous_exec or r.is_rwx or r.is_backing_in_drop]
        total_regions += len(regions)
        if not suspect:
            continue
        flagged += 1
        try:
            import psutil
            name = psutil.Process(pid).name()
        except Exception:
            name = "?"
        print(f"\npid={pid} {name}  — {len(suspect)} suspect region(s) of {len(regions)} total")
        for r in suspect[:10]:
            tags = []
            if r.is_rwx:               tags.append("RWX")
            if r.is_anonymous_exec:    tags.append("ANON-EXEC")
            if r.is_backing_in_drop:   tags.append("DROP-BACKED")
            print(f"  {r.perms} 0x{r.start:016x}-0x{r.end:016x} ({r.size:>10} B) "
                  f"[{','.join(tags):<25}] {r.backing}")
            if rules:
                hits = yara_scan_region(r, rules=rules)
                for h in hits:
                    print(f"     YARA: rule={h['rule']} tags={h['tags']}")
        if len(suspect) > 10:
            print(f"  …{len(suspect) - 10} more")
    print(f"\nscanned {total_pids} pid(s), {total_regions} total regions, {flagged} pid(s) flagged")
    return 0


def cmd_memory_dump(args: argparse.Namespace) -> int:
    from digger.memory.maps import list_regions_for_pid
    from digger.memory.dumper import dump_region, can_dump_pid

    ok, reason = can_dump_pid(args.pid)
    if not ok:
        print(f"cannot dump pid {args.pid}: {reason}", file=sys.stderr)
        return 2

    regions = list_regions_for_pid(args.pid)
    if args.addr:
        addr = int(args.addr, 0)
        target = next((r for r in regions if r.start == addr), None)
        if target is None:
            print(f"no region at {args.addr}", file=sys.stderr)
            return 2
        regions = [target]
    else:
        regions = [r for r in regions if r.is_anonymous_exec or r.is_rwx]

    Path(args.out_dir).mkdir(parents=True, exist_ok=True)
    written = 0
    for r in regions:
        data = dump_region(r, max_bytes=args.max_bytes)
        if data is None:
            continue
        name = f"pid{args.pid}-0x{r.start:016x}-{r.perms}.bin"
        out = Path(args.out_dir) / name
        out.write_bytes(data)
        print(f"  wrote {out}  ({len(data):,} B)")
        written += 1
    print(f"\ndumped {written} region(s) to {args.out_dir}")
    return 0


# ---- opsec subcommands ------------------------------------------------ #


def cmd_opsec_status(args: argparse.Namespace) -> int:
    from digger.opsec import opsec_status
    print(json.dumps(opsec_status(), indent=2, default=str))
    return 0


def cmd_opsec_watchers(args: argparse.Namespace) -> int:
    from digger.opsec import find_watchers
    ws = find_watchers()
    if not ws:
        print("no watchers detected")
        return 0
    by_sev = {"high": [], "medium": [], "low": [], "info": []}
    for w in ws:
        by_sev.setdefault(w.severity, []).append(w)
    for sev in ("high", "medium", "low", "info"):
        for w in by_sev.get(sev, []):
            print(f"  [{sev:>6}] {w.category:>16} pid={str(w.pid or '-'):>6} {w.name}")
            if args.verbose:
                print(f"           {w.note}")
                if w.cmdline:
                    print(f"           {w.cmdline[:160]}")
    return 0


def cmd_opsec_encrypt(args: argparse.Namespace) -> int:
    from digger.opsec import encrypt_case
    result = encrypt_case(
        case_dir=args.case_dir,
        out_path=args.out,
        recipient_public_key=args.recipient,
        kem_alg=args.kem_alg,
        sign_with_secret_key=args.sign_key,
        sig_alg=args.sig_alg,
    )
    print(f"encrypted case {result.case_id}")
    print(f"  algorithm: {result.kem_alg}" + (f" + signed with {result.sig_alg}" if result.signed else ""))
    print(f"  out: {result.out_path}  ({result.bytes_written:,} bytes)")
    return 0


def cmd_opsec_decrypt(args: argparse.Namespace) -> int:
    from digger.opsec import decrypt_case
    out = decrypt_case(
        in_path=args.in_path, recipient_secret_key=args.key,
        out_dir=args.out_dir, verify_signature=not args.no_verify_sig,
    )
    print(f"decrypted to {out}")
    return 0


def cmd_opsec_redact(args: argparse.Namespace) -> int:
    from digger.opsec import RedactionPolicy, redact_case
    policy = RedactionPolicy(
        redact_public_ips=args.redact_public_ips,
        redact_hostnames=not args.keep_hostnames,
        redact_usernames=not args.keep_usernames,
        drop_raw_blobs=not args.keep_raw_blobs,
    )
    summary = redact_case(args.case_dir, args.out_dir, policy=policy)
    print(json.dumps(summary, indent=2, default=str))
    return 0


def cmd_opsec_wipe(args: argparse.Namespace) -> int:
    from digger.opsec import secure_wipe_dir
    if not args.yes:
        print(f"refusing to wipe {args.case_dir} without --yes", file=sys.stderr)
        return 2
    result = secure_wipe_dir(args.case_dir, passes=args.passes)
    print(f"wiped {result.target}")
    print(f"  files overwritten: {result.files_overwritten}")
    print(f"  bytes overwritten: {result.bytes_overwritten:,}")
    print(f"  files unlinked:    {result.files_unlinked}")
    if result.errors:
        print("  errors:")
        for e in result.errors:
            print(f"    {e}")
    if result.note:
        print(f"\n  note: {result.note}")
    return 0 if not result.errors else 1


# ---- hunt subcommands ------------------------------------------------- #


def cmd_hunt_list(args: argparse.Namespace) -> int:
    from digger.hunts import all_hunts
    hunts = all_hunts()
    if args.tag:
        hunts = [h for h in hunts if args.tag in h.tags]
    print(f"{len(hunts)} hunt{'s' if len(hunts) != 1 else ''} available\n")
    for h in hunts:
        print(f"  [{h.severity_hint:>8}] {h.id:34} {h.title}")
        if args.verbose:
            print(f"           tags: {', '.join(h.tags) or '—'}  mitre: {h.mitre or '—'}")
            print(f"           {h.description[:220]}")
            print()
    return 0


def cmd_hunt_run(args: argparse.Namespace) -> int:
    from digger.hunts import all_hunts, run_hunt
    from digger.hunts.report import (
        render_hunts_html, render_hunts_json, render_hunts_markdown,
    )
    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    min_sev = sev_order.get(args.severity, 0)

    hunts = all_hunts()
    if args.hunt:
        wanted = {n.strip() for n in args.hunt.split(",")}
        hunts = [h for h in hunts if h.id in wanted]
    if args.tag:
        hunts = [h for h in hunts if args.tag in h.tags]
    hunts = [h for h in hunts if sev_order.get(h.severity_hint, 0) >= min_sev]

    if not hunts:
        print("no hunts match the selection", file=sys.stderr)
        return 1

    store = EvidenceStore(args.case_dir)
    results = []
    for h in hunts:
        try:
            r = run_hunt(store, h.id)
        except Exception as exc:
            print(f"  [   ERR  ] {h.id}: {exc}", file=sys.stderr)
            continue
        results.append(r)

    total_rows = sum(r.count for r in results)
    nonempty = [r for r in results if r.count]
    nonempty.sort(key=lambda r: (
        -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(r.hunt.severity_hint, 0),
        -r.count, r.hunt.id,
    ))
    print(f"\nran {len(results)} hunt{'s' if len(results) != 1 else ''}, "
          f"{len(nonempty)} returned rows, {total_rows} total rows\n")
    for r in nonempty:
        print(f"  [{r.hunt.severity_hint:>8}] {r.hunt.id:34} {r.count:>4} rows  — {r.hunt.title}")
    empty = [r for r in results if not r.count]
    if empty and args.verbose:
        print("\nclean (no rows):")
        for r in empty:
            print(f"            {r.hunt.id}")

    if args.out:
        host = store.get_meta("host") or {}
        fmt = args.format.lower()
        if fmt == "html":
            content = render_hunts_html(results, host=host)
        elif fmt == "json":
            content = render_hunts_json(results)
        elif fmt in ("md", "markdown"):
            content = render_hunts_markdown(results)
        else:
            print(f"unknown format: {fmt}", file=sys.stderr)
            store.close()
            return 2
        Path(args.out).write_text(content, encoding="utf-8")
        print(f"\nwrote {args.out}")

    store.close()
    return 0


def cmd_firewall_audit(args: argparse.Namespace) -> int:
    """Audit the firewall posture and print findings + remediation."""
    from digger.detectors.firewall_audit import FirewallAuditDetector
    store = EvidenceStore(args.case_dir)
    detector = FirewallAuditDetector()
    findings = list(detector.detect(store))
    store.close()

    if not findings:
        print("[firewall] no audit findings — posture looks clean.")
        return 0

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    show_remedy = bool(args.show_remedy)
    print(f"\n{len(findings)} firewall finding(s):\n")
    for i, f in enumerate(findings, 1):
        ev = f.evidence or {}
        backend = ev.get("backend", "?")
        check = ev.get("check_id", "?")
        print(f"  {i:>2}.  [{f.severity:>8}]  {backend:>9}  {check}")
        print(f"       {f.title}")
        if args.verbose:
            for line in (f.summary or "").splitlines():
                print(f"         {line}")
        if show_remedy and ev.get("remedy"):
            rem = ev["remedy"]
            print(f"       remedy:  {rem.get('description', '')}")
            if rem.get("rationale"):
                print(f"       why:     {rem['rationale']}")
            for cmd in rem.get("commands", []):
                marker = "  [DESTRUCTIVE]" if cmd.get("destructive") else ""
                print(f"         $ {cmd['command']}{marker}")
        print()

    print(
        "\nNOTE: digger NEVER applies these commands itself. Review each one,\n"
        "      then run the ones appropriate for your environment. Destructive\n"
        "      commands are flagged so you can double-check before pasting."
    )
    return 1 if any(f.severity in ("critical", "high") for f in findings) else 0


def cmd_diff(args: argparse.Namespace) -> int:
    from digger.diff import compute_diff, render_diff_html, render_diff_json, render_diff_markdown
    result = compute_diff(args.base, args.new)
    s = result.summary()

    if not result.same_host:
        print(f"WARNING: host fingerprints differ — base={result.base_host.get('node')} "
              f"new={result.new_host.get('node')}", file=sys.stderr)

    print(f"\ndiff:  {result.base_case_id[:8]}  →  {result.new_case_id[:8]}")
    print(f"  artifacts:  +{s['artifact_added']}  −{s['artifact_removed']}  ~{s['artifact_modified']}")
    print(f"  findings:   new={s['finding_new']}  resolved={s['finding_resolved']}  "
          f"modified={s['finding_modified']}  persisted={s['finding_persisted']}")

    if result.findings.new:
        print("\nNew findings:")
        for f in result.findings.new[:20]:
            print(f"  [{f['severity']:>8}] {f['detector']:24} {f['title']}")
        if len(result.findings.new) > 20:
            print(f"  …and {len(result.findings.new) - 20} more")

    if args.out:
        fmt = args.format.lower()
        if fmt == "json":
            content = render_diff_json(result)
        elif fmt in ("md", "markdown"):
            content = render_diff_markdown(result)
        elif fmt == "html":
            content = render_diff_html(result)
        else:
            print(f"unknown --format: {fmt}", file=sys.stderr)
            return 2
        Path(args.out).write_text(content, encoding="utf-8")
        print(f"\nwrote {args.out}")

    return 0


# ---- arg parser ---------------------------------------------------------- #


def _add_case_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument("--case-dir", required=True, help="Directory holding the evidence DB")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="digger",
        description="Cross-platform endpoint forensics + local-LLM triage suite",
    )
    p.add_argument("--version", action="version", version=f"digger {__version__}")
    p.add_argument("--no-banner", action="store_true", help="Suppress the ASCII banner")
    p.add_argument("--fips-mode", action="store_true",
                   help="Run in FIPS 140-3 restricted mode (refuses non-approved algorithms)")
    p.add_argument("--airgap", action="store_true",
                   help="Refuse all network-egress features (intel feeds, LLM triage, TAXII push)")
    p.add_argument("--classification", default="UNCLASSIFIED",
                   help="Case classification marking written to chain of custody")
    p.add_argument("--tlp", default="TLP:AMBER", help="Default TLP marking for the case")
    sub = p.add_subparsers(dest="command", required=True)

    pc = sub.add_parser("collect", help="Run collectors and write to an evidence DB")
    _add_case_arg(pc)
    pc.add_argument("--only", help="Comma-separated collector names to run")
    pc.add_argument("--no-admin", action="store_true", help="Skip collectors that need root/admin")
    pc.set_defaults(func=cmd_collect)

    ps = sub.add_parser("scan", help="Run detectors over collected artifacts")
    _add_case_arg(ps)
    ps.add_argument("--only", help="Comma-separated detector names to run")
    ps.set_defaults(func=cmd_scan)

    pt = sub.add_parser("triage", help="AI-triage findings via local LLM")
    _add_case_arg(pt)
    pt.add_argument("--llm-base-url", help="OpenAI-compatible base URL")
    pt.add_argument("--llm-model", help="Model name to send")
    pt.add_argument("--llm-api-key", default=None)
    pt.add_argument("--skip-below", default="low", choices=["info","low","medium","high","critical"])
    pt.add_argument("--only", help="Triage findings from these detectors only (comma sep)")
    pt.add_argument("--max", type=int, help="Maximum findings to triage")
    pt.add_argument("--no-case-summary", action="store_true")
    pt.add_argument("--force", action="store_true", help="Ignore LLM health check failure")
    pt.set_defaults(func=cmd_triage)

    pr = sub.add_parser("report", help="Render a report")
    _add_case_arg(pr)
    pr.add_argument("--format", default="html", help="json|md|html")
    pr.add_argument("--out", help="Output file path")
    pr.set_defaults(func=cmd_report)

    pf = sub.add_parser(
        "falco",
        help="Falco runtime-security bridge: ingest a Falco NDJSON "
             "event log (any OS) or live-stream from a running falco "
             "(Linux only)",
    )
    f_sub = pf.add_subparsers(dest="falco_cmd", required=True)

    pfi = f_sub.add_parser(
        "ingest",
        help="Parse a Falco JSON-output event log file (NDJSON, "
             "one event per line)",
    )
    _add_case_arg(pfi)
    pfi.add_argument("--log", required=True,
                     help="Path to Falco NDJSON event log")
    pfi.add_argument("--priorities",
                     help="Comma-separated priorities to keep "
                          "(emergency,alert,critical,error,warning,"
                          "notice,info,debug)")
    pfi.add_argument("--rules",
                     help="Comma-separated rule names to keep")
    pfi.add_argument("--after", help="Keep events with ts >= epoch_s")
    pfi.add_argument("--before", help="Keep events with ts <= epoch_s")
    pfi.add_argument("--limit",
                     help="Cap total emitted events")
    pfi.add_argument("--verbose", "-v", action="store_true")
    pfi.set_defaults(func=cmd_falco_ingest)

    pfs = f_sub.add_parser(
        "stream",
        help="Linux only: spawn `falco` and pipe live JSON events "
             "into the case",
    )
    _add_case_arg(pfs)
    pfs.add_argument("--max-events",
                     help="Stop after this many events (default: until "
                          "falco exits or SIGTERM)")
    pfs.set_defaults(func=cmd_falco_stream)

    pk = sub.add_parser(
        "k8s",
        help="Kubernetes cluster-side forensics (requires kubectl + "
             "a reachable cluster)",
    )
    k_sub = pk.add_subparsers(dest="k8s_cmd", required=True)

    pkc = k_sub.add_parser(
        "collect",
        help="Fetch curated cluster resources (pods, RBAC, "
             "networkpolicies, secrets metadata) into the case "
             "as digger Artifacts. K8sSecurityDetector runs on "
             "them at digger scan time.",
    )
    _add_case_arg(pkc)
    pkc.add_argument("--context",
                     help="kubectl context to use (default: current)")
    pkc.add_argument("--namespace", "-n",
                     help="Scope to one namespace (default: all)")
    pkc.add_argument("--verbose", "-v", action="store_true",
                     help="Print per-resource item counts")
    pkc.set_defaults(func=cmd_k8s_collect)

    pi = sub.add_parser(
        "idp",
        help="Identity-provider audit-log ingest "
             "(Okta / Entra / Workspace). Most modern breaches start "
             "at the IdP — ingest the audit stream and let "
             "IdpSecurityDetector find MFA fatigue, OAuth grants, "
             "impossible travel, password spray, federation changes.",
    )
    i_sub = pi.add_subparsers(dest="idp_cmd", required=True)

    pii = i_sub.add_parser(
        "ingest",
        help="Parse an IdP audit-log file (NDJSON or JSON-array) and "
             "emit one Artifact per event",
    )
    _add_case_arg(pii)
    pii.add_argument("--log", required=True,
                     help="Path to the IdP audit-log file")
    pii.add_argument("--provider", required=True,
                     choices=["okta", "entra", "azure",
                              "workspace", "google"],
                     help="Audit-log shape to parse")
    pii.add_argument("--actors",
                     help="Comma-separated actors (email/UPN) to keep")
    pii.add_argument("--after",
                     help="Keep events with ts >= epoch_s")
    pii.add_argument("--before",
                     help="Keep events with ts <= epoch_s")
    pii.add_argument("--limit", help="Cap total emitted events")
    pii.add_argument("--verbose", "-v", action="store_true",
                     help="Print event-type distribution")
    pii.set_defaults(func=cmd_idp_ingest)

    ps = sub.add_parser(
        "slsa",
        help="SLSA / in-toto build-provenance auditor for locally-"
             "installed npm + PyPI packages. Flags missing / "
             "tampered / untrusted-builder / source-mismatched "
             "attestations.",
    )
    s_sub = ps.add_subparsers(dest="slsa_cmd", required=True)

    psa = s_sub.add_parser(
        "audit",
        help="Walk node_modules + site-packages, parse every SLSA "
             "/ in-toto attestation found, emit one Artifact per "
             "package. SlsaAuditDetector runs on them at digger "
             "scan time.",
    )
    _add_case_arg(psa)
    psa.add_argument("--roots",
                     help="Comma-separated directories to search "
                          "(default: auto-discover ~/node_modules, "
                          "system site-packages, user-site)")
    psa.add_argument("--verbose", "-v", action="store_true",
                     help="Print per-ecosystem breakdown")
    psa.set_defaults(func=cmd_slsa_audit)

    pa = sub.add_parser(
        "android",
        help="Android device forensics via adb (requires "
             "android-platform-tools + a USB-attached, debug-"
             "authorized device). Strictly read-only: enumerates "
             "package list, dumpsys packages, device-policy + "
             "accessibility state.",
    )
    a_sub = pa.add_subparsers(dest="android_cmd", required=True)

    pac = a_sub.add_parser(
        "collect",
        help="Pull package list + per-package dumpsys + device-"
             "policy / accessibility / install-source state into "
             "the case. AndroidSecurityDetector runs on them at "
             "digger scan time.",
    )
    _add_case_arg(pac)
    pac.add_argument("--serial", "-s",
                     help="adb serial of target device (default: "
                          "first device in 'device' state)")
    pac.add_argument("--max-packages",
                     help="Cap on per-package dumpsys (default 600)")
    pac.set_defaults(func=cmd_android_collect)

    pm = sub.add_parser(
        "mcp",
        help="MCP (Model Context Protocol) configuration auditor "
             "for LLM agent tooling. Scans Claude Desktop / Claude "
             "Code / Cursor / Continue / Cline / Roo Code config "
             "files (and any project-scoped .mcp.json) for tool-"
             "poisoning patterns.",
    )
    m_sub = pm.add_subparsers(dest="mcp_cmd", required=True)

    pma = m_sub.add_parser(
        "audit",
        help="Parse every MCP-server entry found in well-known "
             "config locations + project-local .mcp.json files, "
             "emit one Artifact per server. McpAuditDetector "
             "runs on them at digger scan time.",
    )
    _add_case_arg(pma)
    pma.add_argument("--roots",
                     help="Comma-separated explicit config files "
                          "to parse (default: auto-discover)")
    pma.add_argument("--verbose", "-v", action="store_true",
                     help="Print per-config-kind breakdown")
    pma.set_defaults(func=cmd_mcp_audit)

    pc = sub.add_parser(
        "ci",
        help="CI/CD pipeline security auditor — currently "
             "GitHub Actions workflows. Parses .github/workflows/"
             "*.yml under the given roots, runs W1-W7 checks "
             "(pwn-request, workflow_run from forks, script-"
             "injection interpolations, unpinned 3rd-party "
             "actions, persist-credentials, write-all "
             "permissions, self-modifying workflows).",
    )
    c_sub = pc.add_subparsers(dest="ci_cmd", required=True)

    pca = c_sub.add_parser(
        "audit-workflows",
        help="Walk .github/workflows/*.yml under the supplied "
             "roots (default: cwd), emit one Artifact per "
             "workflow. CiWorkflowAuditDetector runs on them at "
             "digger scan time.",
    )
    _add_case_arg(pca)
    pca.add_argument("--roots",
                     help="Comma-separated repo / workflow-dir / "
                          "single-file paths (default: cwd)")
    pca.set_defaults(func=cmd_ci_workflow_audit)

    pp = sub.add_parser(
        "plaso",
        help="Plaso (log2timeline) .plaso storage-file ingestion "
             "(requires psort/psteal binary)",
    )
    p_sub = pp.add_subparsers(dest="plaso_cmd", required=True)

    ppi = p_sub.add_parser(
        "info",
        help="Sample a .plaso file and report parsers + data_types seen",
    )
    ppi.add_argument("--plaso", required=True, help="Path to .plaso file")
    ppi.add_argument("--limit", default=5000,
                     help="Number of events to sample (default 5000)")
    ppi.set_defaults(func=cmd_plaso_info)

    ppn = p_sub.add_parser(
        "ingest",
        help="Ingest a .plaso file: emit one Artifact per event",
    )
    _add_case_arg(ppn)
    ppn.add_argument("--plaso", required=True, help="Path to .plaso file")
    ppn.add_argument("--parsers",
                     help="Comma-separated parser names to keep "
                          "(e.g. winreg,chrome_history)")
    ppn.add_argument("--data-types",
                     help="Comma-separated data_type strings to keep")
    ppn.add_argument("--after", help="Keep events with ts >= this (epoch s)")
    ppn.add_argument("--before", help="Keep events with ts <= this (epoch s)")
    ppn.add_argument("--limit",
                     help="Maximum events to emit (no limit by default)")
    ppn.set_defaults(func=cmd_plaso_ingest)

    phs = sub.add_parser(
        "hindsight",
        help="Opt-in deep Chromium profile parser (history / cookies "
             "/ logins metadata; sensitive blobs LENGTH ONLY, never "
             "decrypted)",
    )
    hs_sub = phs.add_subparsers(dest="hs_cmd", required=True)

    phss = hs_sub.add_parser(
        "scan",
        help="Run the deep parser against discovered Chromium profiles",
    )
    phss.add_argument("--case-dir", help="Case directory (EvidenceStore)")
    phss.add_argument("--deep-browser-parse", action="store_true",
                      help="Required to actually parse — paired with "
                           "DIGGER_HINDSIGHT_OK=1 env var")
    phss.add_argument(
        "--include",
        help="Comma-separated data kinds to include "
             "(default: history,downloads,bookmarks). "
             "All: history,downloads,bookmarks,cookies,logins,"
             "autofill,web_data",
    )
    phss.add_argument(
        "--profile",
        help="Comma-separated explicit profile directories "
             "(default: auto-discover)",
    )
    phss.add_argument("--list-kinds", action="store_true",
                      help="List supported data kinds and exit")
    phss.set_defaults(func=cmd_hindsight_scan)

    pvol = sub.add_parser(
        "vol",
        help="Volatility 3 memory-image bridge (requires `vol` binary)",
    )
    vol_sub = pvol.add_subparsers(dest="vol_cmd", required=True)

    pvi = vol_sub.add_parser(
        "info",
        help="Identify image OS + list the curated plugin set; "
             "without --image, just list the curated plugins per OS",
    )
    pvi.add_argument("--image", help="Path to memory image file")
    pvi.set_defaults(func=cmd_vol_info)

    pvs = vol_sub.add_parser(
        "scan",
        help="Run the curated plugin set against an image; emit "
             "one Artifact per row into the case",
    )
    _add_case_arg(pvs)
    pvs.add_argument("--image", required=True,
                     help="Path to memory image file")
    pvs.add_argument("--plugins",
                     help="Comma-separated plugin list (overrides curated)")
    pvs.add_argument("--os",
                     help="Force OS: windows | linux | mac "
                          "(skip image_info auto-detect)")
    pvs.add_argument("--plugin-timeout", default=600,
                     help="Per-plugin timeout in seconds (default 600)")
    pvs.add_argument("--verbose", "-v", action="store_true")
    pvs.set_defaults(func=cmd_vol_scan)

    pfa = sub.add_parser(
        "fa",
        help="ForensicArtifacts knowledge base — Google/DFIR-community "
             "YAML library of forensic-artifact definitions",
    )
    fa_sub = pfa.add_subparsers(dest="fa_cmd", required=True)

    pfau = fa_sub.add_parser(
        "update",
        help="Clone or fast-forward ForensicArtifacts/artifacts into the cache",
    )
    pfau.add_argument(
        "--target",
        help="Where to place the corpus (default: ~/.cache/digger/forensic-artifacts)",
    )
    pfau.set_defaults(func=cmd_fa_update)

    pfal = fa_sub.add_parser(
        "list",
        help="List loaded artifact definitions, filterable by --os / --tags",
    )
    pfal.add_argument("--os", help="Filter by supported OS (linux/darwin/windows)")
    pfal.add_argument("--tags", help="Comma-separated label match (any-of)")
    pfal.add_argument("--limit", type=int, help="Show only the first N")
    pfal.set_defaults(func=cmd_fa_list)

    pfar = fa_sub.add_parser(
        "run",
        help="Execute one or more artifacts; emit digger Artifacts to the case",
    )
    _add_case_arg(pfar)
    pfar.add_argument("--name",
                      help="Comma-separated artifact name(s) to run")
    pfar.add_argument("--tags",
                      help="Comma-separated tag match (alternative to --name)")
    pfar.set_defaults(func=cmd_fa_run)

    pq = sub.add_parser(
        "query",
        help="Run a read-only SELECT against the case evidence.db "
             "(VQL-style ad-hoc query)",
    )
    pq.add_argument("sql", nargs="?",
                    help="SQL: SELECT ... FROM findings WHERE ...")
    pq.add_argument("--case-dir", help="Case directory (evidence.db)")
    pq.add_argument("--canned", help="Run a named pre-canned query")
    pq.add_argument("--list-canned", action="store_true",
                    help="List available canned queries and exit")
    pq.add_argument("--format", default="text",
                    help="Output format: text | json | csv (default text)")
    pq.add_argument("--limit", type=int,
                    help="Add a LIMIT clause when none is present")
    pq.set_defaults(func=cmd_query)

    pw = sub.add_parser(
        "watch",
        help="Continuous-monitoring daemon: re-collect + re-scan on a timer, "
             "emit only new findings",
    )
    _add_case_arg(pw)
    pw.add_argument("--interval", default=60,
                    help="Seconds between cycles (default 60)")
    pw.add_argument("--only-collectors",
                    help="Comma-separated collector names to limit each tick")
    pw.add_argument("--only-detectors",
                    help="Comma-separated detector names to limit each tick")
    pw.add_argument("--alert-on",
                    help="Comma-separated severity names that should trip rc=2 "
                         "on a new finding (e.g. critical,high)")
    pw.add_argument("--webhook",
                    help="HTTP(S) endpoint to POST new-finding batches to")
    pw.add_argument("--verbose", "-v", action="store_true",
                    help="Print finding evidence inline")
    pw.add_argument("--no-admin", action="store_true",
                    help="Skip collectors that require admin")
    pw.set_defaults(func=cmd_watch)

    pst = sub.add_parser(
        "storyline",
        help="Reconstruct event chains from findings (Aftermath-style narrative)",
    )
    _add_case_arg(pst)
    pst.add_argument("--format", default="text", help="text|markdown|json")
    pst.add_argument("--top", type=int, default=10,
                     help="Limit to top N storylines (default 10)")
    pst.set_defaults(func=cmd_storyline)

    pi = sub.add_parser("investigate", help="collect + scan + triage + report")
    _add_case_arg(pi)
    pi.add_argument("--only")
    pi.add_argument("--no-admin", action="store_true")
    pi.add_argument("--no-triage", action="store_true")
    pi.add_argument("--llm-base-url")
    pi.add_argument("--llm-model")
    pi.add_argument("--llm-api-key")
    pi.add_argument("--skip-below", default="low")
    pi.add_argument("--max", type=int)
    pi.add_argument("--no-case-summary", action="store_true")
    pi.add_argument("--force", action="store_true")
    pi.add_argument("--report", help="Report output path")
    pi.add_argument("--report-format", default="html", help="json|md|html (default html)")
    pi.set_defaults(func=cmd_investigate)

    pintel = sub.add_parser("intel", help="Threat-intel feed operations")
    intel_sub = pintel.add_subparsers(dest="intel_cmd", required=True)

    pup = intel_sub.add_parser("update", help="Refresh feeds")
    pup.add_argument("--only")
    pup.add_argument("--force", action="store_true")
    pup.add_argument("--sign-key", help="PQC secret key to auto-sign the intel cache after update "
                                         "(can also be set via DIGGER_INTEL_SIGN_KEY)")
    pup.add_argument("--sign-alg", default="ML-DSA-65",
                     help="PQC algorithm for auto-sign (default ML-DSA-65)")
    pup.set_defaults(func=cmd_intel_update)

    pst = intel_sub.add_parser("status", help="Show cached-feed freshness + integrity")
    pst.set_defaults(func=cmd_intel_status)

    pwat = intel_sub.add_parser("watch", help="Continuously poll feeds in foreground")
    pwat.add_argument("--force-first", action="store_true")
    pwat.set_defaults(func=cmd_intel_watch)

    pisign = intel_sub.add_parser("sign", help="PQC-sign the intel cache (defense in depth)")
    pisign.add_argument("--key", required=True, help="Path to your PQC secret key (matching .pub must be alongside)")
    pisign.add_argument("--algorithm", default="ML-DSA-65")
    pisign.add_argument("--target", help="Override intel cache directory")
    pisign.add_argument("--note", help="Free-form note baked into the signature bundle")
    pisign.set_defaults(func=cmd_intel_sign)

    piver = intel_sub.add_parser("verify", help="Verify the PQC signature against the intel cache")
    piver.add_argument("--target", help="Override intel cache directory")
    piver.set_defaults(func=cmd_intel_verify)

    pv = sub.add_parser("verify", help="Verify the evidence hash chain")
    _add_case_arg(pv)
    pv.set_defaults(func=cmd_verify)

    pqc = sub.add_parser("pqc", help="Post-quantum signing / encryption operations")
    pqc_sub = pqc.add_subparsers(dest="pqc_cmd", required=True)

    psg = pqc_sub.add_parser("sign", help="PQC-sign the evidence chain tip")
    _add_case_arg(psg)
    psg.add_argument("--algorithm", default="ML-DSA-65")
    psg.add_argument("--key", help="Path to existing secret key (auto-generated if missing)")
    psg.add_argument("--note", default="", help="Free-form note in the signature bundle")
    psg.set_defaults(func=cmd_sign)

    pvf = pqc_sub.add_parser("verify", help="Verify a PQC signature against the chain tip")
    _add_case_arg(pvf)
    pvf.add_argument("--signature", help="Path to signature bundle (defaults to case_signature.json)")
    pvf.set_defaults(func=cmd_pqc_verify)

    pinfo = pqc_sub.add_parser("info", help="Show available PQC algorithms and coverage")
    pinfo.add_argument("--mode", default="all", choices=["fips","round4","onramp","all"])
    pinfo.set_defaults(func=cmd_pqc_info)

    # ---- compliance ---- #
    pcomp = sub.add_parser("compliance", help="Compliance framework operations")
    comp_sub = pcomp.add_subparsers(dest="comp_cmd", required=True)

    pcl = comp_sub.add_parser("list", help="List available compliance frameworks")
    pcl.set_defaults(func=cmd_compliance_list)

    pca = comp_sub.add_parser("assess", help="Assess controls against collected evidence")
    _add_case_arg(pca)
    pca.add_argument("--frameworks", help="Comma-separated framework names (default: all)")
    pca.add_argument("--format", default="html", choices=["html","md","json","all"])
    pca.add_argument("--out-dir", help="Output directory (default: <case>/compliance/)")
    pca.set_defaults(func=cmd_compliance_assess)

    # ---- FIPS ---- #
    pfips = sub.add_parser("fips", help="FIPS 140-3 mode operations")
    fips_sub = pfips.add_subparsers(dest="fips_cmd", required=True)

    pfs = fips_sub.add_parser("status", help="Show FIPS posture")
    pfs.set_defaults(func=cmd_fips_status)

    pfe = fips_sub.add_parser("enable", help="Enable FIPS mode for this process")
    pfe.add_argument("--force", action="store_true", help="Skip self-test enforcement")
    pfe.set_defaults(func=cmd_fips_enable)

    # ---- generate (detection rules) ---- #
    pgen = sub.add_parser("generate", help="Generate portable detection rules from findings")
    gen_sub = pgen.add_subparsers(dest="gen_cmd", required=True)

    pgs = gen_sub.add_parser("sigma", help="Sigma YAML rules — one per mappable finding, or per-detector templates")
    pgs.add_argument("--case-dir", help="Directory holding the evidence DB (required unless --from-detectors)")
    pgs.add_argument("--finding", help="Generate only for this finding UUID")
    pgs.add_argument("--from-detectors", action="store_true",
                     help="Emit one per-detector generic Sigma template (no case required)")
    pgs.add_argument("--out-dir", help="Where to write the .yml files (default: <case>/sigma-out/ or out/sigma/)")
    pgs.add_argument("--verbose", "-v", action="store_true")
    pgs.set_defaults(func=cmd_generate_sigma)

    phm = gen_sub.add_parser(
        "heatmap",
        help="MITRE ATT&CK coverage heatmap derived from detector tags",
    )
    phm.add_argument("--format", choices=("text", "json", "html"),
                     default="text",
                     help="Output format (default: text)")
    phm.add_argument("--out", help="Output file path (default: stdout for text/json, required for html)")
    phm.set_defaults(func=cmd_generate_heatmap)

    # ---- export ---- #
    pexp = sub.add_parser("export", help="Export findings to interchange formats")
    exp_sub = pexp.add_subparsers(dest="exp_cmd", required=True)

    pst = exp_sub.add_parser("stix", help="STIX 2.1 bundle")
    _add_case_arg(pst)
    pst.add_argument("--out", help="Output path (default: <case>/case.stix.json)")
    pst.add_argument("--tlp", default="TLP:AMBER", help="Sharing TLP marking")
    pst.set_defaults(func=cmd_export_stix)

    pmi = exp_sub.add_parser("misp", help="MISP event JSON")
    _add_case_arg(pmi)
    pmi.add_argument("--out")
    pmi.add_argument("--tlp", default="TLP:AMBER")
    pmi.set_defaults(func=cmd_export_misp)

    pel = exp_sub.add_parser(
        "elk",
        help="ELK / OpenSearch _bulk NDJSON for ingestion via curl POST /_bulk",
    )
    _add_case_arg(pel)
    pel.add_argument("--out", help="Output file path (default: <case>/elk.ndjson)")
    pel.add_argument("--findings-index", default="digger-findings")
    pel.add_argument("--artifacts-index", default="digger-artifacts")
    pel.add_argument("--no-artifacts", action="store_true",
                     help="Emit only findings, not the full artifact corpus")
    pel.add_argument("--host-name", default="",
                     help="Override host.name field (defaults to case meta)")
    pel.set_defaults(func=cmd_export_elk)

    pat = exp_sub.add_parser("attack-navigator", help="MITRE ATT&CK Navigator layer JSON")
    _add_case_arg(pat)
    pat.add_argument("--out")
    pat.set_defaults(func=cmd_export_attack)

    ptx = exp_sub.add_parser("taxii", help="Push STIX bundle to a TAXII 2.1 server")
    _add_case_arg(ptx)
    ptx.add_argument("--base-url", required=True)
    ptx.add_argument("--api-root", required=True)
    ptx.add_argument("--collection", required=True)
    ptx.add_argument("--username")
    ptx.add_argument("--password")
    ptx.add_argument("--token")
    ptx.add_argument("--tlp", default="TLP:AMBER")
    ptx.set_defaults(func=cmd_export_taxii)

    # ---- sigma scan ---- #
    psig = sub.add_parser("sigma", help="Run Sigma rules against collected artifacts")
    _add_case_arg(psig)
    psig.add_argument("--dirs", help="Comma-separated rule directories (default: digger/rules/sigma/)")
    psig.set_defaults(func=cmd_sigma_scan)

    # ---- art / atomic-red-team ---- #
    part = sub.add_parser(
        "art",
        help="Atomic Red Team coverage + sandbox-gated detector validation",
    )
    art_sub = part.add_subparsers(dest="art_cmd", required=True)

    pau = art_sub.add_parser(
        "update",
        help="Clone or fast-forward redcanaryco/atomic-red-team into the cache",
    )
    pau.add_argument(
        "--target",
        help="Where to place the corpus (default: ~/.cache/digger/atomic-red-team)",
    )
    pau.set_defaults(func=cmd_art_update)

    pac = art_sub.add_parser(
        "coverage",
        help="ART × digger coverage matrix (text / json output)",
    )
    pac.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="Output format (default text)",
    )
    pac.set_defaults(func=cmd_art_coverage)

    # ---- loki / signature-base ---- #
    plok = sub.add_parser("loki", help="Neo23x0/signature-base (LOKI corpus) operations")
    loki_sub = plok.add_subparsers(dest="loki_cmd", required=True)

    plu = loki_sub.add_parser("update", help="Clone or update signature-base via git")
    plu.add_argument("--target", help="Where to place signature-base (default: ~/.cache/digger/signature-base)")
    plu.add_argument("--sign-key", help="PQC secret key to auto-sign the corpus with after update "
                                         "(can also be set via DIGGER_LOKI_SIGN_KEY)")
    plu.add_argument("--sign-alg", default="ML-DSA-65",
                     help="PQC signature algorithm for auto-sign (default ML-DSA-65, FIPS 204)")
    plu.set_defaults(func=cmd_loki_update)

    pls = loki_sub.add_parser("status", help="Show loaded signature-base counts + integrity status")
    pls.set_defaults(func=cmd_loki_status)

    plk = loki_sub.add_parser("scan", help="Run LOKI-style IOC matching against a case")
    _add_case_arg(plk)
    plk.set_defaults(func=cmd_loki_scan)

    plsign = loki_sub.add_parser("sign", help="PQC-sign the signature-base tree (defense in depth against corpus tampering)")
    plsign.add_argument("--key", required=True, help="Path to your PQC secret key (matching .pub must be alongside)")
    plsign.add_argument("--algorithm", default="ML-DSA-65")
    plsign.add_argument("--target", help="Override the signature-base directory")
    plsign.add_argument("--note", help="Free-form note baked into the signature bundle")
    plsign.set_defaults(func=cmd_loki_sign)

    plver = loki_sub.add_parser("verify", help="Verify the PQC signature on the signature-base tree")
    plver.add_argument("--target", help="Override the signature-base directory")
    plver.set_defaults(func=cmd_loki_verify)

    # ---- memory ---- #
    pmem = sub.add_parser("memory", help="In-memory forensics — VM region anomalies and YARA-on-memory")
    mem_sub = pmem.add_subparsers(dest="mem_cmd", required=True)

    pms = mem_sub.add_parser("scan", help="Scan running processes for anomalous VM regions (and optional YARA)")
    pms.add_argument("--pid", type=int, help="Limit to a single PID (default: all readable)")
    pms.add_argument("--yara", action="store_true", help="YARA-scan the dumped bytes from each suspect region")
    pms.set_defaults(func=cmd_memory_scan)

    pmd = mem_sub.add_parser("dump", help="Dump bytes from a process's anonymous-exec / RWX regions")
    pmd.add_argument("--pid", type=int, required=True)
    pmd.add_argument("--addr", help="Hex start address of a specific region (default: all suspect regions)")
    pmd.add_argument("--out-dir", required=True, help="Directory to write region.bin files into")
    pmd.add_argument("--max-bytes", type=int, default=16 * 1024 * 1024,
                     help="Cap per-region dump size in bytes (default 16 MiB)")
    pmd.set_defaults(func=cmd_memory_dump)

    # ---- opsec ---- #
    pops = sub.add_parser("opsec", help="Operator-side opsec: bundles, redaction, watchers, air-gap, wipe")
    ops_sub = pops.add_subparsers(dest="opsec_cmd", required=True)

    pos = ops_sub.add_parser("status", help="One-shot operator posture summary (JSON)")
    pos.set_defaults(func=cmd_opsec_status)

    pow_ = ops_sub.add_parser("watchers", help="Enumerate processes that may be observing this investigation")
    pow_.add_argument("--verbose", "-v", action="store_true")
    pow_.set_defaults(func=cmd_opsec_watchers)

    poe = ops_sub.add_parser("encrypt", help="Hybrid PQC-KEM + AES-256-GCM encrypt a whole case directory")
    _add_case_arg(poe)
    poe.add_argument("--out", required=True, help="Path to write the .digger archive")
    poe.add_argument("--recipient", required=True, help="Path to the recipient's PQC-KEM public key")
    poe.add_argument("--kem-alg", default="ML-KEM-768")
    poe.add_argument("--sign-key", help="Optional path to a PQC signing secret key (must have .pub alongside)")
    poe.add_argument("--sig-alg", default="ML-DSA-65")
    poe.set_defaults(func=cmd_opsec_encrypt)

    pod = ops_sub.add_parser("decrypt", help="Decrypt + verify a .digger archive")
    pod.add_argument("--in", dest="in_path", required=True, help="Path to the .digger archive")
    pod.add_argument("--key", required=True, help="Path to your PQC-KEM secret key")
    pod.add_argument("--out-dir", required=True, help="Where to extract the case directory")
    pod.add_argument("--no-verify-sig", action="store_true",
                     help="Skip PQC signature verification (NOT RECOMMENDED)")
    pod.set_defaults(func=cmd_opsec_decrypt)

    por = ops_sub.add_parser("redact", help="Produce a pseudonymized copy of a case for sharing")
    _add_case_arg(por)
    por.add_argument("--out-dir", required=True, help="Where to write the redacted case dir")
    por.add_argument("--keep-hostnames", action="store_true")
    por.add_argument("--keep-usernames", action="store_true")
    por.add_argument("--keep-raw-blobs", action="store_true")
    por.add_argument("--redact-public-ips", action="store_true",
                     help="Also pseudonymize public-routable IPs (default keeps them)")
    por.set_defaults(func=cmd_opsec_redact)

    pow2 = ops_sub.add_parser("wipe", help="Secure-delete a case directory")
    _add_case_arg(pow2)
    pow2.add_argument("--yes", action="store_true", help="Acknowledge that this destroys evidence")
    pow2.add_argument("--passes", type=int, default=3)
    pow2.set_defaults(func=cmd_opsec_wipe)

    # ---- hunt ---- #
    phunt = sub.add_parser("hunt", help="Threat-hunting query library — exploratory tabular queries")
    hunt_sub = phunt.add_subparsers(dest="hunt_cmd", required=True)

    phl = hunt_sub.add_parser("list", help="List available hunts")
    phl.add_argument("--tag", help="Filter to hunts carrying this tag")
    phl.add_argument("--verbose", "-v", action="store_true", help="Print description + mitre + tags")
    phl.set_defaults(func=cmd_hunt_list)

    phr = hunt_sub.add_parser("run", help="Run hunts against a case directory")
    _add_case_arg(phr)
    phr.add_argument("--hunt", help="Comma-separated hunt IDs to run (default: all)")
    phr.add_argument("--tag",  help="Run only hunts with this tag")
    phr.add_argument("--severity", default="info", help="Skip hunts with severity-hint below this")
    phr.add_argument("--out", help="Write a structured report to this path")
    phr.add_argument("--format", default="html", choices=["html", "md", "markdown", "json"])
    phr.add_argument("--verbose", "-v", action="store_true", help="List hunts that returned no rows")
    phr.set_defaults(func=cmd_hunt_run)

    # ---- diff ---- #
    pdiff = sub.add_parser("diff", help="Diff two case directories (what changed since last collection)")
    pdiff.add_argument("--base", required=True, help="Baseline case directory")
    pdiff.add_argument("--new",  required=True, help="Newer case directory to compare against base")
    pdiff.add_argument("--out", help="Write a structured report to this path")
    pdiff.add_argument("--format", default="html", choices=["html", "md", "markdown", "json"])
    pdiff.set_defaults(func=cmd_diff)

    pfw = sub.add_parser("firewall", help="Audit firewall posture and print remediation commands")
    fw_sub = pfw.add_subparsers(dest="firewall_cmd", required=True)
    pfwa = fw_sub.add_parser("audit", help="Audit firewall posture for a case directory")
    pfwa.add_argument("--case-dir", required=True, help="Case directory (must contain collected firewall artifacts)")
    pfwa.add_argument("--show-remedy", action="store_true",
                      help="Print the exact remediation commands for each finding (default: title only)")
    pfwa.add_argument("--verbose", "-v", action="store_true", help="Include the full finding summary")
    pfwa.set_defaults(func=cmd_firewall_audit)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not getattr(args, "no_banner", False):
        _print_banner()
    # Enable FIPS mode if requested via CLI or env. Aborts on self-test failure.
    if getattr(args, "fips_mode", False):
        from digger.fips.mode import enable_fips_mode
        try:
            state = enable_fips_mode()
            print(f"[FIPS] mode enabled (self-test passed={state.self_test_passed})")
        except Exception as exc:
            print(f"[FIPS] FAILED to enable: {exc}", file=sys.stderr)
            return 2
    else:
        from digger.fips.mode import auto_enable_from_env
        auto_enable_from_env()
    # Air-gap mode (CLI flag or DIGGER_AIRGAP env). Once enabled, every
    # outbound HTTP path refuses with AirgapViolation.
    if getattr(args, "airgap", False):
        from digger.opsec.airgap import enable_airgap
        enable_airgap()
        print("[AIRGAP] mode enabled — all network-egress features will refuse")
    else:
        from digger.opsec.airgap import auto_enable_from_env as _ag_env
        if _ag_env():
            print("[AIRGAP] mode enabled via DIGGER_AIRGAP env")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
