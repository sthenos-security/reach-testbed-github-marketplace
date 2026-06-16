#!/usr/bin/env python3
"""Build a public Reachable Pages summary for the demo workflow.

This page is intentionally smaller than the full Reachable dashboard. It is
safe for a public demo repo: DB-backed baseline/fix proof, selected public
DB demo rows, remediation ledger status, compatibility exports, and links. It
does not publish raw prompt bundles, agent transcripts, local databases, or
private logs.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import shutil
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

SEVERITY_ORDER = {"error": 0, "warning": 1, "note": 2, "none": 3}
RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "UNKNOWN": 5}
REACHABILITY_ORDER = {"exploitable": 0, "reachable": 1, "unknown": 2, "defended": 3, "defendable": 4}
DEFENDED_STATES = {"DEFENDED", "DEFENDABLE", "NOT_EXPLOITABLE", "SAFE", "SUPPRESSED"}
AI_LLM_TERMS = (
    " ai ",
    " llm",
    "prompt",
    "rag",
    "mcp",
    "model",
    "embedding",
    "agent",
    "tool call",
    "training data",
)
MALWARE_TERMS = ("malware", "malicious", "guarddog", "yara", "suspicious package", "osv malicious")
DLP_TERMS = ("dlp", " pii", "personal data", "sensitive data", "ssn", "credit card", "passport", "email address")
OWASP_WEB_CWE_MAP = {
    "A01 Broken Access Control": {22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706, 862, 863, 913, 922, 1275},
    "A02 Cryptographic Failures": {259, 310, 319, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916},
    "A03 Injection": {20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 100, 113, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917, 943},
    "A04 Insecure Design": {209, 256, 501, 522, 525, 602, 656, 657, 799, 807, 840, 841, 927},
    "A05 Security Misconfiguration": {2, 11, 13, 15, 16, 209, 311, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1004},
    "A07 Identification and Authentication Failures": {287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940},
    "A08 Software and Data Integrity Failures": {345, 353, 426, 494, 502, 565, 784, 829, 830, 915},
    "A09 Security Logging and Monitoring Failures": {117, 223, 532, 778},
    "A10 Server-Side Request Forgery": {918},
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sarif", default=".reachable/ci-artifacts/reachable-code-scanning.sarif")
    parser.add_argument("--ledger", default=".reachable/ci-artifacts/remediation-ledger.json")
    parser.add_argument("--out", default=".reachable/ci-artifacts/pages")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    sarif_path = Path(args.sarif)
    ledger_path = Path(args.ledger)
    sarif = _load_json(sarif_path) if sarif_path.exists() else {}
    ledger = _load_json(ledger_path) if ledger_path.exists() else {}
    artifacts: list[dict[str, str]] = []
    if sarif_path.exists():
        shutil.copy2(sarif_path, out_dir / "reachable.sarif")
        artifacts.append({"label": "SARIF compatibility export", "href": "reachable.sarif"})
    if ledger_path.exists():
        shutil.copy2(ledger_path, out_dir / "remediation-ledger.json")
        artifacts.append({"label": "Sanitized remediation ledger", "href": "remediation-ledger.json"})
    db_verdict_path = ledger_path.parent / "db-remediation-verdict.json"
    if db_verdict_path.exists():
        shutil.copy2(db_verdict_path, out_dir / "db-remediation-verdict.json")
        artifacts.append({"label": "DB remediation verdict", "href": "db-remediation-verdict.json"})
    docs_dir = Path(__file__).resolve().parents[1] / "docs"
    favicon_path = docs_dir / "favicon.svg"
    if favicon_path.exists():
        shutil.copy2(favicon_path, out_dir / "favicon.svg")
    expected_html_path = docs_dir / "expected-results.html"
    if expected_html_path.exists():
        shutil.copy2(expected_html_path, out_dir / "expected-results.html")
        artifacts.append({"label": "Expected issue contract", "href": "expected-results.html"})
    run_evidence = _copy_cache_evidence(ledger_path.parent, out_dir)
    for item in run_evidence.get("artifacts", []):
        if isinstance(item, dict):
            artifacts.append(item)
    compliance = _copy_latest_compliance_pack(out_dir)

    summary = _summarize(sarif=sarif, ledger=ledger, compliance=compliance)
    summary["compliance"] = compliance
    summary["artifacts"] = artifacts
    summary["run_evidence"] = run_evidence
    try:
        summary["expected_demo"] = _expected_demo_summary(artifact_dir=ledger_path.parent)
    except FileNotFoundError as exc:
        summary["expected_demo"] = _expected_demo_unavailable(reason=str(exc))
    _apply_db_verdict(summary)
    summary["ai_economics"] = _demo_ai_economics(summary["expected_demo"])
    summary["artifacts"].extend(
        [
            {"label": "Summary JSON", "href": "summary.json"},
        ]
    )
    page_url = _pages_url()
    code_scanning_url = _code_scanning_url()
    run_url = _run_url()

    (out_dir / "index.html").write_text(
        _render_html(
            summary=summary,
            generated_at=datetime.now(timezone.utc).isoformat(),
            page_url=page_url,
            code_scanning_url=code_scanning_url,
            run_url=run_url,
        ),
        encoding="utf-8",
    )
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = _render_markdown(summary=summary, page_url=page_url, code_scanning_url=code_scanning_url, run_url=run_url)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a", encoding="utf-8") as handle:
            handle.write(markdown)
            handle.write("\n")
    elif os.environ.get("GITLAB_CI"):
        print(markdown)
    return 0


def _apply_db_verdict(summary: dict[str, Any]) -> None:
    expected_demo = summary.get("expected_demo") if isinstance(summary.get("expected_demo"), dict) else {}
    if not expected_demo:
        return
    clean = bool(expected_demo.get("clean"))
    status = "success" if clean else "needs_review"
    message = str(expected_demo.get("headline") or "")
    remediation = summary.get("remediation") if isinstance(summary.get("remediation"), dict) else {}
    remediation["status"] = status
    remediation["message"] = f"DB-backed verdict: {message}"
    summary["remediation"] = remediation
    verification = summary.get("verification") if isinstance(summary.get("verification"), dict) else {}
    verification.update(
        {
            "status": "db_verified" if clean else "db_needs_review",
            "mode": "DB-backed baseline/remediation proof",
            "clean": clean,
            "blocking_results": int(expected_demo.get("after_total") or 0),
            "results": int(expected_demo.get("after_total") or 0),
            "label": "repo.db expected-contract comparison",
            "message": message,
        }
    )
    summary["verification"] = verification


def _load_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - CI summary should still render.
        return {"_error": f"failed to parse {path}: {exc}"}


def _load_json_required(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _expected_demo_unavailable(*, reason: str) -> dict[str, Any]:
    expected_path = Path(
        os.environ.get("REACHABLE_EXPECTED_CONTRACT")
        or Path(__file__).resolve().parents[1] / "expected" / "baseline.json"
    )
    expected_total = 0
    verified_with = ""
    name = "reach-testbed-go golden baseline"
    if expected_path.exists():
        expected = _load_json(expected_path)
        expected_total = len(((expected.get("sarif") or {}).get("results") or []))
        verified_with = str(expected.get("verified_with_reachable") or "")
        name = str(expected.get("name") or name)
    return {
        "available": False,
        "name": name,
        "verified_with_reachable": verified_with,
        "expected_total": expected_total,
        "baseline_found": 0,
        "baseline_missing": expected_total,
        "fixed": 0,
        "still_present": 0,
        "after_available": False,
        "after_total": None,
        "clean": False,
        "headline": f"Structured scan database proof is unavailable for this run: {reason}",
        "rows": [],
        "contract_path": "EXPECTED.md" if expected_path.exists() else "",
        "baseline": {},
        "after": {},
        "baseline_ai": {},
        "after_ai": {},
        "evidence_source": "unavailable",
        "unavailable_reason": reason,
    }


def _expected_demo_summary(*, artifact_dir: Path) -> dict[str, Any]:
    expected_path = Path(
        os.environ.get("REACHABLE_EXPECTED_CONTRACT")
        or Path(__file__).resolve().parents[1] / "expected" / "baseline.json"
    )
    if not expected_path.exists():
        raise FileNotFoundError(f"expected demo contract is required: {expected_path}")

    expected = _load_json_required(expected_path)
    expected_rows = [_expected_row(tuple(item)) for item in ((expected.get("sarif") or {}).get("results") or [])]
    deferred_rows = _deferred_expected_rows(expected)
    baseline_ctx = _scan_db_context(artifact_dir / "reports" / "baseline" / "scan-path.txt")
    after_ctx = _scan_db_context(artifact_dir / "reports" / "after-final" / "scan-path.txt")
    baseline_rows = _db_expected_row_map(baseline_ctx)
    after_rows = _db_expected_row_map(after_ctx)
    after_actionable_total = _db_actionable_count(after_ctx, deferred_keys=set(deferred_rows))
    baseline_ai = _db_ai_usage_summary(baseline_ctx)
    after_ai = _db_ai_usage_summary(after_ctx)

    rows: list[dict[str, Any]] = []
    baseline_found = 0
    fixed = 0
    still_present = 0
    deferred_present = 0
    missing = 0
    for row in expected_rows:
        key = row["match_key"]
        deferred = deferred_rows.get(key)
        before_items = baseline_rows.get(key, [])
        after_items = after_rows.get(key, [])
        found_before = bool(before_items)
        blocking_after_items = [item for item in after_items if _signal_blocks_remediation(item)]
        defended_after_items = [item for item in after_items if not _signal_blocks_remediation(item)]
        found_after = bool(after_items)
        blocking_after = bool(blocking_after_items)
        if found_before:
            baseline_found += 1
        else:
            missing += 1
        if found_before and not found_after:
            fixed += 1
            status = "fixed"
            status_label = "Fixed - no longer reported"
        elif found_before and defended_after_items and not blocking_after:
            fixed += 1
            status = "defended_after_remediation"
            status_label = "Resolved - residual row is defended"
        elif blocking_after and deferred:
            deferred_present += 1
            status = "deferred_manual_review"
            status_label = "Deferred - manual review"
        elif blocking_after:
            still_present += 1
            status = "still_present"
            status_label = "Still blocking after remediation"
        elif found_after:
            status = "defended_after_remediation"
            status_label = "Residual row is defended"
        else:
            status = "baseline_missing"
            status_label = "Expected baseline row was not detected"
        baseline_signal = before_items[0] if before_items else {}
        after_signal = (blocking_after_items or defended_after_items or after_items or [{}])[0]
        exploitability = _expected_exploitability(row, baseline_signal)
        rows.append(
            {
                **row,
                "found_before": found_before,
                "found_after": found_after,
                "blocking_after": blocking_after,
                "deferred": bool(deferred),
                "deferred_reason": (deferred or {}).get("reason", ""),
                "status": status,
                "status_label": status_label,
                "baseline_signal": _public_signal(baseline_signal),
                "after_signal": _public_signal(after_signal),
                "actual_risk": baseline_signal.get("risk_level") or baseline_signal.get("severity") or "",
                "actual_reachability": baseline_signal.get("app_reachability") or "",
                "actual_exploitability": exploitability,
                "remediation_action": baseline_signal.get("remediation_action") or _expected_business_value(row),
                "signal_title": baseline_signal.get("title") or "",
                "signal_description": baseline_signal.get("description") or "",
            }
        )

    expected_total = len(expected_rows)
    clean = baseline_found == expected_total and still_present == 0 and after_actionable_total == 0
    if clean and deferred_present:
        headline = "All non-deferred demo vulnerabilities were fixed; one documented case is deferred for manual review."
    elif clean and baseline_found == expected_total:
        headline = "All expected demo vulnerabilities were found and the remediation branch has no blocking findings."
    elif still_present == 0:
        headline = "The remediation proof scan has no blocking findings, but the baseline contract did not fully match."
    else:
        headline = "The remediation proof scan still has expected findings to review."

    observed_before = _db_observed_scan(baseline_ctx)
    observed_after = _db_observed_scan(after_ctx, deferred_keys=set(deferred_rows))
    stats = _demo_status_stats(
        expected=expected,
        rows=rows,
        observed_before=observed_before,
        observed_after=observed_after,
        after_actionable_total=after_actionable_total,
    )

    return {
        "available": True,
        "name": expected.get("name") or "reach-testbed-github-marketplace golden baseline",
        "verified_with_reachable": expected.get("verified_with_reachable") or "",
        "expected_total": expected_total,
        "baseline_found": baseline_found,
        "baseline_missing": missing,
        "fixed": fixed,
        "still_present": still_present,
        "deferred_present": deferred_present,
        "after_available": True,
        "after_total": after_actionable_total,
        "clean": clean,
        "headline": headline,
        "rows": rows,
        "contract_path": "expected-results.html",
        "baseline": baseline_ctx["meta"],
        "after": after_ctx["meta"],
        "baseline_ai": baseline_ai,
        "after_ai": after_ai,
        "observed": {
            "before": observed_before,
            "after": observed_after,
        },
        "stats": stats,
        "evidence_source": "repo.db",
    }


def _deferred_expected_rows(expected: dict[str, Any]) -> dict[tuple[str, str, int], dict[str, Any]]:
    deferred: dict[tuple[str, str, int], dict[str, Any]] = {}
    for item in expected.get("deferred_remediation") or []:
        if not isinstance(item, dict):
            continue
        key = _expected_match_key(item.get("rule"), item.get("path"), item.get("line") or 0)
        deferred[key] = item
    return deferred


def _copy_cache_evidence(artifact_dir: Path, out_dir: Path) -> dict[str, Any]:
    phases = ("before-install", "after-install", "after-scan")
    evidence: dict[str, Any] = {"available": False, "phases": {}, "artifacts": []}
    for phase in phases:
        source = artifact_dir / f"reachable-cache-{phase}.json"
        if not source.exists():
            continue
        target = out_dir / source.name
        shutil.copy2(source, target)
        payload = _load_json(source)
        evidence["available"] = True
        evidence["phases"][phase] = payload
        evidence["artifacts"].append({"label": f"Run evidence: {phase}", "href": target.name})
    evidence["summary"] = _run_evidence_summary(evidence.get("phases") or {})
    return evidence


def _run_evidence_summary(phases: dict[str, Any]) -> dict[str, Any]:
    before = phases.get("before-install") if isinstance(phases.get("before-install"), dict) else {}
    after_install = phases.get("after-install") if isinstance(phases.get("after-install"), dict) else {}
    after_scan = phases.get("after-scan") if isinstance(phases.get("after-scan"), dict) else {}
    latest = after_scan or after_install or before
    before_db_count = _safe_int(before.get("repo_db_count"))
    after_db_count = _safe_int(latest.get("repo_db_count"))
    before_size = _safe_int(before.get("reachable_home_size_kb"))
    after_size = _safe_int(latest.get("reachable_home_size_kb"))
    return {
        "fresh_scan_requested": bool(before.get("fresh_scan_requested") or after_install.get("fresh_scan_requested") or after_scan.get("fresh_scan_requested")),
        "cache_restored": bool(before.get("cache_restored") or after_install.get("cache_restored") or after_scan.get("cache_restored")),
        "cache_source": latest.get("cache_source") or latest.get("provider") or "",
        "install_mode": after_install.get("install_mode") or latest.get("install_mode") or "",
        "target_version": latest.get("target_version") or "",
        "installed_version": after_install.get("installed_version") or latest.get("installed_version") or "",
        "repo_db_count_before": before_db_count,
        "repo_db_count_after": after_db_count,
        "repo_db_reused": before_db_count > 0 and after_db_count >= before_db_count,
        "scan_session_count": _safe_int(latest.get("scan_session_count")),
        "cache_size_kb_before": before_size,
        "cache_size_kb_after": after_size,
        "latest_repo_db_hash": str(latest.get("latest_repo_db_hash") or ""),
        "latest_scan": (latest.get("latest_repo_db") or {}).get("latest_scan") if isinstance(latest.get("latest_repo_db"), dict) else {},
    }


def _expected_row(item: tuple[Any, ...]) -> dict[str, Any]:
    rule, reachability, risk, prod, path, line = item
    location = f"{path}:{line}" if line else str(path)
    return {
        "match_key": _expected_match_key(rule, path, line),
        "rule_id": str(rule or ""),
        "expected_reachability": str(reachability or ""),
        "expected_risk": str(risk or ""),
        "prod_status": str(prod or ""),
        "family": _expected_family(rule),
        "path": str(path or ""),
        "line": int(line or 0),
        "location": location,
        "kind": _plain_kind(str(rule or "")),
        "problem_ref": "expected-results.html#expected-findings-table",
    }


def _scan_db_context(scan_path_file: Path) -> dict[str, Any]:
    if not scan_path_file.exists():
        raise FileNotFoundError(f"required scan-path file is missing: {scan_path_file}")
    scan_dir = Path(scan_path_file.read_text(encoding="utf-8").strip())
    db_path = scan_dir.parent.parent / "repo.db"
    if not db_path.exists():
        raise FileNotFoundError(f"repo.db is required for demo proof and was not found: {db_path}")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    scan_meta = _scan_meta(conn, scan_dir)
    return {"db_path": db_path, "scan_dir": scan_dir, "scan_id": scan_meta["id"], "meta": scan_meta}


def _scan_meta(conn: sqlite3.Connection, scan_dir: Path) -> dict[str, Any]:
    rows = conn.execute(
        """
        SELECT id, branch, commit_hash, commit_short, scan_dir, timestamp,
               duration_seconds, version, status, total_findings,
               reachable_findings, critical_count, high_count, medium_count,
               low_count, risk_level
          FROM scans
         ORDER BY id DESC
        """
    ).fetchall()
    matches = [dict(row) for row in rows if Path(str(row["scan_dir"] or "")) == scan_dir]
    if not matches:
        raise RuntimeError(f"scan directory {scan_dir} was not found in repo.db scans table")
    meta = matches[0]
    meta["db_scan_id"] = meta["id"]
    meta.pop("scan_dir", None)
    return meta


def _db_expected_row_map(ctx: dict[str, Any]) -> dict[tuple[str, str, int], list[dict[str, Any]]]:
    db_path = Path(ctx["db_path"])
    scan_id = int(ctx["scan_id"])
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    attacker = _attacker_map(conn, scan_id)
    mapped: dict[tuple[str, str, int], list[dict[str, Any]]] = {}
    rows = conn.execute(
        """
        SELECT id, signal_type, finding_id, display_id, file_path, line_number,
               severity, title, description, app_reachability, cwe_id, cve_id,
               secret_type, pii_type, package_name, package_version, scanner,
               rule_id, risk_level, prod_status, remediation_kind,
               remediation_target, remediation_action, synthesis_hints_json,
               exploit_verdict_json
          FROM signals
         WHERE scan_id = ?
           AND COALESCE(prod_status, 'UNKNOWN') != 'NON_PROD'
        """,
        (scan_id,),
    ).fetchall()
    for raw in rows:
        row = dict(raw)
        path = _normalize_demo_path(str(row.get("file_path") or ""))
        line = int(row.get("line_number") or 0)
        row["normalized_path"] = path
        row["line_number"] = line
        row["attacker"] = attacker.get((_db_family(row), path, line), {})
        for key in _db_match_keys(row):
            mapped.setdefault(key, []).append(row)
    return mapped


def _public_signal(row: dict[str, Any]) -> dict[str, Any]:
    if not row:
        return {}
    attacker = row.get("attacker") if isinstance(row.get("attacker"), dict) else {}
    public: dict[str, Any] = {
        "id": row.get("id"),
        "signal_type": row.get("signal_type"),
        "finding_id": row.get("finding_id"),
        "display_id": row.get("display_id"),
        "file_path": row.get("normalized_path") or _normalize_demo_path(str(row.get("file_path") or "")),
        "line_number": row.get("line_number"),
        "severity": row.get("severity"),
        "risk_level": row.get("risk_level"),
        "title": row.get("title"),
        "description": row.get("description"),
        "app_reachability": row.get("app_reachability"),
        "prod_status": row.get("prod_status"),
        "cwe_id": row.get("cwe_id"),
        "cve_id": row.get("cve_id"),
        "secret_type": row.get("secret_type"),
        "pii_type": row.get("pii_type"),
        "package_name": row.get("package_name"),
        "package_version": row.get("package_version"),
        "scanner": row.get("scanner"),
        "rule_id": row.get("rule_id"),
        "remediation_kind": row.get("remediation_kind"),
        "remediation_target": row.get("remediation_target"),
        "remediation_action": row.get("remediation_action"),
    }
    if attacker:
        public["attacker"] = {
            "exploitable": attacker.get("exploitable"),
            "severity": attacker.get("severity"),
            "defense_rationale": attacker.get("defense_rationale"),
            "blocked_by": _blocked_by_list(attacker.get("blocked_by_json")),
            "model_used": attacker.get("model_used"),
            "created_at": attacker.get("created_at"),
            "error": attacker.get("error"),
        }
    evidence = _defense_evidence(row)
    if evidence:
        public["defense_evidence"] = evidence
    return {key: value for key, value in public.items() if value not in (None, "")}


def _db_actionable_count(ctx: dict[str, Any], *, deferred_keys: set[tuple[str, str, int]] | None = None) -> int:
    deferred_keys = deferred_keys or set()
    conn = sqlite3.connect(Path(ctx["db_path"]))
    conn.row_factory = sqlite3.Row
    scan_id = int(ctx["scan_id"])
    try:
        attacker = _attacker_map(conn, scan_id)
        rows = conn.execute(
            """
            SELECT id, signal_type, finding_id, display_id, file_path, line_number,
                   severity, title, description, app_reachability, cwe_id, cve_id,
                   secret_type, pii_type, package_name, package_version, scanner,
                   rule_id, risk_level, prod_status, remediation_kind,
                   remediation_target, remediation_action, synthesis_hints_json,
                   exploit_verdict_json
              FROM signals
             WHERE scan_id = ?
               AND UPPER(COALESCE(prod_status, 'UNKNOWN')) = 'PRODUCTION'
               AND UPPER(COALESCE(risk_level, severity, 'UNKNOWN')) != 'INFO'
            """,
            (scan_id,),
        ).fetchall()
        count = 0
        for raw in rows:
            row = dict(raw)
            path = _normalize_demo_path(str(row.get("file_path") or ""))
            line = int(row.get("line_number") or 0)
            row["normalized_path"] = path
            row["line_number"] = line
            row["attacker"] = attacker.get((_db_family(row), path, line), {})
            if _signal_blocks_remediation(row) and not _row_matches_deferred(row, deferred_keys):
                count += 1
        return count
    finally:
        conn.close()


def _row_matches_deferred(row: dict[str, Any], deferred_keys: set[tuple[str, str, int]]) -> bool:
    if not deferred_keys:
        return False
    return any(key in deferred_keys for key in _db_match_keys(row))


def _db_ai_usage_summary(ctx: dict[str, Any]) -> dict[str, Any]:
    conn = sqlite3.connect(Path(ctx["db_path"]))
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) AS calls,
                   COALESCE(SUM(CAST(tokens_in AS INTEGER)), 0) AS tokens_in,
                   COALESCE(SUM(CAST(tokens_out AS INTEGER)), 0) AS tokens_out,
                   COALESCE(SUM(CAST(cost_usd AS REAL)), 0.0) AS cost_usd,
                   COALESCE(SUM(CAST(duration_ms AS REAL)), 0.0) AS duration_ms
              FROM enzo_attacker_audit
             WHERE scan_id = ?
            """,
            (int(ctx["scan_id"]),),
        ).fetchone()
    except sqlite3.OperationalError:
        return {"calls": 0, "tokens_in": 0, "tokens_out": 0, "tokens_total": 0, "cost_usd": 0.0, "duration_seconds": 0.0}
    tokens_in = int(row[1] or 0)
    tokens_out = int(row[2] or 0)
    return {
        "calls": int(row[0] or 0),
        "tokens_in": tokens_in,
        "tokens_out": tokens_out,
        "tokens_total": tokens_in + tokens_out,
        "cost_usd": float(row[3] or 0.0),
        "duration_seconds": float(row[4] or 0.0) / 1000.0,
    }


def _db_observed_scan(
    ctx: dict[str, Any],
    *,
    deferred_keys: set[tuple[str, str, int]] | None = None,
) -> dict[str, Any]:
    """Return public, observed DB findings for one concrete scan.

    This intentionally does not compare against the expected contract and does
    not read SARIF. It is the customer-facing "what did this scan report?"
    view for the vulnerable baseline and the remediated proof scan.
    """
    conn = sqlite3.connect(Path(ctx["db_path"]))
    conn.row_factory = sqlite3.Row
    scan_id = int(ctx["scan_id"])
    attacker = _attacker_map(conn, scan_id)
    rows = conn.execute(
        """
        SELECT id, signal_type, finding_id, display_id, file_path, line_number,
               severity, title, description, app_reachability, cwe_id, cve_id,
               secret_type, pii_type, package_name, package_version, scanner,
               rule_id, risk_level, prod_status, remediation_kind,
               remediation_target, remediation_action, synthesis_hints_json,
               exploit_verdict_json
          FROM signals
         WHERE scan_id = ?
           AND COALESCE(prod_status, 'UNKNOWN') != 'NON_PROD'
         ORDER BY
               CASE UPPER(COALESCE(risk_level, severity, 'UNKNOWN'))
                 WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2
                 WHEN 'LOW' THEN 3 WHEN 'INFO' THEN 4 ELSE 5 END,
               file_path,
               line_number,
               id
        """,
        (scan_id,),
    ).fetchall()
    public_rows: list[dict[str, Any]] = []
    for raw in rows:
        row = dict(raw)
        path = _normalize_demo_path(str(row.get("file_path") or ""))
        line = int(row.get("line_number") or 0)
        row["normalized_path"] = path
        row["line_number"] = line
        row["attacker"] = attacker.get((_db_family(row), path, line), {})
        row["deferred"] = _row_matches_deferred(row, deferred_keys or set())
        public_rows.append(_observed_public_row(row))
    public_rows.sort(key=_observed_sort_key)
    return {
        "meta": ctx["meta"],
        "db_total_findings": _safe_int((ctx.get("meta") or {}).get("total_findings")),
        "production_rows": len(public_rows),
        "release_blockers": sum(1 for row in public_rows if row.get("blocks_release")),
        "stats": _observed_status_stats(public_rows),
        "rows": public_rows,
    }


def _observed_status_stats(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize the public DB rows by release-decision category.

    The page deliberately separates release blockers from evidence-only rows:
    a row can be "not attacked" and still block release if it is a reachable
    dependency, secret, DLP/PII, or AI-boundary exposure. Conversely, defended
    rows are retained as evidence and do not block release.
    """
    stats: dict[str, Any] = {
        "total": len(rows),
        "release_blockers": 0,
        "deferred": 0,
        "evidence_only": 0,
        "defended": 0,
        "not_attacked_blockers": 0,
        "not_attacked_evidence": 0,
        "exploitable_blockers": 0,
        "uncertain_blockers": 0,
        "by_exploitability": {},
        "by_release_status": {},
    }
    by_exploitability: Counter[str] = Counter()
    by_release_status: Counter[str] = Counter()
    for row in rows:
        exploitability = str(row.get("exploitability") or "UNKNOWN").upper()
        by_exploitability[exploitability] += 1
        if row.get("deferred"):
            stats["deferred"] += 1
            by_release_status["deferred"] += 1
            continue
        if row.get("blocks_release"):
            stats["release_blockers"] += 1
            by_release_status["release_blocker"] += 1
            if exploitability == "EXPLOITABLE":
                stats["exploitable_blockers"] += 1
            elif exploitability == "NOT ATTACKED":
                stats["not_attacked_blockers"] += 1
            elif exploitability in {"UNCERTAIN", "ATTACK ERROR"}:
                stats["uncertain_blockers"] += 1
            continue
        stats["evidence_only"] += 1
        by_release_status["evidence_only"] += 1
        if exploitability == "DEFENDED":
            stats["defended"] += 1
        elif exploitability == "NOT ATTACKED":
            stats["not_attacked_evidence"] += 1
    stats["by_exploitability"] = dict(sorted(by_exploitability.items()))
    stats["by_release_status"] = dict(sorted(by_release_status.items()))
    return stats


def _demo_status_stats(
    *,
    expected: dict[str, Any],
    rows: list[dict[str, Any]],
    observed_before: dict[str, Any],
    observed_after: dict[str, Any],
    after_actionable_total: int,
) -> dict[str, Any]:
    before = observed_before.get("stats") if isinstance(observed_before.get("stats"), dict) else {}
    after = observed_after.get("stats") if isinstance(observed_after.get("stats"), dict) else {}
    expected_db = expected.get("db") if isinstance(expected.get("db"), dict) else {}
    expected_attacker = expected_db.get("attacker") if isinstance(expected_db.get("attacker"), dict) else {}
    expected_action_required = expected_db.get("action_required") if isinstance(expected_db.get("action_required"), dict) else {}
    expected_release_blockers = _safe_int(expected_action_required.get("total"))
    expected_exploitable = _safe_int(expected_attacker.get("exploitable"))
    expected_defended = _safe_int(expected_attacker.get("defended"))
    expected_raw_total = _safe_int(expected_db.get("total_signals"))
    expected_filtered = max(0, expected_raw_total - expected_release_blockers - expected_defended)
    contract_status = Counter(str(row.get("status") or "unknown") for row in rows)
    contract_exploitability = Counter(str(row.get("actual_exploitability") or "UNKNOWN") for row in rows)
    return {
        "remediation_policy": (
            "Reachable remediates release blockers. Defended rows remain evidence-only "
            "unless a code change naturally removes them. Not-attacked rows are remediated "
            "only when the database still marks them as release blockers."
        ),
        "expected": {
            "raw_db_signals": expected_raw_total,
            "release_blockers": expected_release_blockers,
            "exploitable_blockers": expected_exploitable,
            "not_attacked_or_exposure_blockers": max(0, expected_release_blockers - expected_exploitable),
            "defended_evidence": expected_defended,
            "filtered_fixture_evidence": expected_filtered,
            "proof_target": 0,
        },
        "before": before,
        "after": after,
        "contract": {
            "rows": len(rows),
            "fixed": int(contract_status.get("fixed", 0) + contract_status.get("defended_after_remediation", 0)),
            "deferred": int(contract_status.get("deferred_manual_review", 0)),
            "still_present": int(contract_status.get("still_present", 0)),
            "missing": int(contract_status.get("baseline_missing", 0)),
            "by_status": dict(sorted(contract_status.items())),
            "by_exploitability": dict(sorted(contract_exploitability.items())),
        },
        "final_actionable": int(after_actionable_total),
    }


def _observed_public_row(row: dict[str, Any]) -> dict[str, Any]:
    risk = str(row.get("risk_level") or row.get("severity") or "UNKNOWN").upper()
    reachability = str(row.get("app_reachability") or "UNKNOWN").upper()
    exploitability = _signal_exploitability(row)
    signal_type = str(row.get("signal_type") or "other").upper()
    location = _format_location(row)
    return {
        "id": row.get("display_id") or row.get("cve_id") or row.get("cwe_id") or row.get("finding_id") or row.get("rule_id") or signal_type,
        "signal_type": signal_type,
        "risk": risk,
        "reachability": reachability,
        "exploitability": exploitability,
        "prod_status": str(row.get("prod_status") or "UNKNOWN").upper(),
        "deferred": bool(row.get("deferred")),
        "blocks_release": _signal_blocks_remediation(row) and not bool(row.get("deferred")),
        "location": location,
        "package": _package_label(row),
        "message": str(row.get("title") or row.get("description") or row.get("rule_id") or ""),
        "evidence": _defense_evidence(row),
    }


def _signal_exploitability(row: dict[str, Any]) -> str:
    attacker = row.get("attacker") if isinstance(row.get("attacker"), dict) else {}
    if attacker:
        if str(attacker.get("error") or "").strip():
            return "ATTACK ERROR"
        exploitable = str(attacker.get("exploitable") or "").strip().lower()
        if exploitable in {"1", "true", "yes", "exploitable"}:
            return "EXPLOITABLE"
        if exploitable in {"0", "false", "no", "not_exploitable", "defended"}:
            return "DEFENDED"
        return "UNCERTAIN"
    verdict = _exploit_verdict_outcome(row)
    if verdict == "exploitable":
        return "EXPLOITABLE"
    if verdict == "defended":
        return "DEFENDED"
    if verdict == "uncertain":
        return "UNCERTAIN"
    reachability = str(row.get("app_reachability") or "").upper().replace("-", "_").replace(" ", "_")
    if reachability in DEFENDED_STATES:
        return "DEFENDED"
    return "NOT ATTACKED"


def _blocked_by_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if not isinstance(value, str):
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return [value] if value.strip() else []
    if isinstance(parsed, list):
        return [str(item) for item in parsed if str(item).strip()]
    if isinstance(parsed, dict):
        return [f"{key}: {val}" for key, val in parsed.items() if str(val).strip()]
    return [str(parsed)] if str(parsed).strip() else []


def _defense_evidence(row: dict[str, Any]) -> str:
    attacker = row.get("attacker") if isinstance(row.get("attacker"), dict) else {}
    parts: list[str] = []
    rationale = str(attacker.get("defense_rationale") or "").strip() if attacker else ""
    if rationale:
        parts.append(rationale)
    blocked_by = _blocked_by_list(attacker.get("blocked_by_json")) if attacker else []
    if blocked_by:
        parts.append("Blocked by: " + "; ".join(blocked_by[:3]))
    if parts:
        return " ".join(parts)
    if _signal_exploitability(row) == "DEFENDED":
        return "Classified as defended because Reachable found the code path but Enzo attacker did not confirm an exploitable path."
    if not _signal_blocks_remediation(row):
        return "Not release-blocking in the proof database."
    return ""


def _observed_sort_key(row: dict[str, Any]) -> tuple[int, int, str, str]:
    blocker_rank = 0 if row.get("blocks_release") else 1
    risk_rank = RISK_ORDER.get(str(row.get("risk") or "UNKNOWN").upper(), 9)
    return (blocker_rank, risk_rank, str(row.get("signal_type") or ""), str(row.get("location") or ""))


def _package_label(row: dict[str, Any]) -> str:
    package = str(row.get("package_name") or "")
    version = str(row.get("package_version") or "")
    if package and version:
        return f"{package}@{version}"
    return package


def _format_location(row: dict[str, Any]) -> str:
    path = str(row.get("normalized_path") or _normalize_demo_path(str(row.get("file_path") or "")))
    line = int(row.get("line_number") or 0)
    if path and line:
        return f"{path}:{line}"
    return path


def _attacker_map(conn: sqlite3.Connection, scan_id: int) -> dict[tuple[str, str, int], dict[str, Any]]:
    try:
        rows = conn.execute(
            """
            SELECT finding_type, file_path, line_number, exploitable, severity,
                   attack_vector, defense_rationale, blocked_by_json, model_used,
                   tokens_in, tokens_out, cost_usd, duration_ms, error, created_at
              FROM enzo_attacker_audit
             WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    out: dict[tuple[str, str, int], dict[str, Any]] = {}
    for raw in rows:
        row = dict(raw)
        family = str(row.get("finding_type") or "").lower()
        if family == "secret":
            family = "secret"
        path = _normalize_demo_path(str(row.get("file_path") or ""))
        try:
            line = int(row.get("line_number") or 0)
        except (TypeError, ValueError):
            line = 0
        out[(family, path, line)] = row
    return out


def _expected_match_key(rule: Any, path: Any, line: Any) -> tuple[str, str, int]:
    return (_expected_family(rule), _normalize_demo_path(str(path or "")), int(line or 0))


def _expected_family(rule: Any) -> str:
    prefix = str(rule or "").split("/", 1)[0].lower()
    return {"secret": "secret", "dlp": "dlp", "ai": "ai", "cwe": "cwe", "cve": "cve"}.get(prefix, prefix or "other")


def _db_family(row: dict[str, Any]) -> str:
    return str(row.get("signal_type") or "").lower()


def _db_match_keys(row: dict[str, Any]) -> set[tuple[str, str, int]]:
    family = _db_family(row)
    path = str(row.get("normalized_path") or _normalize_demo_path(str(row.get("file_path") or "")))
    line = int(row.get("line_number") or 0)
    keys = {(family, path, line)}
    cwe_id = str(row.get("cwe_id") or "").upper()
    title = str(row.get("title") or "")
    description = str(row.get("description") or "")
    haystack = f" {cwe_id} {title} {description} ".lower()
    if family == "cwe" and (cwe_id == "CWE-359" or "pii" in haystack or "data leakage" in haystack):
        keys.add(("dlp", path, line))
        keys.add(("ai", path, line))
    if family == "ai" and ("pii" in haystack or "data leakage" in haystack):
        keys.add(("dlp", path, line))
    return keys


def _signal_blocks_remediation(row: dict[str, Any]) -> bool:
    if not row:
        return False
    prod_status = str(row.get("prod_status") or "UNKNOWN").upper()
    if prod_status != "PRODUCTION":
        return False
    risk = str(row.get("risk_level") or row.get("severity") or "UNKNOWN").upper()
    if risk == "INFO":
        return False
    attacker = row.get("attacker") if isinstance(row.get("attacker"), dict) else {}
    if attacker:
        if str(attacker.get("error") or "").strip():
            return True
        exploitable = str(attacker.get("exploitable") or "").strip().lower()
        if exploitable in {"0", "false", "no", "not_exploitable", "defended"}:
            return False
        if exploitable in {"1", "true", "yes", "exploitable"}:
            return True
    verdict = _exploit_verdict_outcome(row)
    if verdict == "defended":
        return False
    if verdict == "exploitable":
        return True
    reachability = str(row.get("app_reachability") or "").upper().replace("-", "_").replace(" ", "_")
    if reachability in DEFENDED_STATES:
        return False
    return reachability in {"EXPLOITABLE", "REACHABLE", "UNKNOWN"}


def _exploit_verdict_outcome(row: dict[str, Any]) -> str:
    verdict = _json_object(row.get("exploit_verdict_json"))
    if not verdict:
        return ""
    bool_value = _boolish(verdict.get("exploitable"))
    if bool_value is True:
        return "exploitable"
    if bool_value is False:
        return "defended"
    for key in ("verdict", "status", "outcome", "attackability"):
        value = str(verdict.get(key) or "").strip().lower().replace("-", "_").replace(" ", "_")
        if value in {"exploitable", "attackable", "proven"}:
            return "exploitable"
        if value in {"not_exploitable", "defended", "defendable", "not_attackable", "safe"}:
            return "defended"
        if value in {"uncertain", "unknown", "error"}:
            return "uncertain"
    return ""


def _json_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _boolish(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "exploitable", "attackable"}:
        return True
    if text in {"0", "false", "no", "n", "not_exploitable", "defended", "defendable", "not_attackable"}:
        return False
    return None


def _expected_exploitability(expected: dict[str, Any], signal: dict[str, Any]) -> str:
    if not signal:
        return ""
    attacker = signal.get("attacker") if isinstance(signal.get("attacker"), dict) else {}
    if attacker:
        if str(attacker.get("error") or "").strip():
            return "ATTACK ERROR"
        exploitable = str(attacker.get("exploitable") or "").strip().lower()
        if exploitable in {"1", "true", "yes", "exploitable"}:
            return "EXPLOITABLE"
        if exploitable in {"0", "false", "no", "not_exploitable", "defended"}:
            return "DEFENDED"
        return "UNCERTAIN"
    expected_state = str(expected.get("expected_reachability") or "").strip().lower()
    return expected_state.upper() if expected_state in {"exploitable", "defended", "defendable"} else "NOT ATTACKED"


def _plain_kind(rule_id: str) -> str:
    if rule_id.startswith("CVE/"):
        return "Vulnerable dependency"
    if rule_id.startswith("CWE/78"):
        return "Command injection"
    if rule_id.startswith("CWE/918"):
        return "Server-side request forgery"
    if rule_id.startswith("CWE/319"):
        return "Cleartext network exposure"
    if rule_id.startswith("CWE/200"):
        return "Information disclosure"
    if rule_id.startswith("SECRET/"):
        return "Secret exposure"
    if rule_id.startswith("DLP/"):
        return "PII / sensitive data exposure"
    if rule_id.startswith("AI/"):
        return "AI / LLM security issue"
    return "Security finding"


def _sarif_row_map(path: Path) -> Counter[tuple[str, str, str, str, str, int]]:
    rows: Counter[tuple[str, str, str, str, str, int]] = Counter()
    if not path.exists():
        return rows
    data = _load_json(path)
    for run in data.get("runs") or []:
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            loc = ((result.get("locations") or [{}])[0].get("physicalLocation") or {})
            artifact = (loc.get("artifactLocation") or {}).get("uri") or ""
            region = loc.get("region") or {}
            props = result.get("properties") or {}
            rows[
                _row_key(
                    result.get("ruleId"),
                    props.get("reachabilityState"),
                    props.get("riskLevel"),
                    props.get("prodStatus"),
                    _normalize_demo_path(str(artifact)),
                    int(region.get("startLine") or 0),
                )
            ] += 1
    return rows


def _row_key(rule: Any, reachability: Any, risk: Any, prod: Any, path: Any, line: Any) -> tuple[str, str, str, str, str, int]:
    return (
        str(rule or ""),
        str(reachability or "").lower(),
        str(risk or "").upper(),
        str(prod or "").upper(),
        _normalize_demo_path(str(path or "")),
        int(line or 0),
    )


def _normalize_demo_path(path: str) -> str:
    for marker in ("/internal/", "/cmd/", "/config/", "/deploy/", "/testdata/"):
        if marker in path:
            return marker.strip("/") + "/" + path.split(marker, 1)[1]
    return path


def _copy_latest_compliance_pack(out_dir: Path) -> dict[str, Any]:
    artifact_root = out_dir.parent
    reports_root = artifact_root / "reports"
    if not reports_root.exists():
        return {"available": False}
    report_dirs = [path for path in reports_root.iterdir() if path.is_dir()]
    preferred = ["after-final", *sorted((path.name for path in report_dirs), reverse=True)]
    for label in preferred:
        report_dir = reports_root / label
        md_path = report_dir / "compliance.md"
        json_path = report_dir / "compliance.json"
        narrative_md_path = report_dir / "compliance-narrative.md"
        narrative_json_path = report_dir / "compliance-narrative.json"
        if not any(path.exists() for path in (md_path, json_path, narrative_md_path, narrative_json_path)):
            continue
        copied: dict[str, Any] = {"available": True, "label": label}
        if json_path.exists():
            shutil.copy2(json_path, out_dir / "compliance.json")
            copied["json"] = "compliance.json"
            compliance_json = _load_json(json_path)
            proof_counts = (compliance_json.get("summary") or {}).get("proof_run_counts")
            if isinstance(proof_counts, dict):
                copied["proof_run_counts"] = proof_counts
        if narrative_json_path.exists():
            shutil.copy2(narrative_json_path, out_dir / "compliance-narrative.json")
            copied["narrative_json"] = "compliance-narrative.json"
        return copied
    return {"available": False}


def _summarize(*, sarif: dict[str, Any], ledger: dict[str, Any], compliance: dict[str, Any] | None = None) -> dict[str, Any]:
    run = (sarif.get("runs") or [{}])[0] if isinstance(sarif, dict) else {}
    rules = {
        str(rule.get("id") or ""): rule
        for rule in (((run.get("tool") or {}).get("driver") or {}).get("rules") or [])
        if isinstance(rule, dict)
    }
    results = [item for item in (run.get("results") or []) if isinstance(item, dict)]
    findings = [_result_summary(result, rules.get(str(result.get("ruleId") or ""), {})) for result in results]
    findings.sort(key=_priority_key)
    top_priority = [
        item
        for item in findings
        if item["reachability"].lower() in {"exploitable", "reachable"}
    ][:12]
    top_defended = [item for item in findings if _is_defended(item)][:12]
    by_family = Counter(family for item in findings for family in item.get("families", []))
    suspicious_package_count = sum(1 for item in findings if _is_suspicious_package(item))

    return {
        "repo": _repo_slug(),
        "ref": os.environ.get("CI_COMMIT_REF_NAME") or os.environ.get("GITHUB_REF_NAME", ""),
        "sha": os.environ.get("CI_COMMIT_SHA") or os.environ.get("GITHUB_SHA", ""),
        "run_id": os.environ.get("CI_PIPELINE_ID") or os.environ.get("GITHUB_RUN_ID", ""),
        "total": len(findings),
        "by_level": dict(Counter(item["level"] for item in findings)),
        "by_type": dict(Counter(item["type"] for item in findings)),
        "by_reachability": dict(Counter(item["reachability"] for item in findings)),
        "by_family": dict(by_family),
        "suspicious_package_count": suspicious_package_count,
        "top_priority": top_priority,
        "top_defended": top_defended,
        "top": findings[:25],
        "remediation": _remediation_summary(ledger),
        "verification": _verification_summary(ledger=ledger, findings=findings),
        "proof": _proof_summary(run=run, findings=findings, compliance=compliance or {}),
        "sarif_error": sarif.get("_error"),
        "ledger_error": ledger.get("_error"),
    }


def _result_summary(result: dict[str, Any], rule: dict[str, Any]) -> dict[str, Any]:
    props = result.get("properties") or {}
    rule_id = str(result.get("ruleId") or rule.get("id") or "REACHABLE")
    prefix = rule_id.split("/", 1)[0] if "/" in rule_id else "OTHER"
    message = str(((result.get("message") or {}).get("text")) or "")
    package = str(props.get("package") or "")
    fix = str(props.get("fixVersion") or props.get("workaround") or "")
    level = str(result.get("level") or "warning").lower()
    title = str(((rule.get("shortDescription") or {}).get("text")) or rule.get("name") or rule_id)
    reachability = _reachability_state(props, message, title)
    risk = _risk_level(props, result, rule)
    families = _families_for_result(rule_id=rule_id, prefix=prefix, title=title, message=message, props=props)
    return {
        "rule_id": rule_id,
        "type": prefix,
        "title": title,
        "message": message,
        "level": level,
        "risk": risk,
        "reachability": reachability,
        "package": package,
        "fix": fix,
        "location": _location(result),
        "families": families,
        "proof": _sanitize_proof_evidence(props.get("proofEvidence")),
    }


def _reachability_state(props: dict[str, Any], message: str, title: str) -> str:
    raw = str(
        props.get("reachabilityState")
        or props.get("state")
        or props.get("attackerOutcome")
        or props.get("attackOutcome")
        or "unknown"
    ).strip()
    normalized = raw.upper().replace("-", "_").replace(" ", "_")
    haystack = f" {title} {message} ".lower()
    if normalized in {"DEFENDED", "DEFENDABLE", "NOT_EXPLOITABLE", "SAFE", "SUPPRESSED"}:
        return "DEFENDED" if normalized in {"NOT_EXPLOITABLE", "SAFE", "SUPPRESSED"} else normalized
    if "not exploitable" in haystack or "blocked by" in haystack or "defended" in haystack:
        return "DEFENDED"
    return normalized or "UNKNOWN"


def _risk_level(props: dict[str, Any], result: dict[str, Any], rule: dict[str, Any]) -> str:
    raw = (
        props.get("riskLevel")
        or props.get("risk")
        or props.get("severity")
        or ((rule.get("properties") or {}).get("severity") if isinstance(rule.get("properties"), dict) else None)
        or result.get("level")
        or "UNKNOWN"
    )
    risk = str(raw).upper().replace("-", "_").replace(" ", "_")
    if risk == "ERROR":
        return "HIGH"
    if risk == "WARNING":
        return "MEDIUM"
    if risk == "NOTE":
        return "LOW"
    return risk


def _families_for_result(*, rule_id: str, prefix: str, title: str, message: str, props: dict[str, Any]) -> list[str]:
    text = f" {rule_id} {prefix} {title} {message} {json.dumps(props, sort_keys=True, default=str)} ".lower()
    families: list[str] = []
    if prefix in {"MALWARE", "SUSPICIOUS"} or any(term in text for term in MALWARE_TERMS):
        families.append("Malware / suspicious supply chain")
    if prefix == "DLP" or any(term in text for term in DLP_TERMS):
        families.append("DLP / PII")
    if prefix in {"AI", "LLM", "MCP", "RAG"} or any(term in text for term in AI_LLM_TERMS):
        families.append("OWASP AI / LLM")
    web_labels = _owasp_web_labels(rule_id, title, message, props)
    if web_labels:
        families.append("OWASP Web Top 10")
        families.extend(web_labels[:2])
    if prefix == "CVE":
        families.append("OWASP Web Top 10")
        families.append("A06 Vulnerable and Outdated Components")
    if prefix == "SECRET":
        families.append("Secrets")
    return sorted(dict.fromkeys(families))


def _owasp_web_labels(rule_id: str, title: str, message: str, props: dict[str, Any]) -> list[str]:
    text = f" {rule_id} {title} {message} {json.dumps(props, sort_keys=True, default=str)} "
    cwes = {int(match) for match in re.findall(r"CWE[-_ ]?(\d+)", text, flags=re.IGNORECASE)}
    return [label for label, members in OWASP_WEB_CWE_MAP.items() if cwes & members]


def _is_defended(item: dict[str, Any]) -> bool:
    return str(item.get("reachability") or "").upper() in DEFENDED_STATES


def _is_suspicious_package(item: dict[str, Any]) -> bool:
    rule_id = str(item.get("rule_id") or "").upper()
    return item.get("type") == "SUSPICIOUS" or rule_id.startswith("SUSPICIOUS/")


def _location(result: dict[str, Any]) -> str:
    locations = result.get("locations") or []
    if not locations:
        return ""
    physical = ((locations[0].get("physicalLocation") or {}) if isinstance(locations[0], dict) else {})
    uri = str(((physical.get("artifactLocation") or {}).get("uri")) or "")
    uri = _repo_relative_uri(uri)
    region = physical.get("region") or {}
    line = region.get("startLine")
    return f"{uri}:{line}" if uri and line else uri


def _repo_relative_uri(uri: str) -> str:
    if not uri:
        return ""
    normalized = uri.replace("\\", "/")
    repo = os.environ.get("GITHUB_REPOSITORY", "").split("/")[-1] or os.environ.get("CI_PROJECT_NAME", "")
    if repo:
        marker = f"/{repo}/"
        if marker in normalized:
            return normalized.split(marker, 1)[1]
    for marker in ("/work/", "/builds/"):
        if marker in normalized:
            tail = normalized.split(marker, 1)[1]
            parts = tail.split("/")
            if len(parts) > 2:
                return "/".join(parts[2:])
    return normalized.lstrip("/")


def _priority_key(item: dict[str, str]) -> tuple[int, int, str, str]:
    return (
        REACHABILITY_ORDER.get(item["reachability"].lower(), 9),
        RISK_ORDER.get(item.get("risk", "UNKNOWN").upper(), 9),
        item["type"],
        item["rule_id"],
    )


def _remediation_summary(ledger: dict[str, Any]) -> dict[str, Any]:
    if not ledger:
        return {"status": "not-run", "message": "No remediation ledger was produced."}
    outcome = ledger.get("outcome") if isinstance(ledger.get("outcome"), dict) else {}
    attempts = ledger.get("attempts") or []
    scans = ledger.get("scans") or []
    workflow = ledger.get("workflow") if isinstance(ledger.get("workflow"), dict) else {}
    inputs = workflow.get("inputs") if isinstance(workflow.get("inputs"), dict) else {}
    batch_scans = [
        scan
        for scan in scans
        if isinstance(scan, dict) and str(scan.get("label") or "").startswith("after-batch-")
    ]
    used_batches = max(len(batch_scans), len(attempts))
    selected_rules = []
    for attempt in attempts:
        if isinstance(attempt, dict):
            selected_rules.extend(attempt.get("selected_rules") or [])
    return {
        "status": outcome.get("status") or ledger.get("status") or "unknown",
        "message": outcome.get("message") or ledger.get("message") or "",
        "attempt_count": len(attempts),
        "used_batches": used_batches,
        "max_batches": _safe_int(inputs.get("max_batches")) or used_batches,
        "rescan_strategy": str(inputs.get("rescan_strategy") or ""),
        "remediation_branch": str(ledger.get("remediation_branch") or ""),
        "batch_scan_labels": [str(scan.get("label") or "") for scan in batch_scans],
        "scan_count": len(scans),
        "proof_scan": ledger.get("proof_scan") or {},
        "selected_rule_count": len(selected_rules),
        "selected_rules": selected_rules[:12],
    }


def _verification_summary(*, ledger: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    if not ledger:
        return {
            "status": "not-run",
            "mode": "none",
            "clean": len(findings) == 0,
            "results": len(findings),
            "label": "repo.db proof unavailable",
            "message": "No remediation ledger was produced.",
        }
    outcome = ledger.get("outcome") if isinstance(ledger.get("outcome"), dict) else {}
    workflow = ledger.get("workflow") if isinstance(ledger.get("workflow"), dict) else {}
    inputs = workflow.get("inputs") if isinstance(workflow.get("inputs"), dict) else {}
    proof_scan = ledger.get("proof_scan") if isinstance(ledger.get("proof_scan"), dict) else {}
    results = _safe_int(proof_scan.get("results") if proof_scan else len(findings))
    rescan_only = str(inputs.get("rescan_only") or "").lower() == "true"
    remediation_enabled = str(inputs.get("remediate") or "").lower() == "true"
    if rescan_only:
        mode = "rescan-only branch verification"
    elif remediation_enabled:
        mode = "automatic post-remediation proof"
    else:
        mode = "scan-only baseline"
    status = str(outcome.get("status") or "unknown")
    return {
        "status": status,
        "mode": mode,
        "clean": results == 0,
        "results": results,
        "label": str(proof_scan.get("label") or "compatibility export"),
        "message": str(outcome.get("message") or ""),
        "branch": str(ledger.get("remediation_branch") or workflow.get("ref") or ""),
        "run_url": str(workflow.get("run_url") or ""),
    }


def _proof_summary(*, run: dict[str, Any], findings: list[dict[str, Any]], compliance: dict[str, Any]) -> dict[str, Any]:
    proof = _sanitize_proof_evidence((run.get("properties") or {}).get("proofEvidence"))
    source = "compatibility-export" if proof.get("run_count") else ""
    if not proof.get("run_count"):
        proof = _proof_from_compliance_counts(compliance.get("proof_run_counts"))
        source = "compliance" if proof.get("run_count") else ""
    if not proof.get("run_count"):
        proof = _proof_from_findings(findings)
        source = "compatibility-export-results" if proof.get("run_count") else "none"
    proof["source"] = source
    return proof


def _sanitize_proof_evidence(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _empty_proof_summary()
    return {
        "profile_count": _safe_int(value.get("profileCount")),
        "run_count": _safe_int(value.get("runCount")),
        "verified_exploitable": _safe_int(value.get("verifiedExploitable")),
        "defended_after_reattack": _safe_int(value.get("defendedAfterReattack")),
        "needs_review": _safe_int(value.get("needsReview")),
        "failed": _safe_int(value.get("failed")),
        "skipped_policy": _safe_int(value.get("skippedPolicy")),
        "by_state": _safe_int_map(value.get("byState")),
        "profile_kinds": [str(item) for item in (value.get("profileKinds") or []) if item],
    }


def _proof_from_compliance_counts(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _empty_proof_summary()
    return {
        "profile_count": _safe_int(value.get("total_profiles")),
        "run_count": _safe_int(value.get("total_runs")),
        "verified_exploitable": _safe_int(value.get("verified_exploitable")),
        "defended_after_reattack": _safe_int(value.get("defended_after_reattack")),
        "needs_review": _safe_int(value.get("needs_review")),
        "failed": _safe_int(value.get("failed")),
        "skipped_policy": _safe_int(value.get("skipped_policy")),
        "by_state": _safe_int_map(value.get("by_state")),
        "profile_kinds": sorted(str(item) for item in (value.get("by_profile_kind") or {}).keys() if item),
    }


def _proof_from_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    summary = _empty_proof_summary()
    kinds: set[str] = set()
    for item in findings:
        proof = item.get("proof")
        if not isinstance(proof, dict) or not proof.get("run_count"):
            continue
        summary["profile_count"] += _safe_int(proof.get("profile_count"))
        summary["run_count"] += _safe_int(proof.get("run_count"))
        summary["verified_exploitable"] += _safe_int(proof.get("verified_exploitable"))
        summary["defended_after_reattack"] += _safe_int(proof.get("defended_after_reattack"))
        summary["needs_review"] += _safe_int(proof.get("needs_review"))
        summary["failed"] += _safe_int(proof.get("failed"))
        summary["skipped_policy"] += _safe_int(proof.get("skipped_policy"))
        for state, count in (proof.get("by_state") or {}).items():
            summary["by_state"][state] = summary["by_state"].get(state, 0) + _safe_int(count)
        kinds.update(str(kind) for kind in (proof.get("profile_kinds") or []) if kind)
    summary["profile_kinds"] = sorted(kinds)
    return summary


def _empty_proof_summary() -> dict[str, Any]:
    return {
        "profile_count": 0,
        "run_count": 0,
        "verified_exploitable": 0,
        "defended_after_reattack": 0,
        "needs_review": 0,
        "failed": 0,
        "skipped_policy": 0,
        "by_state": {},
        "profile_kinds": [],
    }


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_int_map(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    return {str(key): _safe_int(count) for key, count in value.items() if key}


def _render_html(*, summary: dict[str, Any], generated_at: str, page_url: str, code_scanning_url: str, run_url: str) -> str:
    by_reach = summary.get("by_reachability") or {}
    by_type = summary.get("by_type") or {}
    by_family = summary.get("by_family") or {}
    remediation = summary.get("remediation") or {}
    verification = summary.get("verification") or {}
    compliance = summary.get("compliance") or {}
    proof = summary.get("proof") or {}
    run_evidence = summary.get("run_evidence") if isinstance(summary.get("run_evidence"), dict) else {}
    run_evidence_summary = run_evidence.get("summary") if isinstance(run_evidence.get("summary"), dict) else {}
    expected_demo = summary.get("expected_demo") or {}
    defended_count = sum(int(by_reach.get(state, 0)) for state in DEFENDED_STATES)
    suspicious_count = int(summary.get("suspicious_package_count") or 0)
    priority_rows = "\n".join(_issue_row(item) for item in summary.get("top_priority") or [])
    if not priority_rows:
        priority_rows = '<tr><td colspan="8">No exploitable or reachable findings were reported.</td></tr>'
    defended_rows = "\n".join(_issue_row(item) for item in summary.get("top_defended") or [])
    if not defended_rows:
        defended_rows = '<tr><td colspan="8">No defended or defendable findings were included in the compatibility export.</td></tr>'
    rows = "\n".join(_issue_row(item) for item in summary.get("top") or [])
    if not rows:
        rows = '<tr><td colspan="8">No release-blocking signals were reported.</td></tr>'
    expected_rows = "\n".join(_expected_demo_row(item) for item in expected_demo.get("rows") or [])
    if not expected_rows:
        expected_rows = '<tr><td colspan="9">No checked-in expected baseline contract was found.</td></tr>'
    observed = expected_demo.get("observed") if isinstance(expected_demo.get("observed"), dict) else {}
    observed_before = observed.get("before") if isinstance(observed.get("before"), dict) else {}
    observed_after = observed.get("after") if isinstance(observed.get("after"), dict) else {}
    status_stats = expected_demo.get("stats") if isinstance(expected_demo.get("stats"), dict) else {}
    artifact_links = _artifact_links(summary.get("artifacts") or [], compliance)
    expected_status = "Clean" if expected_demo.get("clean") else "Needs review"
    baseline_meta = expected_demo.get("baseline") if isinstance(expected_demo.get("baseline"), dict) else {}
    after_meta = expected_demo.get("after") if isinstance(expected_demo.get("after"), dict) else {}
    baseline_ai = expected_demo.get("baseline_ai") if isinstance(expected_demo.get("baseline_ai"), dict) else {}
    after_ai = expected_demo.get("after_ai") if isinstance(expected_demo.get("after_ai"), dict) else {}
    ai_economics = summary.get("ai_economics") if isinstance(summary.get("ai_economics"), dict) else {}
    expected_class = "ok" if expected_demo.get("clean") else "bad"
    hero_title = "Reachable fixed the vulnerable branch" if expected_demo.get("clean") else "Reachable remediation needs review"
    hero_headline = str(expected_demo.get("headline") or "Reachable Go Demo")
    top_meta = _top_metadata_strip(
        summary=summary,
        generated_at=generated_at,
        page_url=page_url,
        run_url=run_url,
        after_meta=after_meta,
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reachable Go Demo - Last Verified Run</title>
  <link rel="icon" href="favicon.svg" type="image/svg+xml">
  <style>
    :root {{ color-scheme: light dark; --bg:#0e151c; --fg:#f7fafc; --muted:#98a7b5; --line:#253342; --card:#141f29; --accent:#5fe0a3; --warn:#ffd166; --bad:#ff7b7b; }}
    body {{ margin:0; font-family:Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:var(--bg); color:var(--fg); }}
    main {{ max-width:1220px; margin:0 auto; padding:32px 20px 48px; }}
    h1 {{ margin:0 0 8px; font-size:32px; letter-spacing:0; }}
    h2 {{ margin:32px 0 12px; font-size:20px; }}
    p {{ color:var(--muted); line-height:1.5; }}
    a {{ color:var(--accent); }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr)); gap:12px; margin:24px 0; }}
    .card {{ background:var(--card); border:1px solid var(--line); border-radius:8px; padding:16px; }}
    .hero {{ border:1px solid var(--line); border-radius:8px; padding:22px; background:#101923; }}
    .hero.ok {{ border-color:rgba(95,224,163,.55); }}
    .hero.bad {{ border-color:rgba(255,123,123,.65); }}
    .hero h1 {{ font-size:34px; }}
    .verdict {{ border:1px solid rgba(95,224,163,.45); border-radius:8px; background:#0d201a; padding:12px 14px; margin:14px 0; color:#dff8ec; }}
    .verdict strong {{ color:var(--accent); }}
    .meta-strip {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:8px; margin:0 0 18px; }}
    .meta-item {{ border:1px solid var(--line); border-radius:8px; padding:9px 10px; background:#101923; min-width:0; }}
    .meta-label {{ display:block; color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.07em; margin-bottom:3px; }}
    .meta-value {{ display:block; color:var(--fg); font-size:13px; overflow-wrap:anywhere; }}
    .brand {{ display:flex; align-items:center; gap:9px; border:1px solid rgba(95,224,163,.45); border-radius:8px; padding:9px 11px; background:#0d201a; color:var(--accent); font-weight:800; letter-spacing:.12em; }}
    .brand .sigma {{ display:inline-flex; align-items:center; justify-content:center; width:24px; height:24px; border:1px solid rgba(95,224,163,.6); border-radius:6px; font-size:18px; line-height:1; }}
    .subgrid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(270px,1fr)); gap:12px; margin-top:16px; }}
    .status {{ font-size:13px; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); }}
    .status.ok {{ color:var(--accent); }}
    .status.bad {{ color:var(--bad); }}
    .num {{ font-size:28px; font-weight:750; }}
    .label {{ color:var(--muted); font-size:13px; margin-top:4px; }}
    .links {{ display:flex; flex-wrap:wrap; gap:10px; margin:18px 0 4px; }}
    .links a {{ border:1px solid var(--line); border-radius:6px; padding:8px 10px; text-decoration:none; background:#101923; }}
    .artifact-list {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:8px; font-size:12px; }}
    .artifact-list a {{ display:block; border:1px solid var(--line); border-radius:6px; padding:8px 10px; text-decoration:none; background:#101923; }}
    .tabs {{ display:flex; flex-wrap:wrap; gap:8px; margin:18px 0 22px; }}
    .tabs a {{ border:1px solid var(--line); border-radius:999px; padding:8px 12px; text-decoration:none; background:#101923; color:var(--fg); }}
    .tabs a:hover {{ border-color:var(--accent); color:var(--accent); }}
    .scan-tabs {{ margin-top:12px; }}
    .scan-tabs input {{ position:absolute; opacity:0; pointer-events:none; }}
    .scan-tab-labels {{ display:flex; flex-wrap:wrap; gap:8px; margin:12px 0 14px; }}
    .scan-tab-labels label {{ border:1px solid var(--line); border-radius:999px; padding:9px 13px; cursor:pointer; background:#101923; color:var(--fg); }}
    #scan-before:checked ~ .scan-tab-labels label[for="scan-before"],
    #scan-after:checked ~ .scan-tab-labels label[for="scan-after"] {{ border-color:var(--accent); color:#0d201a; background:var(--accent); }}
    .scan-panel {{ display:none; }}
    #scan-before:checked ~ .scan-before,
    #scan-after:checked ~ .scan-after {{ display:block; }}
    .table-scroll {{ overflow-x:auto; border:1px solid var(--line); border-radius:8px; }}
    .table-scroll table {{ border:0; border-radius:0; min-width:980px; }}
    table {{ width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:hidden; }}
    th, td {{ padding:10px 12px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; font-size:14px; }}
    th {{ color:#dce7ee; background:#111b26; }}
    .muted {{ color:var(--muted); }}
    .pill {{ display:inline-block; border:1px solid var(--line); border-radius:999px; padding:2px 8px; font-size:12px; }}
    .reachable {{ color:var(--accent); }}
    .warning {{ color:var(--warn); }}
    .bad {{ color:var(--bad); }}
    footer {{ margin-top:32px; padding-top:18px; border-top:1px solid var(--line); color:var(--muted); font-size:12px; }}
    details p {{ margin:8px 0 0; }}
    code {{ word-break:break-word; }}
    @media (max-width: 640px) {{
      main {{ padding:20px 12px 36px; }}
      h1, .hero h1 {{ font-size:28px; line-height:1.1; }}
      th, td {{ padding:8px 9px; font-size:13px; }}
    }}
  </style>
</head>
<body>
  <main>
    {top_meta}
    <section class="hero {expected_class}">
      <div class="status {expected_class}">Reachable autonomous remediation demo · {html.escape(expected_status)}</div>
      <h1>{html.escape(hero_title)}</h1>
      <div class="verdict"><strong>Verdict:</strong> {html.escape(hero_headline)}</div>
      <p>Public, sanitized proof for the intentionally vulnerable Reachable Go testbed. The page is built from the Reachable scan database: vulnerable baseline scan, remediation proof scan, expected issue contract, branch, commit, scan number, timestamp, and AI cost telemetry. Private prompts, rules, agent transcripts, and local databases are not published.</p>
      {_status_metric_cards(expected_demo, status_stats, remediation, ai_economics)}
      {_release_logic_panel(status_stats)}
      <div class="subgrid">
        {_proof_panel("Vulnerable baseline", baseline_meta, baseline_ai)}
        {_proof_panel("Remediated branch proof", after_meta, after_ai)}
        {_remediation_batch_panel(remediation, expected_demo)}
        {_run_evidence_panel(run_evidence_summary)}
      </div>
    </section>
    <nav class="tabs" aria-label="Reachable report sections">
      <a href="#scan-output">Before / After Scans</a>
      <a href="#expected">Expected Fix Proof</a>
      <a href="#run-evidence">Run Evidence</a>
      <a href="#findings">Remaining Findings</a>
      <a href="#defended">Defended</a>
      <a href="#remediation">Remediation</a>
      <a href="#artifacts">Artifacts</a>
    </nav>
    <section class="card" id="artifacts">
      <h2>Sanitized Artifacts</h2>
      <p class="muted">These are convenience exports. The public page does not publish the private remediation bundle, prompt text, generated rules, agent transcript, raw witnesses, or local databases.</p>
      <div class="artifact-list">{artifact_links}</div>
    </section>
    <section class="card" id="scan-output">
      <h2>Observed Scan Output</h2>
      <p>This is the direct database view of the two scans in the demo run. It does not compare against the expected contract and does not use SARIF. Scan 1 is the intentionally vulnerable baseline. Scan 2 is the remediation branch proof scan.</p>
      <div class="scan-tabs">
        <input type="radio" name="scan-view" id="scan-before" checked>
        <input type="radio" name="scan-view" id="scan-after">
        <div class="scan-tab-labels">
          <label for="scan-before">Scan 1: Before</label>
          <label for="scan-after">Scan 2: Remediated</label>
        </div>
        <div class="scan-panel scan-before">
          {_observed_scan_panel("Scan 1: Before remediation", observed_before)}
        </div>
        <div class="scan-panel scan-after">
          {_observed_scan_panel("Scan 2: Remediated proof", observed_after)}
        </div>
      </div>
    </section>
    <section class="card">
      <h2 id="expected">Demo Contract: Expected Vulnerabilities Fixed</h2>
      <p><strong>{html.escape(expected_status)}:</strong> This table is the demo contract. Each row is an expected vulnerable fixture. “Fixed” means it was present in the vulnerable baseline database and absent from the remediation proof database. Defended evidence is allowed to remain only when it is still nonblocking; release blockers must be gone or explicitly deferred.</p>
      {_contract_status_table(status_stats)}
      <table>
        <thead><tr><th>Expected issue</th><th>Risk</th><th>Reachability</th><th>Exploitability</th><th>Location</th><th>Baseline</th><th>Remediation proof</th><th>Status</th><th>Fix / evidence</th></tr></thead>
        <tbody>{expected_rows}</tbody>
      </table>
    </section>
    <section class="card">
      <h2 id="run-evidence">Run Evidence: Install, Cache, Database</h2>
      <p>This section proves the CI run used an installed Reachable version and either restored or initialized the Reachable cache. The raw proof files are sanitized JSON artifacts; the demo verdict still comes from the scan database.</p>
      {_run_evidence_table(run_evidence_summary)}
    </section>
    <h2 id="findings">Remaining Release Blockers</h2>
    <div class="cards">
      {_card("Selected public findings", str(summary.get("total", 0)))}
      {_card("Exploitable", str(by_reach.get("EXPLOITABLE", 0)))}
      {_card("Reachable", str(by_reach.get("REACHABLE", 0)))}
      {_card("Unknown", str(by_reach.get("UNKNOWN", 0)))}
      {_card("Defended", str(defended_count))}
      {_card("Suspicious packages", str(suspicious_count))}
    </div>
    <p class="muted">This section is a selected public DB summary for release review. Platform exports such as SARIF are linked only as compatibility reports; the demo pass/fail proof above is DB-backed.</p>
    <table>
      <thead><tr><th>Signal</th><th>Reachability</th><th>Risk</th><th>Families</th><th>Package</th><th>Fix</th><th>Location</th><th>Message</th></tr></thead>
      <tbody>{priority_rows}</tbody>
    </table>
    <h2 id="defended">Defended / Defendable Evidence</h2>
    <table>
      <thead><tr><th>Signal</th><th>Reachability</th><th>Risk</th><th>Families</th><th>Package</th><th>Fix</th><th>Location</th><th>Message</th></tr></thead>
      <tbody>{defended_rows}</tbody>
    </table>
    <h2>All Release-Blocking Signals</h2>
    <table>
      <thead><tr><th>Signal</th><th>Reachability</th><th>Risk</th><th>Families</th><th>Package</th><th>Fix</th><th>Location</th><th>Message</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    <h2 id="remediation">Remediation Attempt</h2>
    <p>Status: <strong>{html.escape(str(remediation.get("status") or "unknown"))}</strong>. {html.escape(str(remediation.get("message") or ""))}</p>
    {_remediation_loop_table(remediation, expected_demo)}
    <p class="muted">Detailed remediation rules are intentionally not published because they are generated prompt material. The public evidence shows the branch, batch count, project-test gate, proof scan, and final DB verdict.</p>
    <footer>Copyright © 2026 Sthenos Security, Inc. All rights reserved.</footer>
  </main>
</body>
</html>
"""


def _card(label: str, value: str) -> str:
    return f'<div class="card"><div class="num">{html.escape(value)}</div><div class="label">{html.escape(label)}</div></div>'


def _status_metric_cards(
    expected_demo: dict[str, Any],
    stats: dict[str, Any],
    remediation: dict[str, Any],
    ai_economics: dict[str, Any],
) -> str:
    before = stats.get("before") if isinstance(stats.get("before"), dict) else {}
    after = stats.get("after") if isinstance(stats.get("after"), dict) else {}
    contract = stats.get("contract") if isinstance(stats.get("contract"), dict) else {}
    expected = stats.get("expected") if isinstance(stats.get("expected"), dict) else {}
    cards = [
        _card("Contract rows matched", f"{_safe_int(expected_demo.get('baseline_found'))}/{_safe_int(expected_demo.get('expected_total'))}"),
        _card("Expected release blockers", _before_after(expected.get("release_blockers"), stats.get("final_actionable"))),
        _card("Exploitable blockers", _before_after(expected.get("exploitable_blockers"), 0)),
        _card("Not-attacked / exposure blockers", _before_after(expected.get("not_attacked_or_exposure_blockers"), 0)),
        _card("Defended evidence", f"{_safe_int(expected.get('defended_evidence'))} evidence"),
        _card("Deferred manual review", str(_safe_int(contract.get("deferred") or expected_demo.get("deferred_present")))),
        _card("Final actionable", str(_safe_int(stats.get("final_actionable") if stats else expected_demo.get("after_total")))),
        _card("Remediation batches", _batch_count_label(remediation)),
        _card("AI cost / tokens", f"{_money(ai_economics.get('cost_usd'))} / {_number(ai_economics.get('tokens_total'))}"),
    ]
    return f'<div class="cards">{"".join(cards)}</div>'


def _release_logic_panel(stats: dict[str, Any]) -> str:
    before = stats.get("before") if isinstance(stats.get("before"), dict) else {}
    after = stats.get("after") if isinstance(stats.get("after"), dict) else {}
    expected = stats.get("expected") if isinstance(stats.get("expected"), dict) else {}
    policy = str(stats.get("remediation_policy") or "")
    rows = [
        (
            "Release blockers",
            _before_after(expected.get("release_blockers"), stats.get("final_actionable")),
            "Yes",
            "These rows are the remediation queue. The proof must reduce them to zero, except explicitly deferred manual-review cases.",
        ),
        (
            "Exploitable blockers",
            _before_after(expected.get("exploitable_blockers"), 0),
            "Yes",
            "Enzo attacker proved a reachable attack path. These are the strongest fix candidates.",
        ),
        (
            "Not-attacked / exposure blockers",
            _before_after(expected.get("not_attacked_or_exposure_blockers"), 0),
            "Yes, when blocking",
            "No attack proof was run or applicable, but the DB still marks the row as release-blocking, such as reachable CVEs, secret/DLP exposure, or AI-boundary authority risk.",
        ),
        (
            "Defended evidence",
            f"{_safe_int(expected.get('defended_evidence'))} evidence rows",
            "No",
            "Reachable found a security-shaped path, but Enzo attacker could not prove external control and impact. These rows are audit evidence, not release blockers.",
        ),
        (
            "Filtered fixture evidence",
            f"{_safe_int(expected.get('filtered_fixture_evidence'))} evidence rows",
            "No",
            "Synthetic not-reachable or non-production markers prove detector coverage and are excluded from the fix queue.",
        ),
        (
            "Deferred",
            _before_after(before.get("deferred"), after.get("deferred")),
            "Manual review",
            "A documented exception remains visible so the release owner understands what is not automatically fixed in this demo.",
        ),
    ]
    body = "\n".join(
        "<tr>"
        f"<td>{html.escape(label)}</td>"
        f"<td><strong>{html.escape(count)}</strong></td>"
        f"<td>{html.escape(remediated)}</td>"
        f"<td>{html.escape(meaning)}</td>"
        "</tr>"
        for label, count, remediated, meaning in rows
    )
    return (
        '<div class="card">'
        "<h2>What Gets Remediated</h2>"
        f"<p>{html.escape(policy)}</p>"
        "<div class=\"table-scroll\"><table>"
        "<thead><tr><th>Category</th><th>Before → proof</th><th>Remediated?</th><th>Release-owner meaning</th></tr></thead>"
        f"<tbody>{body}</tbody>"
        "</table></div>"
        "</div>"
    )


def _contract_status_table(stats: dict[str, Any]) -> str:
    contract = stats.get("contract") if isinstance(stats.get("contract"), dict) else {}
    rows = [
        ("Resolved by remediation", contract.get("fixed"), "Expected rows found on the vulnerable baseline and gone or safely nonblocking in the proof scan."),
        ("Deferred manual review", contract.get("deferred"), "Documented exceptions that remain visible and do not count as an automated proof failure."),
        ("Still blocking", contract.get("still_present"), "Expected rows that would fail the proof if any remained."),
        ("Missing from baseline", contract.get("missing"), "Expected rows that were not detected on the vulnerable baseline and would indicate a scanner/testbed mismatch."),
    ]
    body = "\n".join(
        "<tr>"
        f"<td>{html.escape(label)}</td>"
        f"<td><strong>{_safe_int(value)}</strong></td>"
        f"<td>{html.escape(meaning)}</td>"
        "</tr>"
        for label, value, meaning in rows
    )
    return (
        '<div class="table-scroll"><table>'
        '<thead><tr><th>Contract result</th><th>Rows</th><th>Meaning</th></tr></thead>'
        f"<tbody>{body}</tbody>"
        "</table></div>"
    )


def _before_after(before: Any, after: Any) -> str:
    return f"{_safe_int(before)} → {_safe_int(after)}"


def _batch_count_label(remediation: dict[str, Any]) -> str:
    used = _safe_int(remediation.get("used_batches") or remediation.get("attempt_count"))
    allowed = _safe_int(remediation.get("max_batches"))
    if allowed:
        return f"{used}/{allowed}"
    return str(used)


def _remediation_stop_reason(remediation: dict[str, Any], expected_demo: dict[str, Any]) -> str:
    if expected_demo.get("clean"):
        return "Stopped early because the DB proof was clean."
    used = _safe_int(remediation.get("used_batches") or remediation.get("attempt_count"))
    allowed = _safe_int(remediation.get("max_batches"))
    if allowed and used >= allowed:
        return "Stopped because the configured maximum remediation batches was reached."
    if used:
        return "Stopped because no further agent changes were produced; DB proof remains the authority."
    return "No remediation batch ran."


def _remediation_batch_panel(remediation: dict[str, Any], expected_demo: dict[str, Any]) -> str:
    branch = str(remediation.get("remediation_branch") or "")
    strategy = str(remediation.get("rescan_strategy") or "")
    labels = ", ".join(str(label) for label in remediation.get("batch_scan_labels") or []) or "none"
    return (
        '<div class="card">'
        "<h2>Bounded remediation loop</h2>"
        f"<p><strong>Batches used:</strong> {html.escape(_batch_count_label(remediation))}<br>"
        f"<strong>Proof strategy:</strong> {html.escape(strategy or 'final')}<br>"
        f"<strong>Remediation branch:</strong> <code>{html.escape(branch or 'n/a')}</code><br>"
        f"<strong>Batch proof scans:</strong> {html.escape(labels)}<br>"
        f"<strong>Stop reason:</strong> {html.escape(_remediation_stop_reason(remediation, expected_demo))}</p>"
        "</div>"
    )


def _remediation_loop_table(remediation: dict[str, Any], expected_demo: dict[str, Any]) -> str:
    rows = [
        ("Configured maximum batches", str(_safe_int(remediation.get("max_batches")) or "not set")),
        ("Batches used", str(_safe_int(remediation.get("used_batches") or remediation.get("attempt_count")))),
        ("Rescan strategy", str(remediation.get("rescan_strategy") or "final")),
        ("Stop condition", _remediation_stop_reason(remediation, expected_demo)),
        ("Final DB release blockers", str(_safe_int(expected_demo.get("after_total")))),
    ]
    body = "\n".join(
        f"<tr><th>{html.escape(label)}</th><td>{html.escape(value)}</td></tr>"
        for label, value in rows
    )
    return (
        '<p class="muted">Reachable runs a bounded remediation loop: generate one focused task from the current scan database, let the agent patch the review branch, run project tests, rescan the branch into repo.db, then stop as soon as the DB proof is clean or when the configured maximum is reached.</p>'
        f"<table><tbody>{body}</tbody></table>"
    )


def _proof_panel(title: str, meta: dict[str, Any], ai: dict[str, Any]) -> str:
    commit = str(meta.get("commit_short") or str(meta.get("commit_hash") or "")[:12])
    duration = _duration(float(meta.get("duration_seconds") or 0))
    ai_tokens = int(ai.get("tokens_total") or 0)
    ai_calls = int(ai.get("calls") or 0)
    ai_cost = _money(float(ai.get("cost_usd") or 0.0))
    return (
        '<div class="card">'
        f"<h2>{html.escape(title)}</h2>"
        f"<p><strong>Scan:</strong> {html.escape(_scan_label(meta))}<br>"
        f"<strong>Branch:</strong> {html.escape(str(meta.get('branch') or ''))}<br>"
        f"<strong>Commit:</strong> <code>{html.escape(commit)}</code><br>"
        f"<strong>Timestamp:</strong> {html.escape(str(meta.get('timestamp') or ''))}<br>"
        f"<strong>Runtime:</strong> {html.escape(duration)}<br>"
        f"<strong>AI:</strong> {ai_calls} calls, {ai_tokens:,} tokens, {html.escape(ai_cost)}</p>"
        "</div>"
    )


def _run_evidence_panel(evidence: dict[str, Any]) -> str:
    fresh = "yes" if evidence.get("fresh_scan_requested") else "no"
    restored = "yes" if evidence.get("cache_restored") else "no"
    reused = "yes" if evidence.get("repo_db_reused") else "no"
    hash_short = str(evidence.get("latest_repo_db_hash") or "")[:12]
    latest_scan = evidence.get("latest_scan") if isinstance(evidence.get("latest_scan"), dict) else {}
    return (
        '<div class="card">'
        "<h2>CI cache / install evidence</h2>"
        f"<p><strong>Fresh scan requested:</strong> {html.escape(fresh)}<br>"
        f"<strong>Cache restored:</strong> {html.escape(restored)}<br>"
        f"<strong>Install mode:</strong> {html.escape(str(evidence.get('install_mode') or 'unknown'))}<br>"
        f"<strong>Version:</strong> target {html.escape(str(evidence.get('target_version') or 'latest'))}, installed {html.escape(str(evidence.get('installed_version') or 'unknown'))}<br>"
        f"<strong>repo.db reused:</strong> {html.escape(reused)} ({_safe_int(evidence.get('repo_db_count_before'))} before, {_safe_int(evidence.get('repo_db_count_after'))} after)<br>"
        f"<strong>Latest DB hash:</strong> <code>{html.escape(hash_short or 'n/a')}</code><br>"
        f"<strong>Latest scan:</strong> #{html.escape(str(latest_scan.get('id') or 'n/a'))} commit <code>{html.escape(str(latest_scan.get('commit_short') or latest_scan.get('commit_hash') or 'n/a'))}</code></p>"
        "</div>"
    )


def _run_evidence_table(evidence: dict[str, Any]) -> str:
    if not evidence:
        return '<p class="bad">Run evidence JSON was not produced.</p>'
    rows = [
        ("Fresh scan requested", "yes" if evidence.get("fresh_scan_requested") else "no"),
        ("Cache restored", "yes" if evidence.get("cache_restored") else "no"),
        ("Cache source", str(evidence.get("cache_source") or "")),
        ("Install mode", str(evidence.get("install_mode") or "")),
        ("Target version", str(evidence.get("target_version") or "latest")),
        ("Installed version", str(evidence.get("installed_version") or "")),
        ("repo.db reused", "yes" if evidence.get("repo_db_reused") else "no"),
        ("repo.db count before", str(_safe_int(evidence.get("repo_db_count_before")))),
        ("repo.db count after", str(_safe_int(evidence.get("repo_db_count_after")))),
        ("Scan sessions after", str(_safe_int(evidence.get("scan_session_count")))),
        ("Cache size before", f"{_safe_int(evidence.get('cache_size_kb_before')):,} KB"),
        ("Cache size after", f"{_safe_int(evidence.get('cache_size_kb_after')):,} KB"),
        ("Latest repo.db hash", str(evidence.get("latest_repo_db_hash") or "")),
    ]
    body = "\n".join(
        f"<tr><th>{html.escape(label)}</th><td><code>{html.escape(value)}</code></td></tr>"
        for label, value in rows
    )
    return f"<table><tbody>{body}</tbody></table>"


def _top_metadata_strip(
    *,
    summary: dict[str, Any],
    generated_at: str,
    page_url: str,
    run_url: str,
    after_meta: dict[str, Any],
) -> str:
    repo = str(summary.get("repo") or "")
    repo_url = _repo_url(repo)
    branch = str(after_meta.get("branch") or (summary.get("remediation") or {}).get("remediation_branch") or "")
    branch_url = f"{repo_url}/tree/{branch}" if repo_url and branch else ""
    workflow_sha = str(summary.get("sha") or "")
    workflow_short = workflow_sha[:8]
    workflow_commit_url = f"{repo_url}/commit/{workflow_sha}" if repo_url and workflow_sha else ""
    proof_sha = str(after_meta.get("commit_hash") or "")
    proof_short = str(after_meta.get("commit_short") or proof_sha[:8])
    proof_commit_url = f"{repo_url}/commit/{proof_sha}" if repo_url and proof_sha else ""
    scan_id = str(after_meta.get("id") or after_meta.get("db_scan_id") or "")
    generated_dt = _parse_dt(generated_at)
    pacific = generated_dt.astimezone(ZoneInfo("America/Los_Angeles"))
    pacific_text = pacific.strftime("%Y-%m-%d %I:%M:%S %p %Z")
    utc_text = generated_dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        '<section class="meta-strip" aria-label="Run metadata">'
        '<div class="brand"><span class="sigma">Σ</span><span>REACHABLE</span></div>'
        f'{_meta_item("Generated", pacific_text, "", f"UTC: {utc_text}")}'
        f'{_meta_item("Repository", repo, repo_url)}'
        f'{_meta_item("Workflow run", str(summary.get("run_id") or ""), run_url)}'
        f'{_meta_item("Workflow commit", workflow_short, workflow_commit_url)}'
        f'{_meta_item("Remediation branch", branch, branch_url)}'
        f'{_meta_item("Proof scan", f"#{scan_id}" if scan_id else "", "")}'
        f'{_meta_item("Proof commit", proof_short, proof_commit_url)}'
        f'{_meta_item("Page", page_url, page_url)}'
        "</section>"
    )


def _parse_dt(value: str) -> datetime:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _repo_url(repo: str) -> str:
    if os.environ.get("GITLAB_CI"):
        return os.environ.get("CI_PROJECT_URL", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{repo}" if repo else ""


def _meta_item(label: str, value: str, href: str = "", title: str = "") -> str:
    shown = value or "n/a"
    value_html = html.escape(shown)
    if href:
        value_html = f'<a href="{html.escape(href)}">{value_html}</a>'
    title_attr = f' title="{html.escape(title)}"' if title else ""
    return (
        f'<div class="meta-item"{title_attr}>'
        f'<span class="meta-label">{html.escape(label)}</span>'
        f'<span class="meta-value">{value_html}</span>'
        "</div>"
    )


def _observed_scan_panel(title: str, observed: dict[str, Any]) -> str:
    if not observed:
        return '<p class="bad">Observed scan data was not available from repo.db.</p>'
    meta = observed.get("meta") if isinstance(observed.get("meta"), dict) else {}
    stats = observed.get("stats") if isinstance(observed.get("stats"), dict) else {}
    rows = observed.get("rows") if isinstance(observed.get("rows"), list) else []
    table_rows = "\n".join(_observed_scan_row(item) for item in rows)
    if not table_rows:
        table_rows = '<tr><td colspan="8">No production DB findings were reported for this scan.</td></tr>'
    return f"""
      <div class="subgrid">
        {_card("DB scan", _scan_label(meta))}
        {_card("Branch", str(meta.get("branch") or ""))}
        {_card("Commit", str(meta.get("commit_short") or str(meta.get("commit_hash") or "")[:8]))}
        {_card("Timestamp", str(meta.get("timestamp") or ""))}
        {_card("Raw DB findings", str(_safe_int(observed.get("db_total_findings"))))}
        {_card("Production rows listed", str(_safe_int(observed.get("production_rows"))))}
        {_card("Release blockers", str(_safe_int(observed.get("release_blockers"))))}
        {_card("Exploitable blockers", str(_safe_int(stats.get("exploitable_blockers"))))}
        {_card("Not-attacked blockers", str(_safe_int(stats.get("not_attacked_blockers"))))}
        {_card("Defended evidence", str(_safe_int(stats.get("defended"))))}
        {_card("Deferred", str(_safe_int(stats.get("deferred"))))}
      </div>
      <h3>{html.escape(title)}</h3>
      <div class="table-scroll">
        <table>
          <thead><tr><th>Signal</th><th>Risk</th><th>Reachability</th><th>Exploitability</th><th>Release status</th><th>Location</th><th>Package</th><th>Message / evidence</th></tr></thead>
          <tbody>{table_rows}</tbody>
        </table>
      </div>
    """


def _observed_scan_row(item: dict[str, Any]) -> str:
    if item.get("deferred"):
        blocker = "Deferred"
        blocker_class = "warning"
    elif item.get("blocks_release"):
        blocker = "Blocker"
        blocker_class = "bad"
    else:
        blocker = "No blocker"
        blocker_class = "reachable"
    evidence = str(item.get("evidence") or "")
    message = str(item.get("message") or "")
    if evidence:
        message = f"{message} Why: {evidence}" if message else f"Why: {evidence}"
    return (
        "<tr>"
        f"<td><code>{html.escape(str(item.get('id') or ''))}</code><br><span class=\"muted\">{html.escape(str(item.get('signal_type') or ''))}</span></td>"
        f"<td>{html.escape(str(item.get('risk') or ''))}</td>"
        f"<td>{html.escape(str(item.get('reachability') or ''))}</td>"
        f"<td>{html.escape(str(item.get('exploitability') or ''))}</td>"
        f"<td><span class=\"{blocker_class}\">{html.escape(blocker)}</span></td>"
        f"<td><code>{html.escape(str(item.get('location') or ''))}</code></td>"
        f"<td>{html.escape(str(item.get('package') or ''))}</td>"
        f"<td>{html.escape(message)}</td>"
        "</tr>"
    )


def _demo_ai_economics(expected_demo: dict[str, Any]) -> dict[str, Any]:
    baseline_ai = expected_demo.get("baseline_ai") if isinstance(expected_demo.get("baseline_ai"), dict) else {}
    after_ai = expected_demo.get("after_ai") if isinstance(expected_demo.get("after_ai"), dict) else {}
    cost = float(baseline_ai.get("cost_usd") or 0.0) + float(after_ai.get("cost_usd") or 0.0)
    tokens = int(baseline_ai.get("tokens_total") or 0) + int(after_ai.get("tokens_total") or 0)
    calls = int(baseline_ai.get("calls") or 0) + int(after_ai.get("calls") or 0)
    return {
        "source": "repo.db/enzo_attacker_audit",
        "estimated": True,
        "calls": calls,
        "tokens_total": tokens,
        "cost_usd": cost,
    }


def _scan_label(meta: dict[str, Any]) -> str:
    if not meta:
        return ""
    scan_id = meta.get("id") or meta.get("db_scan_id") or ""
    version = meta.get("version") or ""
    status = meta.get("status") or ""
    return f"#{scan_id} {version} {status}".strip()


def _money(value: float | int | None) -> str:
    amount = float(value or 0.0)
    return f"${amount:.4f}" if amount < 1 else f"${amount:,.2f}"


def _number(value: Any) -> str:
    try:
        return f"{int(value or 0):,}"
    except (TypeError, ValueError):
        return "0"


def _duration(seconds: float | int | None) -> str:
    total = int(float(seconds or 0))
    if total <= 0:
        return "n/a"
    minutes, sec = divmod(total, 60)
    if minutes:
        return f"{minutes}m {sec}s"
    return f"{sec}s"


def _compliance_links(compliance: dict[str, Any]) -> str:
    if not compliance.get("available"):
        return ""
    links = []
    if compliance.get("json"):
        links.append('<a href="compliance.json">Download compliance JSON</a>')
    if compliance.get("narrative_json"):
        links.append('<a href="compliance-narrative.json">Download narrative JSON</a>')
    return "\n      ".join(links)


def _artifact_links(artifacts: list[dict[str, str]], compliance: dict[str, Any]) -> str:
    candidates = [
        ("Code scanning alerts", _code_scanning_url(), True),
        ("CI run", _run_url(), True),
        *[(item.get("label", ""), item.get("href", ""), True) for item in artifacts if isinstance(item, dict)],
        ("Compliance JSON", "compliance.json", bool(compliance.get("json"))),
        ("Auditor narrative JSON", "compliance-narrative.json", bool(compliance.get("narrative_json"))),
    ]
    links = [
        f'<a href="{html.escape(url)}">{html.escape(label)}</a>'
        for label, url, available in candidates
        if available and url
    ]
    return "\n      ".join(links) or '<span class="muted">No downloadable sanitized artifacts were created.</span>'


def _issue_row(item: dict[str, str]) -> str:
    reachability = item.get("reachability", "")
    reach_class = "reachable" if reachability in {"REACHABLE", "EXPLOITABLE"} else "defended" if reachability in DEFENDED_STATES else ""
    risk_class = "warning" if item.get("risk") in {"HIGH", "MEDIUM"} else ""
    families = " ".join(f'<span class="pill">{html.escape(str(family))}</span>' for family in item.get("families", [])[:3])
    return (
        "<tr>"
        f"<td><code>{html.escape(item.get('rule_id', ''))}</code></td>"
        f"<td><span class=\"pill {reach_class}\">{html.escape(item.get('reachability', ''))}</span></td>"
        f"<td><span class=\"{risk_class}\">{html.escape(item.get('risk', ''))}</span></td>"
        f"<td>{families}</td>"
        f"<td>{html.escape(item.get('package', ''))}</td>"
        f"<td>{html.escape(item.get('fix', ''))}</td>"
        f"<td><code>{html.escape(item.get('location', ''))}</code></td>"
        f"<td>{html.escape(item.get('message', ''))}</td>"
        "</tr>"
    )


def _expected_demo_row(item: dict[str, Any]) -> str:
    status = str(item.get("status") or "")
    status_label = str(item.get("status_label") or status)
    status_class = (
        "reachable"
        if status == "fixed"
        else "warning"
        if status in {"still_present", "baseline_missing", "deferred_manual_review"}
        else ""
    )
    baseline = "Found" if item.get("found_before") else "Missing"
    after = "Still reported" if item.get("found_after") else "Not reported"
    actual_risk = str(item.get("actual_risk") or item.get("expected_risk") or "")
    actual_reach = str(item.get("actual_reachability") or item.get("expected_reachability") or "")
    exploitability = str(item.get("actual_exploitability") or "")
    title = str(item.get("signal_title") or item.get("kind") or "Security finding")
    details = str(item.get("signal_description") or "")
    remediation_action = str(item.get("remediation_action") or _expected_business_value(item))
    if item.get("deferred") and item.get("deferred_reason"):
        remediation_action = f"Deferred for this demo: {item.get('deferred_reason')}"
    after_signal = item.get("after_signal") if isinstance(item.get("after_signal"), dict) else {}
    baseline_signal = item.get("baseline_signal") if isinstance(item.get("baseline_signal"), dict) else {}
    defense_evidence = str(
        after_signal.get("defense_evidence")
        or baseline_signal.get("defense_evidence")
        or ""
    )
    if defense_evidence and status in {"defended_after_remediation", "deferred_manual_review"}:
        remediation_action = f"{remediation_action} Why: {defense_evidence}"
    problem_ref = str(item.get("problem_ref") or "expected-results.html#expected-findings-table")
    detail_html = ""
    if details:
        detail_html = f"<details><summary>Details</summary><p>{html.escape(details)}</p></details>"
    return (
        "<tr>"
        f"<td><code>{html.escape(str(item.get('rule_id') or ''))}</code><br><span class=\"muted\">{html.escape(title)}</span><br><a href=\"{html.escape(problem_ref)}\">Problem contract</a></td>"
        f"<td>{html.escape(actual_risk)}</td>"
        f"<td>{html.escape(actual_reach)}</td>"
        f"<td>{html.escape(exploitability)}</td>"
        f"<td><code>{html.escape(str(item.get('location') or ''))}</code></td>"
        f"<td>{html.escape(baseline)}</td>"
        f"<td>{html.escape(after)}</td>"
        f"<td><span class=\"pill {status_class}\">{html.escape(status_label)}</span></td>"
        f"<td>{html.escape(remediation_action)}{detail_html}</td>"
        "</tr>"
    )


def _expected_business_value(item: dict[str, Any]) -> str:
    rule_id = str(item.get("rule_id") or "")
    if rule_id.startswith("CVE/"):
        return "Dependency risk removed or upgraded; build manager no longer has to chase the vulnerable library manually."
    if rule_id.startswith("CWE/78"):
        return "Agent removed command-execution risk and proof scan confirms the sink is gone."
    if rule_id.startswith("CWE/918"):
        return "Agent removed arbitrary outbound fetch behavior that could become SSRF."
    if rule_id.startswith("CWE/200"):
        return "Internal error details are no longer exposed to callers where remediation applied."
    if rule_id.startswith("SECRET/"):
        return "Synthetic secret exposure is removed from release-blocking DB evidence."
    if rule_id.startswith("DLP/"):
        return "Synthetic PII exposure is removed from logs or outbound data paths."
    if rule_id.startswith("AI/"):
        return "AI/LLM unsafe data flow is removed or covered by the underlying code fix."
    return "Expected vulnerable fixture row is no longer present in the proof scan."


def _rule_row(item: dict[str, Any]) -> str:
    signals = ", ".join(str(value) for value in (item.get("finding_ids") or item.get("backing_signals") or [])[:6])
    return (
        "<tr>"
        f"<td><code>{html.escape(str(item.get('rule_id') or item.get('remediation_key') or ''))}</code></td>"
        f"<td>{html.escape(str(item.get('package') or ''))}</td>"
        f"<td>{html.escape(signals)}</td>"
        f"<td>{html.escape(str(item.get('suggested_fix') or item.get('status') or ''))}</td>"
        "</tr>"
    )


def _render_markdown(*, summary: dict[str, Any], page_url: str, code_scanning_url: str, run_url: str) -> str:
    by_reach = summary.get("by_reachability") or {}
    by_type = summary.get("by_type") or {}
    by_family = summary.get("by_family") or {}
    remediation = summary.get("remediation") or {}
    verification = summary.get("verification") or {}
    compliance = summary.get("compliance") or {}
    proof = summary.get("proof") or {}
    run_evidence = summary.get("run_evidence") if isinstance(summary.get("run_evidence"), dict) else {}
    run_evidence_summary = run_evidence.get("summary") if isinstance(run_evidence.get("summary"), dict) else {}
    defended_count = sum(int(by_reach.get(state, 0)) for state in DEFENDED_STATES)
    suspicious_count = int(summary.get("suspicious_package_count") or 0)
    lines = [
        "## Reachable Go Demo - Last Scan",
        "",
        f"- DB evidence rows used in public proof: `{summary.get('total', 0)}`",
        f"- Exploitable: `{by_reach.get('EXPLOITABLE', 0)}`",
        f"- Reachable: `{by_reach.get('REACHABLE', 0)}`",
        f"- Unknown: `{by_reach.get('UNKNOWN', 0)}`",
        f"- Defended / defendable: `{defended_count}`",
        f"- CVE: `{by_type.get('CVE', 0)}`",
        f"- CWE: `{by_type.get('CWE', 0)}`",
        f"- Secret: `{by_type.get('SECRET', 0)}`",
        f"- Malware: `{by_type.get('MALWARE', 0)}`",
        f"- Suspicious packages: `{suspicious_count}`",
        f"- DLP / PII: `{by_family.get('DLP / PII', 0)}`",
        f"- OWASP Web Top 10: `{by_family.get('OWASP Web Top 10', 0)}`",
        f"- OWASP AI / LLM: `{by_family.get('OWASP AI / LLM', 0)}`",
        f"- Proof runs: `{proof.get('run_count', 0)}` from `{proof.get('source', 'none')}`",
        f"- Verified proof runs: `{proof.get('verified_exploitable', 0)}`",
        f"- Defended re-attacks: `{proof.get('defended_after_reattack', 0)}`",
        f"- Proof needs review: `{proof.get('needs_review', 0)}`",
        f"- Verification status: `{verification.get('status', 'unknown')}`",
        f"- Verification mode: `{verification.get('mode', 'unknown')}`",
        f"- Verification proof source: `{verification.get('label', 'repo.db expected-contract comparison')}`",
        f"- Verification remaining DB actionable rows: `{verification.get('results', 0)}`",
        f"- Remediation status: `{remediation.get('status', 'unknown')}`",
        f"- Fresh scan requested: `{str(bool(run_evidence_summary.get('fresh_scan_requested'))).lower()}`",
        f"- Cache restored: `{str(bool(run_evidence_summary.get('cache_restored'))).lower()}`",
        f"- Install mode: `{run_evidence_summary.get('install_mode', 'unknown')}`",
        f"- Reachable version: `{run_evidence_summary.get('installed_version') or 'unknown'}`",
        f"- repo.db reuse: `{str(bool(run_evidence_summary.get('repo_db_reused'))).lower()}` (`{run_evidence_summary.get('repo_db_count_before', 0)}` before, `{run_evidence_summary.get('repo_db_count_after', 0)}` after)",
        f"- Cached scan sessions: `{run_evidence_summary.get('scan_session_count', 0)}`",
        f"- Compliance evidence pack: `{('available from Pages' if compliance.get('available') else 'not available')}`",
        f"- Compliance narrative JSON: `{('available from Pages' if compliance.get('narrative_json') else 'not available')}`",
        f"- Published results page: {page_url or 'available after results are published to Pages'}",
        f"- Security dashboard: {code_scanning_url}",
        f"- CI run: {run_url}",
        "",
        "### Production actionable: exploitable / reachable",
        "",
    ]
    for item in (summary.get("top_priority") or [])[:10]:
        suffix = f" fix `{item['fix']}`" if item.get("fix") else ""
        location = f" at `{item['location']}`" if item.get("location") else ""
        lines.append(f"- `{item['rule_id']}` {item['reachability']} risk `{item['risk']}`{suffix}{location}")
    if not (summary.get("top_priority") or []):
        lines.append("- No exploitable or reachable findings were reported.")
    lines.extend(["", "### Production actionable: defended / defendable", ""])
    for item in (summary.get("top_defended") or [])[:10]:
        location = f" at `{item['location']}`" if item.get("location") else ""
        lines.append(f"- `{item['rule_id']}` {item['reachability']} risk `{item['risk']}`{location}")
    if not (summary.get("top_defended") or []):
        lines.append("- No defended or defendable findings were included in the compatibility export.")
    return "\n".join(lines) + "\n"


def _code_scanning_url() -> str:
    if os.environ.get("GITLAB_CI"):
        pages_url = os.environ.get("CI_PAGES_URL", "").rstrip("/")
        return f"{pages_url}/gl-sast-report.json" if pages_url else "gl-sast-report.json"
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{repo}/security/code-scanning?query=category%3Areachable" if repo else ""


def _run_url() -> str:
    if os.environ.get("GITLAB_CI"):
        return os.environ.get("CI_PIPELINE_URL", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    return f"{server}/{repo}/actions/runs/{run_id}" if repo and run_id else ""


def _pages_url() -> str:
    pages_url = os.environ.get("CI_PAGES_URL", "")
    if pages_url:
        return pages_url.rstrip("/") + "/"
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return ""
    owner, name = repo.split("/", 1)
    return f"https://{owner}.github.io/{name}/"


def _repo_slug() -> str:
    return os.environ.get("CI_PROJECT_PATH") or os.environ.get("GITHUB_REPOSITORY", "")


if __name__ == "__main__":
    raise SystemExit(main())
