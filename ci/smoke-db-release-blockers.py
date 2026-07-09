#!/usr/bin/env python3
"""Smoke-test the single-scan DB release-blocker gate."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).with_name("check-db-release-blockers.py")


def _create_case(root: Path, *, blocking: bool, defended: bool = False) -> Path:
    scan_dir = root / "repo" / "main" / "20260604-000000-smoke"
    scan_dir.mkdir(parents=True)
    db_path = root / "repo" / "repo.db"
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            branch TEXT,
            commit_short TEXT,
            commit_hash TEXT,
            scan_dir TEXT,
            timestamp TEXT,
            status TEXT
        );
        CREATE TABLE signals (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER,
            signal_type TEXT,
            finding_id TEXT,
            display_id TEXT,
            file_path TEXT,
            line_number INTEGER,
            title TEXT,
            description TEXT,
            app_reachability TEXT,
            risk_level TEXT,
            severity TEXT,
            cwe_id TEXT,
            cve_id TEXT,
            secret_type TEXT,
            pii_type TEXT,
            package_name TEXT,
            package_version TEXT,
            scanner TEXT,
            rule_id TEXT,
            prod_status TEXT,
            remediation_kind TEXT,
            remediation_target TEXT,
            remediation_action TEXT,
            synthesis_hints_json TEXT,
            exploit_verdict_json TEXT
        );
        CREATE TABLE enzo_attacker_audit (
            scan_id INTEGER,
            finding_type TEXT,
            file_path TEXT,
            line_number INTEGER,
            exploitable TEXT,
            severity TEXT,
            attack_vector TEXT,
            defense_rationale TEXT,
            blocked_by_json TEXT,
            model_used TEXT,
            tokens_in INTEGER,
            tokens_out INTEGER,
            cost_usd REAL,
            duration_ms REAL,
            error TEXT,
            created_at TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
        (1, "main", "abc123", "abc123", str(scan_dir), "2026-06-04 00:00:00", "complete"),
    )
    if blocking or defended:
        conn.execute(
            """
            INSERT INTO signals (
                scan_id, signal_type, finding_id, display_id, file_path, line_number,
                title, description, app_reachability, risk_level, severity,
                cwe_id, cve_id, secret_type, pii_type, package_name,
                package_version, scanner, rule_id, prod_status,
                remediation_kind, remediation_target, remediation_action,
                synthesis_hints_json, exploit_verdict_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1,
                "cwe",
                "smoke-cwe-78",
                "CWE-78",
                "internal/handlers/cwe.go",
                12,
                "OS command injection",
                "Synthetic smoke blocker",
                "REACHABLE",
                "CRITICAL",
                "CRITICAL",
                "CWE-78",
                "",
                "",
                "",
                "",
                "",
                "smoke",
                "smoke-cwe-78",
                "PRODUCTION",
                "",
                "",
                "",
                "",
                "",
            ),
        )
    if defended:
        conn.execute(
            """
            INSERT INTO enzo_attacker_audit (
                scan_id, finding_type, file_path, line_number, exploitable,
                severity, attack_vector, defense_rationale, blocked_by_json,
                model_used, tokens_in, tokens_out, cost_usd, duration_ms,
                error, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1,
                "cwe",
                "internal/handlers/cwe.go",
                12,
                "0",
                "INFO",
                "",
                "Defended by smoke sanitizer.",
                "[]",
                "smoke",
                0,
                0,
                0.0,
                0.0,
                "",
                "2026-06-04 00:00:01",
            ),
        )
    conn.commit()
    conn.close()
    return scan_dir


def _run(scan_dir: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(scan_dir)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp_raw:
        tmp = Path(tmp_raw)
        clean = _run(_create_case(tmp / "clean", blocking=False))
        if clean.returncode != 0:
            print(clean.stdout)
            print(clean.stderr, file=sys.stderr)
            return 1
        blocking = _run(_create_case(tmp / "blocking", blocking=True))
        if blocking.returncode != 3:
            print(blocking.stdout)
            print(blocking.stderr, file=sys.stderr)
            return 1
        defended = _run(_create_case(tmp / "defended", blocking=False, defended=True))
        if defended.returncode != 0:
            print(defended.stdout)
            print(defended.stderr, file=sys.stderr)
            return 1
    print("DB release-blocker gate smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
