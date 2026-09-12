#!/usr/bin/env python3
"""Smoke-test DB-backed demo remediation proof without CI or a real scan."""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from path_safety import resolve_within

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "ci" / "check-db-remediation-proof.py"
EXPECTED = ROOT / "expected" / "baseline.json"


def _write_expected(root: Path, path: Path) -> None:
    safe_path = resolve_within(root, path)
    safe_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "name": "smoke expected contract",
                "sarif": {
                    "results": [
                        [
                            "CWE/78",
                            "exploitable",
                            "CRITICAL",
                            "PRODUCTION",
                            "internal/handlers/cwe.go",
                            12,
                        ]
                    ]
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def _write_db(
    db_path: Path,
    *,
    baseline_present: bool,
    blocking_after: bool,
    defended_after: bool = False,
    exploit_verdict_defended_after: bool = False,
) -> tuple[Path, Path]:
    baseline_dir = db_path.parent / "main" / "20260604-000001-baseline"
    after_dir = db_path.parent / "main" / "20260604-000002-after"
    baseline_dir.mkdir(parents=True)
    after_dir.mkdir(parents=True)
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE scans (
            id INTEGER PRIMARY KEY,
            branch TEXT,
            commit_hash TEXT,
            commit_short TEXT,
            scan_dir TEXT,
            timestamp TEXT,
            duration_seconds REAL,
            version TEXT,
            status TEXT,
            total_findings INTEGER,
            reachable_findings INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,
            risk_level TEXT
        );
        CREATE TABLE signals (
            id INTEGER PRIMARY KEY,
            scan_id INTEGER,
            signal_type TEXT,
            finding_id TEXT,
            display_id TEXT,
            file_path TEXT,
            line_number INTEGER,
            severity TEXT,
            title TEXT,
            description TEXT,
            app_reachability TEXT,
            cwe_id TEXT,
            cve_id TEXT,
            secret_type TEXT,
            pii_type TEXT,
            package_name TEXT,
            package_version TEXT,
            scanner TEXT,
            rule_id TEXT,
            risk_level TEXT,
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
    conn.executemany(
        """
        INSERT INTO scans VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        [
            (1, "main", "abc123", "abc123", str(baseline_dir), "2026-06-04 00:00:01", 1.0, "1.0.0b99", "complete", 1, 1, 1, 0, 0, 0, "CRITICAL"),
            (2, "reachable-remediate-smoke", "def456", "def456", str(after_dir), "2026-06-04 00:00:02", 1.0, "1.0.0b99", "complete", 1 if blocking_after else 0, 1 if blocking_after else 0, 1 if blocking_after else 0, 0, 0, 0, "CRITICAL" if blocking_after else "LOW"),
        ],
    )
    if baseline_present:
        conn.execute(
            """
            INSERT INTO signals (
                scan_id, signal_type, finding_id, display_id, file_path,
                line_number, severity, title, description, app_reachability,
                cwe_id, scanner, rule_id, risk_level, prod_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1,
                "cwe",
                "smoke-command-injection",
                "CWE-78",
                "internal/handlers/cwe.go",
                12,
                "CRITICAL",
                "OS command injection via exec.Command with shell",
                "Synthetic smoke baseline signal",
                "REACHABLE",
                "CWE-78",
                "smoke",
                "smoke-cwe-78",
                "CRITICAL",
                "PRODUCTION",
            ),
        )
    if blocking_after or defended_after or exploit_verdict_defended_after:
        exploit_verdict_json = None
        if exploit_verdict_defended_after:
            exploit_verdict_json = json.dumps(
                {
                    "exploitable": False,
                    "verdict": "not_exploitable",
                    "defense_rationale": "Smoke residual is defended by explicit exploit verdict.",
                }
            )
        conn.execute(
            """
            INSERT INTO signals (
                scan_id, signal_type, finding_id, display_id, file_path,
                line_number, severity, title, description, app_reachability,
                cwe_id, scanner, rule_id, risk_level, prod_status,
                exploit_verdict_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                2,
                "cwe",
                "smoke-command-injection-after",
                "CWE-78",
                "internal/handlers/cwe.go",
                12,
                "CRITICAL",
                "OS command injection via exec.Command with shell",
                "Synthetic smoke after signal",
                "REACHABLE",
                "CWE-78",
                "smoke",
                "smoke-cwe-78",
                "CRITICAL",
                "PRODUCTION",
                exploit_verdict_json,
            ),
        )
    if defended_after:
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
                2,
                "cwe",
                "internal/handlers/cwe.go",
                12,
                "0",
                "INFO",
                "",
                "Smoke residual is defended by sanitizer.",
                "[]",
                "smoke",
                0,
                0,
                0.0,
                0.0,
                "",
                "2026-06-04 00:00:03",
            ),
        )
    conn.commit()
    conn.close()
    return baseline_dir, after_dir


def _run_case(
    tmp: Path,
    *,
    expected_path: Path,
    name: str,
    baseline_present: bool,
    blocking_after: bool,
    defended_after: bool = False,
    exploit_verdict_defended_after: bool = False,
    remove_scan_dirs: bool = False,
) -> int:
    artifact_dir = resolve_within(tmp, tmp / f"artifacts-{name}")
    artifact_dir.mkdir(parents=True)
    reports = resolve_within(artifact_dir, artifact_dir / "reports")
    (reports / "baseline").mkdir(parents=True)
    (reports / "after-final").mkdir(parents=True)
    repo_root = resolve_within(tmp, tmp / f"repo-{name}")
    repo_root.mkdir(parents=True)
    db_path = resolve_within(repo_root, repo_root / "repo.db")
    baseline_dir, after_dir = _write_db(
        db_path,
        baseline_present=baseline_present,
        blocking_after=blocking_after,
        defended_after=defended_after,
        exploit_verdict_defended_after=exploit_verdict_defended_after,
    )
    if remove_scan_dirs:
        shutil.rmtree(baseline_dir)
        shutil.rmtree(after_dir)
    resolve_within(reports, reports / "baseline" / "scan-path.txt").write_text(str(baseline_dir), encoding="utf-8")
    resolve_within(reports, reports / "after-final" / "scan-path.txt").write_text(str(after_dir), encoding="utf-8")
    env = os.environ.copy()
    env["REACHABLE_EXPECTED_CONTRACT"] = str(expected_path)
    result = subprocess.run(
        [sys.executable, str(CHECKER), str(artifact_dir)],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    verdict_path = resolve_within(artifact_dir, artifact_dir / "db-remediation-verdict.json")
    verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
    if blocking_after or not baseline_present:
        return 0 if result.returncode == 3 and not verdict["clean"] else 1
    return 0 if result.returncode == 0 and verdict["clean"] else 1


def main() -> int:
    if not EXPECTED.exists():
        print(f"missing expected contract: {EXPECTED}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="reachable-db-proof-") as raw:
        tmp = Path(raw)
        expected_path = tmp / "expected.json"
        _write_expected(tmp, expected_path)
        escape = tmp / "escape"
        escape.symlink_to(tmp.parent, target_is_directory=True)
        try:
            _write_expected(tmp, escape / "outside-expected.json")
        except ValueError:
            pass
        else:  # pragma: no cover - smoke contract
            raise AssertionError("expected symlink escape rejection")
        pass_status = _run_case(
            tmp,
            expected_path=expected_path,
            name="pass",
            baseline_present=True,
            blocking_after=False,
        )
        fail_status = _run_case(
            tmp,
            expected_path=expected_path,
            name="blocking-fail",
            baseline_present=True,
            blocking_after=True,
        )
        missing_status = _run_case(
            tmp,
            expected_path=expected_path,
            name="baseline-missing-fail",
            baseline_present=False,
            blocking_after=False,
        )
        defended_status = _run_case(
            tmp,
            expected_path=expected_path,
            name="defended-residual-pass",
            baseline_present=True,
            blocking_after=False,
            defended_after=True,
        )
        exploit_verdict_defended_status = _run_case(
            tmp,
            expected_path=expected_path,
            name="exploit-verdict-defended-residual-pass",
            baseline_present=True,
            blocking_after=False,
            exploit_verdict_defended_after=True,
        )
        missing_dirs_status = _run_case(
            tmp,
            expected_path=expected_path,
            name="missing-session-dirs-pass",
            baseline_present=True,
            blocking_after=False,
            remove_scan_dirs=True,
        )
    if (
        pass_status
        or fail_status
        or missing_status
        or defended_status
        or exploit_verdict_defended_status
        or missing_dirs_status
    ):
        print("DB remediation proof smoke failed", file=sys.stderr)
        return 1
    print("DB remediation proof smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
