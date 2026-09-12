#!/usr/bin/env python3
"""Smoke checks for Reachable cache evidence sanitization."""

from __future__ import annotations

import importlib.util
import sqlite3
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "ci" / "reachable-cache-evidence.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("reachable_cache_evidence", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    mod = _load_module()
    with tempfile.TemporaryDirectory(prefix="reachable-cache-evidence-") as raw:
        tmp = Path(raw)
        db_path = tmp / "repo.db"
        conn = sqlite3.connect(db_path)
        conn.executescript(
            """
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY,
                branch TEXT,
                commit_short TEXT,
                commit_hash TEXT,
                timestamp TEXT,
                version TEXT,
                status TEXT,
                total_findings INTEGER,
                reachable_findings INTEGER
            );
            CREATE TABLE signals (id INTEGER PRIMARY KEY);
            """
        )
        conn.execute(
            """
            INSERT INTO scans (
                id, branch, commit_short, commit_hash, timestamp, version,
                status, total_findings, reachable_findings
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                7,
                "feature/redact\n" + ("x" * 400),
                "abc123",
                "deadbeef" * 8,
                "2026-09-12 00:00:00",
                "1.2.3",
                "complete\tok",
                4,
                2,
            ),
        )
        conn.commit()
        conn.close()

        summary = mod._db_summary(db_path)
        latest_scan = summary["latest_scan"]
        assert "\n" not in latest_scan["branch"]
        assert len(latest_scan["branch"]) <= mod.MAX_DB_TEXT
        assert latest_scan["status"] == "complete ok"
        assert latest_scan["total_findings"] == 4
        assert latest_scan["reachable_findings"] == 2

        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM scans")
        conn.execute(
            """
            INSERT INTO scans (
                id, branch, commit_short, commit_hash, timestamp, version,
                status, total_findings, reachable_findings
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (8, "main", "def456", "cafebabe" * 8, "2026-09-12 00:00:01", "1.2.4", "complete", 1, 1),
        )
        conn.commit()
        conn.close()

        summary = mod._db_summary(db_path)
        latest_scan = summary["latest_scan"]
        assert latest_scan["branch"] == "main"
        assert latest_scan["commit_short"] == "def456"
        assert latest_scan["status"] == "complete"

    print("Reachable cache evidence smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
