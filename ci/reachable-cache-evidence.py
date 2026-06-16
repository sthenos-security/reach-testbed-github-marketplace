#!/usr/bin/env python3
"""Emit Reachable cache/install evidence for CI logs and Pages summaries."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["before-install", "after-install", "after-scan"])
    parser.add_argument("--out-dir", default=".reachable/ci-artifacts")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    payload = _build_payload(args.phase)
    out_path = out_dir / f"reachable-cache-{args.phase}.json"
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _print_block(payload, out_path)
    return 0


def _build_payload(phase: str) -> dict[str, Any]:
    home = Path.home() / ".reachable"
    dbs = sorted((home / "scans").glob("*/repo.db")) if (home / "scans").exists() else []
    latest_db = max(dbs, key=lambda p: p.stat().st_mtime) if dbs else None
    cache_restored = _cache_restored()
    installed = _installed_version()
    db_summary = _db_summary(latest_db) if latest_db else {}
    return {
        "schema_version": 1,
        "phase": phase,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "provider": _provider(),
        "cache_restored": cache_restored,
        "fresh_scan_requested": _fresh_scan_requested(),
        "cache_primary_key": os.environ.get("REACHABLE_CACHE_PRIMARY_KEY", ""),
        "cache_matched_key": os.environ.get("REACHABLE_CACHE_MATCHED_KEY", ""),
        "cache_source": os.environ.get("REACHABLE_CACHE_SOURCE", ""),
        "install_mode": _install_mode(phase, cache_restored, installed),
        "reachable_home_exists": home.exists(),
        "reachable_home_size_kb": _du_kb(home),
        "installed_version": installed,
        "target_version": "latest",
        "repo_db_count": len(dbs),
        "latest_repo_db_hash": _sha256(latest_db) if latest_db else "",
        "latest_repo_db_size_kb": _du_kb(latest_db) if latest_db else 0,
        "latest_repo_db": db_summary,
        "scan_session_count": _scan_session_count(home),
    }


def _provider() -> str:
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return "github_actions"
    if os.environ.get("GITLAB_CI"):
        return "gitlab_ci"
    return "local"


def _cache_restored() -> bool:
    value = os.environ.get("REACHABLE_CACHE_RESTORED", "").strip().lower()
    if value in {"1", "true", "yes"}:
        return True
    if value in {"0", "false", "no"}:
        return False
    return bool(os.environ.get("REACHABLE_CACHE_MATCHED_KEY"))


def _fresh_scan_requested() -> bool:
    return os.environ.get("REACHABLE_FRESH_SCAN", "").strip().lower() in {"1", "true", "yes"}


def _install_mode(phase: str, cache_restored: bool, installed_version: str) -> str:
    if phase == "before-install":
        if _fresh_scan_requested():
            return "fresh-requested"
        return "pending"
    if _fresh_scan_requested() and installed_version:
        return "fresh-install"
    if installed_version and cache_restored:
        return "overlay-upgrade"
    if installed_version:
        return "installed"
    return "fresh-install"


def _installed_version() -> str:
    candidates = [
        [str(Path.home() / ".reachable" / "venv" / "bin" / "reachctl"), "version"],
        ["reachctl", "version"],
        [str(Path.home() / ".reachable" / "venv" / "bin" / "python"), "-m", "pip", "show", "reachable"],
    ]
    for cmd in candidates:
        try:
            proc = subprocess.run(cmd, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=8)
        except Exception:
            continue
        output = (proc.stdout or "").strip()
        if proc.returncode != 0 or not output:
            continue
        for line in output.splitlines():
            if line.startswith("Version:"):
                return line.split(":", 1)[1].strip()
        match = output.splitlines()[0].strip()
        if match:
            return match.replace("reachable ", "").strip()
    return ""


def _db_summary(db_path: Path) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    try:
        con = sqlite3.connect(str(db_path))
        con.row_factory = sqlite3.Row
        summary["schema_version"] = con.execute("PRAGMA user_version").fetchone()[0]
        try:
            row = con.execute(
                """
                SELECT id, branch, commit_short, commit_hash, timestamp, version,
                       status, total_findings, reachable_findings
                  FROM scans
                 ORDER BY id DESC
                 LIMIT 1
                """
            ).fetchone()
            if row:
                summary["latest_scan"] = dict(row)
        except sqlite3.OperationalError:
            summary["latest_scan"] = {}
        for table in ("scans", "signals", "ai_bom_entries", "taint_flows"):
            try:
                summary[f"{table}_count"] = int(con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            except sqlite3.OperationalError:
                summary[f"{table}_count"] = 0
        con.close()
    except Exception as exc:  # pragma: no cover - CI evidence helper
        summary["error"] = str(exc)
    return summary


def _scan_session_count(home: Path) -> int:
    scans = home / "scans"
    if not scans.exists():
        return 0
    return sum(1 for p in scans.glob("*/*/20*") if p.is_dir())


def _du_kb(path: Path | None) -> int:
    if path is None or not path.exists():
        return 0
    try:
        output = subprocess.check_output(["du", "-sk", str(path)], text=True, stderr=subprocess.DEVNULL)
        return int(output.split()[0])
    except Exception:
        if path.is_file():
            return max(1, path.stat().st_size // 1024)
        return 0


def _sha256(path: Path | None) -> str:
    if path is None or not path.exists() or not path.is_file():
        return ""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _print_block(payload: dict[str, Any], out_path: Path) -> None:
    print("")
    print(f"Reachable cache evidence ({payload['phase']})")
    print(f"  REACHABLE_CACHE_RESTORED={str(payload['cache_restored']).lower()}")
    print(f"  REACHABLE_FRESH_SCAN={str(payload.get('fresh_scan_requested')).lower()}")
    print(f"  REACHABLE_CACHE_PROVIDER={payload['provider']}")
    print(f"  REACHABLE_CACHE_SOURCE={payload.get('cache_source') or 'n/a'}")
    print(f"  REACHABLE_CACHE_MATCHED_KEY={payload.get('cache_matched_key') or 'none'}")
    print(f"  REACHABLE_INSTALL_MODE={payload.get('install_mode') or 'unknown'}")
    print(f"  REACHABLE_INSTALL_TARGET={payload.get('target_version') or 'latest'}")
    print(f"  REACHABLE_INSTALLED={payload.get('installed_version') or 'none'}")
    print(f"  REACHABLE_HOME_SIZE_KB={payload.get('reachable_home_size_kb')}")
    print(f"  REACHABLE_REPO_DB_COUNT={payload.get('repo_db_count')}")
    print(f"  REACHABLE_SCAN_SESSION_COUNT={payload.get('scan_session_count')}")
    latest = payload.get("latest_repo_db") if isinstance(payload.get("latest_repo_db"), dict) else {}
    latest_scan = latest.get("latest_scan") if isinstance(latest.get("latest_scan"), dict) else {}
    if latest_scan:
        print(f"  REACHABLE_LATEST_SCAN_ID={latest_scan.get('id')}")
        print(f"  REACHABLE_LATEST_SCAN_COMMIT={latest_scan.get('commit_short') or latest_scan.get('commit_hash')}")
    print(f"  REACHABLE_CACHE_EVIDENCE_FILE={out_path}")
    print("")


if __name__ == "__main__":
    raise SystemExit(main())
