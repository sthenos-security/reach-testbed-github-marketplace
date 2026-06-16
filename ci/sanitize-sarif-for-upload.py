#!/usr/bin/env python3
"""Sanitize Reachable SARIF compatibility exports for platform upload."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sarif", help="SARIF file to sanitize in place")
    args = parser.parse_args()

    path = Path(args.sarif)
    data = json.loads(path.read_text(encoding="utf-8"))
    removed = sanitize(data)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Sanitized SARIF compatibility export: removed {removed} misplaced logicalLocation field(s).")
    return 0


def sanitize(data: dict[str, Any]) -> int:
    removed = 0
    for run in data.get("runs") or []:
        if not isinstance(run, dict):
            continue
        for result in run.get("results") or []:
            if not isinstance(result, dict):
                continue
            for location in result.get("locations") or []:
                if not isinstance(location, dict):
                    continue
                if "logicalLocation" in location:
                    location.pop("logicalLocation", None)
                    removed += 1
                artifact = location.get("physicalLocation", {}).get("artifactLocation", {})
                if isinstance(artifact, dict) and str(artifact.get("uri") or "").startswith("pkg:"):
                    artifact["uri"] = "package-lock.json"
                    artifact.pop("uriBaseId", None)
                    removed += 1
    return removed


if __name__ == "__main__":
    raise SystemExit(main())
