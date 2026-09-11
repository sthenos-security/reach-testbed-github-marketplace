#!/usr/bin/env python3
"""Smoke checks for reachable-cache-evidence sanitization helpers."""

from __future__ import annotations

import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "ci" / "reachable-cache-evidence.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    mod = _load_module(MODULE_PATH, "reachable_cache_evidence")
    assert mod._safe_text("x" * 80, limit=16) == "x" * 16
    assert mod._safe_text("alice@example.com", limit=64) == "[redacted]"
    assert mod._safe_text("123-45-6789", limit=64) == "[redacted]"
    assert mod._safe_text("4111111111111111", limit=64) == "[redacted]"
    assert mod._safe_text("4111111111111111", limit=64, redact_long_digits=False) == "4111111111111111"
    assert mod._safe_int("7") == 7
    assert mod._safe_int("not-a-number") == 0
    assert mod._safe_int(float("inf")) == 0
    print("Reachable cache evidence smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
