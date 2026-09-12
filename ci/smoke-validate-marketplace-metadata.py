#!/usr/bin/env python3
"""Smoke checks for marketplace metadata validation."""

from __future__ import annotations

import importlib.util
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "ci" / "validate-marketplace-metadata.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("validate_marketplace_metadata", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    mod = _load_module()
    with tempfile.TemporaryDirectory(prefix="marketplace-metadata-") as raw:
        tmp = Path(raw)
        (tmp / "action.yml").write_text(
            "name: Demo Action\n"
            "description: Short marketplace description\n"
            "branding:\n"
            "  icon: shield\n"
            "  color: blue\n",
            encoding="utf-8",
        )
        (tmp / "README.md").write_text("# Demo\n", encoding="utf-8")
        assert mod.validate_metadata(tmp) == []

        outside = tmp.parent / "outside-action.yml"
        outside.write_text(
            "name: Escape Action\n"
            "description: Short marketplace description\n"
            "branding:\n"
            "  icon: shield\n"
            "  color: blue\n",
            encoding="utf-8",
        )
        (tmp / "action.yml").unlink()
        (tmp / "action.yml").symlink_to(outside)
        errors = mod.validate_metadata(tmp)
        assert any("path escapes repository root" in error for error in errors)

    print("Marketplace metadata smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
