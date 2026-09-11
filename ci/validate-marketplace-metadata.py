#!/usr/bin/env python3
# Copyright © 2026 Sthenos Security, Inc. All rights reserved.
"""Validate action.yml against GitHub Marketplace publish rules.

These are the checks GitHub runs when the "Publish this Action to the GitHub
Marketplace" box is ticked on a release. They exist here because the failure
otherwise surfaces ONLY in the release UI, at click time, to a human --
2026-09-10: publication was blocked twice in one morning, first by a
misattributed repo, then by a description 10 characters over the limit that
nothing in CI had ever measured.
"""
import sys
from pathlib import Path

import yaml

MAX_DESCRIPTION = 125  # GitHub: "Description must be less than 125 characters."


def _resolve_within(base_dir: Path, path: Path) -> Path:
    base = base_dir.resolve()
    resolved = path.resolve()
    resolved.relative_to(base)
    return resolved


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    action_path = _resolve_within(root, root / "action.yml")
    action = yaml.safe_load(action_path.read_text(encoding="utf-8"))
    errors = []

    name = action.get("name") or ""
    if not name.strip():
        errors.append("action.yml has no name; the name is the Marketplace listing identity")

    description = action.get("description") or ""
    if not description.strip():
        errors.append("action.yml has no description")
    elif len(description) >= MAX_DESCRIPTION:
        errors.append(
            f"description is {len(description)} characters; GitHub refuses to "
            f"publish at >= {MAX_DESCRIPTION}"
        )

    branding = action.get("branding") or {}
    for field in ("icon", "color"):
        if not str(branding.get(field) or "").strip():
            errors.append(f"branding.{field} is missing; Marketplace publish requires it")

    if not (root / "README.md").is_file():
        errors.append("README.md is missing; Marketplace publish requires one")

    if errors:
        for error in errors:
            print(f"MARKETPLACE-BLOCKER: {error}", file=sys.stderr)
        return 1
    print(
        f"marketplace metadata ok: name={name!r}, description "
        f"{len(description)}/{MAX_DESCRIPTION - 1} chars, branding "
        f"{branding.get('icon')}/{branding.get('color')}, README present"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
