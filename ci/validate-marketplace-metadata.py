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

from path_safety import resolve_within

MAX_DESCRIPTION = 125  # GitHub: "Description must be less than 125 characters."


def validate_metadata(root: Path) -> list[str]:
    errors = []
    try:
        action_path = resolve_within(root, root / "action.yml")
        readme_path = resolve_within(root, root / "README.md")
    except ValueError as exc:
        return [str(exc)]

    action = yaml.safe_load(action_path.read_text(encoding="utf-8"))

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

    if not readme_path.is_file():
        errors.append("README.md is missing; Marketplace publish requires one")
    return errors


def main(root: Path | None = None) -> int:
    root = root or Path(__file__).resolve().parents[1]
    errors = validate_metadata(root)

    if errors:
        for error in errors:
            print(f"MARKETPLACE-BLOCKER: {error}", file=sys.stderr)
        return 1
    action = yaml.safe_load(resolve_within(root, root / "action.yml").read_text(encoding="utf-8"))
    name = action.get("name") or ""
    description = action.get("description") or ""
    branding = action.get("branding") or {}
    print(
        f"marketplace metadata ok: name={name!r}, description "
        f"{len(description)}/{MAX_DESCRIPTION - 1} chars, branding "
        f"{branding.get('icon')}/{branding.get('color')}, README present"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
