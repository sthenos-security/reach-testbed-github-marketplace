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


def _load_action(root: Path) -> tuple[dict, list[str]]:
    try:
        action_path = resolve_within(root, root / "action.yml")
    except ValueError as exc:
        return {}, [str(exc)]
    try:
        action = yaml.safe_load(action_path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        return {}, ["action.yml is missing"]
    return action, []


def validate_metadata(root: Path) -> tuple[dict, list[str]]:
    action, load_errors = _load_action(root)
    errors = list(load_errors)
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

    readme_candidate = root / "README.md"
    try:
        readme_path = resolve_within(root, readme_candidate)
    except ValueError as exc:
        if readme_candidate.exists() or readme_candidate.is_symlink():
            errors.append(str(exc))
        else:
            errors.append("README.md is missing; Marketplace publish requires one")
    else:
        if not readme_path.is_file():
            errors.append("README.md is missing; Marketplace publish requires one")
    return action, errors


def main(root: Path | None = None) -> int:
    root = root or Path(__file__).resolve().parents[1]
    action, errors = validate_metadata(root)

    if errors:
        for error in errors:
            print(f"MARKETPLACE-BLOCKER: {error}", file=sys.stderr)
        return 1
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
