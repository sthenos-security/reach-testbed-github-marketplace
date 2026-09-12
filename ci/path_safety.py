from __future__ import annotations

from pathlib import Path


def resolve_within(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve()
    candidate = candidate if candidate.is_absolute() else resolved_root / candidate
    existing_parent = candidate
    missing_parts: list[str] = []
    while not existing_parent.exists():
        missing_parts.append(existing_parent.name)
        next_parent = existing_parent.parent
        if next_parent == existing_parent:
            break
        existing_parent = next_parent
    resolved_candidate = existing_parent.resolve()
    if missing_parts:
        resolved_candidate = resolved_candidate.joinpath(*reversed(missing_parts))
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {candidate}") from exc
    return resolved_candidate
