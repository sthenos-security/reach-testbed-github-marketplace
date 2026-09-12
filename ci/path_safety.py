from __future__ import annotations

from pathlib import Path


def resolve_within(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve()
    candidate = candidate if candidate.is_absolute() else resolved_root / candidate
    try:
        if candidate.exists():
            resolved_candidate = candidate.resolve(strict=True)
        else:
            resolved_parent = candidate.parent.resolve(strict=True)
            resolved_parent.relative_to(resolved_root)
            resolved_candidate = resolved_parent / candidate.name
    except (FileNotFoundError, ValueError) as exc:
        raise ValueError(f"path escapes repository root: {candidate}") from exc
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {candidate}") from exc
    return resolved_candidate
