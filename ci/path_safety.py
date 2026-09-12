from __future__ import annotations

from pathlib import Path


def resolve_within(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve()
    candidate = candidate if candidate.is_absolute() else resolved_root / candidate
    if candidate.exists() or candidate.is_symlink():
        try:
            resolved_candidate = candidate.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ValueError(f"target path does not exist: {candidate}") from exc
    else:
        try:
            resolved_parent = candidate.parent.resolve(strict=True)
        except FileNotFoundError as exc:
            raise ValueError(f"parent path does not exist: {candidate.parent}") from exc
        try:
            resolved_parent.relative_to(resolved_root)
        except ValueError as exc:
            raise ValueError(f"path escapes repository root: {candidate}") from exc
        resolved_candidate = resolved_parent / candidate.name
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {candidate}") from exc
    return resolved_candidate
