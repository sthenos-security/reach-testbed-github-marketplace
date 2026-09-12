from __future__ import annotations

from pathlib import Path


def resolve_within(root: Path, candidate: Path) -> Path:
    resolved_root = root.resolve()
    resolved_candidate = candidate.resolve(strict=False)
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"path escapes repository root: {candidate}") from exc
    return resolved_candidate
