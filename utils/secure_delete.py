"""Best-effort secure deletion helpers."""

from __future__ import annotations

import secrets
from pathlib import Path

from crypto.exceptions import ValidationError


def secure_delete(path: Path, passes: int = 1) -> None:
    """Overwrite a file with random data before deleting it.

    Args:
        path: File to remove.
        passes: Number of overwrite passes.
    """

    if not path.exists():
        return
    if not path.is_file():
        raise ValidationError(f"Cannot securely delete non-file path: {path}")
    size = path.stat().st_size
    with path.open("r+b") as handle:
        for _ in range(max(1, passes)):
            handle.seek(0)
            handle.write(secrets.token_bytes(size))
            handle.flush()
    path.unlink(missing_ok=True)
