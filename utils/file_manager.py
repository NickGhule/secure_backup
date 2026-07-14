"""File and stream helpers used by the services layer."""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO


class FileManager:
    """Encapsulate file system operations for testability."""

    def open_read(self, path: Path) -> BinaryIO:
        """Open a file for binary reading."""

        return path.open("rb")

    def open_write(self, path: Path) -> BinaryIO:
        """Open a file for binary writing."""

        path.parent.mkdir(parents=True, exist_ok=True)
        return path.open("wb")

    def file_size(self, path: Path) -> int:
        """Return the file size in bytes."""

        return path.stat().st_size

    def ensure_parent_directory(self, path: Path) -> None:
        """Create the parent directory when it does not exist."""

        path.parent.mkdir(parents=True, exist_ok=True)
