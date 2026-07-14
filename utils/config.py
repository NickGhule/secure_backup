"""Runtime configuration objects for secure_backup."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from crypto.constants import DEFAULT_CHUNK_SIZE_BYTES


@dataclass(slots=True)
class AppConfig:
    """Application-level runtime configuration."""

    log_level: str = "INFO"
    verbose: bool = False
    quiet: bool = False
    overwrite: bool = False
    verify: bool = False
    checksum: bool = False
    chunk_size_bytes: int = DEFAULT_CHUNK_SIZE_BYTES
    log_directory: Path = Path("logs")
