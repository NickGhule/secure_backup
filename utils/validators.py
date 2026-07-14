"""Input and output validation helpers."""

from __future__ import annotations

import os
from pathlib import Path

from crypto.constants import ContainerLimits, DEFAULT_OUTPUT_EXTENSION
from crypto.exceptions import ConfigurationError, ValidationError


class Validator:
    """Centralized validation logic for paths, sizes, and permissions."""

    def __init__(self, limits: ContainerLimits | None = None) -> None:
        self._limits = limits or ContainerLimits()

    def validate_input_file(self, path: Path) -> None:
        """Ensure the input file exists and is readable."""

        if not path.exists():
            raise ValidationError(f"Input file does not exist: {path}")
        if not path.is_file():
            raise ValidationError(f"Input path is not a file: {path}")
        if not os.access(path, os.R_OK):
            raise ValidationError(f"Input file is not readable: {path}")

    def validate_key_file(self, path: Path) -> None:
        """Ensure a key file exists and is readable."""

        if not path.exists():
            raise ValidationError(f"Key file does not exist: {path}")
        if not path.is_file():
            raise ValidationError(f"Key path is not a file: {path}")
        if not os.access(path, os.R_OK):
            raise ValidationError(f"Key file is not readable: {path}")

    def validate_output_path(self, path: Path, overwrite: bool) -> None:
        """Ensure the output target is writable or can be replaced."""

        parent = path.parent if path.parent != Path("") else Path.cwd()
        if not parent.exists():
            raise ValidationError(f"Output directory does not exist: {parent}")
        if not parent.is_dir():
            raise ValidationError(f"Output directory is not a directory: {parent}")
        if path.exists() and not overwrite:
            raise ValidationError(f"Output file already exists: {path}")

    def validate_chunk_size(self, chunk_size_bytes: int) -> None:
        """Validate the configured chunk size."""

        if not (self._limits.min_chunk_size_bytes <= chunk_size_bytes <= self._limits.max_chunk_size_bytes):
            raise ValidationError(
                f"Chunk size must be between {self._limits.min_chunk_size_bytes} and {self._limits.max_chunk_size_bytes} bytes"
            )

    def validate_passphrase(self, passphrase: bytes) -> None:
        """Ensure a passphrase is present."""

        if not passphrase:
            raise ConfigurationError("A non-empty passphrase is required")

    def default_output_path(self, input_path: Path, output_path: Path | None) -> Path:
        """Derive a default output path when one is not supplied."""

        return output_path or input_path.with_suffix(input_path.suffix + DEFAULT_OUTPUT_EXTENSION)
