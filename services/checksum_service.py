"""Checksum generation for streamed file verification."""

from __future__ import annotations

import hashlib
from typing import BinaryIO

from crypto.models import FileChecksum, AlgorithmId


class ChecksumService:
    """Compute SHA-256 checksums incrementally."""

    def calculate_stream(self, stream: BinaryIO, chunk_size_bytes: int) -> FileChecksum:
        """Calculate a SHA-256 digest for a binary stream."""

        digest = hashlib.sha256()
        while True:
            chunk = stream.read(chunk_size_bytes)
            if not chunk:
                break
            digest.update(chunk)
        return FileChecksum(algorithm=AlgorithmId.SHA256, digest=digest.digest())

    def digest_bytes(self, data: bytes) -> FileChecksum:
        """Calculate a SHA-256 digest for an in-memory byte string."""

        digest = hashlib.sha256(data).digest()
        return FileChecksum(algorithm=AlgorithmId.SHA256, digest=digest)
