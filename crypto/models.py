"""Data models for secure_backup metadata and results."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path


class AlgorithmId(IntEnum):
    """Algorithm identifiers encoded in the container header."""

    AES_256_GCM = 1
    RSA_OAEP_SHA256 = 2
    SHA256 = 3


@dataclass(frozen=True, slots=True)
class ContainerHeader:
    """Metadata describing the encrypted container."""

    version: int
    algorithm_symmetric: AlgorithmId
    algorithm_asymmetric: AlgorithmId
    algorithm_hash: AlgorithmId
    rsa_key_size: int
    chunk_size_bytes: int
    original_size_bytes: int
    encrypted_session_key: bytes
    original_filename: str


@dataclass(frozen=True, slots=True)
class ParsedContainer:
    """A parsed encrypted container payload."""

    header: ContainerHeader
    header_bytes: bytes
    payload_start_offset: int
    payload_end_offset: int
    checksum: bytes


@dataclass(frozen=True, slots=True)
class KeyPair:
    """Locations for generated RSA key material."""

    public_key_path: Path
    private_key_path: Path


@dataclass(frozen=True, slots=True)
class FileChecksum:
    """Checksum metadata for encrypted or decrypted files."""

    algorithm: AlgorithmId
    digest: bytes
