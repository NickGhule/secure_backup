"""Constants for the secure backup container and cryptographic parameters."""

from __future__ import annotations

from dataclasses import dataclass

MAGIC_NUMBER: bytes = b"SBKPX01\x00"
CURRENT_VERSION: int = 1
DEFAULT_RSA_KEY_SIZE: int = 4096
DEFAULT_AES_KEY_SIZE_BYTES: int = 32
AES_GCM_NONCE_SIZE_BYTES: int = 12
AES_GCM_TAG_SIZE_BYTES: int = 16
SHA256_DIGEST_SIZE_BYTES: int = 32
DEFAULT_CHUNK_SIZE_BYTES: int = 64 * 1024 * 1024
MIN_CHUNK_SIZE_BYTES: int = 4 * 1024
MAX_CHUNK_SIZE_BYTES: int = 512 * 1024 * 1024
DEFAULT_LOG_FILE_NAME: str = "secure_backup.log"
DEFAULT_LOG_DIR_NAME: str = "logs"
DEFAULT_OUTPUT_EXTENSION: str = ".secure"
HEADER_STRUCT_FORMAT: str = ">8sHBBBHIQII"
CHUNK_HEADER_STRUCT_FORMAT: str = ">I H"
CHUNK_TRAILER_STRUCT_FORMAT: str = ">II"
UINT16_MAX: int = 2**16 - 1
UINT32_MAX: int = 2**32 - 1
UINT64_MAX: int = 2**64 - 1

@dataclass(frozen=True, slots=True)
class ContainerLimits:
    """Container limits used for validation."""

    min_chunk_size_bytes: int = MIN_CHUNK_SIZE_BYTES
    max_chunk_size_bytes: int = MAX_CHUNK_SIZE_BYTES
