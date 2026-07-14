"""Tests for the hybrid container helpers."""

from __future__ import annotations

import struct

import pytest

from crypto.constants import CURRENT_VERSION, HEADER_STRUCT_FORMAT, MAGIC_NUMBER, SHA256_DIGEST_SIZE_BYTES
from crypto.exceptions import FileFormatError
from crypto.hybrid import HybridCipher
from crypto.models import AlgorithmId, ContainerHeader


def _header_total_size(header_bytes: bytes) -> int:
    """Compute the full header size from serialized header bytes."""

    header_size = struct.calcsize(HEADER_STRUCT_FORMAT)
    _, _, _, _, _, _, _, _, encrypted_key_len, filename_len = struct.unpack(HEADER_STRUCT_FORMAT, header_bytes[:header_size])
    return header_size + encrypted_key_len + filename_len


def test_hybrid_header_round_trip() -> None:
    """Serialized headers should parse back into the same metadata."""

    cipher = HybridCipher()
    header = ContainerHeader(
        version=CURRENT_VERSION,
        algorithm_symmetric=AlgorithmId.AES_256_GCM,
        algorithm_asymmetric=AlgorithmId.RSA_OAEP_SHA256,
        algorithm_hash=AlgorithmId.SHA256,
        rsa_key_size=4096,
        chunk_size_bytes=1024,
        original_size_bytes=777,
        encrypted_session_key=b"encrypted-session-key",
        original_filename="backup.zip",
    )

    header_bytes = cipher.build_header(header)
    parsed = cipher.parse_header(header_bytes)

    assert parsed == header


def test_hybrid_encrypt_and_decrypt_chunk() -> None:
    """A chunk should round-trip through the AES-GCM wrapper."""

    cipher = HybridCipher()
    key = b"0" * 32
    nonce = b"1" * 12
    plaintext = b"streaming-chunk"
    associated_data = b"aad"

    envelope = cipher.encrypt_chunk(key, plaintext, nonce, associated_data)
    decrypted = cipher.decrypt_chunk(key, envelope, associated_data)

    assert decrypted == plaintext


def test_hybrid_rejects_invalid_magic_number() -> None:
    """Malformed headers with the wrong magic number should fail."""

    cipher = HybridCipher()
    header = ContainerHeader(
        version=CURRENT_VERSION,
        algorithm_symmetric=AlgorithmId.AES_256_GCM,
        algorithm_asymmetric=AlgorithmId.RSA_OAEP_SHA256,
        algorithm_hash=AlgorithmId.SHA256,
        rsa_key_size=4096,
        chunk_size_bytes=1024,
        original_size_bytes=777,
        encrypted_session_key=b"encrypted-session-key",
        original_filename="backup.zip",
    )
    header_bytes = bytearray(cipher.build_header(header))
    header_bytes[0] ^= 0xFF

    with pytest.raises(FileFormatError):
        cipher.parse_header(bytes(header_bytes))


def test_hybrid_rejects_invalid_version() -> None:
    """Unsupported versions should be rejected."""

    cipher = HybridCipher()
    header = ContainerHeader(
        version=CURRENT_VERSION,
        algorithm_symmetric=AlgorithmId.AES_256_GCM,
        algorithm_asymmetric=AlgorithmId.RSA_OAEP_SHA256,
        algorithm_hash=AlgorithmId.SHA256,
        rsa_key_size=4096,
        chunk_size_bytes=1024,
        original_size_bytes=777,
        encrypted_session_key=b"encrypted-session-key",
        original_filename="backup.zip",
    )
    header_bytes = bytearray(cipher.build_header(header))
    struct.pack_into(">H", header_bytes, 8, CURRENT_VERSION + 1)

    with pytest.raises(FileFormatError):
        cipher.parse_header(bytes(header_bytes))


def test_hybrid_rejects_invalid_algorithm_identifier() -> None:
    """Unsupported algorithm IDs should fail during parsing."""

    cipher = HybridCipher()
    header = ContainerHeader(
        version=CURRENT_VERSION,
        algorithm_symmetric=AlgorithmId.AES_256_GCM,
        algorithm_asymmetric=AlgorithmId.RSA_OAEP_SHA256,
        algorithm_hash=AlgorithmId.SHA256,
        rsa_key_size=4096,
        chunk_size_bytes=1024,
        original_size_bytes=777,
        encrypted_session_key=b"encrypted-session-key",
        original_filename="backup.zip",
    )
    header_bytes = bytearray(cipher.build_header(header))
    struct.pack_into("B", header_bytes, 10, 99)

    with pytest.raises(FileFormatError):
        cipher.parse_header(bytes(header_bytes))


def test_hybrid_parse_container_extracts_checksum() -> None:
    """The container parser should split header, payload, and checksum."""

    cipher = HybridCipher()
    header = ContainerHeader(
        version=CURRENT_VERSION,
        algorithm_symmetric=AlgorithmId.AES_256_GCM,
        algorithm_asymmetric=AlgorithmId.RSA_OAEP_SHA256,
        algorithm_hash=AlgorithmId.SHA256,
        rsa_key_size=4096,
        chunk_size_bytes=1024,
        original_size_bytes=777,
        encrypted_session_key=b"encrypted-session-key",
        original_filename="backup.zip",
    )
    header_bytes = cipher.build_header(header)
    payload = b"payload-bytes"
    checksum = b"c" * SHA256_DIGEST_SIZE_BYTES

    parsed = cipher.parse_container(header_bytes + payload + checksum)

    assert parsed.header == header
    assert parsed.header_bytes == header_bytes
    assert parsed.payload_start_offset == len(header_bytes)
    assert parsed.payload_end_offset == len(header_bytes) + len(payload)
    assert parsed.checksum == checksum
