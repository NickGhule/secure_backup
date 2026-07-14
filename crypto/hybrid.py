"""Hybrid file encryption and decryption primitives."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from .aes import AesGcmCipher
from .constants import (
    AES_GCM_NONCE_SIZE_BYTES,
    AES_GCM_TAG_SIZE_BYTES,
    CURRENT_VERSION,
    DEFAULT_CHUNK_SIZE_BYTES,
    HEADER_STRUCT_FORMAT,
    MAGIC_NUMBER,
    SHA256_DIGEST_SIZE_BYTES,
)
from .exceptions import AuthenticationFailedError, DecryptionError, EncryptionError, FileFormatError
from .models import AlgorithmId, ContainerHeader, ParsedContainer
from .rsa import RsaOaepCipher


@dataclass(slots=True)
class ChunkEnvelope:
    """In-memory metadata for a single encrypted chunk record."""

    chunk_number: int
    nonce: bytes
    plaintext_length: int
    ciphertext: bytes
    tag: bytes


class HybridCipher:
    """High-level hybrid encryption engine for streamed files."""

    def __init__(self, aes_cipher: AesGcmCipher | None = None, rsa_cipher: RsaOaepCipher | None = None) -> None:
        self._aes_cipher = aes_cipher or AesGcmCipher()
        self._rsa_cipher = rsa_cipher or RsaOaepCipher()

    def build_header(self, header: ContainerHeader) -> bytes:
        """Serialize a header to binary form."""

        encoded_filename = header.original_filename.encode("utf-8")
        if len(encoded_filename) > 65535:
            raise FileFormatError("Original filename is too long")
        if len(header.encrypted_session_key) > 2**32 - 1:
            raise FileFormatError("Encrypted session key is too large")
        return struct.pack(
            HEADER_STRUCT_FORMAT,
            MAGIC_NUMBER,
            header.version,
            int(header.algorithm_symmetric),
            int(header.algorithm_asymmetric),
            int(header.algorithm_hash),
            header.rsa_key_size,
            header.chunk_size_bytes,
            header.original_size_bytes,
            len(header.encrypted_session_key),
            len(encoded_filename),
        ) + header.encrypted_session_key + encoded_filename

    def parse_header(self, data: bytes) -> ContainerHeader:
        """Deserialize a container header from binary form."""

        header_size = struct.calcsize(HEADER_STRUCT_FORMAT)
        if len(data) < header_size:
            raise FileFormatError("Container header is truncated")
        unpacked = struct.unpack(HEADER_STRUCT_FORMAT, data[:header_size])
        magic, version, sym_alg, asym_alg, hash_alg, rsa_key_size, chunk_size, original_size, encrypted_key_len, filename_len = unpacked
        if magic != MAGIC_NUMBER:
            raise FileFormatError("Invalid magic number")
        if version != CURRENT_VERSION:
            raise FileFormatError("Unsupported container version")
        expected_total = header_size + encrypted_key_len + filename_len
        if len(data) < expected_total:
            raise FileFormatError("Container header payload is truncated")
        encrypted_key_start = header_size
        encrypted_key_end = encrypted_key_start + encrypted_key_len
        filename_end = encrypted_key_end + filename_len
        try:
            algorithm_symmetric = AlgorithmId(sym_alg)
            algorithm_asymmetric = AlgorithmId(asym_alg)
            algorithm_hash = AlgorithmId(hash_alg)
        except ValueError as exc:
            raise FileFormatError("Unsupported algorithm identifier") from exc
        try:
            original_filename = data[encrypted_key_end:filename_end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise FileFormatError("Original filename is not valid UTF-8") from exc
        return ContainerHeader(
            version=version,
            algorithm_symmetric=algorithm_symmetric,
            algorithm_asymmetric=algorithm_asymmetric,
            algorithm_hash=algorithm_hash,
            rsa_key_size=rsa_key_size,
            chunk_size_bytes=chunk_size,
            original_size_bytes=original_size,
            encrypted_session_key=data[encrypted_key_start:encrypted_key_end],
            original_filename=original_filename,
        )

    def parse_container(self, data: bytes) -> ParsedContainer:
        """Parse an entire container payload into metadata and offsets."""

        header_size = struct.calcsize(HEADER_STRUCT_FORMAT)
        if len(data) < header_size + SHA256_DIGEST_SIZE_BYTES:
            raise FileFormatError("Container is too small")
        unpacked = struct.unpack(HEADER_STRUCT_FORMAT, data[:header_size])
        encrypted_key_len = unpacked[8]
        filename_len = unpacked[9]
        header_total = header_size + encrypted_key_len + filename_len
        if len(data) < header_total + SHA256_DIGEST_SIZE_BYTES:
            raise FileFormatError("Container is truncated")
        header = self.parse_header(data[:header_total])
        checksum = data[-SHA256_DIGEST_SIZE_BYTES:]
        payload_start_offset = header_total
        payload_end_offset = len(data) - SHA256_DIGEST_SIZE_BYTES
        return ParsedContainer(
            header=header,
            header_bytes=data[:header_total],
            payload_start_offset=payload_start_offset,
            payload_end_offset=payload_end_offset,
            checksum=checksum,
        )

    def encrypt_chunk(self, key: bytes, plaintext: bytes, nonce: bytes, associated_data: bytes) -> ChunkEnvelope:
        """Encrypt a single chunk and split ciphertext from the authentication tag."""

        encrypted = self._aes_cipher.encrypt(key, plaintext, nonce, associated_data)
        ciphertext, tag = self._aes_cipher.split_ciphertext_and_tag(encrypted)
        return ChunkEnvelope(
            chunk_number=0,
            nonce=nonce,
            plaintext_length=len(plaintext),
            ciphertext=ciphertext,
            tag=tag,
        )

    def decrypt_chunk(self, key: bytes, envelope: ChunkEnvelope, associated_data: bytes) -> bytes:
        """Decrypt a single chunk and validate its tag."""

        ciphertext_and_tag = self._aes_cipher.join_ciphertext_and_tag(envelope.ciphertext, envelope.tag)
        return self._aes_cipher.decrypt(key, ciphertext_and_tag, envelope.nonce, associated_data)
