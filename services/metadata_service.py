"""Metadata serialization and parsing services for the custom container format."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from crypto.constants import CURRENT_VERSION, HEADER_STRUCT_FORMAT, MAGIC_NUMBER, SHA256_DIGEST_SIZE_BYTES
from crypto.exceptions import FileFormatError
from crypto.hybrid import HybridCipher
from crypto.models import AlgorithmId, ContainerHeader, ParsedContainer


@dataclass(slots=True)
class ParsedHeaderResult:
    """Convenience structure returned while parsing headers from streams."""

    header: ContainerHeader
    header_bytes: bytes


class MetadataService:
    """Handle binary header encoding and decoding."""

    def __init__(self, hybrid_cipher: HybridCipher | None = None) -> None:
        self._hybrid_cipher = hybrid_cipher or HybridCipher()

    def build_header(self, header: ContainerHeader) -> bytes:
        """Serialize a header using the container wire format."""

        return self._hybrid_cipher.build_header(header)

    def parse_header_bytes(self, data: bytes) -> ContainerHeader:
        """Deserialize a header from in-memory bytes."""

        return self._hybrid_cipher.parse_header(data)

    def parse_stream_header(self, stream, total_size_bytes: int) -> ParsedHeaderResult:
        """Read and validate the header prefix from a binary stream."""

        fixed_size = struct.calcsize(HEADER_STRUCT_FORMAT)
        fixed_prefix = stream.read(fixed_size)
        if len(fixed_prefix) != fixed_size:
            raise FileFormatError("Container header is truncated")
        unpacked = struct.unpack(HEADER_STRUCT_FORMAT, fixed_prefix)
        magic = unpacked[0]
        if magic != MAGIC_NUMBER:
            raise FileFormatError("Invalid magic number")
        version = unpacked[1]
        if version != CURRENT_VERSION:
            raise FileFormatError("Unsupported container version")
        encrypted_key_len = unpacked[8]
        filename_len = unpacked[9]
        variable_size = encrypted_key_len + filename_len
        variable_bytes = stream.read(variable_size)
        if len(variable_bytes) != variable_size:
            raise FileFormatError("Container header payload is truncated")
        header_bytes = fixed_prefix + variable_bytes
        header = self._hybrid_cipher.parse_header(header_bytes)
        minimum_payload_size = len(header_bytes) + SHA256_DIGEST_SIZE_BYTES
        if total_size_bytes < minimum_payload_size:
            raise FileFormatError("Container is truncated")
        return ParsedHeaderResult(header=header, header_bytes=header_bytes)

    def parse_container_bytes(self, data: bytes) -> ParsedContainer:
        """Deserialize a full container from bytes."""

        return self._hybrid_cipher.parse_container(data)
