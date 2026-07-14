"""Protocol definitions for dependency injection and strategy selection."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from .models import ContainerHeader, ParsedContainer


class SymmetricCipher(Protocol):
    """Symmetric authenticated encryption contract."""

    def encrypt(
        self,
        key: bytes,
        plaintext: bytes,
        nonce: bytes,
        associated_data: bytes,
    ) -> bytes:
        """Encrypt bytes using an AEAD mode."""

    def decrypt(
        self,
        key: bytes,
        ciphertext_and_tag: bytes,
        nonce: bytes,
        associated_data: bytes,
    ) -> bytes:
        """Decrypt bytes using an AEAD mode."""


class AsymmetricCipher(Protocol):
    """Public key encryption contract for session keys."""

    def encrypt_session_key(self, public_key_path: Path, session_key: bytes) -> bytes:
        """Encrypt a symmetric session key with a public key."""

    def decrypt_session_key(self, private_key_path: Path, passphrase: bytes, encrypted_session_key: bytes) -> bytes:
        """Decrypt a symmetric session key with a private key."""


class MetadataSerializer(Protocol):
    """Binary container metadata serializer contract."""

    def build_header(
        self,
        header: ContainerHeader,
    ) -> bytes:
        """Serialize a container header to bytes."""

    def parse_header(self, data: bytes) -> ContainerHeader:
        """Deserialize a container header from bytes."""

    def parse_container(self, data: bytes) -> ParsedContainer:
        """Deserialize a full container payload."""
