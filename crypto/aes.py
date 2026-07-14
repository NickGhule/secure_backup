"""AES-GCM helpers used by the hybrid encryption engine."""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .constants import AES_GCM_NONCE_SIZE_BYTES, DEFAULT_AES_KEY_SIZE_BYTES, SHA256_DIGEST_SIZE_BYTES
from .exceptions import EncryptionError, DecryptionError


class AesGcmCipher:
    """Wrap the cryptography AESGCM primitive with validation."""

    key_size_bytes: int = DEFAULT_AES_KEY_SIZE_BYTES
    nonce_size_bytes: int = AES_GCM_NONCE_SIZE_BYTES
    tag_size_bytes: int = 16

    def generate_key(self) -> bytes:
        """Generate a random AES-256 key.

        Returns:
            Random key material suitable for AES-256-GCM.
        """

        return secrets.token_bytes(self.key_size_bytes)

    def generate_nonce(self) -> bytes:
        """Generate a random nonce for AES-GCM.

        Returns:
            A unique nonce of the configured size.
        """

        return secrets.token_bytes(self.nonce_size_bytes)

    def encrypt(self, key: bytes, plaintext: bytes, nonce: bytes, associated_data: bytes) -> bytes:
        """Encrypt a chunk of plaintext.

        Args:
            key: AES key bytes.
            plaintext: Plaintext chunk to encrypt.
            nonce: AES-GCM nonce.
            associated_data: Additional authenticated data.

        Returns:
            Ciphertext with the authentication tag appended.

        Raises:
            EncryptionError: If encryption fails.
        """

        try:
            return AESGCM(key).encrypt(nonce, plaintext, associated_data)
        except Exception as exc:  # pragma: no cover - cryptography-specific failure path
            raise EncryptionError("AES-GCM encryption failed") from exc

    def decrypt(self, key: bytes, ciphertext_and_tag: bytes, nonce: bytes, associated_data: bytes) -> bytes:
        """Decrypt a chunk of ciphertext.

        Args:
            key: AES key bytes.
            ciphertext_and_tag: Encrypted chunk with the tag appended.
            nonce: AES-GCM nonce.
            associated_data: Additional authenticated data.

        Returns:
            The decrypted plaintext.

        Raises:
            DecryptionError: If authentication or decryption fails.
        """

        try:
            return AESGCM(key).decrypt(nonce, ciphertext_and_tag, associated_data)
        except Exception as exc:  # pragma: no cover - cryptography-specific failure path
            raise DecryptionError("AES-GCM authentication failed") from exc

    def split_ciphertext_and_tag(self, ciphertext_and_tag: bytes) -> tuple[bytes, bytes]:
        """Split AES-GCM output into ciphertext and tag."""

        if len(ciphertext_and_tag) < self.tag_size_bytes:
            raise EncryptionError("Ciphertext is too short to contain an authentication tag")
        return (
            ciphertext_and_tag[:-self.tag_size_bytes],
            ciphertext_and_tag[-self.tag_size_bytes :],
        )

    def join_ciphertext_and_tag(self, ciphertext: bytes, tag: bytes) -> bytes:
        """Join ciphertext and tag into a single AEAD payload."""

        if len(tag) != self.tag_size_bytes:
            raise EncryptionError("Invalid authentication tag size")
        return ciphertext + tag
