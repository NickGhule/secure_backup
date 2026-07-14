"""Tests for the AES-GCM helper."""

from __future__ import annotations

import secrets

import pytest

from crypto.aes import AesGcmCipher
from crypto.exceptions import EncryptionError


def test_aes_round_trip() -> None:
    """AES-GCM should round-trip a plaintext chunk."""

    cipher = AesGcmCipher()
    key = cipher.generate_key()
    nonce = cipher.generate_nonce()
    plaintext = secrets.token_bytes(4096)
    aad = b"header-aad"

    encrypted = cipher.encrypt(key, plaintext, nonce, aad)
    decrypted = cipher.decrypt(key, encrypted, nonce, aad)

    assert decrypted == plaintext
    assert encrypted != plaintext


def test_aes_split_and_join() -> None:
    """AES-GCM output should split and rejoin cleanly."""

    cipher = AesGcmCipher()
    key = cipher.generate_key()
    nonce = cipher.generate_nonce()
    plaintext = b"hello world"
    aad = b"metadata"

    encrypted = cipher.encrypt(key, plaintext, nonce, aad)
    ciphertext, tag = cipher.split_ciphertext_and_tag(encrypted)
    assert cipher.join_ciphertext_and_tag(ciphertext, tag) == encrypted


def test_aes_split_rejects_short_payload() -> None:
    """Ciphertext shorter than the tag should be rejected."""

    cipher = AesGcmCipher()
    with pytest.raises(EncryptionError):
        cipher.split_ciphertext_and_tag(b"short")
