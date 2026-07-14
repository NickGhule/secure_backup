"""Tests for the RSA-OAEP helper."""

from __future__ import annotations

import secrets

import pytest

from crypto.exceptions import InvalidKeyError
from crypto.rsa import RsaOaepCipher


def test_rsa_key_generation_and_round_trip(tmp_path, passphrase: bytes) -> None:
    """RSA keys should serialize and unwrap a session key."""

    cipher = RsaOaepCipher()
    key_pair = cipher.save_key_pair(cipher.generate_private_key(2048), tmp_path / "keys", passphrase)
    session_key = secrets.token_bytes(32)

    encrypted = cipher.encrypt_session_key(key_pair.public_key_path, session_key)
    decrypted = cipher.decrypt_session_key(key_pair.private_key_path, passphrase, encrypted)

    assert decrypted == session_key
    assert key_pair.public_key_path.exists()
    assert key_pair.private_key_path.exists()


def test_rsa_private_key_requires_correct_passphrase(tmp_path, passphrase: bytes) -> None:
    """An incorrect passphrase should fail to load the private key."""

    cipher = RsaOaepCipher()
    key_pair = cipher.save_key_pair(cipher.generate_private_key(2048), tmp_path / "keys", passphrase)

    with pytest.raises(InvalidKeyError):
        cipher.load_private_key(key_pair.private_key_path, b"wrong-passphrase")
