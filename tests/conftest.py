"""Pytest fixtures and helpers for secure_backup tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from crypto.rsa import RsaOaepCipher

PASSPHRASE = b"test-passphrase"


@pytest.fixture()
def passphrase() -> bytes:
    """Return the shared test passphrase."""

    return PASSPHRASE


@pytest.fixture()
def rsa_cipher() -> RsaOaepCipher:
    """Return a fresh RSA cipher helper."""

    return RsaOaepCipher()


@pytest.fixture()
def key_pair(tmp_path: Path, passphrase: bytes):
    """Create an encrypted RSA key pair for tests."""

    cipher = RsaOaepCipher()
    private_key = cipher.generate_private_key(2048)
    return cipher.save_key_pair(private_key, tmp_path / "keys", passphrase)


@pytest.fixture()
def sample_file(tmp_path: Path) -> tuple[Path, bytes]:
    """Create a moderately sized sample input file."""

    data = (b"backup-zip-data-" * 8192) + b"end"
    file_path = tmp_path / "backup.zip"
    file_path.write_bytes(data)
    return file_path, data
