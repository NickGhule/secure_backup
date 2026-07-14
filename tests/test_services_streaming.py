"""Integration-style tests for streaming encryption and decryption."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from crypto.constants import HEADER_STRUCT_FORMAT, SHA256_DIGEST_SIZE_BYTES
from crypto.exceptions import AuthenticationFailedError, ChecksumMismatchError, DecryptionError, FileFormatError
from crypto.rsa import RsaOaepCipher
from services.decryption_service import DecryptionService
from services.encryption_service import EncryptionService


def _header_total_size(data: bytes) -> int:
    """Compute the serialized header size for a container blob."""

    header_size = struct.calcsize(HEADER_STRUCT_FORMAT)
    _, _, _, _, _, _, _, _, encrypted_key_len, filename_len = struct.unpack(HEADER_STRUCT_FORMAT, data[:header_size])
    return header_size + encrypted_key_len + filename_len


def _first_ciphertext_offset(data: bytes) -> int:
    """Locate the first ciphertext byte in the container payload."""

    header_total = _header_total_size(data)
    offset = header_total
    _, nonce_len = struct.unpack(">IH", data[offset : offset + 6])
    offset += 6 + nonce_len
    plaintext_len, ciphertext_len = struct.unpack(">II", data[offset : offset + 8])
    offset += 8
    assert plaintext_len == ciphertext_len
    return offset


@pytest.fixture()
def key_pair(tmp_path: Path, passphrase: bytes):
    """Create an RSA key pair for streaming tests."""

    cipher = RsaOaepCipher()
    return cipher.save_key_pair(cipher.generate_private_key(2048), tmp_path / "keys", passphrase)


@pytest.fixture()
def encrypted_file(tmp_path: Path, sample_file: tuple[Path, bytes], key_pair) -> tuple[Path, Path, bytes]:
    """Encrypt the sample file for reuse across tests."""

    input_path, expected_data = sample_file
    output_path = tmp_path / "backup.secure"
    service = EncryptionService()
    service.encrypt_file(input_path, key_pair.public_key_path, output_path, chunk_size_bytes=4096, overwrite=False)
    return output_path, input_path, expected_data


def test_streaming_round_trip(tmp_path: Path, sample_file: tuple[Path, bytes], key_pair, passphrase: bytes) -> None:
    """Encryption and decryption should preserve the input bytes."""

    input_path, expected_data = sample_file
    encrypted_path = tmp_path / "backup.secure"
    decrypted_path = tmp_path / "backup.out"

    encryption_service = EncryptionService()
    encryption_service.encrypt_file(input_path, key_pair.public_key_path, encrypted_path, chunk_size_bytes=4096, overwrite=False)

    decryption_service = DecryptionService()
    result = decryption_service.decrypt_file(encrypted_path, key_pair.private_key_path, passphrase, decrypted_path, verify_checksum=True, overwrite=False)

    assert decrypted_path.read_bytes() == expected_data
    assert result.digest.hex()


def test_large_file_round_trip(tmp_path: Path, key_pair, passphrase: bytes) -> None:
    """A multi-chunk file should encrypt and decrypt correctly."""

    input_path = tmp_path / "large.bin"
    expected_data = (b"0123456789abcdef" * 8192) + (b"Z" * 123)
    input_path.write_bytes(expected_data)
    encrypted_path = tmp_path / "large.secure"
    decrypted_path = tmp_path / "large.out"

    encryption_service = EncryptionService()
    encryption_service.encrypt_file(input_path, key_pair.public_key_path, encrypted_path, chunk_size_bytes=16 * 1024, overwrite=False)

    decryption_service = DecryptionService()
    decryption_service.decrypt_file(encrypted_path, key_pair.private_key_path, passphrase, decrypted_path, verify_checksum=True, overwrite=False)

    assert decrypted_path.read_bytes() == expected_data


def test_modified_ciphertext_fails(tmp_path: Path, sample_file: tuple[Path, bytes], key_pair, passphrase: bytes) -> None:
    """Tampering with ciphertext should fail authentication."""

    input_path, _ = sample_file
    encrypted_path = tmp_path / "tampered.secure"
    decrypted_path = tmp_path / "tampered.out"

    EncryptionService().encrypt_file(input_path, key_pair.public_key_path, encrypted_path, chunk_size_bytes=4096, overwrite=False)
    tampered = bytearray(encrypted_path.read_bytes())
    offset = _first_ciphertext_offset(bytes(tampered))
    tampered[offset] ^= 0x01
    encrypted_path.write_bytes(tampered)

    with pytest.raises(AuthenticationFailedError):
        DecryptionService().decrypt_file(encrypted_path, key_pair.private_key_path, passphrase, decrypted_path, verify_checksum=True, overwrite=False)


def test_wrong_private_key_fails(tmp_path: Path, sample_file: tuple[Path, bytes], key_pair, passphrase: bytes) -> None:
    """Decrypting with the wrong RSA private key should fail."""

    input_path, _ = sample_file
    encrypted_path = tmp_path / "wrong-key.secure"
    decrypted_path = tmp_path / "wrong-key.out"
    other_key_pair = RsaOaepCipher().save_key_pair(RsaOaepCipher().generate_private_key(2048), tmp_path / "other-keys", passphrase)

    EncryptionService().encrypt_file(input_path, key_pair.public_key_path, encrypted_path, chunk_size_bytes=4096, overwrite=False)

    with pytest.raises(DecryptionError):
        DecryptionService().decrypt_file(encrypted_path, other_key_pair.private_key_path, passphrase, decrypted_path, verify_checksum=True, overwrite=False)


def test_checksum_mismatch_fails(tmp_path: Path, sample_file: tuple[Path, bytes], key_pair, passphrase: bytes) -> None:
    """Altering the footer checksum should be detected."""

    input_path, _ = sample_file
    encrypted_path = tmp_path / "checksum.secure"
    decrypted_path = tmp_path / "checksum.out"

    EncryptionService().encrypt_file(input_path, key_pair.public_key_path, encrypted_path, chunk_size_bytes=4096, overwrite=False)
    tampered = bytearray(encrypted_path.read_bytes())
    tampered[-1] ^= 0x01
    encrypted_path.write_bytes(tampered)

    with pytest.raises(ChecksumMismatchError):
        DecryptionService().decrypt_file(encrypted_path, key_pair.private_key_path, passphrase, decrypted_path, verify_checksum=True, overwrite=False)


def test_invalid_header_fails(tmp_path: Path, sample_file: tuple[Path, bytes], key_pair, passphrase: bytes) -> None:
    """An invalid magic number should be rejected."""

    input_path, _ = sample_file
    encrypted_path = tmp_path / "invalid-header.secure"
    decrypted_path = tmp_path / "invalid-header.out"

    EncryptionService().encrypt_file(input_path, key_pair.public_key_path, encrypted_path, chunk_size_bytes=4096, overwrite=False)
    tampered = bytearray(encrypted_path.read_bytes())
    tampered[0] ^= 0xFF
    encrypted_path.write_bytes(tampered)

    with pytest.raises(FileFormatError):
        DecryptionService().decrypt_file(encrypted_path, key_pair.private_key_path, passphrase, decrypted_path, verify_checksum=True, overwrite=False)


def test_invalid_version_fails(tmp_path: Path, sample_file: tuple[Path, bytes], key_pair, passphrase: bytes) -> None:
    """An unsupported version should be rejected."""

    input_path, _ = sample_file
    encrypted_path = tmp_path / "invalid-version.secure"
    decrypted_path = tmp_path / "invalid-version.out"

    EncryptionService().encrypt_file(input_path, key_pair.public_key_path, encrypted_path, chunk_size_bytes=4096, overwrite=False)
    tampered = bytearray(encrypted_path.read_bytes())
    struct.pack_into(">H", tampered, 8, 2)
    encrypted_path.write_bytes(tampered)

    with pytest.raises(FileFormatError):
        DecryptionService().decrypt_file(encrypted_path, key_pair.private_key_path, passphrase, decrypted_path, verify_checksum=True, overwrite=False)
