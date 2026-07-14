"""Streaming encryption service for backup artifacts."""

from __future__ import annotations

import hashlib
import secrets
import struct
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from crypto.constants import AES_GCM_NONCE_SIZE_BYTES, CURRENT_VERSION
from crypto.exceptions import EncryptionError
from crypto.hybrid import HybridCipher
from crypto.models import AlgorithmId, ContainerHeader, FileChecksum
from crypto.rsa import RsaOaepCipher
from services.checksum_service import ChecksumService
from services.metadata_service import MetadataService
from utils.file_manager import FileManager
from utils.secure_delete import secure_delete
from utils.validators import Validator


class EncryptionService:
    """Encrypt files into the secure_backup container format."""

    def __init__(
        self,
        file_manager: FileManager | None = None,
        validator: Validator | None = None,
        checksum_service: ChecksumService | None = None,
        metadata_service: MetadataService | None = None,
        rsa_cipher: RsaOaepCipher | None = None,
        hybrid_cipher: HybridCipher | None = None,
    ) -> None:
        self._file_manager = file_manager or FileManager()
        self._validator = validator or Validator()
        self._checksum_service = checksum_service or ChecksumService()
        self._metadata_service = metadata_service or MetadataService(hybrid_cipher=hybrid_cipher)
        self._rsa_cipher = rsa_cipher or RsaOaepCipher()
        self._hybrid_cipher = hybrid_cipher or HybridCipher(rsa_cipher=self._rsa_cipher)

    def encrypt_file(
        self,
        input_path: Path,
        public_key_path: Path,
        output_path: Path,
        chunk_size_bytes: int,
        overwrite: bool,
    ) -> FileChecksum:
        """Encrypt a file to a single streaming container.

        Returns:
            The SHA-256 checksum of the plaintext.
        """

        self._validator.validate_input_file(input_path)
        self._validator.validate_key_file(public_key_path)
        self._validator.validate_output_path(output_path, overwrite=overwrite)
        self._validator.validate_chunk_size(chunk_size_bytes)
        file_size = self._file_manager.file_size(input_path)
        session_key = bytearray(secrets.token_bytes(32))
        try:
            public_key = self._rsa_cipher.load_public_key(public_key_path)
            encrypted_session_key = public_key.encrypt(
                bytes(session_key),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            header = ContainerHeader(
                version=CURRENT_VERSION,
                algorithm_symmetric=AlgorithmId.AES_256_GCM,
                algorithm_asymmetric=AlgorithmId.RSA_OAEP_SHA256,
                algorithm_hash=AlgorithmId.SHA256,
                rsa_key_size=public_key.key_size,
                chunk_size_bytes=chunk_size_bytes,
                original_size_bytes=file_size,
                encrypted_session_key=encrypted_session_key,
                original_filename=input_path.name,
            )
            header_bytes = self._metadata_service.build_header(header)
            digest = hashlib.sha256()
            with self._file_manager.open_read(input_path) as source, self._file_manager.open_write(output_path) as destination:
                destination.write(header_bytes)
                chunk_number = 0
                while True:
                    plaintext = source.read(chunk_size_bytes)
                    if not plaintext:
                        break
                    digest.update(plaintext)
                    nonce = secrets.token_bytes(AES_GCM_NONCE_SIZE_BYTES)
                    associated_data = header_bytes + struct.pack(">II", chunk_number, len(plaintext))
                    encrypted = self._hybrid_cipher.encrypt_chunk(bytes(session_key), plaintext, nonce, associated_data)
                    destination.write(struct.pack(">IH", chunk_number, len(nonce)))
                    destination.write(nonce)
                    destination.write(struct.pack(">II", encrypted.plaintext_length, len(encrypted.ciphertext)))
                    destination.write(encrypted.ciphertext)
                    destination.write(encrypted.tag)
                    chunk_number += 1
                checksum = digest.digest()
                destination.write(checksum)
            return FileChecksum(algorithm=AlgorithmId.SHA256, digest=checksum)
        except Exception as exc:  # pragma: no cover - service wrapper path
            secure_delete(output_path)
            raise EncryptionError("Encryption failed") from exc
        finally:
            for index in range(len(session_key)):
                session_key[index] = 0
