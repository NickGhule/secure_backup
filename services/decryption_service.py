"""Streaming decryption service for backup artifacts."""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from crypto.constants import AES_GCM_NONCE_SIZE_BYTES, AES_GCM_TAG_SIZE_BYTES, HEADER_STRUCT_FORMAT, SHA256_DIGEST_SIZE_BYTES
from crypto.exceptions import AuthenticationFailedError, ChecksumMismatchError, DecryptionError, FileFormatError
from crypto.hybrid import ChunkEnvelope, HybridCipher
from crypto.models import AlgorithmId, FileChecksum
from crypto.rsa import RsaOaepCipher
from services.metadata_service import MetadataService
from utils.file_manager import FileManager
from utils.secure_delete import secure_delete
from utils.validators import Validator


class DecryptionService:
    """Decrypt secure_backup containers in a streaming fashion."""

    def __init__(
        self,
        file_manager: FileManager | None = None,
        validator: Validator | None = None,
        metadata_service: MetadataService | None = None,
        rsa_cipher: RsaOaepCipher | None = None,
        hybrid_cipher: HybridCipher | None = None,
    ) -> None:
        self._file_manager = file_manager or FileManager()
        self._validator = validator or Validator()
        self._metadata_service = metadata_service or MetadataService(hybrid_cipher=hybrid_cipher)
        self._rsa_cipher = rsa_cipher or RsaOaepCipher()
        self._hybrid_cipher = hybrid_cipher or HybridCipher(rsa_cipher=self._rsa_cipher)

    def decrypt_file(
        self,
        input_path: Path,
        private_key_path: Path,
        passphrase: bytes,
        output_path: Path,
        verify_checksum: bool,
        overwrite: bool,
    ) -> FileChecksum:
        """Decrypt a secure_backup container.

        Returns:
            The SHA-256 checksum of the decrypted plaintext.
        """

        self._validator.validate_input_file(input_path)
        self._validator.validate_key_file(private_key_path)
        self._validator.validate_output_path(output_path, overwrite=overwrite)
        file_size = self._file_manager.file_size(input_path)
        if file_size < SHA256_DIGEST_SIZE_BYTES:
            raise FileFormatError("Container is too small")
        digest = hashlib.sha256()
        try:
            with self._file_manager.open_read(input_path) as source:
                parsed_header = self._metadata_service.parse_stream_header(source, file_size)
                header = parsed_header.header
                encrypted_session_key = header.encrypted_session_key
                session_key = self._rsa_cipher.decrypt_session_key(private_key_path, passphrase, encrypted_session_key)
                payload_end = file_size - SHA256_DIGEST_SIZE_BYTES
                bytes_written = 0
                with self._file_manager.open_write(output_path) as destination:
                    while source.tell() < payload_end:
                        chunk_header = source.read(6)
                        if len(chunk_header) != 6:
                            raise FileFormatError("Chunk header is truncated")
                        chunk_number, nonce_len = struct.unpack(">IH", chunk_header)
                        if nonce_len != AES_GCM_NONCE_SIZE_BYTES:
                            raise FileFormatError("Unsupported nonce size")
                        nonce = source.read(nonce_len)
                        if len(nonce) != nonce_len:
                            raise FileFormatError("Chunk nonce is truncated")
                        lengths = source.read(8)
                        if len(lengths) != 8:
                            raise FileFormatError("Chunk length fields are truncated")
                        plaintext_len, ciphertext_len = struct.unpack(">II", lengths)
                        if ciphertext_len != plaintext_len:
                            raise FileFormatError("Ciphertext length does not match plaintext length")
                        ciphertext = source.read(ciphertext_len)
                        if len(ciphertext) != ciphertext_len:
                            raise FileFormatError("Chunk ciphertext is truncated")
                        tag = source.read(AES_GCM_TAG_SIZE_BYTES)
                        if len(tag) != AES_GCM_TAG_SIZE_BYTES:
                            raise FileFormatError("Chunk authentication tag is truncated")
                        associated_data = parsed_header.header_bytes + struct.pack(">II", chunk_number, plaintext_len)
                        envelope = ChunkEnvelope(
                            chunk_number=chunk_number,
                            nonce=nonce,
                            plaintext_length=plaintext_len,
                            ciphertext=ciphertext,
                            tag=tag,
                        )
                        try:
                            plaintext = self._hybrid_cipher.decrypt_chunk(session_key, envelope, associated_data)
                        except DecryptionError as exc:
                            raise AuthenticationFailedError("Chunk authentication failed") from exc
                        destination.write(plaintext)
                        bytes_written += len(plaintext)
                        digest.update(plaintext)
                checksum = source.read(SHA256_DIGEST_SIZE_BYTES)
                if len(checksum) != SHA256_DIGEST_SIZE_BYTES:
                    raise FileFormatError("Checksum footer is truncated")
                computed = digest.digest()
                if bytes_written != header.original_size_bytes:
                    raise FileFormatError("Decrypted output size does not match container metadata")
                if verify_checksum and checksum != computed:
                    raise ChecksumMismatchError("SHA-256 checksum mismatch")
                if checksum != computed:
                    raise ChecksumMismatchError("SHA-256 checksum mismatch")
                return FileChecksum(algorithm=AlgorithmId.SHA256, digest=computed)
        except AuthenticationFailedError:
            secure_delete(output_path)
            raise
        except ChecksumMismatchError:
            secure_delete(output_path)
            raise
        except FileFormatError:
            secure_delete(output_path)
            raise
        except Exception as exc:  # pragma: no cover - service wrapper path
            secure_delete(output_path)
            raise DecryptionError("Decryption failed") from exc
