"""RSA-OAEP helpers for hybrid encryption key wrapping and key generation."""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .constants import DEFAULT_RSA_KEY_SIZE
from .exceptions import InvalidKeyError
from .models import KeyPair


class RsaOaepCipher:
    """Encapsulate RSA key generation, serialization, and OAEP wrapping."""

    def generate_private_key(self, key_size: int = DEFAULT_RSA_KEY_SIZE) -> rsa.RSAPrivateKey:
        """Generate a new RSA private key.

        Args:
            key_size: RSA modulus size in bits.

        Returns:
            An RSA private key object.
        """

        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    def save_key_pair(self, private_key: rsa.RSAPrivateKey, output_directory: Path, passphrase: bytes) -> KeyPair:
        """Persist an encrypted private key and matching public key to disk.

        Args:
            private_key: The RSA private key to serialize.
            output_directory: Destination directory.
            passphrase: Passphrase used to encrypt the private key.

        Returns:
            Paths to the generated key files.

        Raises:
            InvalidKeyError: If serialization fails.
        """

        output_directory.mkdir(parents=True, exist_ok=True)
        private_key_path = output_directory / "private.pem"
        public_key_path = output_directory / "public.pem"
        try:
            private_key_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
            )
            public_key_bytes = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            private_key_path.write_bytes(private_key_bytes)
            public_key_path.write_bytes(public_key_bytes)
        except Exception as exc:  # pragma: no cover - serialization failure path
            raise InvalidKeyError("Failed to save RSA key pair") from exc
        return KeyPair(public_key_path=public_key_path, private_key_path=private_key_path)

    def load_public_key(self, public_key_path: Path) -> rsa.RSAPublicKey:
        """Load a PEM encoded RSA public key."""

        try:
            return serialization.load_pem_public_key(public_key_path.read_bytes())
        except Exception as exc:  # pragma: no cover - I/O or parsing failure path
            raise InvalidKeyError("Invalid public key") from exc

    def load_private_key(self, private_key_path: Path, passphrase: bytes) -> rsa.RSAPrivateKey:
        """Load a PEM encoded encrypted RSA private key."""

        try:
            return serialization.load_pem_private_key(private_key_path.read_bytes(), password=passphrase)
        except Exception as exc:  # pragma: no cover - I/O or parsing failure path
            raise InvalidKeyError("Invalid private key or passphrase") from exc

    def encrypt_session_key(self, public_key_path: Path, session_key: bytes) -> bytes:
        """Encrypt a symmetric session key with RSA-OAEP.

        Args:
            public_key_path: Path to a PEM encoded RSA public key.
            session_key: Random symmetric key.

        Returns:
            RSA-OAEP encrypted key material.
        """

        public_key = self.load_public_key(public_key_path)
        return public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt_session_key(self, private_key_path: Path, passphrase: bytes, encrypted_session_key: bytes) -> bytes:
        """Decrypt a symmetric session key with RSA-OAEP.

        Args:
            private_key_path: Path to the encrypted PEM private key.
            passphrase: Passphrase for the private key.
            encrypted_session_key: RSA-OAEP encrypted session key.

        Returns:
            The decrypted symmetric key.
        """

        private_key = self.load_private_key(private_key_path, passphrase)
        return private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
