"""Custom exception hierarchy for secure_backup."""

from __future__ import annotations


class SecureBackupError(Exception):
    """Base class for secure_backup failures."""


class EncryptionError(SecureBackupError):
    """Raised when encryption fails."""


class DecryptionError(SecureBackupError):
    """Raised when decryption fails."""


class InvalidKeyError(SecureBackupError):
    """Raised when a key file is invalid or unusable."""


class FileFormatError(SecureBackupError):
    """Raised when an encrypted container is malformed."""


class ChecksumMismatchError(DecryptionError):
    """Raised when a checksum comparison fails."""


class AuthenticationFailedError(DecryptionError):
    """Raised when authenticated decryption fails."""


class ConfigurationError(SecureBackupError):
    """Raised when the application configuration is invalid."""


class ValidationError(SecureBackupError):
    """Raised when an input or output validation rule fails."""
