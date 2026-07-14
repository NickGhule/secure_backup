# secure_backup

Production-grade hybrid encryption for backup files, built for streamed file handling and cloud storage workflows.

## Overview

`secure_backup` encrypts files using a hybrid design:

- A random AES-256 key encrypts the file payload with AES-256-GCM.
- The AES session key is wrapped with RSA-OAEP using SHA-256.
- The encrypted payload is written as a single binary container.
- Decryption validates integrity and recovers the original file bytes.

The design assumes the cloud provider and storage layer may be compromised, while the RSA private key remains protected by the operator.

## Architecture

The codebase is organized by responsibility:

- `crypto/` contains the cryptographic primitives, container models, and binary format helpers.
- `services/` contains orchestration logic for encryption, decryption, metadata parsing, and checksums.
- `utils/` contains logging, validation, file handling, secure deletion, and configuration helpers.
- `encrypt.py`, `decrypt.py`, and `generate_keys.py` are the CLI entrypoints.
- `tests/` contains pytest coverage for the crypto primitives and streaming workflow.

## Security Model

Threat model:

- The cloud storage backend may be fully compromised.
- Attackers may read, copy, truncate, or modify encrypted files.
- Attackers must not be able to recover plaintext without the private key and passphrase.

Security assumptions:

- The RSA private key is protected by a strong passphrase.
- The `cryptography` library provides the primitive implementations.
- AES-GCM nonce reuse does not occur because each chunk uses a fresh random nonce.

## Installation

```bash
python -m pip install -r requirements.txt
```

Python 3.12 or newer is recommended.

## Key Management

Generate an encrypted RSA key pair:

```bash
python generate_keys.py --output keys/
```

This writes:

- `keys/public.pem`
- `keys/private.pem`

The private key is serialized as PKCS8 and encrypted with `BestAvailableEncryption()`.

## Usage

Encrypt a file:

```bash
python encrypt.py --input backup.zip --public-key keys/public.pem --output backup.secure
```

Decrypt a file:

```bash
python decrypt.py --input backup.secure --private-key keys/private.pem --output backup.zip
```

## CLI Reference

### generate_keys.py

Options:

- `--output`: Output directory for the generated key pair.
- `--key-size`: RSA modulus size in bits, defaults to 4096.
- `--log-level`: Log level.
- `--verbose`: Increase console verbosity.
- `--quiet`: Reduce console output.

### encrypt.py

Options:

- `--input`: Input file to encrypt.
- `--public-key`: RSA public key used to wrap the AES session key.
- `--output`: Encrypted output container.
- `--chunk-size`: Streaming chunk size in bytes.
- `--overwrite`: Allow replacing an existing output file.
- `--log-level`: Log level.
- `--verbose`: Increase console verbosity.
- `--quiet`: Reduce console output.
- `--checksum`: Print the plaintext SHA-256 checksum.

### decrypt.py

Options:

- `--input`: Encrypted container to decrypt.
- `--private-key`: Encrypted RSA private key.
- `--output`: Decrypted output file.
- `--overwrite`: Allow replacing an existing output file.
- `--verify`: Explicitly verify the embedded checksum.
- `--log-level`: Log level.
- `--verbose`: Increase console verbosity.
- `--quiet`: Reduce console output.
- `--checksum`: Print the plaintext SHA-256 checksum.

## Container Format

The binary container stores:

- Magic number
- Version
- Algorithm identifiers
- RSA key size
- Chunk size
- Original size
- RSA-encrypted AES session key length and bytes
- Original filename length and bytes
- Chunk records containing chunk number, nonce, plaintext length, ciphertext length, ciphertext, and tag
- SHA-256 checksum footer

All metadata is versioned. Unsupported versions and malformed headers are rejected.

## Recovery

If decryption fails:

- Confirm the passphrase is correct.
- Confirm the RSA private key matches the public key used at encryption time.
- Confirm the encrypted file was not truncated or modified.
- Confirm the output file path is writable.

If the checksum fails, the container has been modified or corrupted.

## Best Practices

- Use a unique RSA key pair per environment or security boundary.
- Protect private keys with a strong passphrase.
- Rotate keys on an operational schedule.
- Store encrypted containers in untrusted storage only after successful validation.
- Keep `--chunk-size` large enough for performance but small enough for predictable memory usage.

## Limitations

- The project encrypts file content, not file system metadata beyond the original filename.
- Secure deletion is best effort and depends on the underlying storage medium.
- The checksum footer is a plaintext integrity check in addition to AES-GCM authentication, not a substitute for key management.

## FAQ

### Why AES-GCM instead of CBC?

AES-GCM provides authenticated encryption and avoids the integrity hazards of unauthenticated modes.

### Why RSA-OAEP?

RSA-OAEP with SHA-256 is the standard safe choice for wrapping small session keys.

### Can it handle very large files?

Yes. The implementation streams input in chunks and does not load the full file into memory.

### Is the private key ever written unencrypted?

No. The generated private key is always encrypted with a passphrase.

## Testing

Run the test suite:

```bash
pytest
```

The tests cover:

- AES helper round trips
- RSA key generation and wrapping
- Container header parsing
- Streaming encryption and decryption
- Corrupted ciphertext
- Wrong key handling
- Invalid magic number and version detection
- Checksum mismatch handling
