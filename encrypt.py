"""CLI for encrypting files into the secure_backup container format."""

from __future__ import annotations

import argparse
from pathlib import Path
from time import perf_counter

from services.encryption_service import EncryptionService
from utils.logger import configure_logging


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""

    parser = argparse.ArgumentParser(description="Encrypt a file using AES-256-GCM and RSA-OAEP.")
    parser.add_argument("--input", type=Path, required=True, help="Path to the file to encrypt.")
    parser.add_argument("--public-key", type=Path, required=True, help="Path to the RSA public key.")
    parser.add_argument("--output", type=Path, required=True, help="Path to the encrypted output file.")
    parser.add_argument("--chunk-size", type=int, default=64 * 1024 * 1024, help="Streaming chunk size in bytes.")
    parser.add_argument("--overwrite", action="store_true", help="Allow an existing output file to be replaced.")
    parser.add_argument("--log-level", type=str, default="INFO", help="Logging level.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--quiet", action="store_true", help="Reduce console output.")
    parser.add_argument("--checksum", action="store_true", help="Print the plaintext SHA-256 checksum after encryption.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Encrypt a file and emit a secure container."""

    parser = build_parser()
    args = parser.parse_args(argv)
    logger = configure_logging(log_level=args.log_level, verbose=args.verbose, quiet=args.quiet)
    service = EncryptionService()
    logger.info("Starting encryption for input file size %s bytes", args.input.stat().st_size)
    started_at = perf_counter()
    checksum = service.encrypt_file(args.input, args.public_key, args.output, args.chunk_size, args.overwrite)
    elapsed = perf_counter() - started_at
    logger.info("Encryption completed in %.3f seconds", elapsed)
    logger.info("SHA256 checksum %s", checksum.digest.hex())
    if args.checksum:
        print(checksum.digest.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
