"""CLI for decrypting secure_backup containers."""

from __future__ import annotations

import argparse
from getpass import getpass
from pathlib import Path
from time import perf_counter

from services.decryption_service import DecryptionService
from utils.logger import configure_logging


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""

    parser = argparse.ArgumentParser(description="Decrypt a secure_backup container.")
    parser.add_argument("--input", type=Path, required=True, help="Path to the encrypted input file.")
    parser.add_argument("--private-key", type=Path, required=True, help="Path to the encrypted RSA private key.")
    parser.add_argument("--output", type=Path, required=True, help="Path to the decrypted output file.")
    parser.add_argument("--overwrite", action="store_true", help="Allow an existing output file to be replaced.")
    parser.add_argument("--verify", action="store_true", help="Verify the embedded SHA-256 checksum.")
    parser.add_argument("--log-level", type=str, default="INFO", help="Logging level.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--quiet", action="store_true", help="Reduce console output.")
    parser.add_argument("--checksum", action="store_true", help="Print the plaintext SHA-256 checksum after decryption.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Decrypt a secure_backup container and validate its checksum."""

    parser = build_parser()
    args = parser.parse_args(argv)
    logger = configure_logging(log_level=args.log_level, verbose=args.verbose, quiet=args.quiet)
    passphrase = getpass("Enter private key passphrase: ").encode("utf-8")
    service = DecryptionService()
    logger.info("Starting decryption for input file size %s bytes", args.input.stat().st_size)
    started_at = perf_counter()
    checksum = service.decrypt_file(args.input, args.private_key, passphrase, args.output, args.verify, args.overwrite)
    elapsed = perf_counter() - started_at
    logger.info("Decryption completed in %.3f seconds", elapsed)
    logger.info("SHA256 checksum %s", checksum.digest.hex())
    if args.checksum:
        print(checksum.digest.hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
