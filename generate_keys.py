"""CLI for generating encrypted RSA key pairs."""

from __future__ import annotations

import argparse
from getpass import getpass
from pathlib import Path
from time import perf_counter

from crypto.constants import DEFAULT_RSA_KEY_SIZE
from crypto.rsa import RsaOaepCipher
from utils.logger import configure_logging


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""

    parser = argparse.ArgumentParser(description="Generate an encrypted RSA key pair for secure_backup.")
    parser.add_argument("--output", type=Path, required=True, help="Directory where public.pem and private.pem will be written.")
    parser.add_argument("--key-size", type=int, default=DEFAULT_RSA_KEY_SIZE, help="RSA key size in bits.")
    parser.add_argument("--log-level", type=str, default="INFO", help="Logging level.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging.")
    parser.add_argument("--quiet", action="store_true", help="Reduce console output.")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Generate a protected RSA key pair."""

    parser = build_parser()
    args = parser.parse_args(argv)
    logger = configure_logging(log_level=args.log_level, verbose=args.verbose, quiet=args.quiet)
    cipher = RsaOaepCipher()
    passphrase = getpass("Enter passphrase for the private key: ").encode("utf-8")
    confirmation = getpass("Confirm passphrase: ").encode("utf-8")
    if passphrase != confirmation:
        parser.error("Passphrases do not match")
    logger.info("Generating RSA key pair with key size %s bits", args.key_size)
    started_at = perf_counter()
    private_key = cipher.generate_private_key(args.key_size)
    key_pair = cipher.save_key_pair(private_key, args.output, passphrase)
    elapsed = perf_counter() - started_at
    logger.info("Encryption-ready key pair written to %s and %s", key_pair.public_key_path, key_pair.private_key_path)
    logger.info("Key generation completed in %.3f seconds", elapsed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
