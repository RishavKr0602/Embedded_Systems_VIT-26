#!/usr/bin/env python3
"""Secure-boot bootstrap for a provisioned Raspberry Pi node artifact.

TRUST MODEL -- READ THIS FIRST
==============================
This launcher is the UNVERIFIED ROOT OF TRUST of the deployment. It is an
ordinary, readable Python script sitting in the same directory as the artifact
it protects. Whatever checks the signed artifact must itself already be
trusted, and nothing here is measured, attested, or protected by hardware.
Anyone who can rewrite this file -- or the Python interpreter, or the
``cryptography`` package -- defeats the check below entirely.

This is an educational, application-level demonstration of verify-then-execute.
It is NOT a hardware-rooted secure bootloader: no Raspberry Pi firmware,
U-Boot, TPM, or OTP key store participates, and it must not be presented as
providing those guarantees. See README.md for the real limitations.

What it does:
  1. reads ``<config>/node.json``;
  2. verifies the SHA-256/ECDSA signature of the artifact named there against
     the manufacturer public key, taken from ``--manufacturer-public-key`` when
     supplied (recommended: it keeps the trust anchor OUTSIDE the writable
     directory that holds the artifact), otherwise from ``<config>``;
  3. refuses to continue -- and opens no socket -- if verification fails;
  4. on success executes the artifact with a normal command line, forwarding
     every remaining argument plus ``--config <config_dir>``.
"""

from __future__ import annotations

import argparse
import json
import runpy
import sys
from pathlib import Path


def _fail(reason: str) -> int:
    """Report a failed boot on stderr and return a non-zero exit code."""
    print(
        json.dumps({"event": "secure_boot", "status": "FAIL", "reason": reason}),
        file=sys.stderr,
    )
    return 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure_launcher.py",
        description=(
            "Verify the signed node artifact, then execute it. Every argument "
            "other than --config and --manufacturer-public-key is forwarded to "
            "the artifact, together with --config <node_dir>."
        ),
    )
    parser.add_argument("--config", required=True, help="provisioned node directory")
    parser.add_argument(
        "--manufacturer-public-key",
        default=None,
        metavar="PEM",
        help=(
            "manufacturer trust anchor read from outside the node directory; "
            "defaults to <config>/manufacturer_public.pem"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args, remaining = _parser().parse_known_args(argv)
    config_dir = Path(args.config).resolve()

    # The artifact does ``from ECC_Integration...``; make the node directory and
    # this script's own directory importable no matter the current directory.
    for entry in (config_dir, Path(__file__).resolve().parent):
        text = str(entry)
        if text not in sys.path:
            sys.path.insert(0, text)

    try:
        from cryptography.hazmat.primitives import serialization
        from ECC_Integration.Secure_Boot import SecureBoot
    except ImportError as error:
        return _fail(f"cryptographic support is unavailable: {error}")

    try:
        config = json.loads((config_dir / "node.json").read_text())
        artifact_name = config["artifact"]
        signature_name = config["artifact_signature"]
        artifact_path = config_dir / artifact_name
        signature_path = config_dir / signature_name
        anchor_path = (
            Path(args.manufacturer_public_key).resolve()
            if args.manufacturer_public_key
            else config_dir / config["manufacturer_public_key"]
        )

        for path, label in (
            (artifact_path, "artifact"),
            (signature_path, "artifact signature"),
            (anchor_path, "manufacturer public key"),
        ):
            if not path.is_file():
                return _fail(f"{label} is missing: {path}")

        anchor = serialization.load_pem_public_key(anchor_path.read_bytes())
        secure_boot = SecureBoot(str(artifact_path), str(signature_path))
        secure_boot.load_signature_from_file()
        valid, digest = secure_boot.verify_firmware(anchor)
    except (OSError, ValueError, KeyError, TypeError) as error:
        return _fail(f"secure boot configuration error: {error}")

    if not valid:
        return _fail("artifact signature does not match the manufacturer public key")

    print(
        json.dumps(
            {
                "event": "secure_boot",
                "status": "PASS",
                "artifact": artifact_name,
                "sha256": digest.hex(),
            }
        )
    )

    # Hand the artifact a normal command line: its own path first, then the
    # arguments the operator did not consume, then the config directory.
    sys.argv = [str(artifact_path)] + list(remaining) + ["--config", str(config_dir)]
    runpy.run_path(str(artifact_path), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
