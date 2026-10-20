#!/usr/bin/env python3
"""Provision two Raspberry Pi identities and sign the deployed application artifact."""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ECC_Integration.Secure_Boot import SecureBoot


def write_private(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)


def write_public(path: Path, key: ec.EllipticCurvePublicKey) -> None:
    path.write_bytes(
        key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    os.chmod(path, 0o644)


def provision(args: argparse.Namespace) -> None:
    output = Path(args.output).resolve()
    firmware = Path(args.firmware).resolve()
    if not firmware.is_file():
        raise FileNotFoundError(f"firmware artifact does not exist: {firmware}")
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    manufacturer_private = ec.generate_private_key(ec.SECP256R1())
    manufacturer_public = manufacturer_private.public_key()
    manufacturer_private_path = output / "manufacturer_private.pem"
    manufacturer_public_path = output / "manufacturer_public.pem"
    write_private(manufacturer_private_path, manufacturer_private)
    write_public(manufacturer_public_path, manufacturer_public)

    firmware_copy = output / firmware.name
    shutil.copyfile(firmware, firmware_copy)
    firmware_signature = output / f"{firmware.name}.sig"
    secure_boot = SecureBoot(str(firmware_copy), str(firmware_signature))
    secure_boot.compute_firmware_hash()
    secure_boot.signature = secure_boot.sign_firmware(manufacturer_private)
    secure_boot.save_signature_to_file()

    identities: dict[str, ec.EllipticCurvePrivateKey] = {}
    for node_id in ("pi-a", "pi-b"):
        node_dir = output / node_id
        node_dir.mkdir()
        identity_private = ec.generate_private_key(ec.SECP256R1())
        identities[node_id] = identity_private
        write_private(node_dir / "identity_private.pem", identity_private)
        write_public(node_dir / "identity_public.pem", identity_private.public_key())
        shutil.copyfile(firmware_copy, node_dir / firmware_copy.name)
        shutil.copyfile(firmware_signature, node_dir / firmware_signature.name)
        shutil.copyfile(manufacturer_public_path, node_dir / "manufacturer_public.pem")

    for node_id, peer_id in (("pi-a", "pi-b"), ("pi-b", "pi-a")):
        node_dir = output / node_id
        write_public(node_dir / "peer_identity_public.pem", identities[peer_id].public_key())
        config = {
            "node_id": node_id,
            "peer_id": peer_id,
            "identity_private_key": "identity_private.pem",
            "peer_identity_public_key": "peer_identity_public.pem",
            "manufacturer_public_key": "manufacturer_public.pem",
            "firmware": firmware_copy.name,
            "firmware_signature": firmware_signature.name,
        }
        (node_dir / "node.json").write_text(json.dumps(config, indent=2) + "\n")

    manufacturer_private_path.unlink()
    print(f"Provisioned {output / 'pi-a'} and {output / 'pi-b'}")
    print(f"Keep {output} private and copy each node directory to its Raspberry Pi.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision the two Raspberry Pi nodes")
    parser.add_argument("--firmware", required=True, help="signed application/firmware artifact")
    parser.add_argument("--output", default="deployment", help="output directory")
    provision(parser.parse_args())


if __name__ == "__main__":
    main()
