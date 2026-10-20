#!/usr/bin/env python3
"""Provision two self-contained Raspberry Pi node directories.

Each generated node directory is a COMPLETE deployment. It carries the signed
artifact, that artifact's signature, the node configuration, the node's own
identity private key, its pinned peer identity public key, the manufacturer
trust anchor, the launcher, the ``ECC_Integration`` package and
``requirements.txt``.

Because each directory is self-contained, a Raspberry Pi needs only its OWN
directory. Copying both directories to both devices would place the peer's
private identity key on the other device and destroy the mutual-authentication
property this project is built on.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ECC_Integration.Secure_Boot import SecureBoot

PROJECT_ROOT = Path(__file__).resolve().parent
NODE_IDS = ("pi-a", "pi-b")
PEERS = {"pi-a": "pi-b", "pi-b": "pi-a"}
PACKAGE_DIR = "ECC_Integration"
LAUNCHER_NAME = "secure_launcher.py"
REQUIREMENTS_NAME = "requirements.txt"
IGNORED_COPY_PATTERNS = ("__pycache__", "*.pyc", "*.pyo")


def write_bytes(path: Path, payload: bytes, mode: int) -> None:
    """Create *path* with *mode* up front and write *payload* through the fd.

    The file never exists with a wider mode than *mode*, so a private key is
    never briefly world-readable.
    """
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        handle = os.fdopen(descriptor, "wb")
    except BaseException:
        os.close(descriptor)
        raise
    with handle:
        handle.write(payload)


def write_private(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    write_bytes(
        path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        0o600,
    )


def write_public(path: Path, key: ec.EllipticCurvePublicKey) -> None:
    write_bytes(
        path,
        key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
        0o644,
    )


def load_manufacturer_private(path: Path) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError(f"manufacturer key is not an EC private key: {path}")
    return key


def provision(args: argparse.Namespace) -> None:
    output = Path(args.output).resolve()
    firmware = Path(args.firmware).resolve()
    if not firmware.is_file():
        raise FileNotFoundError(f"artifact does not exist: {firmware}")
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"output directory is not empty: {output}")

    package_source = PROJECT_ROOT / PACKAGE_DIR
    if not (package_source / "__init__.py").is_file():
        raise FileNotFoundError(f"missing importable package: {package_source}")
    launcher_source = PROJECT_ROOT / LAUNCHER_NAME
    if not launcher_source.is_file():
        raise FileNotFoundError(f"missing launcher: {launcher_source}")
    requirements_source = PROJECT_ROOT / REQUIREMENTS_NAME
    if not requirements_source.is_file():
        raise FileNotFoundError(f"missing requirements file: {requirements_source}")

    output.mkdir(parents=True, exist_ok=True)

    # Trust anchor: import a stable offline key when given, otherwise mint a
    # throwaway key for this run only. The private half is deleted below, so a
    # generated key cannot be used to re-sign anything afterwards.
    transient_key_path: Path | None = None
    if args.manufacturer_key:
        manufacturer_private = load_manufacturer_private(args.manufacturer_key)
    else:
        manufacturer_private = ec.generate_private_key(ec.SECP256R1())
        transient_key_path = output / "manufacturer_private.pem"
        write_private(transient_key_path, manufacturer_private)
    manufacturer_public = manufacturer_private.public_key()

    # Sign the artifact exactly once, over the bytes that are copied verbatim
    # into every node directory.
    secure_boot = SecureBoot(str(firmware))
    secure_boot.compute_firmware_hash()
    signature = secure_boot.sign_firmware(manufacturer_private)

    artifact_name = firmware.name
    signature_name = f"{artifact_name}.sig"

    identities = {
        node_id: ec.generate_private_key(ec.SECP256R1()) for node_id in NODE_IDS
    }

    for node_id in NODE_IDS:
        peer_id = PEERS[node_id]
        node_dir = output / node_id
        node_dir.mkdir()

        write_private(node_dir / "identity_private.pem", identities[node_id])
        write_public(
            node_dir / "peer_identity_public.pem", identities[peer_id].public_key()
        )
        write_public(node_dir / "manufacturer_public.pem", manufacturer_public)

        shutil.copyfile(firmware, node_dir / artifact_name)
        write_bytes(node_dir / signature_name, signature, 0o644)

        shutil.copytree(
            package_source,
            node_dir / PACKAGE_DIR,
            ignore=shutil.ignore_patterns(*IGNORED_COPY_PATTERNS),
        )
        shutil.copyfile(launcher_source, node_dir / LAUNCHER_NAME)
        shutil.copyfile(requirements_source, node_dir / REQUIREMENTS_NAME)

        config = {
            "node_id": node_id,
            "peer_id": peer_id,
            "identity_private_key": "identity_private.pem",
            "peer_identity_public_key": "peer_identity_public.pem",
            "manufacturer_public_key": "manufacturer_public.pem",
            "artifact": artifact_name,
            "artifact_signature": signature_name,
        }
        (node_dir / "node.json").write_text(json.dumps(config, indent=2) + "\n")

    if transient_key_path is not None:
        transient_key_path.unlink()

    print(f"Provisioned {output / 'pi-a'} and {output / 'pi-b'}")
    print("Each node directory is self-contained: copy ONLY the directory for that Pi.")
    print(f"Keep {output} private and never commit generated key material.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision two self-contained Raspberry Pi node directories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Without --manufacturer-key a NEW manufacturer signing key is generated\n"
            "on every run and its private half is deleted as soon as the artifact is\n"
            "signed. Nothing from that run can re-sign a modified artifact later.\n"
            "Pass --manufacturer-key with a key you keep offline to make the trust\n"
            "anchor stable across runs."
        ),
    )
    parser.add_argument(
        "--firmware",
        required=True,
        help="application artifact to sign and deploy (the file the Pis execute)",
    )
    parser.add_argument(
        "--output", default="deployment", help="output directory (default: deployment)"
    )
    parser.add_argument(
        "--manufacturer-key",
        default=None,
        metavar="PEM",
        help=(
            "existing manufacturer PRIVATE key (PEM) used to sign the artifact; "
            "without it a new, throwaway manufacturer key is generated every run"
        ),
    )
    provision(parser.parse_args())


if __name__ == "__main__":
    main()
