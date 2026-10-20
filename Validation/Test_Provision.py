"""Regression tests for ``provision.py``.

A provisioned node directory is the complete deployment unit: it must carry the
signed artifact, the node's own private identity, its pinned PEER identity, the
manufacturer trust anchor, the launcher, the ``ECC_Integration`` package and
``requirements.txt`` -- and nothing else. In particular it must never carry a
private key that is not the node's own, and it must never carry build droppings
(``__pycache__``/``*.pyc``).

Every test provisions into a ``tempfile`` directory; nothing is written into the
repository.
"""

import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# Make the suite runnable from ANY working directory: ``unittest discover -s
# <dir>`` puts the *start* directory on sys.path, not the repository root.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from cryptography.exceptions import InvalidSignature  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import provision as provision_module  # noqa: E402

ARTIFACT = REPO_ROOT / "pi_node.py"
PROVISION_SCRIPT = REPO_ROOT / "provision.py"

NODE_IDS = ("pi-a", "pi-b")
PEERS = {"pi-a": "pi-b", "pi-b": "pi-a"}

# Files every node directory must contain, on top of the node.json entries.
PACKAGE_FILES = (
    "__init__.py",
    "ASCON_Encryption.py",
    "ECC_Core.py",
    "ECDSA_Auth.py",
    "Secure_Boot.py",
)
CONFIG_FIELDS = (
    "node_id",
    "peer_id",
    "identity_private_key",
    "peer_identity_public_key",
    "manufacturer_public_key",
    "artifact",
    "artifact_signature",
)


def load_private(path):
    """Load an EC private key from a PEM file."""
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def load_public(path):
    """Load an EC public key from a PEM file."""
    return serialization.load_pem_public_key(Path(path).read_bytes())


def public_bytes(key):
    """Canonical bytes for comparing two public keys."""
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def walk_files(root):
    """Every file below *root*."""
    return [path for path in Path(root).rglob("*") if path.is_file()]


class ProvisionTestCase(unittest.TestCase):
    """Shared helpers: a temporary workspace and an in-process provisioning run."""

    def setUp(self):
        self.workspace = Path(tempfile.mkdtemp(prefix="provision-test-"))
        self.addCleanup(shutil.rmtree, str(self.workspace), True)
        self.output = self.workspace / "deployment"

    def provision(self, output=None, manufacturer_key=None, firmware=ARTIFACT):
        """Run provision() in-process and return the output directory."""
        target = Path(output) if output is not None else self.output
        args = argparse.Namespace(
            firmware=str(firmware),
            output=str(target),
            manufacturer_key=str(manufacturer_key) if manufacturer_key else None,
        )
        with contextlib.redirect_stdout(io.StringIO()):
            provision_module.provision(args)
        return target

    def read_config(self, node_dir):
        """Parse a node's node.json."""
        return json.loads((Path(node_dir) / "node.json").read_text())


class TestProvisionedLayout(ProvisionTestCase):
    """The directory layout a Pi actually receives."""

    def setUp(self):
        super().setUp()
        self.provision()

    def test_both_node_directories_exist(self):
        """Provisioning produces exactly pi-a and pi-b"""
        for node_id in NODE_IDS:
            self.assertTrue(
                (self.output / node_id).is_dir(),
                f"missing provisioned node directory: {node_id}",
            )
        self.assertEqual(
            sorted(path.name for path in self.output.iterdir() if path.is_dir()),
            sorted(NODE_IDS),
        )

    def test_every_file_named_in_node_json_exists(self):
        """Each node.json reference resolves inside that node's own directory"""
        for node_id in NODE_IDS:
            node_dir = self.output / node_id
            config = self.read_config(node_dir)
            for field in CONFIG_FIELDS:
                self.assertIn(field, config, f"{node_id}/node.json lacks {field!r}")
            for field in (
                "identity_private_key",
                "peer_identity_public_key",
                "manufacturer_public_key",
                "artifact",
                "artifact_signature",
            ):
                target = node_dir / config[field]
                self.assertTrue(
                    target.is_file(),
                    f"{node_id}/node.json points at a missing file: {config[field]}",
                )
                self.assertFalse(
                    Path(config[field]).is_absolute(),
                    f"{node_id}/node.json must use relative paths: {config[field]}",
                )

    def test_node_json_describes_the_peer_relationship(self):
        """node_id and peer_id are set to opposite ends of the pair"""
        for node_id in NODE_IDS:
            config = self.read_config(self.output / node_id)
            self.assertEqual(config["node_id"], node_id)
            self.assertEqual(config["peer_id"], PEERS[node_id])

    def test_artifact_and_signature_are_the_real_ones(self):
        """The copied artifact is byte-identical and its signature is present"""
        expected = ARTIFACT.read_bytes()
        for node_id in NODE_IDS:
            node_dir = self.output / node_id
            config = self.read_config(node_dir)
            self.assertEqual(
                (node_dir / config["artifact"]).read_bytes(),
                expected,
                f"{node_id} does not carry the signed artifact verbatim",
            )
            signature = (node_dir / config["artifact_signature"]).read_bytes()
            self.assertTrue(signature, f"{node_id} carries an empty signature")

    def test_package_and_launcher_are_present(self):
        """The ECC_Integration package, the launcher and requirements.txt ship along"""
        for node_id in NODE_IDS:
            node_dir = self.output / node_id
            package = node_dir / "ECC_Integration"
            self.assertTrue(package.is_dir(), f"{node_id} is missing ECC_Integration/")
            for name in PACKAGE_FILES:
                self.assertTrue(
                    (package / name).is_file(),
                    f"{node_id}/ECC_Integration/{name} is missing",
                )
            self.assertTrue((node_dir / "secure_launcher.py").is_file())
            self.assertTrue((node_dir / "requirements.txt").is_file())

    def test_requirements_do_not_ask_for_the_ascon_package(self):
        """The deployed requirements must not pin the non-existent ascon release"""
        for node_id in NODE_IDS:
            text = (self.output / node_id / "requirements.txt").read_text().lower()
            self.assertNotIn("ascon", text, f"{node_id} requirements pin ascon")

    def test_identity_private_key_is_mode_0600(self):
        """The node's private identity must not be group or world readable"""
        for node_id in NODE_IDS:
            path = self.output / node_id / "identity_private.pem"
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(
                mode, 0o600, f"{node_id}/identity_private.pem has mode {oct(mode)}"
            )

    def test_no_private_key_other_than_the_nodes_own_is_shipped(self):
        """No manufacturer (or peer) private key may survive provisioning"""
        self.assertFalse(
            (self.output / "manufacturer_private.pem").exists(),
            "the transient manufacturer private key was left behind",
        )
        holders = [
            path
            for path in walk_files(self.output)
            if b"PRIVATE KEY" in path.read_bytes()
        ]
        expected = sorted(
            str(self.output / node_id / "identity_private.pem") for node_id in NODE_IDS
        )
        self.assertEqual(
            sorted(str(path) for path in holders),
            expected,
            "a private key other than each node's own identity was shipped",
        )

    def test_no_identity_public_key_is_emitted(self):
        """Only the peer public key is shipped: a node never publishes its own"""
        for node_id in NODE_IDS:
            node_dir = self.output / node_id
            self.assertFalse(
                (node_dir / "identity_public.pem").exists(),
                f"{node_id} emitted its own public identity",
            )
            self.assertEqual(
                sorted(path.name for path in node_dir.glob("*.pem")),
                [
                    "identity_private.pem",
                    "manufacturer_public.pem",
                    "peer_identity_public.pem",
                ],
            )

    def test_no_python_build_droppings_are_copied(self):
        """__pycache__ and *.pyc must never be copied into a deployment"""
        for node_id in NODE_IDS:
            node_dir = self.output / node_id
            caches = [path for path in node_dir.rglob("__pycache__") if path.is_dir()]
            self.assertEqual(caches, [], f"{node_id} contains __pycache__: {caches}")
            bytecode = [
                path
                for path in walk_files(node_dir)
                if path.suffix in (".pyc", ".pyo")
            ]
            self.assertEqual(bytecode, [], f"{node_id} contains bytecode: {bytecode}")

    def test_nodes_pin_each_others_public_key_not_their_own(self):
        """Mutual authentication depends on each node pinning its PEER"""
        a_private = load_private(self.output / "pi-a" / "identity_private.pem")
        b_private = load_private(self.output / "pi-b" / "identity_private.pem")
        a_peer = load_public(self.output / "pi-a" / "peer_identity_public.pem")
        b_peer = load_public(self.output / "pi-b" / "peer_identity_public.pem")

        self.assertEqual(
            public_bytes(a_peer),
            public_bytes(b_private.public_key()),
            "pi-a must pin pi-b's public identity",
        )
        self.assertEqual(
            public_bytes(b_peer),
            public_bytes(a_private.public_key()),
            "pi-b must pin pi-a's public identity",
        )
        self.assertNotEqual(
            public_bytes(a_peer),
            public_bytes(a_private.public_key()),
            "pi-a pinned its own key instead of its peer's",
        )
        self.assertNotEqual(
            public_bytes(b_peer),
            public_bytes(b_private.public_key()),
            "pi-b pinned its own key instead of its peer's",
        )

    def test_pinned_peer_key_actually_verifies_the_peer_signature(self):
        """The pinning is functional, not merely present"""
        a_peer = load_public(self.output / "pi-a" / "peer_identity_public.pem")
        b_private = load_private(self.output / "pi-b" / "identity_private.pem")
        a_private = load_private(self.output / "pi-a" / "identity_private.pem")

        message = b"handshake transcript"
        signature = b_private.sign(message, ec.ECDSA(hashes.SHA256()))
        a_peer.verify(signature, message, ec.ECDSA(hashes.SHA256()))

        # pi-a's own key must not be the one that signed pi-b's transcript.
        with self.assertRaises(InvalidSignature):
            a_private.public_key().verify(signature, message, ec.ECDSA(hashes.SHA256()))


class TestProvisionRefusals(ProvisionTestCase):
    """Provisioning must refuse to clobber an existing deployment."""

    def test_non_empty_output_directory_is_refused(self):
        """A non-empty --output directory is refused, untouched"""
        self.output.mkdir(parents=True)
        existing = self.output / "keep-me.txt"
        existing.write_text("precious")

        with self.assertRaises(FileExistsError):
            self.provision()

        self.assertEqual(existing.read_text(), "precious")
        self.assertEqual(
            sorted(path.name for path in self.output.iterdir()),
            ["keep-me.txt"],
            "a refused provisioning run must not add anything",
        )

    def test_empty_existing_output_directory_is_accepted(self):
        """An existing but empty output directory is fine"""
        self.output.mkdir(parents=True)
        self.provision()
        for node_id in NODE_IDS:
            self.assertTrue((self.output / node_id).is_dir())

    def test_missing_artifact_is_refused(self):
        """A --firmware path that does not exist must fail loudly"""
        with self.assertRaises(FileNotFoundError):
            self.provision(firmware=self.workspace / "does-not-exist.py")
        self.assertFalse(self.output.exists(), "nothing should have been created")


class TestManufacturerKey(ProvisionTestCase):
    """--manufacturer-key must make the trust anchor stable and match the key."""

    def setUp(self):
        super().setUp()
        self.manufacturer_private = ec.generate_private_key(ec.SECP256R1())
        self.key_path = self.workspace / "manufacturer_private.pem"
        self.key_path.write_bytes(
            self.manufacturer_private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    def test_emitted_anchor_matches_the_supplied_key(self):
        """Every node ships the public half of the --manufacturer-key we passed"""
        self.provision(manufacturer_key=self.key_path)
        expected = public_bytes(self.manufacturer_private.public_key())
        for node_id in NODE_IDS:
            shipped = load_public(self.output / node_id / "manufacturer_public.pem")
            self.assertEqual(
                public_bytes(shipped),
                expected,
                f"{node_id} ships a manufacturer anchor that is not the supplied key",
            )

    def test_supplied_key_verifies_the_artifact_signature(self):
        """The shipped signature verifies against the supplied anchor"""
        self.provision(manufacturer_key=self.key_path)
        for node_id in NODE_IDS:
            node_dir = self.output / node_id
            config = self.read_config(node_dir)
            anchor = load_public(node_dir / config["manufacturer_public_key"])
            signature = (node_dir / config["artifact_signature"]).read_bytes()
            digest = hashlib.sha256(
                (node_dir / config["artifact"]).read_bytes()
            ).digest()
            anchor.verify(signature, digest, ec.ECDSA(hashes.SHA256()))

    def test_the_supplied_private_key_is_never_copied(self):
        """Passing a key must not leak it into the deployment"""
        self.provision(manufacturer_key=self.key_path)
        for path in walk_files(self.output):
            self.assertNotEqual(
                path.read_bytes(),
                self.key_path.read_bytes(),
                f"the manufacturer private key was copied to {path}",
            )
            self.assertNotIn("manufacturer_private", path.name)

    def test_two_runs_with_the_same_key_share_an_anchor(self):
        """A stable anchor is what makes offline re-signing possible"""
        first = self.workspace / "first"
        second = self.workspace / "second"
        self.provision(output=first, manufacturer_key=self.key_path)
        self.provision(output=second, manufacturer_key=self.key_path)
        self.assertEqual(
            public_bytes(load_public(first / "pi-a" / "manufacturer_public.pem")),
            public_bytes(load_public(second / "pi-a" / "manufacturer_public.pem")),
        )


class TestProvisionCommandLine(ProvisionTestCase):
    """The documented command line must work."""

    def run_cli(self, *extra, cwd=None):
        """Run provision.py as a subprocess and return the CompletedProcess."""
        command = [
            sys.executable,
            str(PROVISION_SCRIPT),
            "--firmware",
            str(ARTIFACT),
            "--output",
            str(self.output),
            *extra,
        ]
        return subprocess.run(
            command,
            cwd=str(cwd) if cwd else str(self.workspace),
            capture_output=True,
            text=True,
            timeout=120,
        )

    def test_cli_provisions_a_pair(self):
        """`python provision.py --firmware ... --output ...` succeeds"""
        completed = self.run_cli()
        self.assertEqual(
            completed.returncode,
            0,
            f"provision.py failed:\n{completed.stdout}\n{completed.stderr}",
        )
        for node_id in NODE_IDS:
            self.assertTrue(
                (self.output / node_id / "node.json").is_file(),
                f"the CLI did not produce {node_id}",
            )
        self.assertFalse((self.output / "manufacturer_private.pem").exists())

    def test_cli_refuses_a_non_empty_output_directory(self):
        """The CLI must fail, not overwrite, when the output is not empty"""
        self.output.mkdir(parents=True)
        (self.output / "keep-me.txt").write_text("precious")

        completed = self.run_cli()

        self.assertNotEqual(completed.returncode, 0, "the CLI clobbered a live deployment")
        self.assertEqual((self.output / "keep-me.txt").read_text(), "precious")
        self.assertFalse((self.output / "pi-a").exists())


if __name__ == "__main__":
    unittest.main()
