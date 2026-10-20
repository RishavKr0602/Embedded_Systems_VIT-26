"""
Comprehensive Cryptographic Testing Suite

Tests: ECC Core, ASCON-128a AEAD, Secure Boot, ECDSA Authentication

These tests cover the cryptographic primitives used by the Pi deployment.

Every test is hermetic: nothing is written into the source tree. Secure-boot
tests work entirely inside a ``tempfile`` directory so an interrupted run can
never leave a stray ``*.bin`` artifact behind in ``Validation/``.
"""

import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

# Make the suite runnable from ANY working directory. ``unittest discover -s
# <dir>`` puts the *start* directory on sys.path, not the repository root, so
# ``import ECC_Integration`` would otherwise only resolve when the current
# directory happens to be the repository root. (``Validation/__init__.py`` is
# not sufficient on its own: without an explicit ``-t``, unittest sets the
# top-level directory to the start directory itself.)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from ECC_Integration.ECC_Core import ECCCore  # noqa: E402
from ECC_Integration.ASCON_Encryption import ASCONEncryption  # noqa: E402
from ECC_Integration.ECDSA_Auth import ECDSAAuthentication  # noqa: E402
from ECC_Integration.Secure_Boot import (  # noqa: E402
    SecureBoot,
    generate_signing_keys,
)

VALIDATION_DIR = os.path.dirname(os.path.abspath(__file__))
ASCON_MODULE_PATH = os.path.join(
    REPO_ROOT, "ECC_Integration", "ASCON_Encryption.py"
)
REQUIREMENTS_PATH = os.path.join(REPO_ROOT, "requirements.txt")


class TestECCCore(unittest.TestCase):
    """Test ECC Core functionality"""

    def setUp(self):
        self.ecc = ECCCore()

    def test_key_generation(self):
        """Test key pair generation"""
        result = self.ecc.generate_keypair()
        self.assertTrue(result)
        self.assertIsNotNone(self.ecc.private_key)
        self.assertIsNotNone(self.ecc.public_key)

    def test_shared_secret(self):
        """Test ECDH shared secret computation"""
        node1 = ECCCore()
        node2 = ECCCore()
        node1.generate_keypair()
        node2.generate_keypair()

        pub1 = node1.get_public_key_bytes()
        pub2 = node2.get_public_key_bytes()

        peer1 = node1.load_peer_public_key(pub2)
        peer2 = node2.load_peer_public_key(pub1)

        secret1 = node1.compute_shared_secret(peer1)
        secret2 = node2.compute_shared_secret(peer2)

        self.assertEqual(secret1, secret2)

    def test_session_key_derivation(self):
        """Test HKDF session key derivation produces 16-byte key for ASCON-128a"""
        node = ECCCore()
        shared_secret = hashlib.sha256(b"test").digest()
        key = node.derive_session_key(shared_secret)
        self.assertEqual(len(key), 16)  # 128-bit key for ASCON-128a


class TestASCON(unittest.TestCase):
    """Test ASCON-128a authenticated encryption"""

    def setUp(self):
        self.key = hashlib.sha256(b"test_key").digest()[:16]
        self.ascon = ASCONEncryption(self.key)

    def test_encrypt_decrypt(self):
        """Test successful ASCON-128a encryption and decryption"""
        message = b"Secure boot firmware verification"
        nonce, ciphertext, tag = self.ascon.encrypt(message)
        decrypted = self.ascon.decrypt(nonce, ciphertext, tag)
        self.assertEqual(message, decrypted)

    def test_encrypt_decrypt_with_aad(self):
        """Test ASCON-128a encryption/decryption with associated data"""
        message = b"Sensor reading: temperature=25.3C"
        aad = b"device_id=NODE_A,seq=42"
        nonce, ciphertext, tag = self.ascon.encrypt(message, associated_data=aad)
        decrypted = self.ascon.decrypt(nonce, ciphertext, tag, associated_data=aad)
        self.assertEqual(message, decrypted)

    def test_aad_mismatch_fails(self):
        """Test that mismatched AAD causes decryption failure"""
        message = b"Sensor reading"
        aad = b"device_id=NODE_A"
        nonce, ciphertext, tag = self.ascon.encrypt(message, associated_data=aad)
        with self.assertRaises(ValueError):
            self.ascon.decrypt(nonce, ciphertext, tag, associated_data=b"device_id=NODE_B")

    def test_tamper_detection_ciphertext(self):
        """Test that modifying the ciphertext causes decryption to fail"""
        message = b"Test message"
        nonce, ciphertext, tag = self.ascon.encrypt(message)

        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        if tampered:
            tampered[0] ^= 0x01

        with self.assertRaises(ValueError):
            self.ascon.decrypt(nonce, bytes(tampered), tag)

    def test_tamper_detection_tag(self):
        """Test that modifying the authentication tag causes decryption to fail"""
        message = b"Test message for tag tamper"
        nonce, ciphertext, tag = self.ascon.encrypt(message)

        # Tamper with authentication tag
        tampered_tag = bytearray(tag)
        tampered_tag[0] ^= 0x01

        with self.assertRaises(ValueError):
            self.ascon.decrypt(nonce, ciphertext, bytes(tampered_tag))

    def test_hkdf_session_key_with_ascon(self):
        """Test that the HKDF-derived session key works end-to-end with ASCON-128a"""
        # Simulate full ECDH + HKDF flow
        node1 = ECCCore()
        node2 = ECCCore()
        node1.generate_keypair()
        node2.generate_keypair()

        pub1 = node1.get_public_key_bytes()
        pub2 = node2.get_public_key_bytes()

        peer1 = node1.load_peer_public_key(pub2)
        peer2 = node2.load_peer_public_key(pub1)

        secret1 = node1.compute_shared_secret(peer1)
        secret2 = node2.compute_shared_secret(peer2)

        key1 = node1.derive_session_key(secret1)
        key2 = node2.derive_session_key(secret2)

        # Both nodes derive the same 16-byte key
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), 16)

        # Encrypt with node1's key, decrypt with node2's key
        enc1 = ASCONEncryption(key1)
        enc2 = ASCONEncryption(key2)

        plaintext = b"End-to-end ECDH + HKDF + ASCON-128a test"
        nonce, ciphertext, tag = enc1.encrypt(plaintext)
        decrypted = enc2.decrypt(nonce, ciphertext, tag)
        self.assertEqual(plaintext, decrypted)

    def test_invalid_key_size_rejected(self):
        """Test that a 32-byte key is rejected (ASCON-128a needs 16 bytes)"""
        bad_key = os.urandom(32)
        with self.assertRaises(ValueError):
            ASCONEncryption(bad_key)

    def test_nonce_is_16_bytes(self):
        """Test that generated nonces are 16 bytes"""
        message = b"nonce length test"
        nonce, _, _ = self.ascon.encrypt(message)
        self.assertEqual(len(nonce), 16)


class TestSecureBoot(unittest.TestCase):
    """Test Secure Boot functionality.

    Everything happens inside a per-test temporary directory. The previous
    version of this class wrote ``test_firmware.bin`` next to the test file and
    removed it in ``tearDown``, so a crash or Ctrl-C left the artifact behind in
    the source tree. Nothing here ever touches the repository.
    """

    def setUp(self):
        self.workdir = tempfile.mkdtemp(prefix="secure-boot-test-")
        self.addCleanup(shutil.rmtree, self.workdir, True)

        self.firmware_path = os.path.join(self.workdir, "firmware.bin")
        self.signature_path = os.path.join(self.workdir, "firmware.bin.sig")
        with open(self.firmware_path, "wb") as handle:
            handle.write(b"Test firmware content")

        self.private_key, self.public_key = generate_signing_keys()
        self.sb = SecureBoot(self.firmware_path)

    def test_firmware_artifact_lives_outside_the_source_tree(self):
        """The firmware under test is never written inside the repository"""
        real_workdir = os.path.realpath(self.workdir)
        real_validation = os.path.realpath(VALIDATION_DIR)
        self.assertFalse(
            real_workdir.startswith(real_validation + os.sep),
            f"temp firmware landed inside the source tree: {real_workdir}",
        )
        self.assertTrue(os.path.isfile(self.firmware_path))

    def test_firmware_signing_and_verification(self):
        """Test firmware signing and verification"""
        # Compute hash
        hash_val = self.sb.compute_firmware_hash()
        self.assertEqual(len(hash_val), 32)

        # Sign
        signature = self.sb.sign_firmware(self.private_key)
        self.assertIsNotNone(signature)

        # Verify
        valid, hash_val = self.sb.verify_firmware(self.public_key)
        self.assertTrue(valid)

    def test_signature_survives_a_file_round_trip(self):
        """A signature written to disk and reloaded still verifies"""
        self.sb.compute_firmware_hash()
        self.sb.sign_firmware(self.private_key)
        self.sb.signature_path = self.signature_path
        self.assertTrue(self.sb.save_signature_to_file())

        reloaded = SecureBoot(self.firmware_path, self.signature_path)
        reloaded.load_signature_from_file()
        valid, digest = reloaded.verify_firmware(self.public_key)
        self.assertTrue(valid, "reloaded signature must verify")
        self.assertEqual(digest, self.sb.compute_firmware_hash())

    def test_tampered_firmware_fails_verification(self):
        """Changing the firmware after signing must break verification"""
        self.sb.compute_firmware_hash()
        signature = self.sb.sign_firmware(self.private_key)

        with open(self.firmware_path, "ab") as handle:
            handle.write(b"\nmalicious payload")

        tampered = SecureBoot(self.firmware_path)
        valid, _ = tampered.verify_firmware(self.public_key, signature)
        self.assertFalse(valid, "a modified artifact must not verify")

    def test_signature_from_another_key_is_rejected(self):
        """A signature made with a different key must not verify"""
        self.sb.compute_firmware_hash()
        other_private, _ = generate_signing_keys()
        signature = self.sb.sign_firmware(other_private)
        valid, _ = self.sb.verify_firmware(self.public_key, signature)
        self.assertFalse(valid, "a foreign signature must not verify")

    def test_verification_without_a_signature_raises(self):
        """Verifying with no signature is a programming error, not a mismatch"""
        with self.assertRaises(ValueError):
            self.sb.verify_firmware(self.public_key)

    def test_test_run_leaves_no_bin_files_in_validation_directory(self):
        """Regression: an interrupted run must not leave *.bin in Validation/"""
        stray = sorted(glob.glob(os.path.join(VALIDATION_DIR, "*.bin")))
        self.assertEqual(
            stray,
            [],
            f"the test run left firmware artifacts in {VALIDATION_DIR}: {stray}",
        )
        self.assertFalse(
            os.path.exists(os.path.join(VALIDATION_DIR, "test_firmware.bin")),
            "the old in-tree test_firmware.bin artifact has reappeared",
        )


class TestASCONDependency(unittest.TestCase):
    """Regression: ASCON must not depend on the third-party ``ascon`` package.

    ``requirements.txt`` used to pin a non-existent ``ascon`` release, which
    made the whole install fail. The implementation is now pure standard
    library, so it must import with no site-packages at all.
    """

    def _module_source(self):
        with open(ASCON_MODULE_PATH, encoding="utf-8") as handle:
            return handle.read()

    def test_ascon_module_has_no_ascon_import(self):
        """No import of the third-party `ascon` package appears in the source"""
        source = self._module_source()
        offenders = [
            line.strip()
            for line in source.splitlines()
            if line.strip() == "import ascon"
            or line.strip().startswith("import ascon.")
            or line.strip().startswith("import ascon ")
            or line.strip().startswith("from ascon ")
            or line.strip().startswith("from ascon.")
        ]
        self.assertEqual(offenders, [], f"third-party ascon import found: {offenders}")
        self.assertNotIn("import ascon", source)

    def test_requirements_do_not_pin_ascon(self):
        """requirements.txt must not ask pip for the non-existent ascon release"""
        with open(REQUIREMENTS_PATH, encoding="utf-8") as handle:
            lines = [
                line.strip()
                for line in handle
                if line.strip() and not line.strip().startswith("#")
            ]
        for line in lines:
            self.assertFalse(
                line.split("=")[0].split(">")[0].split("<")[0].strip().lower()
                == "ascon",
                f"requirements.txt still pins the third-party ascon package: {line}",
            )

    def test_module_imports_with_the_standard_library_only(self):
        """The module imports in isolated mode with site-packages disabled"""
        script = (
            "import json, sys\n"
            f"sys.path.insert(0, {REPO_ROOT!r})\n"
            "import ECC_Integration.ASCON_Encryption as module\n"
            "names = sorted({name.split('.')[0] for name in sys.modules})\n"
            "print(json.dumps({'file': module.__file__, 'modules': names}))\n"
        )
        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-c", script],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(
            completed.returncode,
            0,
            "importing ECC_Integration.ASCON_Encryption without site-packages "
            f"failed:\n{completed.stdout}\n{completed.stderr}",
        )
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        self.assertEqual(
            os.path.realpath(payload["file"]), os.path.realpath(ASCON_MODULE_PATH)
        )
        self.assertNotIn(
            "ascon",
            payload["modules"],
            "the module pulled in a top-level package named 'ascon'",
        )


class TestECDSA(unittest.TestCase):
    """Test ECDSA authentication"""

    def setUp(self):
        self.ecdsa = ECDSAAuthentication()
        self.ecdsa.generate_identity_keypair()

    def test_sign_verify(self):
        """Test signing and verification"""
        challenge = hashlib.sha256(b"test_challenge").digest()
        signature = self.ecdsa.sign_challenge(challenge)
        self.assertIsNotNone(signature)

        peer_pub = self.ecdsa.get_public_key_bytes()
        peer = self.ecdsa.load_peer_public_key(peer_pub)
        valid = self.ecdsa.verify_signature(peer, challenge, signature)
        self.assertTrue(valid)


if __name__ == "__main__":
    unittest.main()
