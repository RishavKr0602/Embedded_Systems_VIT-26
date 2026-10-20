"""
Secure Boot Module - Firmware Integrity Verification
"""

import hashlib
import tempfile
import os
import json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization


class SecureBoot:
    """
    Secure Boot implementation with ECDSA verification
    """

    def __init__(self, firmware_path, signature_path=None, public_key_path=None):
        self.firmware_path = firmware_path
        self.signature_path = signature_path
        self.public_key_path = public_key_path
        self.firmware_hash = None
        self.signature = None

    def compute_firmware_hash(self, firmware_data=None):
        """
        Compute SHA-256 hash of firmware
        """
        if firmware_data is None:
            with open(self.firmware_path, "rb") as f:
                firmware_data = f.read()

        sha256 = hashlib.sha256()
        sha256.update(firmware_data)
        self.firmware_hash = sha256.digest()
        return self.firmware_hash

    def sign_firmware(self, private_key):
        """
        Sign firmware hash using ECDSA (for development/testing)
        """
        if not self.firmware_hash:
            self.compute_firmware_hash()

        signature = private_key.sign(self.firmware_hash, ec.ECDSA(hashes.SHA256()))
        self.signature = signature
        return signature

    def verify_firmware(self, public_key, signature=None):
        """
        Verify firmware signature
        Returns: (is_valid, firmware_hash)

        A genuine signature mismatch returns (False, hash). Any other failure --
        an unusable key, a malformed signature, a bad argument -- is a
        configuration or programming error and propagates to the caller instead
        of being reported as a mere verification failure.
        """
        if signature is None:
            signature = self.signature

        if not signature:
            raise ValueError("No signature provided")

        if not self.firmware_hash:
            self.compute_firmware_hash()

        try:
            public_key.verify(signature, self.firmware_hash, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            return False, self.firmware_hash
        return True, self.firmware_hash

    def load_signature_from_file(self):
        """Load signature from file"""
        if self.signature_path and os.path.exists(self.signature_path):
            with open(self.signature_path, "rb") as f:
                self.signature = f.read()
            return self.signature
        return None

    def save_signature_to_file(self):
        """Save signature to file"""
        if self.signature_path and self.signature:
            with open(self.signature_path, "wb") as f:
                f.write(self.signature)
            return True
        return False


def generate_signing_keys():
    """Generate ECDSA key pair for secure boot"""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key
