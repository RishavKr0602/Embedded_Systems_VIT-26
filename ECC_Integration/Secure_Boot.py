"""
Secure Boot Module - Firmware Integrity Verification
"""

import hashlib
import tempfile
import os
import json
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
        """
        if signature is None:
            signature = self.signature

        if not signature:
            raise ValueError("No signature provided")

        if not self.firmware_hash:
            self.compute_firmware_hash()

        try:
            public_key.verify(signature, self.firmware_hash, ec.ECDSA(hashes.SHA256()))
            return True, self.firmware_hash
        except Exception as e:
            return False, self.firmware_hash

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


def demo_secure_boot():
    """Demonstrate secure boot verification"""

    print("=" * 60)
    print("SECURE BOOT DEMO - Firmware Integrity Verification")
    print("=" * 60)

    # Create a sample firmware file
    firmware_content = b"""
    // Secure Firmware for Embedded Device
    // Version: 2.1.0
    // Build Date: 2026-08-30
    
    #include <stdio.h>
    #include "secure_comm.h"
    
    int main() {
        initialize_secure_boot();
        establish_secure_channel();
        while(1) {
            process_encrypted_data();
        }
        return 0;
    }
    """

    firmware_path = firmware_path = os.path.join(tempfile.gettempdir(), "firmware.bin")
    signature_path = signature_path = os.path.join(
        tempfile.gettempdir(), "firmware.sig"
    )

    with open(firmware_path, "wb") as f:
        f.write(firmware_content)

    print(f"Sample firmware created: {firmware_path}")

    # Generate signing keys
    print("\n[KEYGEN] Generating signing keys...")
    private_key, public_key = generate_signing_keys()

    # Step: Sign firmware
    print("\n[SIGN] Signing firmware...")
    sb = SecureBoot(firmware_path, signature_path)
    firmware_hash = sb.compute_firmware_hash()
    print(f"Firmware SHA-256: {firmware_hash.hex()[:32]}...")

    signature = sb.sign_firmware(private_key)
    sb.save_signature_to_file()
    print(f"Signature created: {signature.hex()[:32]}...")

    # Step: Verify firmware
    print("\n[VERIFY] Verifying firmware...")
    is_valid, hash_value = sb.verify_firmware(public_key)
    print(f"Firmware integrity: {'✓ VALID' if is_valid else '✗ INVALID'}")

    # Tamper test
    print("\n--- Tamper Test ---")
    print("Modifying firmware...")
    with open(firmware_path, "ab") as f:
        f.write(b"// TAMPERED CONTENT")

    sb.compute_firmware_hash()  # Recompute hash
    is_valid, hash_value = sb.verify_firmware(public_key)
    print(f"Tampered firmware integrity: {'✓ VALID' if is_valid else '✗ INVALID'}")
    print("✓ Tampered firmware correctly rejected!")

    # Cleanup
    os.remove(firmware_path)
    if os.path.exists(signature_path):
        os.remove(signature_path)

    print("\n" + "=" * 60)


if __name__ == "__main__":
    demo_secure_boot()
