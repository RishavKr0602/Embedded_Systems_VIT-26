"""
ECC Core Module - Key Generation, ECDH Key Exchange, and Shared Secret Derivation
Based on NIST P-256 Curve (secp256r1)
"""

import os
import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class ECCCore:
    """Core ECC operations for embedded devices"""

    def __init__(self):
        # NIST P-256 curve parameters (secp256r1)
        self.curve = ec.SECP256R1()
        self.curve_name = "secp256r1"
        self.private_key = None
        self.public_key = None
        self.shared_secret = None

    def generate_keypair(self):
        """
        Step 3-5: Generate ECC key pair
        Private key d_A in [1, n-1], Public key Q_A = d_A * G
        """
        self.private_key = ec.generate_private_key(self.curve, default_backend())
        self.public_key = self.private_key.public_key()
        return True

    def get_public_key_bytes(self):
        """Export public key as bytes for transmission"""
        if not self.public_key:
            raise ValueError("No public key available — call generate_keypair() first")
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

    def load_peer_public_key(self, peer_public_bytes):
        """
        Load peer's public key from bytes
        Step 6: Receive and parse Q_B from Node B
        """
        return ec.EllipticCurvePublicKey.from_encoded_point(
            self.curve, peer_public_bytes
        )

    def compute_shared_secret(self, peer_public_key):
        """
        Step 7: Compute S = d_A * Q_B (Node A) or S = d_B * Q_A (Node B)
        """
        if not self.private_key or not peer_public_key:
            raise ValueError("Private key or peer public key missing")

        # Compute shared secret using ECDH
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        self.shared_secret = shared_secret
        return shared_secret

    def verify_shared_secret_equality(self, peer_shared_secret):
        """
        Step 8: Verify S_A == S_B
        """
        return self.shared_secret == peer_shared_secret

    def derive_session_key(self, shared_secret, salt=None):
        """
        Step 9: HKDF-SHA256 to derive 128-bit ASCON session key
        HKDF = HMAC-based Extract-and-Expand Key Derivation Function

        The derived key is sized for the Pi deployment's ASCON-128a layer.
        """
        if salt is None:
            salt = b"ecc_secure_boot_salt_2026"

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,  # 128-bit key for ASCON-128a
            salt=salt,
            info=b"ascon-128a-session-key",
            backend=default_backend(),
        )
        return hkdf.derive(shared_secret)

    def clear_sensitive_data(self):
        """
        Step 15: Clear all sensitive variables from memory
        """
        self.private_key = None
        self.shared_secret = None
        # Force garbage collection
        import gc

        gc.collect()
