"""
ECDSA Authentication Module - Challenge-Response Protocol
"""

import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import serialization

class ECDSAAuthentication:
    """ECDSA-based challenge-response authentication"""

    def __init__(self):
        self.curve = ec.SECP256R1()
        self.private_key = None
        self.public_key = None

    def generate_identity_keypair(self):
        """Generate ECDSA key pair for device identity"""
        self.private_key = ec.generate_private_key(self.curve)
        self.public_key = self.private_key.public_key()
        return self.private_key, self.public_key

    def sign_challenge(self, challenge):
        """
        Sign a challenge (random nonce) with private key
        Returns: signature (r, s)
        """
        if not self.private_key:
            raise ValueError("Private key not generated")

        signature = self.private_key.sign(
            challenge,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify_signature(self, peer_public_key, challenge, signature):
        """
        Verify peer's signature on the challenge
        Returns: True if valid, False otherwise
        """
        try:
            peer_public_key.verify(
                signature,
                challenge,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception:
            return False

    def get_public_key_bytes(self):
        """Export public key as bytes"""
        if not self.public_key:
            return None
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )

    def load_peer_public_key(self, peer_bytes):
        """Load peer public key from bytes"""
        return ec.EllipticCurvePublicKey.from_encoded_point(
            self.curve, peer_bytes
        )
