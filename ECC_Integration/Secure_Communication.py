"""
Complete Secure Communication Pipeline
Integrates: ECDH + HKDF + ASCON-128a + ECDSA

This module contains the reusable Pi-side cryptographic operations.
"""

import os
import time
import json
from ECC_Core import ECCCore
from ASCON_Encryption import ASCONEncryption
from ECDSA_Auth import ECDSAAuthentication


class SecureCommunicationNode:
    """
    Complete secure communication node with all cryptographic components
    """

    def __init__(self, node_id):
        self.node_id = node_id
        self.ecdh = ECCCore()
        self.ecdsa = ECDSAAuthentication()
        self.session_key = None
        self.peer_public_key = None
        self.is_authenticated = False

    def initialize(self):
        """Generate all cryptographic keys"""
        print(f"[{self.node_id}] Initializing...")
        # Generate ECDH keypair
        self.ecdh.generate_keypair()
        # Generate ECDSA identity keypair
        self.ecdsa.generate_identity_keypair()
        return True

    def get_ecdh_public_key(self):
        """Get ECDH public key for exchange"""
        return self.ecdh.get_public_key_bytes()

    def get_ecdsa_public_key(self):
        """Get ECDSA public key for identity"""
        return self.ecdsa.get_public_key_bytes()

    def perform_ecdh_exchange(self, peer_ecdh_pub_bytes):
        """
        Perform ECDH key exchange with peer
        Returns: session key
        """
        print(f"[{self.node_id}] Performing ECDH key exchange...")

        # Load peer's public key
        peer_public = self.ecdh.load_peer_public_key(peer_ecdh_pub_bytes)
        if peer_public is None:
            raise ValueError("Invalid peer public key")

        # Compute shared secret
        shared_secret = self.ecdh.compute_shared_secret(peer_public)
        if shared_secret is None:
            raise ValueError("Shared secret computation failed")

        # Derive session key using HKDF
        self.session_key = self.ecdh.derive_session_key(shared_secret)

        print(f"[{self.node_id}] Session key derived")
        return self.session_key

    def authenticate_peer(self, peer_ecdsa_pub_bytes, challenge, signature):
        """
        Authenticate peer using ECDSA challenge-response
        """
        print(f"[{self.node_id}] Authenticating peer...")

        # Load peer's ECDSA public key
        peer_pub = self.ecdsa.load_peer_public_key(peer_ecdsa_pub_bytes)

        # Verify signature
        is_valid = self.ecdsa.verify_signature(peer_pub, challenge, signature)

        if is_valid:
            self.is_authenticated = True
            self.peer_public_key = peer_pub
            print(f"[{self.node_id}] Peer authenticated successfully")
        else:
            print(f"[{self.node_id}] Peer authentication failed")

        return is_valid

    def sign_challenge(self, challenge):
        """Sign a challenge for peer authentication"""
        return self.ecdsa.sign_challenge(challenge)

    def encrypt_message(self, plaintext):
        """
        Encrypt message using ASCON-128a with current session key
        """
        if not self.session_key:
            raise ValueError("No session key established")

        enc = ASCONEncryption(self.session_key)
        nonce, ciphertext, tag = enc.encrypt(plaintext.encode("utf-8"))
        return nonce, ciphertext, tag

    def decrypt_message(self, nonce, ciphertext, tag):
        """
        Decrypt and verify message using ASCON-128a
        """
        if not self.session_key:
            raise ValueError("No session key established")

        enc = ASCONEncryption(self.session_key)
        return enc.decrypt(nonce, ciphertext, tag)

    def clear_secure_memory(self):
        """Clear all sensitive data"""
        self.ecdh.clear_sensitive_data()
        self.session_key = None
        import gc

        gc.collect()
        print(f"[{self.node_id}] Secure memory cleared")

    def get_status(self):
        """Get node status"""
        return {
            "node_id": self.node_id,
            "authenticated": self.is_authenticated,
            "session_key_exists": self.session_key is not None,
        }
