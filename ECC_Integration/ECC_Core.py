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
        try:
            # Generate private key
            self.private_key = ec.generate_private_key(self.curve, default_backend())
            self.public_key = self.private_key.public_key()
            return True
        except Exception as e:
            print(f"Key generation failed: {e}")
            return False
    
    def get_public_key_bytes(self):
        """Export public key as bytes for transmission"""
        if not self.public_key:
            return None
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
    
    def load_peer_public_key(self, peer_public_bytes):
        """
        Load peer's public key from bytes
        Step 6: Receive and parse Q_B from Node B
        """
        try:
            peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                self.curve, peer_public_bytes
            )
            return peer_public_key
        except Exception as e:
            print(f"Invalid public key: {e}")
            return None
    
    def compute_shared_secret(self, peer_public_key):
        """
        Step 7: Compute S = d_A * Q_B (Node A) or S = d_B * Q_A (Node B)
        """
        if not self.private_key or not peer_public_key:
            raise ValueError("Private key or peer public key missing")
        
        try:
            # Compute shared secret using ECDH
            shared_secret = self.private_key.exchange(
                ec.ECDH(), peer_public_key
            )
            self.shared_secret = shared_secret
            return shared_secret
        except Exception as e:
            print(f"Shared secret computation failed: {e}")
            return None
    
    def verify_shared_secret_equality(self, peer_shared_secret):
        """
        Step 8: Verify S_A == S_B
        """
        return self.shared_secret == peer_shared_secret
    
    def derive_session_key(self, shared_secret, salt=None):
        """
        Step 9: HKDF-SHA256 to derive 256-bit AES session key
        HKDF = HMAC-based Extract-and-Expand Key Derivation Function
        """
        if salt is None:
            salt = b"ecc_secure_boot_salt_2026"
        
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit key
                salt=salt,
                info=b"aes-256-gcm-session-key",
                backend=default_backend()
            )
            session_key = hkdf.derive(shared_secret)
            return session_key
        except Exception as e:
            print(f"Key derivation failed: {e}")
            return None
    
    def clear_sensitive_data(self):
        """
        Step 15: Clear all sensitive variables from memory
        """
        self.private_key = None
        self.shared_secret = None
        # Force garbage collection
        import gc
        gc.collect()
        print("Sensitive data cleared from memory")


# Standalone ECDH Demo
def demo_ecdh_exchange():
    """Demonstrate complete ECDH key exchange between two nodes"""
    
    print("="*60)
    print("NODE A: Generating keypair...")
    node_a = ECCCore()
    node_a.generate_keypair()
    print(f"Node A Private Key: {node_a.private_key.private_numbers().private_value}")
    
    print("\nNODE B: Generating keypair...")
    node_b = ECCCore()
    node_b.generate_keypair()
    print(f"Node B Private Key: {node_b.private_key.private_numbers().private_value}")
    
    # Step 6: Exchange public keys
    print("\nStep 6: Exchanging public keys...")
    pub_a_bytes = node_a.get_public_key_bytes()
    pub_b_bytes = node_b.get_public_key_bytes()
    
    # Step 7: Compute shared secrets
    print("\nStep 7: Computing shared secrets...")
    peer_a_for_b = node_b.load_peer_public_key(pub_a_bytes)
    peer_b_for_a = node_a.load_peer_public_key(pub_b_bytes)
    
    shared_a = node_a.compute_shared_secret(peer_a_for_b)
    shared_b = node_b.compute_shared_secret(peer_b_for_a)
    
    # Step 8: Verify equality
    print(f"\nStep 8: Shared Secret A: {shared_a.hex()[:32]}...")
    print(f"Shared Secret B: {shared_b.hex()[:32]}...")
    print(f"Secrets Match: {shared_a == shared_b}")
    
    # Step 9: Derive session key
    print("\nStep 9: Deriving session keys...")
    key_a = node_a.derive_session_key(shared_a)
    key_b = node_b.derive_session_key(shared_b)
    print(f"Session Key A: {key_a.hex()[:32]}...")
    print(f"Session Key B: {key_b.hex()[:32]}...")
    print(f"Keys Match: {key_a == key_b}")
    
    # Step 15: Clear sensitive data
    print("\nStep 15: Clearing sensitive data...")
    node_a.clear_sensitive_data()
    node_b.clear_sensitive_data()
    
    print("="*60)
    return node_a, node_b, key_a, key_b

if __name__ == "__main__":
    demo_ecdh_exchange()