"""
Complete Secure Communication Pipeline
Integrates: ECDH + HKDF + ASCON-128a + ECDSA

NOTE: This is the Raspberry Pi (Python) implementation only.
      The ESP32 requires a separate native C ASCON + mbedTLS port.
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


def demo_complete_secure_pipeline():
    """Demonstrate complete secure communication pipeline"""

    print("=" * 70)
    print("COMPLETE SECURE COMMUNICATION PIPELINE DEMO")
    print("ECC + ECDH + HKDF + ASCON-128a + ECDSA")
    print("=" * 70)

    # Initialize nodes
    print("\n[INIT] Creating and initializing nodes...")
    node_a = SecureCommunicationNode("NODE_A")
    node_b = SecureCommunicationNode("NODE_B")
    node_a.initialize()
    node_b.initialize()

    # Step 3-5: Key Generation (done in initialize)
    print("\n[KEYGEN] Keys generated on both nodes")

    # Step 6: Exchange public keys
    print("\n[EXCHANGE] Exchanging public keys...")
    ecdh_pub_a = node_a.get_ecdh_public_key()
    ecdh_pub_b = node_b.get_ecdh_public_key()
    ecdsa_pub_a = node_a.get_ecdsa_public_key()
    ecdsa_pub_b = node_b.get_ecdsa_public_key()

    # Step 7-9: ECDH + HKDF
    print("\n[ECDH] Performing ECDH key exchange...")
    session_key_a = node_a.perform_ecdh_exchange(ecdh_pub_b)
    session_key_b = node_b.perform_ecdh_exchange(ecdh_pub_a)

    print(f"Session Key A: {session_key_a.hex()[:32]}...")  # type: ignore
    print(f"Session Key B: {session_key_b.hex()[:32]}...")  # type: ignore
    print(f"Keys match: {session_key_a == session_key_b}")

    # Step: Mutual authentication with ECDSA
    print("\n[AUTH] Performing mutual authentication...")

    # Node A challenges Node B
    challenge_a = os.urandom(32)
    signature_b = node_b.sign_challenge(challenge_a)
    auth_b = node_a.authenticate_peer(ecdsa_pub_b, challenge_a, signature_b)

    # Node B challenges Node A
    challenge_b = os.urandom(32)
    signature_a = node_a.sign_challenge(challenge_b)
    auth_a = node_b.authenticate_peer(ecdsa_pub_a, challenge_b, signature_a)

    if auth_a and auth_b:
        print("\n✓ Mutual authentication successful!")
    else:
        print("\n✗ Mutual authentication failed!")
        return

    # Step 10-13: Encrypted message exchange
    print("\n[COMM] Sending encrypted message...")

    # Node A sends a message to Node B
    plaintext = "Secure Boot: All systems operational. Firmware version 2.1.0 verified."
    print(f"\nOriginal Message (Node A → Node B): {plaintext}")

    nonce, ciphertext, tag = node_a.encrypt_message(plaintext)
    print(f"\nEncrypted (Node A):")
    print(f"  Nonce: {nonce.hex()[:20]}...")
    print(f"  Ciphertext: {ciphertext.hex()[:30]}...")
    print(f"  Auth Tag: {tag.hex()[:16]}...")

    # Node B decrypts
    decrypted = node_b.decrypt_message(nonce, ciphertext, tag)
    print(f"\nDecrypted (Node B): {decrypted.decode('utf-8')}")

    # Node B replies
    reply = "Acknowledged: Secure channel established. Ready for data."
    nonce2, ciphertext2, tag2 = node_b.encrypt_message(reply)
    decrypted2 = node_a.decrypt_message(nonce2, ciphertext2, tag2)
    print(f"\nReply (Node B → Node A): {decrypted2.decode('utf-8')}")

    # Step 15: Clear secure memory
    print("\n[CLEANUP] Clearing secure memory...")
    node_a.clear_secure_memory()
    node_b.clear_secure_memory()

    print("\n" + "=" * 70)
    print("✓ Secure communication pipeline complete!")
    print("=" * 70)


if __name__ == "__main__":
    demo_complete_secure_pipeline()
