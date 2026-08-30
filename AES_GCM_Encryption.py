"""
AES-256-GCM Module - Authenticated Encryption with Integrity Verification
"""

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AESGCMEncryption:
    """AES-256-GCM encryption/decryption with authentication tag"""
    
    def __init__(self, session_key):
        """
        Initialize with 256-bit session key (32 bytes)
        """
        if len(session_key) != 32:
            raise ValueError("Session key must be 32 bytes (256-bit)")
        self.session_key = session_key
        self.aes_gcm = AESGCM(session_key)
        
    def encrypt(self, plaintext, nonce=None):
        """
        Step 10: Encrypt message M using AES-256-GCM
        Returns: (nonce, ciphertext, auth_tag)
        """
        if nonce is None:
            nonce = os.urandom(12)  # 96-bit nonce as recommended for GCM
        
        # Encrypt and get authentication tag
        ciphertext = self.aes_gcm.encrypt(nonce, plaintext, None)
        # Note: In AESGCM, the tag is appended to ciphertext
        # We'll separate them for clarity
        tag = ciphertext[-16:]  # Last 16 bytes are the auth tag
        actual_ciphertext = ciphertext[:-16]  # Rest is the encrypted data
        
        return nonce, actual_ciphertext, tag
    
    def decrypt(self, nonce, ciphertext, tag):
        """
        Step 12: Decrypt and verify authentication tag
        Returns: plaintext if tag valid, raises exception if tampered
        """
        # Reconstruct combined ciphertext with tag
        combined = ciphertext + tag
        
        try:
            plaintext = self.aes_gcm.decrypt(nonce, combined, None)
            return plaintext
        except Exception as e:
            # Step 13: Authentication failed
            raise ValueError(f"Integrity verification failed: {e}")
    
    def send_encrypted_message(self, message, recipient_public_key=None):
        """
        Complete message encryption with nonce generation
        """
        nonce, ciphertext, tag = self.encrypt(message.encode('utf-8'))
        return nonce, ciphertext, tag


# Demo
def demo_aes_gcm():
    """Demonstrate AES-256-GCM encryption/decryption"""
    
    print("="*60)
    print("AES-256-GCM Encryption Demo")
    
    # Create a 256-bit key (simulating from HKDF)
    session_key = os.urandom(32)
    
    # Initialize encryption
    crypto = AESGCMEncryption(session_key)
    
    # Message to encrypt
    message = "Secure Boot: Firmware integrity verified. Session established."
    print(f"\nOriginal Message: {message}")
    
    # Step 10: Encrypt
    print("\nStep 10: Encrypting...")
    nonce, ciphertext, tag = crypto.encrypt(message.encode('utf-8'))
    print(f"Nonce: {nonce.hex()[:16]}...")
    print(f"Ciphertext: {ciphertext.hex()[:32]}...")
    print(f"Authentication Tag: {tag.hex()[:16]}...")
    
    # Step 11: Transmit (simulated)
    print("\nStep 11: Transmitting encrypted data...")
    
    # Step 12-13: Decrypt and verify
    print("\nStep 12-13: Decrypting and verifying...")
    try:
        decrypted = crypto.decrypt(nonce, ciphertext, tag)
        print(f"Decrypted Message: {decrypted.decode('utf-8')}")
        print("✓ Authentication Tag Valid - Message Integrity Confirmed")
    except ValueError as e:
        print(f"✗ Decryption Failed: {e}")
    
    # Tamper test
    print("\n--- Tamper Test ---")
    print("Modifying ciphertext to test integrity check...")
    tampered_ciphertext = bytearray(ciphertext)
    if len(tampered_ciphertext) > 0:
        tampered_ciphertext[0] ^= 0x01  # Flip one bit
    
    try:
        decrypted = crypto.decrypt(nonce, bytes(tampered_ciphertext), tag)
        print("✗ Error: Tampered data was accepted!")
    except ValueError:
        print("✓ Success: Tampered data rejected correctly!")
    
    print("="*60)

if __name__ == "__main__":
    demo_aes_gcm()