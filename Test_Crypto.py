"""
Comprehensive Cryptographic Testing Suite
"""

import unittest
import os
import hashlib
from ecc_core import ECCCore
from aes_gcm_encryption import AESGCMEncryption
from ecdsa_auth import ECDSAAuthentication
from secure_boot import SecureBoot, generate_signing_keys

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
        """Test HKDF session key derivation"""
        node = ECCCore()
        shared_secret = hashlib.sha256(b"test").digest()
        key = node.derive_session_key(shared_secret)
        self.assertEqual(len(key), 32)  # 256-bit key

class TestAESGCM(unittest.TestCase):
    """Test AES-256-GCM encryption"""
    
    def setUp(self):
        self.key = hashlib.sha256(b"test_key").digest()
        self.aes = AESGCMEncryption(self.key)
        
    def test_encrypt_decrypt(self):
        """Test encryption and decryption"""
        message = b"Secure boot firmware verification"
        nonce, ciphertext, tag = self.aes.encrypt(message)
        decrypted = self.aes.decrypt(nonce, ciphertext, tag)
        self.assertEqual(message, decrypted)
        
    def test_tamper_detection(self):
        """Test tamper detection"""
        message = b"Test message"
        nonce, ciphertext, tag = self.aes.encrypt(message)
        
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        if tampered:
            tampered[0] ^= 0x01
            
        with self.assertRaises(ValueError):
            self.aes.decrypt(nonce, bytes(tampered), tag)

class TestSecureBoot(unittest.TestCase):
    """Test Secure Boot functionality"""
    
    def setUp(self):
        self.firmware_path = "/tmp/test_firmware.bin"
        with open(self.firmware_path, 'wb') as f:
            f.write(b"Test firmware content")
        
        self.private_key, self.public_key = generate_signing_keys()
        self.sb = SecureBoot(self.firmware_path)
        
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
        
    def tearDown(self):
        if os.path.exists(self.firmware_path):
            os.remove(self.firmware_path)

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