"""
Comprehensive Cryptographic Testing Suite

Tests: ECC Core, ASCON-128a AEAD, Secure Boot, ECDSA Authentication

NOTE: This covers the Raspberry Pi (Python) implementation only.
      ESP32 requires a separate native C ASCON + mbedTLS port.
"""

import unittest
import os
import hashlib
from ECC_Integration.ECC_Core import ECCCore
from ECC_Integration.ASCON_Encryption import ASCONEncryption
from ECC_Integration.ECDSA_Auth import ECDSAAuthentication
from ECC_Integration.Secure_Boot import SecureBoot, generate_signing_keys

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
    """Test Secure Boot functionality"""
    
    def setUp(self):
        self.firmware_path = os.path.join(os.path.dirname(__file__), "test_firmware.bin")
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