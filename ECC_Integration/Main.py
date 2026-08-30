"""
Main Application - Complete System Integration
Secure Boot + ECDH + AES-256-GCM + ECDSA
"""

import os
import sys
import time
import json
from datetime import datetime
from ecc_core import ECCCore
from secure_boot import SecureBoot, generate_signing_keys
from secure_communication import SecureCommunicationNode

class SecureEmbeddedSystem:
    """
    Complete secure embedded system integration
    """
    
    def __init__(self, node_id):
        self.node_id = node_id
        self.secure_node = SecureCommunicationNode(node_id)
        self.boot_status = False
        self.session_active = False
        self.log_file = f"secure_log_{node_id}.txt"
        
    def secure_boot(self, firmware_path, signing_private_key, signing_public_key):
        """
        Perform secure boot verification
        """
        print(f"\n[{self.node_id}] Performing Secure Boot...")
        
        try:
            # Create firmware signature if not exists
            sb = SecureBoot(firmware_path)
            firmware_hash = sb.compute_firmware_hash()
            
            # Sign or verify firmware
            if not os.path.exists(f"{firmware_path}.sig"):
                print(f"[{self.node_id}] Creating firmware signature...")
                sb.signature = sb.sign_firmware(signing_private_key)
                sb.save_signature_to_file()
            
            # Verify firmware
            sb.load_signature_from_file()
            is_valid, hash_value = sb.verify_firmware(signing_public_key)
            
            if is_valid:
                self.boot_status = True
                print(f"[{self.node_id}] ✓ Secure Boot: SUCCESS")
                self.log_event("SECURE_BOOT", "SUCCESS", f"Hash: {hash_value.hex()[:16]}")
            else:
                self.boot_status = False
                print(f"[{self.node_id}] ✗ Secure Boot: FAILED")
                self.log_event("SECURE_BOOT", "FAILED", "Integrity check failed")
                return False
                
            return True
            
        except Exception as e:
            print(f"[{self.node_id}] Secure Boot error: {e}")
            self.log_event("SECURE_BOOT", "ERROR", str(e))
            return False
    
    def initialize_cryptography(self):
        """
        Initialize cryptographic components
        """
        print(f"\n[{self.node_id}] Initializing cryptography...")
        return self.secure_node.initialize()
    
    def establish_secure_channel(self, peer_ecdh_pub, peer_ecdsa_pub):
        """
        Establish secure channel with peer
        """
        print(f"\n[{self.node_id}] Establishing secure channel...")
        
        # ECDH key exchange
        session_key = self.secure_node.perform_ecdh_exchange(peer_ecdh_pub)
        if session_key is None:
            self.log_event("SECURE_CHANNEL", "FAILED", "ECDH exchange failed")
            return False
        
        # Mutual authentication
        # Generate challenge
        challenge = os.urandom(32)
        signature = self.secure_node.sign_challenge(challenge)
        
        # In real implementation, exchange challenges and signatures
        # For demo, we'll simulate mutual authentication
        
        self.session_active = True
        self.log_event("SECURE_CHANNEL", "ESTABLISHED", "Secure channel active")
        print(f"[{self.node_id}] ✓ Secure channel established")
        return True
    
    def encrypt_and_send(self, message, recipient_node):
        """
        Encrypt and send a message
        """
        if not self.session_active:
            print(f"[{self.node_id}] No active session!")
            return False
        
        try:
            nonce, ciphertext, tag = self.secure_node.encrypt_message(message)
            print(f"[{self.node_id}] Message encrypted and sent")
            self.log_event("MESSAGE_SENT", "SUCCESS", f"Length: {len(message)}")
            
            # Simulate receiving
            decrypted = recipient_node.secure_node.decrypt_message(nonce, ciphertext, tag)
            print(f"[{recipient_node.node_id}] Message received: {decrypted.decode('utf-8')}")
            recipient_node.log_event("MESSAGE_RECEIVED", "SUCCESS", f"Length: {len(decrypted)}")
            
            return True
        except Exception as e:
            print(f"[{self.node_id}] Encryption error: {e}")
            self.log_event("MESSAGE_SEND", "ERROR", str(e))
            return False
    
    def log_event(self, event_type, status, details):
        """Log system events"""
        timestamp = datetime.now().isoformat()
        log_entry = f"{timestamp} | {self.node_id} | {event_type} | {status} | {details}\n"
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
    
    def get_status_report(self):
        """Get comprehensive system status"""
        return {
            'node_id': self.node_id,
            'secure_boot': 'PASS' if self.boot_status else 'FAIL',
            'session_active': self.session_active,
            'timestamp': datetime.now().isoformat()
        }
    
    def secure_shutdown(self):
        """Perform secure shutdown"""
        print(f"\n[{self.node_id}] Performing secure shutdown...")
        self.secure_node.clear_secure_memory()
        self.session_active = False
        self.log_event("SHUTDOWN", "COMPLETE", "System shutdown secure")
        print(f"[{self.node_id}] ✓ Secure shutdown complete")


def main_demo():
    """Complete system demo"""
    
    print("="*70)
    print("SECURE EMBEDDED SYSTEM - COMPLETE DEMO")
    print("Secure Boot | ECDH | AES-256-GCM | ECDSA")
    print("="*70)
    
    # Create firmware for secure boot
    firmware_content = b"SECURE FIRMWARE V2.1.0"
    firmware_path = "/tmp/firmware.bin"
    with open(firmware_path, 'wb') as f:
        f.write(firmware_content)
    
    # Generate signing keys
    signing_private, signing_public = generate_signing_keys()
    
    # Initialize nodes
    print("\n[INIT] Initializing system nodes...")
    node_a = SecureEmbeddedSystem("NODE_A")
    node_b = SecureEmbeddedSystem("NODE_B")
    
    # Secure Boot
    print("\n" + "-"*70)
    print("PHASE 1: SECURE BOOT")
    print("-"*70)
    
    boot_a = node_a.secure_boot(firmware_path, signing_private, signing_public)
    boot_b = node_b.secure_boot(firmware_path, signing_private, signing_public)
    
    if not (boot_a and boot_b):
        print("\n✗ Secure boot failed - aborting")
        return
    
    # Initialize cryptography
    print("\n" + "-"*70)
    print("PHASE 2: CRYPTOGRAPHIC INITIALIZATION")
    print("-"*70)
    
    node_a.initialize_cryptography()
    node_b.initialize_cryptography()
    
    # Establish secure channel
    print("\n" + "-"*70)
    print("PHASE 3: SECURE CHANNEL ESTABLISHMENT")
    print("-"*70)
    
    pub_a_ecdh = node_a.secure_node.get_ecdh_public_key()
    pub_b_ecdh = node_b.secure_node.get_ecdh_public_key()
    pub_a_ecdsa = node_a.secure_node.get_ecdsa_public_key()
    pub_b_ecdsa = node_b.secure_node.get_ecdsa_public_key()
    
    # Each node establishes channel with peer
    channel_a = node_a.establish_secure_channel(pub_b_ecdh, pub_b_ecdsa)
    channel_b = node_b.establish_secure_channel(pub_a_ecdh, pub_a_ecdsa)
    
    if not (channel_a and channel_b):
        print("\n✗ Secure channel establishment failed")
        return
    
    # Secure communication
    print("\n" + "-"*70)
    print("PHASE 4: SECURE COMMUNICATION")
    print("-"*70)
    
    # Send messages
    message1 = "Secure message from Node A: System operational"
    node_a.encrypt_and_send(message1, node_b)
    
    message2 = "Node B acknowledges: Secure channel active"
    node_b.encrypt_and_send(message2, node_a)
    
    # System status
    print("\n" + "-"*70)
    print("PHASE 5: SYSTEM STATUS")
    print("-"*70)
    print(f"Node A Status: {json.dumps(node_a.get_status_report(), indent=2)}")
    print(f"Node B Status: {json.dumps(node_b.get_status_report(), indent=2)}")
    
    # Secure shutdown
    print("\n" + "-"*70)
    print("PHASE 6: SECURE SHUTDOWN")
    print("-"*70)
    node_a.secure_shutdown()
    node_b.secure_shutdown()
    
    # Cleanup
    os.remove(firmware_path)
    if os.path.exists(f"{firmware_path}.sig"):
        os.remove(f"{firmware_path}.sig")
    
    print("\n" + "="*70)
    print("✓ SYSTEM DEMO COMPLETE")
    print("="*70)


if __name__ == "__main__":
    main_demo()