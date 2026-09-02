"""
ASCON-128a Module - Authenticated Encryption with Associated Data (AEAD)

Replaces AES-256-GCM with the ASCON-128a lightweight AEAD cipher.
ASCON is the NIST Lightweight Cryptography Standard (NIST SP 800-232).

Key size:   128-bit (16 bytes)
Nonce size: 128-bit (16 bytes)
Tag size:   128-bit (16 bytes)

NOTE: This is the Raspberry Pi (Python) implementation only.
      The ESP32 requires a separate native C ASCON + mbedTLS port.
"""

import os
import ascon


class ASCONEncryption:
    """ASCON-128a authenticated encryption/decryption with integrity verification"""

    VARIANT = "Ascon-128a"
    KEY_SIZE = 16    # 128-bit key
    NONCE_SIZE = 16  # 128-bit nonce
    TAG_SIZE = 16    # 128-bit authentication tag

    def __init__(self, session_key):
        """
        Initialize with 128-bit session key (16 bytes).

        Args:
            session_key: bytes of length 16 (derived from HKDF).

        Raises:
            ValueError: If session_key is not exactly 16 bytes.
        """
        if len(session_key) != self.KEY_SIZE:
            raise ValueError(
                f"Session key must be {self.KEY_SIZE} bytes (128-bit), "
                f"got {len(session_key)} bytes"
            )
        self.session_key = session_key

    def encrypt(self, plaintext, associated_data=b"", nonce=None):
        """
        Step 10: Encrypt message M using ASCON-128a AEAD.

        Args:
            plaintext:       bytes to encrypt.
            associated_data: optional AAD authenticated but not encrypted.
            nonce:           16-byte nonce (generated randomly if None).

        Returns:
            (nonce, ciphertext, tag) — tag is the last 16 bytes split
            from the ASCON output for interface compatibility.
        """
        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE)

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(
                f"Nonce must be {self.NONCE_SIZE} bytes, got {len(nonce)} bytes"
            )

        # ascon.encrypt returns ciphertext || tag (tag is last 16 bytes)
        ct_with_tag = ascon.encrypt(
            self.session_key,
            nonce,
            associated_data,
            plaintext,
            variant=self.VARIANT,
        )

        # Separate ciphertext and authentication tag for interface compatibility
        tag = ct_with_tag[-self.TAG_SIZE:]
        ciphertext = ct_with_tag[:-self.TAG_SIZE]

        return nonce, ciphertext, tag

    def decrypt(self, nonce, ciphertext, tag, associated_data=b""):
        """
        Step 12: Decrypt and verify authentication tag using ASCON-128a.

        Args:
            nonce:           16-byte nonce used during encryption.
            ciphertext:      encrypted data (without tag).
            tag:             16-byte authentication tag.
            associated_data: optional AAD (must match what was used in encrypt).

        Returns:
            plaintext bytes if authentication succeeds.

        Raises:
            ValueError: If integrity verification fails (tampered data,
                        wrong key, wrong nonce, or wrong AAD).
        """
        # Reconstruct combined ciphertext || tag as expected by ascon.decrypt
        combined = ciphertext + tag

        plaintext = ascon.decrypt(
            self.session_key,
            nonce,
            associated_data,
            combined,
            variant=self.VARIANT,
        )

        # ascon.decrypt returns None on authentication failure
        if plaintext is None:
            raise ValueError(
                "ASCON integrity verification failed: "
                "ciphertext, tag, key, nonce, or associated data is invalid"
            )

        return plaintext

    def send_encrypted_message(self, message, recipient_public_key=None):
        """
        Complete message encryption with nonce generation.

        Args:
            message: string to encrypt.
            recipient_public_key: unused, kept for interface compatibility.

        Returns:
            (nonce, ciphertext, tag)
        """
        nonce, ciphertext, tag = self.encrypt(message.encode("utf-8"))
        return nonce, ciphertext, tag


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------
def demo_ascon():
    """Demonstrate ASCON-128a authenticated encryption/decryption.

    NOTE: Raspberry Pi (Python) implementation only.
          ESP32 requires a native C ASCON + mbedTLS port.
    """

    print("=" * 60)
    print("ASCON-128a Authenticated Encryption Demo")

    # Create a 128-bit key (simulating derivation from HKDF)
    session_key = os.urandom(16)

    # Initialize encryption
    crypto = ASCONEncryption(session_key)

    # Message to encrypt
    message = "Secure Boot: Firmware integrity verified. Session established."
    print(f"\nOriginal Message: {message}")

    # Step 10: Encrypt
    print("\nStep 10: Encrypting with ASCON-128a...")
    nonce, ciphertext, tag = crypto.encrypt(message.encode("utf-8"))
    print(f"Nonce (16 B): {nonce.hex()[:16]}...")
    print(f"Ciphertext:   {ciphertext.hex()[:32]}...")
    print(f"Auth Tag:     {tag.hex()}")

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

    # Tamper test — ciphertext
    print("\n--- Tamper Test (ciphertext) ---")
    tampered_ct = bytearray(ciphertext)
    if len(tampered_ct) > 0:
        tampered_ct[0] ^= 0x01
    try:
        crypto.decrypt(nonce, bytes(tampered_ct), tag)
        print("✗ Error: Tampered data was accepted!")
    except ValueError:
        print("✓ Success: Tampered ciphertext rejected correctly!")

    # Tamper test — tag
    print("\n--- Tamper Test (auth tag) ---")
    tampered_tag = bytearray(tag)
    tampered_tag[0] ^= 0x01
    try:
        crypto.decrypt(nonce, ciphertext, bytes(tampered_tag))
        print("✗ Error: Tampered tag was accepted!")
    except ValueError:
        print("✓ Success: Tampered tag rejected correctly!")

    print("=" * 60)


if __name__ == "__main__":
    demo_ascon()

