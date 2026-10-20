"""
ASCON-128a Module - Authenticated Encryption with Associated Data (AEAD)

Replaces AES-256-GCM with the ASCON-128a lightweight AEAD cipher.
ASCON is the NIST Lightweight Cryptography Standard (NIST SP 800-232);
this module implements the Ascon v1.2 Ascon-128a parameter set
(IV = 0x80800c0800000000), matching the ascon-c reference implementation.

Key size:   128-bit (16 bytes)
Nonce size: 128-bit (16 bytes)
Tag size:   128-bit (16 bytes)

This module is used by the Raspberry Pi deployment.

The cipher is implemented here in pure Python (standard library only) so the
project has no third-party dependency on an `ascon` package.  The 320-bit
state is held as five 64-bit words and serialized big-endian, exactly as
ascon-c's LOADBYTES/STOREBYTES do.

Reference: NIST SP 800-232 / Ascon v1.2 (github.com/ascon/ascon-c, branch v1.2,
crypto_aead/ascon128av12).  Known-answer vectors in Validation/Test_ASCON.py
are taken from that repository's LWC_AEAD_KAT_128_128.txt.
"""

from __future__ import annotations

import hmac
import os

# --------------------------------------------------------------------------
# Algorithm parameters (Ascon-128a)
# --------------------------------------------------------------------------

_MASK64 = (1 << 64) - 1

_RATE = 16        # r = 128 bits, the rate in bytes
_A_ROUNDS = 12    # a = 12 rounds for initialization and finalization
_B_ROUNDS = 8     # b = 8 rounds for each absorbed/squeezed block

# IV for Ascon-128a: ASCON_128A_IV = 0x80800c0800000000
_IV = 0x80800C0800000000

# Round constants RC0..RCb.  p^12 uses RC0..RCb; p^8 uses the LAST 8 of them,
# i.e. RC4..RCb (0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b).
_ROUND_CONSTANTS = (
    0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5,
    0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B,
)


# --------------------------------------------------------------------------
# Permutation
# --------------------------------------------------------------------------

def _rotr64(value: int, shift: int) -> int:
    """Rotate a 64-bit word right by `shift` bits."""
    return ((value >> shift) | (value << (64 - shift))) & _MASK64


def _round(state: list[int], constant: int) -> None:
    """
    One ASCON round, applied in place to the five 64-bit state words.

    The round is: constant addition, the 5-bit S-box (bitsliced across the
    five words), then the linear diffusion layer.
    """
    x0, x1, x2, x3, x4 = state

    # --- constant addition ------------------------------------------------
    x2 ^= constant

    # --- substitution layer (bitsliced S-box) -----------------------------
    x0 ^= x4
    x4 ^= x3
    x2 ^= x1

    t0 = ~x0 & x1
    t1 = ~x1 & x2
    t2 = ~x2 & x3
    t3 = ~x3 & x4
    t4 = ~x4 & x0

    x0 ^= t1
    x1 ^= t2
    x2 ^= t3
    x3 ^= t4
    x4 ^= t0

    x1 ^= x0
    x0 ^= x4
    x3 ^= x2
    x2 = ~x2 & _MASK64

    # --- linear diffusion layer -------------------------------------------
    # Sigma_i(x) = x ^ ROTR(x, r1) ^ ROTR(x, r2)
    x0 ^= _rotr64(x0, 19) ^ _rotr64(x0, 28)
    x1 ^= _rotr64(x1, 61) ^ _rotr64(x1, 39)
    x2 ^= _rotr64(x2, 1) ^ _rotr64(x2, 6)
    x3 ^= _rotr64(x3, 10) ^ _rotr64(x3, 17)
    x4 ^= _rotr64(x4, 7) ^ _rotr64(x4, 41)

    state[0], state[1], state[2], state[3], state[4] = x0, x1, x2, x3, x4


def _permute(state: list[int], rounds: int) -> None:
    """
    Apply p^rounds in place.  p^12 uses RC0..RCb; p^8 uses the last 8
    constants RC4..RCb (never RC0..RC7).
    """
    for constant in _ROUND_CONSTANTS[len(_ROUND_CONSTANTS) - rounds:]:
        _round(state, constant)


# --------------------------------------------------------------------------
# State (de)serialization helpers
# --------------------------------------------------------------------------

def _state_from_bytes(data: bytes) -> list[int]:
    """Deserialize 40 big-endian bytes into five 64-bit words."""
    return [int.from_bytes(data[i * 8:(i + 1) * 8], "big") for i in range(5)]


def _words_to_bytes(high: int, low: int) -> bytes:
    """Serialize two 64-bit words (a full rate block) big-endian."""
    return high.to_bytes(8, "big") + low.to_bytes(8, "big")


def _pad(data: bytes) -> bytes:
    """Pad with a single 1 bit (0x80) then zeros to a multiple of the rate."""
    return data + b"\x80" + b"\x00" * ((-len(data) - 1) % _RATE)


# --------------------------------------------------------------------------
# Core AEAD operations
# --------------------------------------------------------------------------

def _initialize(key: bytes, nonce: bytes) -> list[int]:
    """
    Initialization: S = IV || K || N; S = p^12(S); S = S XOR (0^192 || K).
    """
    state = _state_from_bytes(_IV.to_bytes(8, "big") + key + nonce)
    _permute(state, _A_ROUNDS)
    state[3] ^= int.from_bytes(key[0:8], "big")
    state[4] ^= int.from_bytes(key[8:16], "big")
    return state


def _absorb_associated_data(state: list[int], associated_data: bytes) -> None:
    """
    Absorb the associated data, then apply domain separation.

    AD is padded with 1 || 0* to a multiple of the rate and each block is
    absorbed with a p^8 in between.  Empty AD contributes no blocks but the
    domain separation bit is still applied.
    """
    if associated_data:
        padded = _pad(associated_data)
        for offset in range(0, len(padded), _RATE):
            block = padded[offset:offset + _RATE]
            state[0] ^= int.from_bytes(block[0:8], "big")
            state[1] ^= int.from_bytes(block[8:16], "big")
            _permute(state, _B_ROUNDS)

    # Domain separation: S = S XOR (0^319 || 1)
    state[4] ^= 0x01


def _finalize(state: list[int], key: bytes) -> bytes:
    """
    Finalization: S = S XOR (0^128 || K || 0^64); S = p^12(S);
    S = S XOR (0^192 || K); tag = last 128 bits of S.
    """
    key_high = int.from_bytes(key[0:8], "big")
    key_low = int.from_bytes(key[8:16], "big")

    state[2] ^= key_high
    state[3] ^= key_low
    _permute(state, _A_ROUNDS)
    state[3] ^= key_high
    state[4] ^= key_low

    # The tag is the final 128 bits of the state, i.e. words x3 and x4.
    return _words_to_bytes(state[3], state[4])


def _encrypt(key: bytes, nonce: bytes, associated_data: bytes,
             plaintext: bytes) -> tuple[bytes, bytes]:
    """Raw Ascon-128a encryption; returns (ciphertext, tag)."""
    state = _initialize(key, nonce)
    _absorb_associated_data(state, associated_data)

    # Pad the plaintext and process every block.  Every block except the last
    # is followed by p^8; the final block is NOT followed by a permutation.
    padded = _pad(plaintext)
    block_count = len(padded) // _RATE

    out = bytearray()
    for index in range(block_count):
        block = padded[index * _RATE:(index + 1) * _RATE]
        word_high = state[0] ^ int.from_bytes(block[0:8], "big")
        word_low = state[1] ^ int.from_bytes(block[8:16], "big")
        state[0], state[1] = word_high, word_low
        out += _words_to_bytes(word_high, word_low)
        if index != block_count - 1:
            _permute(state, _B_ROUNDS)

    # The encrypted padding bytes are dropped from the returned ciphertext.
    return bytes(out[:len(plaintext)]), _finalize(state, key)


def _decrypt(key: bytes, nonce: bytes, associated_data: bytes,
             ciphertext: bytes) -> tuple[bytes, bytes]:
    """
    Raw Ascon-128a decryption; returns (plaintext, computed_tag).

    The caller must compare the computed tag against the expected one.
    """
    state = _initialize(key, nonce)
    _absorb_associated_data(state, associated_data)

    # Padding adds at least one byte, so the padded plaintext always has one
    # more block than the ciphertext has whole blocks.
    block_count = len(ciphertext) // _RATE + 1

    out = bytearray()
    for index in range(block_count):
        start = index * _RATE
        last = index == block_count - 1

        if last:
            remainder = ciphertext[start:]
            transmitted = len(remainder)
            block = remainder + b"\x80" + b"\x00" * (_RATE - transmitted - 1)
        else:
            block = ciphertext[start:start + _RATE]

        word_high = state[0] ^ int.from_bytes(block[0:8], "big")
        word_low = state[1] ^ int.from_bytes(block[8:16], "big")
        plain_block = _words_to_bytes(word_high, word_low)
        out += plain_block

        if last:
            # Rebuild the final rate from the padded plaintext block, which is
            # the mirror of encryption: the state rate becomes
            # S_r XOR (P_last || 1 || 0*) == C_last.  No permutation follows.
            padded_plain = (plain_block[:transmitted] + b"\x80"
                            + b"\x00" * (_RATE - transmitted - 1))
            state[0] ^= int.from_bytes(padded_plain[0:8], "big")
            state[1] ^= int.from_bytes(padded_plain[8:16], "big")
        else:
            # The rate becomes the ciphertext block, then p^8.
            state[0] = int.from_bytes(block[0:8], "big")
            state[1] = int.from_bytes(block[8:16], "big")
            _permute(state, _B_ROUNDS)

    return bytes(out[:len(ciphertext)]), _finalize(state, key)


class ASCONEncryption:
    """ASCON-128a authenticated encryption/decryption with integrity verification"""

    VARIANT = "Ascon-128a"
    KEY_SIZE = 16    # 128-bit key
    NONCE_SIZE = 16  # 128-bit nonce
    TAG_SIZE = 16    # 128-bit authentication tag

    def __init__(self, session_key: bytes) -> None:
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

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"",
                nonce: bytes | None = None) -> tuple[bytes, bytes, bytes]:
        """
        Step 10: Encrypt message M using ASCON-128a AEAD.

        Args:
            plaintext:       bytes to encrypt.
            associated_data: optional AAD authenticated but not encrypted.
            nonce:           16-byte nonce (generated randomly if None).

        Returns:
            (nonce, ciphertext, tag) - the ciphertext excludes the tag.

        Raises:
            ValueError: If the nonce is not exactly 16 bytes.
        """
        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE)

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(
                f"Nonce must be {self.NONCE_SIZE} bytes, got {len(nonce)} bytes"
            )

        ciphertext, tag = _encrypt(
            self.session_key, nonce, associated_data, plaintext
        )
        return nonce, ciphertext, tag

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes,
                associated_data: bytes = b"") -> bytes:
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
            ValueError: If a length is wrong, or if integrity verification
                        fails (tampered data, wrong key, wrong nonce, or
                        wrong associated data).
        """
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(
                f"Nonce must be {self.NONCE_SIZE} bytes, got {len(nonce)} bytes"
            )
        if len(tag) != self.TAG_SIZE:
            raise ValueError(
                f"Tag must be {self.TAG_SIZE} bytes, got {len(tag)} bytes"
            )

        plaintext, computed_tag = _decrypt(
            self.session_key, nonce, associated_data, ciphertext
        )

        # Constant-time comparison so a forged tag cannot be found byte by byte.
        if not hmac.compare_digest(computed_tag, tag):
            raise ValueError(
                "ASCON integrity verification failed: "
                "ciphertext, tag, key, nonce, or associated data is invalid"
            )

        return plaintext

    def send_encrypted_message(self, message: str,
                               recipient_public_key=None) -> tuple[bytes, bytes, bytes]:
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
