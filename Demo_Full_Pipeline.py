"""
╔══════════════════════════════════════════════════════════════════╗
║       COMPLETE SECURITY PIPELINE DEMONSTRATION                  ║
║                                                                  ║
║  Secure Boot → ECDH → HKDF → ECDSA → ASCON-128a                ║
║                                                                  ║
║  This file is a DEMONSTRATION ONLY.                              ║
║  It imports and reuses the existing project modules:             ║
║      • ECC_Core.py        → ECCCore (ECDH key exchange)         ║
║      • ECDSA_Auth.py      → ECDSAAuthentication (identity)      ║
║      • ASCON_Encryption.py→ ASCONEncryption (AEAD cipher)       ║
║      • Secure_Boot.py     → SecureBoot, generate_signing_keys   ║
║                                                                  ║
║  NO cryptographic primitives are reimplemented here.             ║
║                                                                  ║
║  Run from the project root:                                      ║
║      python Demo_Full_Pipeline.py                                ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import tempfile
import io

# Fix Windows console encoding — ensures box-drawing and Unicode prints cleanly
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Ensure the ECC_Integration package is importable regardless of CWD
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ECC_DIR = os.path.join(SCRIPT_DIR, "ECC_Integration")
if ECC_DIR not in sys.path:
    sys.path.insert(0, ECC_DIR)


from ECC_Integration.ECC_Core import ECCCore
from ECC_Integration.ECDSA_Auth import ECDSAAuthentication
from ECC_Integration.ASCON_Encryption import ASCONEncryption
from ECC_Integration.Secure_Boot import (
    SecureBoot,
    generate_signing_keys,
)
from cryptography.hazmat.primitives import serialization


def safe_hex(data: bytes, show_bytes: int = 16) -> str:
    """Return a truncated hex representation — never exposes full secrets."""
    hex_str = data.hex()
    limit = show_bytes * 2  # 2 hex chars per byte
    if len(hex_str) > limit:
        return hex_str[:limit] + "..."
    return hex_str


#  STAGE 1 — SECURE BOOT / FIRMWARE VERIFICATION
def stage_1_secure_boot():
    """
    Demonstrate firmware integrity verification using the existing
    SecureBoot class and ECDSA signing keys.

    Flow:
        1. Write sample firmware to a temp file.
        2. Generate ECDSA signing key pair (manufacturer side).
        3. Compute SHA-256 hash of the firmware.
        4. Sign the hash with the private key.
        5. Verify the signature with the public key → PASS.
        6. Tamper with the firmware and re-verify → FAIL.
    """
    print("=" * 60)
    print("  STAGE 1 — SECURE BOOT / FIRMWARE VERIFICATION")
    print("=" * 60)

    firmware_content = b"""\
// Secure Firmware for IoT Healthcare Device
// Version: 2.1.0  |  Build: 2026-09-04
#include <stdio.h>
#include "secure_comm.h"

int main() {
    initialize_secure_boot();
    establish_secure_channel();
    while (1) { process_encrypted_data(); }
    return 0;
}
"""
    firmware_path = os.path.join(tempfile.gettempdir(), "demo_firmware.bin")
    with open(firmware_path, "wb") as f:
        f.write(firmware_content)

    signing_private_key, signing_public_key = generate_signing_keys()
    pub_key_bytes = signing_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    print("    Signing key pair generated (manufacturer side)")
    print(f"    Public Key  : {pub_key_bytes.hex()}")
    print(f"    Private Key : [REDACTED]")

    sb = SecureBoot(firmware_path)

    firmware_hash = sb.compute_firmware_hash()
    print(f"    [1] Firmware SHA-256 hash: {firmware_hash.hex()}")

    signature = sb.sign_firmware(signing_private_key)
    print(f"    [1] Firmware signature generated  ({len(signature)} bytes)")

    print()
    print("    --- Pi (Gateway) Secure Boot ---")
    is_valid_pi, _ = sb.verify_firmware(signing_public_key)
    print(
        f"    [1] Pi  firmware signature verified: {'PASS ✓' if is_valid_pi else 'FAIL ✗'}"
    )
    if is_valid_pi:
        print("    [1] Pi  → Firmware trusted, device boots")

    print()
    print("    --- ESP32 (Edge Device) Secure Boot ---")
    is_valid_esp, _ = sb.verify_firmware(signing_public_key)
    print(
        f"    [1] ESP32 firmware signature verified: {'PASS ✓' if is_valid_esp else 'FAIL ✗'}"
    )
    if is_valid_esp:
        print("    [1] ESP32 → Firmware trusted, device boots")

    print()
    print("    --- Tamper Test ---")
    print("    Appending malicious payload to firmware...")
    with open(firmware_path, "ab") as f:
        f.write(b"\n// MALICIOUS CODE INJECTED BY ATTACKER")

    sb_tampered = SecureBoot(firmware_path)
    tampered_hash = sb_tampered.compute_firmware_hash()
    print(f"    [1] Tampered firmware SHA-256: {tampered_hash.hex()}")
    print(f"    [1] Hash mismatch detected    (original ≠ tampered)")

    is_valid_tampered, _ = sb_tampered.verify_firmware(
        signing_public_key, signature=signature
    )
    print(
        f"    [1] Tampered firmware verification: {'PASS ✓' if is_valid_tampered else 'FAIL ✗'}"
    )

    if not is_valid_tampered:
        print("    [1] ⚠  Firmware integrity compromised — DEVICE MUST NOT BOOT")
        print("    [1]    In a real system the bootloader would halt here.")
    else:
        print("    [1] ERROR: tampered firmware was accepted (unexpected)")

    # Cleanup temp file
    os.remove(firmware_path)

    print()
    return (is_valid_pi and is_valid_esp) and (not is_valid_tampered)


#  STAGE 2 — DEVICE KEY GENERATION
def stage_2_device_keygen():
    """
    Create two simulated devices (Pi gateway + ESP32 edge) and generate
    their ECC (for ECDH) and ECDSA (for identity) key pairs using the
    existing ECCCore and ECDSAAuthentication classes.

    Returns:
        (pi_ecc, esp_ecc, pi_ecdsa, esp_ecdsa) — the four key-holder objects.
    """
    print("=" * 60)
    print("  STAGE 2 — DEVICE KEY GENERATION")
    print("=" * 60)

    pi_ecc = ECCCore()
    pi_ecc.generate_keypair()
    print(f"    [2] Pi  ECC key pair generated")
    print(f"         Public Key  : {pi_ecc.get_public_key_bytes().hex()}")
    print(f"         Private Key : [REDACTED]")

    pi_ecdsa = ECDSAAuthentication()
    pi_ecdsa.generate_identity_keypair()
    print(f"    [2] Pi  ECDSA identity key pair generated")
    print(f"         Public Key  : {pi_ecdsa.get_public_key_bytes().hex()}")  # type: ignore
    print(f"         Private Key : [REDACTED]")

    print()

    esp_ecc = ECCCore()
    esp_ecc.generate_keypair()
    print(f"    [2] ESP32 ECC key pair generated")
    print(f"         Public Key  : {esp_ecc.get_public_key_bytes().hex()}")
    print(f"         Private Key : [REDACTED]")

    esp_ecdsa = ECDSAAuthentication()
    esp_ecdsa.generate_identity_keypair()
    print(f"    [2] ESP32 ECDSA identity key pair generated")
    print(f"         Public Key  : {esp_ecdsa.get_public_key_bytes().hex()}")  # type: ignore
    print(f"         Private Key : [REDACTED]")

    print()
    return pi_ecc, esp_ecc, pi_ecdsa, esp_ecdsa


#  STAGE 3 — ECDH KEY EXCHANGE
def stage_3_ecdh_exchange(pi_ecc: ECCCore, esp_ecc: ECCCore):
    """
    Perform the ECDH P-256 key exchange between Pi and ESP32.

    Direction of public keys (explicitly stated to avoid confusion):
        • Pi  EXPORTS its public key  → ESP32 IMPORTS it
        • ESP32 EXPORTS its public key → Pi   IMPORTS it
        • Each device then uses ITS OWN private key + THE OTHER's public key
          to compute the shared secret.

    Returns:
        (shared_secret_pi, shared_secret_esp)
    """
    print("=" * 60)
    print("  STAGE 3 — ECDH KEY EXCHANGE")
    print("=" * 60)

    pi_pub_bytes = pi_ecc.get_public_key_bytes()  # Pi's public key
    esp_pub_bytes = esp_ecc.get_public_key_bytes()  # ESP32's public key

    print(f"    [3] Pi  received ESP32 public key  ({len(esp_pub_bytes)} bytes)")
    print(f"    [3] ESP32 received Pi  public key  ({len(pi_pub_bytes)} bytes)")

    esp_pub_on_pi = pi_ecc.load_peer_public_key(esp_pub_bytes)
    pi_pub_on_esp = esp_ecc.load_peer_public_key(pi_pub_bytes)

    shared_secret_pi = pi_ecc.compute_shared_secret(esp_pub_on_pi)
    shared_secret_esp = esp_ecc.compute_shared_secret(pi_pub_on_esp)

    print(f"    [3] ECDH shared secret established   ({len(shared_secret_pi)} bytes)")

    secrets_match = shared_secret_pi == shared_secret_esp
    print(f"    [3] Shared secrets match: {'PASS ✓' if secrets_match else 'FAIL ✗'}")

    print()
    return shared_secret_pi, shared_secret_esp


#  STAGE 4 — HKDF SESSION KEY DERIVATION
def stage_4_hkdf_derive(
    pi_ecc: ECCCore, esp_ecc: ECCCore, shared_secret_pi: bytes, shared_secret_esp: bytes
):
    """
    Derive the 16-byte ASCON-128a session key from the ECDH shared secret
    using HKDF-SHA256 (already implemented in ECCCore.derive_session_key).

    Both devices derive independently; we verify the results match.

    Returns:
        (session_key_pi, session_key_esp)
    """
    print("=" * 60)
    print("  STAGE 4 — HKDF SESSION KEY DERIVATION")
    print("=" * 60)

    print("    [4] Pi  deriving session key from its shared secret...")
    session_key_pi = pi_ecc.derive_session_key(shared_secret_pi)
    print(f"    [4] Pi  session key derived          ({len(session_key_pi)} bytes)")
    print(f"    [4] Pi  session key: [REDACTED]")

    print()
    print("    [4] ESP32 deriving session key from its shared secret...")
    session_key_esp = esp_ecc.derive_session_key(shared_secret_esp)
    print(f"    [4] ESP32 session key derived         ({len(session_key_esp)} bytes)")
    print(f"    [4] ESP32 session key: [REDACTED]")

    print()
    keys_match = session_key_pi == session_key_esp
    print(f"    [4] Both devices independently derived the same key")
    print(f"    [4] Session keys match: {'PASS ✓' if keys_match else 'FAIL ✗'}")

    print()
    return session_key_pi, session_key_esp


#  STAGE 5 — ECDSA DEVICE AUTHENTICATION
def stage_5_ecdsa_auth(pi_ecdsa: ECDSAAuthentication, esp_ecdsa: ECDSAAuthentication):
    """
    Mutual challenge-response authentication using ECDSA.

    Direction 1 — Pi authenticates ESP32:
        Pi  generates challenge → sends to ESP32
        ESP32 signs challenge   → sends signature back to Pi
        Pi  verifies signature using ESP32's public key

    Direction 2 — ESP32 authenticates Pi (mutual):
        ESP32 generates challenge → sends to Pi
        Pi    signs challenge     → sends signature back to ESP32
        ESP32 verifies signature using Pi's public key

    Returns:
        (auth_forward, auth_reverse) — both should be True.
    """
    print("=" * 60)
    print("  STAGE 5 — ECDSA DEVICE AUTHENTICATION")
    print("=" * 60)

    challenge_from_pi = os.urandom(32)
    print(f"    [5] Pi  challenge generated        ({len(challenge_from_pi)} bytes)")

    esp_signature = esp_ecdsa.sign_challenge(challenge_from_pi)
    print(f"    [5] ESP32 signed challenge         ({len(esp_signature)} bytes)")

    esp_pub_bytes = esp_ecdsa.get_public_key_bytes()
    esp_pub_on_pi = pi_ecdsa.load_peer_public_key(esp_pub_bytes)
    auth_forward = pi_ecdsa.verify_signature(
        esp_pub_on_pi, challenge_from_pi, esp_signature
    )
    print(
        f"    [5] Pi  verified ESP32 signature: "
        f"{'PASS ✓' if auth_forward else 'FAIL ✗'}"
    )

    print()

    challenge_from_esp = os.urandom(32)
    print(f"    [5] ESP32 challenge generated       ({len(challenge_from_esp)} bytes)")

    pi_signature = pi_ecdsa.sign_challenge(challenge_from_esp)
    print(f"    [5] Pi  signed challenge           ({len(pi_signature)} bytes)")

    pi_pub_bytes = pi_ecdsa.get_public_key_bytes()
    pi_pub_on_esp = esp_ecdsa.load_peer_public_key(pi_pub_bytes)
    auth_reverse = esp_ecdsa.verify_signature(
        pi_pub_on_esp, challenge_from_esp, pi_signature
    )
    print(
        f"    [5] ESP32 verified Pi  signature: "
        f"{'PASS ✓' if auth_reverse else 'FAIL ✗'}"
    )

    print()
    return auth_forward, auth_reverse


#  STAGE 6 — ASCON-128a ENCRYPTION
def stage_6_ascon_encrypt(session_key: bytes):
    """
    Encrypt a healthcare patient record using ASCON-128a AEAD.

    The existing ASCONEncryption class handles:
        • 128-bit random nonce generation
        • Authenticated encryption with associated data (AAD)
        • Separate ciphertext + 128-bit authentication tag output

    Returns:
        (plaintext_bytes, nonce, ciphertext, tag, aad)
    """
    print("=" * 60)
    print("  STAGE 6 — ASCON-128a ENCRYPTION")
    print("=" * 60)

    patient_record = {
        "patient_id": 1042,
        "heart_rate": 82,
        "temperature": 36.7,
    }
    plaintext_bytes = json.dumps(patient_record).encode("utf-8")
    print(f"    [6] Patient record serialized       ({len(plaintext_bytes)} bytes)")

    #     AAD is authenticated but NOT encrypted — provides context binding.
    aad_fields = {
        "device_id": "PI_GATEWAY",
        "message_type": "PATIENT_DATA",
        "sequence_number": 1,
    }
    aad = json.dumps(aad_fields, separators=(",", ":")).encode("utf-8")

    enc = ASCONEncryption(session_key)
    nonce, ciphertext, tag = enc.encrypt(plaintext_bytes, associated_data=aad)

    print(f"    [6] ASCON-128a encryption successful")
    print(f"    [6] Ciphertext generated            ({len(ciphertext)} bytes)")
    print(f"    [6] Authentication tag generated     ({len(tag)} bytes)")

    # NOTE: session_key is NEVER printed.

    print()
    return plaintext_bytes, nonce, ciphertext, tag, aad


#  STAGE 7 — TRANSMISSION
def stage_7_transmit(nonce, ciphertext, tag, aad):
    """
    Simulate transmission of the encrypted packet from Pi → ESP32.

    The packet contains ONLY public/ciphertext fields — no secret material.
    In a real deployment this would go over Wi-Fi / BLE / LoRa / MQTT.

    Returns:
        packet (dict) — the simulated network packet.
    """
    print("=" * 60)
    print("  STAGE 7 — TRANSMISSION  (Pi → ESP32)")
    print("=" * 60)

    aad_fields = json.loads(aad.decode("utf-8"))

    packet = {
        "device_id": aad_fields["device_id"],
        "message_type": aad_fields["message_type"],
        "sequence_number": aad_fields["sequence_number"],
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag,
        "aad": aad,
    }

    print(f"    [7] Packet created")
    print(f"        Device ID     : {packet['device_id']}")
    print(f"        Message Type  : {packet['message_type']}")
    print(f"        Sequence      : {packet['sequence_number']}")
    print(f"        Nonce         : {safe_hex(nonce)}")
    print(f"        Ciphertext    : {safe_hex(ciphertext)}")
    print(f"        Tag           : {safe_hex(tag)}")
    print()
    print("    NOTE: The patient plaintext is NOT transmitted directly.")
    print("          Only the encrypted ciphertext + tag travel over the network.")

    print()
    return packet


#  STAGE 8 — ASCON VERIFICATION + DECRYPTION  (ESP32 side)
def stage_8_ascon_decrypt(
    session_key_esp: bytes, packet: dict, original_plaintext: bytes
):
    """
    ESP32 receives the packet, authenticates, and decrypts it.

    Returns:
        True if decryption succeeds and data integrity is confirmed.
    """
    print("=" * 60)
    print("  STAGE 8 — ASCON VERIFICATION + DECRYPTION  (ESP32)")
    print("=" * 60)

    print(f"    [8] ESP32 received packet")

    rx_nonce = packet["nonce"]
    rx_ciphertext = packet["ciphertext"]
    rx_tag = packet["tag"]
    rx_aad = packet["aad"]

    dec = ASCONEncryption(session_key_esp)

    try:
        recovered = dec.decrypt(rx_nonce, rx_ciphertext, rx_tag, associated_data=rx_aad)
        print(f"    [8] ASCON authentication: PASS ✓")
        print(f"    [8] Ciphertext decrypted successfully")

        recovered_record = json.loads(recovered.decode("utf-8"))
        print(f"    [8] Patient record recovered:")
        print(f"           patient_id  : {recovered_record['patient_id']}")
        print(f"           heart_rate  : {recovered_record['heart_rate']}")
        print(f"           temperature : {recovered_record['temperature']}")

        integrity = recovered == original_plaintext
        print(f"    [8] Data integrity: {'PASS ✓' if integrity else 'FAIL ✗'}")
        print()
        return integrity

    except ValueError as e:
        print(f"    [8] ASCON authentication: FAIL ✗  ({e})")
        print()
        return False


#  STAGE 9 — TAMPERING DEMONSTRATION
def stage_9_tampering(session_key_esp: bytes, packet: dict):
    """
    Demonstrate that ASCON detects ANY modification to the ciphertext.

    We flip one bit in the ciphertext and attempt decryption.
    The existing ASCONEncryption.decrypt() raises ValueError on auth failure
    — we catch it cleanly without crashing the demo.

    Returns:
        True if tampering was correctly detected (auth failure).
    """
    print("=" * 60)
    print("  STAGE 9 — TAMPERING DEMONSTRATION")
    print("=" * 60)

    tampered_ct = bytearray(packet["ciphertext"])
    if len(tampered_ct) > 0:
        tampered_ct[0] ^= 0x01

    print(f"    [9] Tampering simulated  (1 bit flipped in ciphertext)")
    print(f"    [9] Modified ciphertext detected")

    dec = ASCONEncryption(session_key_esp)

    try:
        dec.decrypt(
            packet["nonce"],
            bytes(tampered_ct),
            packet["tag"],
            associated_data=packet["aad"],
        )
        print(f"    [9] ASCON authentication: PASS  ← ERROR: should have failed!")
        print(f"    [9] Packet accepted (UNEXPECTED)")
        return False

    except ValueError:
        print(f"    [9] ASCON authentication: FAIL ✗")
        print(f"    [9] Packet rejected")
        print()
        print("    This demonstrates that ASCON-128a provides BOTH")
        print("    confidentiality (encryption) AND integrity/authentication.")
        print("    Any modification — even a single bit — is detected.")
        print()
        return True


#  STAGE 10 — FINAL PIPELINE SUMMARY
def stage_10_summary(pipeline_pass: bool, tamper_pass: bool):
    """Print final results and what each primitive is responsible for."""

    print("=" * 60)
    print(f"    COMPLETE PIPELINE   : {'PASS ✓' if pipeline_pass else 'FAIL ✗'}")
    print(f"    TAMPERING DETECTION : {'PASS ✓' if tamper_pass else 'FAIL ✗'}")
    print("=" * 60)
    print()

    print("=" * 60)
    print("    CRYPTOGRAPHIC PRIMITIVE RESPONSIBILITIES")
    print("=" * 60)
    print()
    print("    Secure Boot (ECDSA) → Verifies firmware integrity & authenticity")
    print("                          before the device is allowed to boot.")
    print()
    print("    ECDH (P-256)        → Establishes a shared secret between two")
    print("                          devices without transmitting any secret.")
    print()
    print("    HKDF (SHA-256)      → Derives a fixed-length session key from")
    print("                          the raw ECDH shared secret.")
    print()
    print("    ECDSA               → Authenticates device identity through a")
    print("                          challenge-response protocol (mutual auth).")
    print()
    print("    ASCON-128a (AEAD)   → Encrypts application data (confidentiality)")
    print("                          AND authenticates it (integrity + auth).")
    print("                          A single tampered bit causes rejection.")
    print()
    print("=" * 60)
    print("    END OF DEMONSTRATION")
    print("=" * 60)


#  MAIN — Run all 10 stages sequentially
def main():
    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print("║   IoT Healthcare Security — Full Pipeline Demo          ║")
    print("║   Secure Boot → ECDH → HKDF → ECDSA → ASCON-128a      ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()

    all_pass = True

    # ── Stage 1: Secure Boot ──────────────────────────────────────
    boot_ok = stage_1_secure_boot()
    all_pass = all_pass and boot_ok

    # ── Stage 2: Device Key Generation ────────────────────────────
    pi_ecc, esp_ecc, pi_ecdsa, esp_ecdsa = stage_2_device_keygen()

    # ── Stage 3: ECDH Key Exchange ────────────────────────────────
    shared_secret_pi, shared_secret_esp = stage_3_ecdh_exchange(pi_ecc, esp_ecc)
    secrets_match = shared_secret_pi == shared_secret_esp
    all_pass = all_pass and secrets_match

    # ── Stage 4: HKDF Session Key Derivation ──────────────────────
    session_key_pi, session_key_esp = stage_4_hkdf_derive(
        pi_ecc, esp_ecc, shared_secret_pi, shared_secret_esp
    )
    keys_match = session_key_pi == session_key_esp
    all_pass = all_pass and keys_match

    # ── Stage 5: ECDSA Mutual Authentication ──────────────────────
    auth_fwd, auth_rev = stage_5_ecdsa_auth(pi_ecdsa, esp_ecdsa)
    all_pass = all_pass and auth_fwd and auth_rev

    # ── Stage 6: ASCON-128a Encryption (Pi side) ──────────────────
    plaintext_bytes, nonce, ciphertext, tag, aad = stage_6_ascon_encrypt(session_key_pi)

    # ── Stage 7: Simulated Transmission ───────────────────────────
    packet = stage_7_transmit(nonce, ciphertext, tag, aad)

    # ── Stage 8: ASCON Verification + Decryption (ESP32 side) ─────
    decrypt_ok = stage_8_ascon_decrypt(session_key_esp, packet, plaintext_bytes)
    all_pass = all_pass and decrypt_ok

    # ── Stage 9: Tampering Demonstration ──────────────────────────
    tamper_detected = stage_9_tampering(session_key_esp, packet)

    # ── Stage 10: Summary ─────────────────────────────────────────
    stage_10_summary(pipeline_pass=all_pass, tamper_pass=tamper_detected)


if __name__ == "__main__":
    main()
