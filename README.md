# Embedded Systems VIT-26

A lightweight secure embedded communication framework built around ECC-based key establishment, firmware authentication, and ASCON-128a authenticated encryption. The project demonstrates how two devices can establish a secure session, authenticate each other, and exchange encrypted data while preserving integrity and freshness protections.

## Overview

This repository implements a dual-node secure embedded prototype using:

- ECDH for shared secret establishment
- HKDF-SHA256 for session key derivation
- ECDSA for device authentication and firmware signing
- ASCON-128a for authenticated encryption
- Secure boot verification using firmware hashing and signature validation

The current implementation targets a Raspberry Pi / Python prototype and includes ESP32 and Arduino-related components for porting and integration work. The cryptographic design is centered on the newer ASCON workflow rather than the older AES-GCM description used in the earlier project draft.

---

## Why This Project Exists

Embedded and IoT systems often operate in resource-constrained environments where traditional public-key cryptography and heavy authenticated encryption can be too costly. This project focuses on a practical secure-by-design model for devices such as:

- industrial sensors
- healthcare gateways
- low-power edge nodes
- secure boot-enabled microcontrollers

The design balances security, compatibility, and implementation simplicity while remaining suitable for prototype research and educational demonstrations.

---

## Security Pipeline

The implemented flow is:

1. Firmware is hashed and signed during secure boot
2. Device identities are generated using ECDSA
3. Nodes exchange ECDH public keys
4. Shared secret is computed
5. HKDF derives a 128-bit session key
6. ASCON-128a encrypts and authenticates payloads
7. Peer authentication validates challenge-response signatures
8. Sensitive state is cleared when the session ends

Operationally, the flow is:

Power on → Secure Boot → ECDH exchange → HKDF derivation → ECDSA authentication → ASCON-128a encryption → secure transmission → verification and decryption

---

## Core Technologies

| Category                 | Technology / Implementation | Role                                                |
| ------------------------ | --------------------------- | --------------------------------------------------- |
| Key exchange             | ECC (secp256r1 / P-256)     | ECDH shared secret generation                       |
| Session key derivation   | HKDF-SHA256                 | Derives 128-bit ASCON key                           |
| Identity and signing     | ECDSA                       | Device challenge-response and firmware verification |
| Authenticated encryption | ASCON-128a                  | Encrypts and authenticates communication payloads   |
| Secure boot              | SHA-256 + ECDSA signature   | Validates firmware integrity                        |
| Runtime environment      | Python 3.x                  | Raspberry Pi prototype and validation               |
| Embedded target          | ESP32 / Arduino             | Porting and device-side integration                 |

---

## Repository Structure

```text
Embedded_Systems_VIT-26/
├── README.md
├── Demo_Full_Pipeline.py
├── LICENSE
├── secure_log_NODE_A.txt
├── secure_log_NODE_B.txt
├── ECC_Integration/
│   ├── ECC_Core.py
│   ├── ECDSA_Auth.py
│   ├── ASCON_Encryption.py
│   ├── Secure_Boot.py
│   ├── Secure_Communication.py
│   ├── Main.py
│   └── AES_GCM_Encryption.py
├── Arduino_Section/
│   └── ECC_Arduino.ino
├── ESP_32_Config/
│   ├── ESP32_Main.bash
│   ├── SetUp_ESP(32).bash
│   ├── Make_Lists.txt
│   └── SDKConfig.txt
├── Validation/
│   └── Test_Crypto.py
├── Project_Archieves/
└── Project Structure
```

---

## Project Modules

### 1. ECC Core

File: `ECC_Integration/ECC_Core.py`

Implements:

- ECC key pair generation
- ECDH shared secret computation
- HKDF-derived session key generation
- secure memory cleanup routine

This module is the foundation for node-to-node secure session establishment.

### 2. ECDSA Authentication

File: `ECC_Integration/ECDSA_Auth.py`

Implements:

- ECDSA key generation for device identity
- challenge-response signing
- signature verification against peer public keys

This supports mutual authentication between nodes before encrypted communication begins.

### 3. ASCON Encryption

File: `ECC_Integration/ASCON_Encryption.py`

Implements the ASCON-128a AEAD layer.

Key properties:

- 128-bit session key
- 128-bit nonce
- 128-bit authentication tag
- integrity and authenticity checks during decryption
- rejects tampering with ciphertext, tag, or associated data

This is the current preferred authenticated encryption mechanism in the project and replaces the earlier AES-GCM-centric flow in the original documentation.

### 4. Secure Boot

File: `ECC_Integration/Secure_Boot.py`

Implements:

- firmware hashing
- ECDSA signing of firmware hash
- public-key verification of signed firmware
- tamper detection when firmware changes

This models secure boot verification before a device is trusted to run software.

### 5. Secure Communication Pipeline

File: `ECC_Integration/Secure_Communication.py`

Combines:

- ECDH exchange
- HKDF derivation
- ECDSA peer authentication
- ASCON message encryption and decryption

This is the end-to-end secure communication layer used to simulate a protected session between two nodes.

### 6. Full Demo Runner

File: `Demo_Full_Pipeline.py`

Runs the end-to-end demonstration across the project modules. It shows a complete secure boot + ECDH + HKDF + ECDSA + ASCON workflow in a single script.

### 7. Validation Suite

File: `Validation/Test_Crypto.py`

Covers:

- ECC key generation
- shared secret equality
- HKDF key derivation length
- ASCON encryption/decryption
- associated-data validation
- tamper detection
- ECDSA signing and verification

---

## ASCON Update and Current Implementation Notes

The project has moved from an older AES-GCM description to a modern lightweight AEAD design using ASCON-128a:

- ASCON-128a is the NIST lightweight cryptography standard used for low-overhead authenticated encryption
- the derived session key is 16 bytes (128 bits) for compatibility with ASCON
- the Python implementation validates nonces and authentication tags before decryption
- tampering with message data or the authentication tag raises a `ValueError`, ensuring integrity failure is detected immediately

This makes the design better aligned with constrained embedded deployments and the architecture described in the active implementation files.

---

## Quick Start

From the project root, run:

```bash
python Demo_Full_Pipeline.py
```

To run the validation suite:

```bash
python -m unittest discover -s Validation
```

You can also run the individual module demos directly, for example:

```bash
python ECC_Integration/ASCON_Encryption.py
python ECC_Integration/Secure_Boot.py
python ECC_Integration/ECDSA_Auth.py
```

---

## ESP32 and Arduino Notes

The project includes:

- `ESP_32_Config/` with setup and build scripts
- `Arduino_Section/ECC_Arduino.ino` for embedded microcontroller experimentation

Important note:

- the Python implementation of ASCON is used on the Raspberry Pi side
- the ESP32 requires a native C ASCON + mbedTLS port or equivalent embedded-side equivalent for direct deployment

This project therefore represents a hybrid prototype architecture: Python-based validation and simulation, plus embedded-side adaptation files for hardware integration.

---

## Security Properties

The implemented design aims to provide:

- confidentiality through authenticated encryption
- integrity protection via ASCON authentication tags
- mutual authentication via ECDSA challenge-response
- session freshness via unique nonces
- firmware trust via secure boot verification

---

## Current Project State

The codebase is functionally structured around the secure pipeline described above. The active implementation currently includes:

- ECC key exchange and HKDF session derivation
- ECDSA signing and verification
- ASCON AEAD encryption/decryption
- secure boot verification flow
- full demonstration pipeline
- unit-style validation tests for the crypto stack

This project is best understood as a practical embedded security prototype and educational implementation rather than a production-ready device stack.

---

## Future Directions

Possible next steps include:

- ESP32-native ASCON integration
- secure message framing and packet serialization
- real transport-layer handshake between Pi and ESP32
- hardware key storage and secure provisioning
- optimization for low-memory MCU deployment
- formal adversarial testing for replay, tamper, and downgrade attacks

---

## Team

- Rishav Kumar
- Jayaditya Dutta
- Ayush Pathak
- Sneha Selot
- Albin Thomas Jiji
- Arya Mishra

Faculty Mentor: Dr. Balakrishnan R  
School of Electronics Engineering  
Vellore Institute of Technology, Chennai Campus

---

## References

- NIST SP 800-56A: Recommendation for Pair-Wise Key-Establishment Schemes
- FIPS 186-5: Digital Signature Standard (DSS)
- ASCON lightweight cryptography material and NIST lightweight cryptography guidance
- ECC and embedded security literature relevant to ECDH, ECDSA, and secure boot design

---

This project demonstrates a complete secure embedded communication concept using ECC, ECDSA, HKDF, and ASCON-128a in a practical prototype architecture for research, teaching, and embedded-system experimentation.
