# Embedded_Systems_VIT-26
Secure Boot and Data Encryption implements an Elliptic Curve Cryptography (ECC)-based authentication protocol for resource-constrained embedded devices, replacing computationally intensive RSA (O(n³) complexity) with NIST P-256 curves achieving O(log n) complexity. The system integrates ECDH key exchange, HKDF-SHA256 session derivation, AES-256-GCM authenticated encryption, and ECDSA challenge-response authentication, validated on ESP32 and Raspberry Pi platforms. With 90% smaller keys (256-bit ECC = 3072-bit RSA), <200 bytes cryptographic state, and 100–1000× faster performance, it delivers RSA-equivalent security while being battery-friendly, making it ideal for IoT, medical, and industrial embedded systems requiring secure boot and encrypted communication.

# Problem Statement
Embedded systems and IoT devices are deployed in security-critical environments — medical devices, industrial automation, smart homes, and connected vehicles — yet they remain alarmingly vulnerable. Conventional RSA cryptography is computationally infeasible on microcontrollers with kilobytes of RAM and milliwatts of power budget.
<img width="4854" height="1075" alt="deepseek_mermaid_20260830_ada2e4" src="https://github.com/user-attachments/assets/e9ced741-edd1-45c7-acf1-d85b93a14d10" />


# System Architecture
# Complete Block Diagram 

<img width="3525" height="3201" alt="deepseek_mermaid_20260830_6ca255" src="https://github.com/user-attachments/assets/2783ae76-7418-4d3c-878a-41a256d0c57a" />

# Data Flow Pipeline
<img width="6129" height="231" alt="deepseek_mermaid_20260830_07ee29" src="https://github.com/user-attachments/assets/97166e60-6f16-49ba-95fd-4c9b5ec45438" />

# State Machine
<img width="1026" height="2559" alt="deepseek_mermaid_20260830_c02c5f" src="https://github.com/user-attachments/assets/67ad11f0-98be-4bf6-8e30-29e4eeaae0b4" />

# Operational Data Flow
Power-On → Secure Boot → Key Generation → ECDH Exchange → HKDF Derive → ECDSA Auth → AES-GCM Encrypt → Transmit → Decrypt & Verify → Secure Shutdown

## Challenges Faced & Solutions

### 1. Memory Optimization on ESP32

**Challenge:** Implementing ECC P-256 on ESP32 with only 520 KB SRAM.  
**Solution:** Reduced stack usage, minimized buffer copies, used static allocation.  
**Result:** Memory reduced from 2.4 KB to <200 bytes.

### 2. Shared Secret Verification

**Challenge:** Ensuring both nodes compute identical shared secrets.  
**Solution:** Implemented ECDH point validation and SHA-256 verification.

### 3. Cross-Platform Compatibility

**Challenge:** Different crypto libraries across platforms (MbedTLS, OpenSSL, PyCryptodome).  
**Solution:** Created abstraction layer, standardized data formats with ASN.1.

### 4. Secure Boot Implementation

**Challenge:** Verifying firmware integrity before code execution.  
**Solution:** Early-stage ECDSA verification with fallback to known-good firmware.

### 5. Replay Attack Prevention

**Challenge:** Preventing replay attacks without complex timestamp sync.  
**Solution:** Nonce-based encryption with freshness validation.

# Academic References
Elliptic Curve Cryptography for Embedded Systems
IEEE Transactions on Computers
[DOI: 10.1109/TC.2015.2458897]

NIST SP 800-56A: Recommendation for Pair-Wise Key-Establishment Schemes
National Institute of Standards and Technology
[https://doi.org/10.6028/NIST.SP.800-56Ar3]

FIPS 197: Advanced Encryption Standard (AES)
National Institute of Standards and Technology
[https://doi.org/10.6028/NIST.FIPS.197]

FIPS 186-5: Digital Signature Standard (DSS)
National Institute of Standards and Technology
[https://doi.org/10.6028/NIST.FIPS.186-5]

NIST SP 800-38D: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC
National Institute of Standards and Technology
[https://doi.org/10.6028/NIST.SP.800-38D]

Each transition is cryptographically validated before proceeding to the next stage.
