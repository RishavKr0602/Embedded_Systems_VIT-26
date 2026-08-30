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

Each transition is cryptographically validated before proceeding to the next stage.
