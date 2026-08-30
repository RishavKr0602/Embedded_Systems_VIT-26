/**
 * ECC Secure Communication - Arduino UNO Implementation
 * Uses NIST P-256 curve with Arduino Crypto Library
 */

#include <Crypto.h>
#include <ECDH.h>
#include <AES.h>
#include <GCM.h>
#include <SHA256.h>
#include <Curve25519.h>

// P-256 curve parameters
static const uint8_t P256_CURVE[] = {
    // Prime (p), A, B, Gx, Gy, Order (n)
    // Actual values omitted for brevity - use library defaults
};

class ECCSecureNode {
private:
    ECDH<SecP256R1> ecdh;
    uint8_t private_key[32];
    uint8_t public_key[65];  // Uncompressed point
    uint8_t shared_secret[32];
    uint8_t session_key[32];
    uint8_t peer_public_key[65];
    
public:
    void generateKeypair() {
        ecdh.generate(private_key, public_key);
    }
    
    void getPublicKey(uint8_t* output) {
        memcpy(output, public_key, 65);
    }
    
    bool computeSharedSecret(uint8_t* peer_pub_key) {
        memcpy(peer_public_key, peer_pub_key, 65);
        return ecdh.sharedSecret(private_key, peer_public_key, shared_secret);
    }
    
    void deriveSessionKey() {
        // HKDF-SHA256 simplified
        SHA256 hash;
        hash.update(shared_secret, 32);
        hash.update((uint8_t*)"ecc_secure_boot_salt", 20);
        hash.finalize(session_key);
    }
    
    bool encryptMessage(uint8_t* plaintext, int len, uint8_t* ciphertext) {
        // Simplified AES-GCM
        GCM<AES256> gcm;
        uint8_t nonce[12];
        uint8_t tag[16];
        
        // Generate random nonce
        // In real implementation, use hardware RNG
        for(int i = 0; i < 12; i++) {
            nonce[i] = random(0, 255);
        }
        
        gcm.setKey(session_key, 32);
        gcm.setIV(nonce, 12);
        
        // Encrypt
        gcm.encrypt(plaintext, ciphertext, len, tag, 16);
        
        // Prepend nonce and tag to ciphertext
        memcpy(ciphertext, nonce, 12);
        memcpy(ciphertext + len + 12, tag, 16);
        
        return true;
    }
    
    bool decryptMessage(uint8_t* ciphertext, int len, uint8_t* plaintext) {
        // Separate nonce, ciphertext, tag
        uint8_t nonce[12];
        uint8_t tag[16];
        uint8_t* encrypted = ciphertext + 12;
        int encrypted_len = len - 28;  // Subtract nonce(12) + tag(16)
        
        memcpy(nonce, ciphertext, 12);
        memcpy(tag, ciphertext + len - 16, 16);
        
        GCM<AES256> gcm;
        gcm.setKey(session_key, 32);
        gcm.setIV(nonce, 12);
        
        // Decrypt and verify
        return gcm.decrypt(encrypted, plaintext, encrypted_len, tag, 16);
    }
};

// Global instances
ECCSecureNode nodeA, nodeB;

void setup() {
    Serial.begin(115200);
    Serial.println("ECC Secure Communication Demo - Arduino UNO");
    Serial.println("============================================");
    
    // Step 3-5: Generate key pairs
    Serial.println("Generating key pairs...");
    nodeA.generateKeypair();
    nodeB.generateKeypair();
    
    // Step 6: Exchange public keys
    uint8_t pubA[65], pubB[65];
    nodeA.getPublicKey(pubA);
    nodeB.getPublicKey(pubB);
    Serial.println("Public keys exchanged");
    
    // Step 7-9: Shared secret and session key
    Serial.println("Computing shared secrets...");
    nodeA.computeSharedSecret(pubB);
    nodeB.computeSharedSecret(pubA);
    
    nodeA.deriveSessionKey();
    nodeB.deriveSessionKey();
    
    // Step 10-13: Encrypt and send message
    const char* message = "Secure Boot: Firmware verified";
    uint8_t plaintext[64];
    uint8_t ciphertext[128];
    uint8_t decrypted[64];
    int msg_len = strlen(message);
    
    memcpy(plaintext, message, msg_len + 1);
    
    Serial.println("\n--- Encryption Demo ---");
    Serial.print("Original: ");
    Serial.println((char*)plaintext);
    
    nodeA.encryptMessage(plaintext, msg_len + 1, ciphertext);
    Serial.println("Message encrypted");
    
    // Decrypt
    bool valid = nodeB.decryptMessage(ciphertext, msg_len + 1 + 28, decrypted);
    
    if (valid) {
        Serial.print("Decrypted: ");
        Serial.println((char*)decrypted);
        Serial.println("✓ Authentication successful");
    } else {
        Serial.println("✗ Authentication failed");
    }
}

void loop() {
    // Empty
}