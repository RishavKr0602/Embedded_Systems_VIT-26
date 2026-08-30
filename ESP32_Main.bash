/**
 * ESP32 Secure Communication Implementation
 * Using ESP-IDF v5.0+ and MbedTLS
 */

#include <stdio.h>
#include <string.h>
#include "esp_system.h"
#include "esp_log.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

static const char *TAG = "ECC_SECURE";

// P-256 curve context
static mbedtls_ecp_group grp;
static mbedtls_ctr_drbg_context ctr_drbg;
static mbedtls_entropy_context entropy;

typedef struct {
    mbedtls_ecp_keypair keypair;
    uint8_t shared_secret[32];
    uint8_t session_key[32];
} ecdh_context_t;

void init_crypto() {
    mbedtls_ecp_group_init(&grp);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    
    // Initialize P-256 curve
    mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    
    // Seed random generator
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                          (const unsigned char *)"ecc_secure_boot", 16);
}

void generate_keypair(ecdh_context_t *ctx) {
    mbedtls_ecp_keypair_init(&ctx->keypair);
    
    // Generate key pair
    mbedtls_ecp_gen_key(&grp, &ctx->keypair, mbedtls_ctr_drbg_random, &ctr_drbg);
    
    ESP_LOGI(TAG, "Key pair generated successfully");
}

int compute_shared_secret(ecdh_context_t *ctx, mbedtls_ecp_point *peer_public) {
    int ret;
    size_t olen;
    
    ret = mbedtls_ecdh_compute_shared(&grp, ctx->shared_secret, &olen,
                                      peer_public, &ctx->keypair.d,
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
    
    if (ret == 0) {
        ESP_LOGI(TAG, "Shared secret computed: %d bytes", olen);
    } else {
        ESP_LOGE(TAG, "Shared secret computation failed: %d", ret);
    }
    
    return ret;
}

void derive_session_key(uint8_t *shared_secret, uint8_t *session_key) {
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, shared_secret, 32);
    mbedtls_sha256_update(&sha_ctx, (unsigned char *)"hkdf_salt", 10);
    mbedtls_sha256_finish(&sha_ctx, session_key);
    mbedtls_sha256_free(&sha_ctx);
    
    ESP_LOGI(TAG, "Session key derived");
}

int aes_gcm_encrypt(uint8_t *key, uint8_t *plaintext, size_t plaintext_len,
                    uint8_t *ciphertext, uint8_t *tag) {
    int ret;
    mbedtls_gcm_context gcm;
    uint8_t nonce[12];
    
    mbedtls_gcm_init(&gcm);
    
    // Generate random nonce
    mbedtls_ctr_drbg_random(&ctr_drbg, nonce, 12);
    
    // Set key
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) {
        ESP_LOGE(TAG, "GCM setkey failed: %d", ret);
        return ret;
    }
    
    // Encrypt
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                    plaintext_len, nonce, 12,
                                    NULL, 0, plaintext,
                                    ciphertext, 16, tag);
    
    if (ret == 0) {
        ESP_LOGI(TAG, "Encryption successful");
    } else {
        ESP_LOGE(TAG, "Encryption failed: %d", ret);
    }
    
    mbedtls_gcm_free(&gcm);
    return ret;
}

int aes_gcm_decrypt(uint8_t *key, uint8_t *nonce, uint8_t *ciphertext,
                    size_t ciphertext_len, uint8_t *tag,
                    uint8_t *plaintext) {
    int ret;
    mbedtls_gcm_context gcm;
    
    mbedtls_gcm_init(&gcm);
    
    ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0) {
        ESP_LOGE(TAG, "GCM setkey failed: %d", ret);
        return ret;
    }
    
    ret = mbedtls_gcm_auth_decrypt(&gcm, ciphertext_len, nonce, 12,
                                   NULL, 0, tag, 16,
                                   ciphertext, plaintext);
    
    if (ret == 0) {
        ESP_LOGI(TAG, "Decryption successful");
    } else {
        ESP_LOGE(TAG, "Decryption failed: %d", ret);
    }
    
    mbedtls_gcm_free(&gcm);
    return ret;
}

// Main function
void app_main() {
    ESP_LOGI(TAG, "Starting ECC Secure Communication");
    ESP_LOGI(TAG, "==================================");
    
    // Initialize crypto
    init_crypto();
    
    // Create two nodes
    ecdh_context_t node_a, node_b;
    generate_keypair(&node_a);
    generate_keypair(&node_b);
    
    // Exchange public keys (simulated)
    mbedtls_ecp_point pub_a, pub_b;
    mbedtls_ecp_point_init(&pub_a);
    mbedtls_ecp_point_init(&pub_b);
    
    mbedtls_ecp_copy(&pub_a, &node_a.keypair.Q);
    mbedtls_ecp_copy(&pub_b, &node_b.keypair.Q);
    
    // Compute shared secrets
    compute_shared_secret(&node_a, &pub_b);
    compute_shared_secret(&node_b, &pub_a);
    
    // Derive session keys
    derive_session_key(node_a.shared_secret, node_a.session_key);
    derive_session_key(node_b.shared_secret, node_b.session_key);
    
    // Test encryption
    const char *message = "Secure Boot: ESP32 firmware verified";
    uint8_t plaintext[128];
    uint8_t ciphertext[128];
    uint8_t tag[16];
    uint8_t decrypted[128];
    size_t msg_len = strlen(message);
    
    memcpy(plaintext, message, msg_len + 1);
    
    ESP_LOGI(TAG, "Original: %s", plaintext);
    
    // Encrypt
    int ret = aes_gcm_encrypt(node_a.session_key, plaintext, msg_len + 1,
                              ciphertext, tag);
    
    if (ret == 0) {
        ESP_LOGI(TAG, "Encrypted successfully");
        ESP_LOG_BUFFER_HEX("Ciphertext", ciphertext, msg_len + 1);
        ESP_LOG_BUFFER_HEX("Auth Tag", tag, 16);
        
        // Decrypt with Node B's key
        uint8_t nonce[12] = {0};  // In real implementation, use actual nonce
        
        ret = aes_gcm_decrypt(node_b.session_key, nonce, ciphertext,
                              msg_len + 1, tag, decrypted);
        
        if (ret == 0) {
            ESP_LOGI(TAG, "Decrypted: %s", decrypted);
            ESP_LOGI(TAG, "✓ Authentication successful");
        }
    }
    
    ESP_LOGI(TAG, "==================================");
    ESP_LOGI(TAG, "Demo complete");
}