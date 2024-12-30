#include "Crypto.hpp"      // Include the header for Crypto declarations
#include "Logger.hpp"      // For logging
#include <stdexcept>       // For std::runtime_error, etc.
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/err.h>

namespace secure_comm { // Begin namespace secure_comm

namespace {
    // Constants for cryptographic operations
    constexpr int KEY_SIZE = 32;  // 256 bits
    constexpr int IV_SIZE = 12;   // 96 bits for GCM
    constexpr int TAG_SIZE = 16;  // 128 bits for GCM
    
    void handleOpenSSLError(const std::string& operation) {
        std::string error;
        while (unsigned long err = ERR_get_error()) {
            char err_buf[256];
            ERR_error_string_n(err, err_buf, sizeof(err_buf));
            if (!error.empty()) error += "; ";
            error += err_buf;
        }
        throw std::runtime_error(operation + " failed: " + error);
    }

    class ScopedEVP_CIPHER_CTX {
    public:
        ScopedEVP_CIPHER_CTX() : ctx_(EVP_CIPHER_CTX_new()) {
            if (!ctx_) handleOpenSSLError("EVP_CIPHER_CTX_new");
        }
        ~ScopedEVP_CIPHER_CTX() { EVP_CIPHER_CTX_free(ctx_); }
        EVP_CIPHER_CTX* get() { return ctx_; }
    private:
        EVP_CIPHER_CTX* ctx_;
    };

    class ScopedEVP_PKEY {
    public:
        ScopedEVP_PKEY(EVP_PKEY* key = nullptr) : key_(key) {}
        ~ScopedEVP_PKEY() { EVP_PKEY_free(key_); }
        EVP_PKEY* get() { return key_; }
        EVP_PKEY** ptr() { return &key_; }
    private:
        EVP_PKEY* key_;
    };
}

ECDHKeyPair Crypto::generateEphemeralKeyPair() {
    ECDHKeyPair kp;
    
    try {
        // Use X25519 for ECDH key exchange
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!pctx) handleOpenSSLError("EVP_PKEY_CTX_new_id");

        if (EVP_PKEY_keygen_init(pctx) <= 0)
            handleOpenSSLError("EVP_PKEY_keygen_init");

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
            handleOpenSSLError("EVP_PKEY_keygen");

        // Extract public and private keys
        size_t privLen = KEY_SIZE;
        size_t pubLen = KEY_SIZE;
        std::vector<uint8_t> privKey(KEY_SIZE);
        std::vector<uint8_t> pubKey(KEY_SIZE);

        if (EVP_PKEY_get_raw_private_key(pkey, privKey.data(), &privLen) <= 0)
            handleOpenSSLError("EVP_PKEY_get_raw_private_key");

        if (EVP_PKEY_get_raw_public_key(pkey, pubKey.data(), &pubLen) <= 0)
            handleOpenSSLError("EVP_PKEY_get_raw_public_key");

        // Cleanup
        EVP_PKEY_CTX_free(pctx);
        EVP_PKEY_free(pkey);

        kp.privateKey = std::move(privKey);
        kp.publicKey = std::move(pubKey);

        Logger::logEvent(LogLevel::Info, "Generated ephemeral ECDH key pair.");
        return kp;
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Failed to generate key pair: ") + e.what());
        throw;
    }
}

std::vector<uint8_t> Crypto::deriveSessionKey(
    const std::vector<uint8_t>& peerPublicKey,
    const std::vector<uint8_t>& privateKey)
{
    if (peerPublicKey.size() != KEY_SIZE || privateKey.size() != KEY_SIZE) {
        throw std::invalid_argument("Invalid key size");
    }

    try {
        // Create context for our private key
        ScopedEVP_PKEY privKeyCtx(EVP_PKEY_new_raw_private_key(
            EVP_PKEY_X25519, nullptr, 
            privateKey.data(), privateKey.size()));
        if (!privKeyCtx.get()) {
            handleOpenSSLError("EVP_PKEY_new_raw_private_key");
        }

        // Create context for peer's public key
        ScopedEVP_PKEY pubKeyCtx(EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519, nullptr, 
            peerPublicKey.data(), peerPublicKey.size()));
        if (!pubKeyCtx.get()) {
            handleOpenSSLError("EVP_PKEY_new_raw_public_key");
        }

        // Create the key derivation context
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privKeyCtx.get(), nullptr);
        if (!ctx) handleOpenSSLError("EVP_PKEY_CTX_new");

        // Initialize
        if (EVP_PKEY_derive_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            handleOpenSSLError("EVP_PKEY_derive_init");
        }

        // Provide peer public key
        if (EVP_PKEY_derive_set_peer(ctx, pubKeyCtx.get()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            handleOpenSSLError("EVP_PKEY_derive_set_peer");
        }

        // Determine buffer length for shared secret
        size_t secret_len = 0;
        if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            handleOpenSSLError("EVP_PKEY_derive");
        }

        // Create buffer and derive the shared secret
        std::vector<uint8_t> shared_secret(secret_len);
        if (EVP_PKEY_derive(ctx, shared_secret.data(), &secret_len) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            handleOpenSSLError("EVP_PKEY_derive");
        }

        EVP_PKEY_CTX_free(ctx);
        Logger::logEvent(LogLevel::Info, "Derived session key successfully");
        return shared_secret;

    } catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Session key derivation failed: ") + e.what());
        throw;
    }
}

std::vector<uint8_t> Crypto::aesEncrypt(
    const std::string_view plaintext,
    const std::vector<uint8_t>& key)
{
    if (key.size() != AES_KEY_SIZE) {
        throw std::invalid_argument("Invalid key size");
    }

    std::vector<uint8_t> iv(GCM_IV_SIZE);
    std::vector<uint8_t> ciphertext;
    ScopedEVP_CIPHER_CTX ctx;
    
    try {
        // Generate random IV
        if (RAND_bytes(iv.data(), GCM_IV_SIZE) != 1) {
            handleOpenSSLError("RAND_bytes");
        }
        
        // Initialize encryption
        if (!EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, 
            key.data(), iv.data())) {
            handleOpenSSLError("EVP_EncryptInit_ex");
        }
        
        // Prepare output buffer
        ciphertext.resize(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        int len = 0, ciphertext_len = 0;
        
        // Encrypt
        if (!EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<int>(plaintext.size()))) {
            handleOpenSSLError("EVP_EncryptUpdate");
        }
        
        ciphertext_len = len;
        
        // Finalize
        if (!EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len)) {
            handleOpenSSLError("EVP_EncryptFinal_ex");
        }
        
        ciphertext_len += len;
        ciphertext.resize(ciphertext_len);
        
        // Get tag
        std::vector<uint8_t> tag(TAG_SIZE);
        if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data())) {
            handleOpenSSLError("EVP_CIPHER_CTX_ctrl");
        }
        
        // Format final output: [IV | TAG | CIPHERTEXT]
        std::vector<uint8_t> result;
        result.reserve(iv.size() + tag.size() + ciphertext.size());
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), tag.begin(), tag.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        
        // Secure cleanup
        secureWipe(iv);
        secureWipe(tag);
        secureWipe(ciphertext);
        
        return result;
    } catch (...) {
        secureWipe(iv);
        secureWipe(ciphertext);
        throw;
    }
}

std::string Crypto::aesDecrypt(
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key)
{
    if (key.size() != AES_KEY_SIZE) {
        throw std::invalid_argument("Invalid key size");
    }

    if (ciphertext.size() < GCM_IV_SIZE + GCM_TAG_SIZE) {
        throw std::invalid_argument("Ciphertext too short");
    }

    try {
        ScopedEVP_CIPHER_CTX ctx;

        // Extract IV and tag from ciphertext
        std::vector<uint8_t> iv(ciphertext.begin(), 
                               ciphertext.begin() + GCM_IV_SIZE);
        std::vector<uint8_t> tag(ciphertext.begin() + GCM_IV_SIZE, 
                                ciphertext.begin() + GCM_IV_SIZE + GCM_TAG_SIZE);
        
        // Initialize decryption
        if (!EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, 
                               key.data(), iv.data())) {
            handleOpenSSLError("EVP_DecryptInit_ex");
        }

        // Set expected tag value
        if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 
                                GCM_TAG_SIZE, tag.data())) {
            handleOpenSSLError("EVP_CIPHER_CTX_ctrl");
        }

        // Prepare output buffer
        const size_t ciphertext_len = ciphertext.size() - GCM_IV_SIZE - GCM_TAG_SIZE;
        std::vector<uint8_t> plaintext(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
        int len = 0, plaintext_len = 0;

        // Decrypt
        if (!EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                              ciphertext.data() + GCM_IV_SIZE + GCM_TAG_SIZE,
                              static_cast<int>(ciphertext_len))) {
            handleOpenSSLError("EVP_DecryptUpdate");
        }
        plaintext_len = len;

        // Finalize decryption and verify tag
        if (!EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len)) {
            handleOpenSSLError("EVP_DecryptFinal_ex");
        }
        plaintext_len += len;

        // Convert to string and securely clean up
        std::string result(reinterpret_cast<char*>(plaintext.data()), plaintext_len);
        secureWipe(plaintext);
        
        Logger::logEvent(LogLevel::Info, "AES decryption completed successfully");
        return result;

    } catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("AES decryption failed: ") + e.what());
        throw;
    }
}

std::vector<uint8_t> Crypto::sha256(const std::string_view data) {
    try {
        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_len;

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) handleOpenSSLError("EVP_MD_CTX_new");

        if (!EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr)) {
            EVP_MD_CTX_free(ctx);
            handleOpenSSLError("EVP_DigestInit_ex");
        }

        if (!EVP_DigestUpdate(ctx, data.data(), data.size())) {
            EVP_MD_CTX_free(ctx);
            handleOpenSSLError("EVP_DigestUpdate");
        }

        if (!EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
            EVP_MD_CTX_free(ctx);
            handleOpenSSLError("EVP_DigestFinal_ex");
        }

        EVP_MD_CTX_free(ctx);

        std::vector<uint8_t> result(hash, hash + hash_len);
        Logger::logEvent(LogLevel::Info, "SHA-256 hash computed successfully");
        return result;

    } catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("SHA-256 computation failed: ") + e.what());
        throw;
    }
}

std::vector<uint8_t> Crypto::ecdsaSign(
    const std::vector<uint8_t>& hash,
    const std::vector<uint8_t>& privateKey)
{
    try {
        ScopedEVP_PKEY pkey(EVP_PKEY_new_raw_private_key(
            EVP_PKEY_ED25519, nullptr,
            privateKey.data(), privateKey.size()));
        if (!pkey.get()) {
            handleOpenSSLError("EVP_PKEY_new_raw_private_key");
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) handleOpenSSLError("EVP_MD_CTX_new");

        if (!EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey.get())) {
            EVP_MD_CTX_free(ctx);
            handleOpenSSLError("EVP_DigestSignInit");
        }

        size_t sig_len;
        if (!EVP_DigestSign(ctx, nullptr, &sig_len, hash.data(), hash.size())) {
            EVP_MD_CTX_free(ctx);
            handleOpenSSLError("EVP_DigestSign");
        }

        std::vector<uint8_t> signature(sig_len);
        if (!EVP_DigestSign(ctx, signature.data(), &sig_len, 
                           hash.data(), hash.size())) {
            EVP_MD_CTX_free(ctx);
            handleOpenSSLError("EVP_DigestSign");
        }

        EVP_MD_CTX_free(ctx);
        Logger::logEvent(LogLevel::Info, "ECDSA signature created successfully");
        return signature;

    } catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("ECDSA signing failed: ") + e.what());
        throw;
    }
}

bool Crypto::ecdsaVerify(
    const std::vector<uint8_t>& hash,
    const std::vector<uint8_t>& signature,
    const std::vector<uint8_t>& publicKey)
{
    try {
        ScopedEVP_PKEY pkey(EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519, nullptr,
            publicKey.data(), publicKey.size()));
        if (!pkey.get()) {
            handleOpenSSLError("EVP_PKEY_new_raw_public_key");
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) handleOpenSSLError("EVP_MD_CTX_new");

        if (!EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey.get())) {
            EVP_MD_CTX_free(ctx);
            handleOpenSSLError("EVP_DigestVerifyInit");
        }

        int ret = EVP_DigestVerify(ctx, signature.data(), signature.size(),
                                  hash.data(), hash.size());

        EVP_MD_CTX_free(ctx);

        Logger::logEvent(LogLevel::Info, 
            ret == 1 ? "ECDSA signature verified successfully" 
                    : "ECDSA signature verification failed");
        return ret == 1;

    } catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("ECDSA verification failed: ") + e.what());
        return false;
    }
}

void Crypto::secureWipe(std::vector<uint8_t>& data) {
    if (data.empty()) return;
    
    // Use OpenSSL's secure memory wiping function
    OPENSSL_cleanse(data.data(), data.size());
    data.clear();
    data.shrink_to_fit(); // Release the memory back to the system
}

} // namespace secure_comm
