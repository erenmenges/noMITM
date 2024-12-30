#pragma once

#include <string>
#include <vector>
#include "SecureTypes.hpp"

namespace secure_comm {

struct ECDHKeyPair {
    std::vector<uint8_t> privateKey;
    std::vector<uint8_t> publicKey;
    
    ~ECDHKeyPair() {
        Crypto::secureWipe(privateKey);
        Crypto::secureWipe(publicKey);
    }
};

class Crypto {
public:
    // Key generation and management
    static ECDHKeyPair generateEphemeralKeyPair();
    static std::vector<uint8_t> deriveSessionKey(
        const std::vector<uint8_t>& peerPublicKey,
        const std::vector<uint8_t>& privateKey);

    // Symmetric encryption (AES-GCM)
    static std::vector<uint8_t> aesEncrypt(
        const std::string_view plaintext,
        const std::vector<uint8_t>& key);
    static std::string aesDecrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key);

    // Digital signatures
    static std::vector<uint8_t> ecdsaSign(
        const std::vector<uint8_t>& hash,
        const std::vector<uint8_t>& privateKey);
    static bool ecdsaVerify(
        const std::vector<uint8_t>& hash,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& publicKey);

    // Hashing
    static std::vector<uint8_t> sha256(const std::string_view data);

    // Secure memory wiping
    static void secureWipe(std::vector<uint8_t>& data);

private:
    static constexpr size_t AES_KEY_SIZE = 32;  // 256 bits
    static constexpr size_t GCM_IV_SIZE = 12;   // 96 bits
    static constexpr size_t GCM_TAG_SIZE = 16;  // 128 bits
    
    // Prevent instantiation
    Crypto() = delete;
    ~Crypto() = delete;
    Crypto(const Crypto&) = delete;
    Crypto& operator=(const Crypto&) = delete;
};

} // namespace secure_comm
