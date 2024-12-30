#pragma once // Ensures single inclusion of this header

#include <string>       // For std::string
#include <vector>       // For std::vector
#include <cstdint>      // For fixed-width integer types

namespace secure_comm { // Begin namespace secure_comm

class Crypto {
public:
    // Represents an ECDH key pair consisting of a private and a public key
    struct ECDHKeyPair {
        std::vector<uint8_t> privateKey; // The private key bytes
        std::vector<uint8_t> publicKey;  // The public key bytes
    };

    // Generates an ephemeral ECDH key pair for one side of the exchange
    static ECDHKeyPair generateEphemeralKeyPair();

    // Derives a session key using ECDH given a peer's public key and our private key
    static std::vector<uint8_t> deriveSessionKey(
        const std::vector<uint8_t>& peerPublicKey,
        const std::vector<uint8_t>& ourPrivateKey);

    // Encrypts plaintext using AES-256
    static std::vector<uint8_t> aesEncrypt(
        const std::string& plaintext,
        const std::vector<uint8_t>& key);

    // Decrypts ciphertext (AES-256)
    static std::string aesDecrypt(
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key);

    // Computes a SHA-256 hash of the input data
    static std::vector<uint8_t> sha256(const std::string& data);

    // Signs the given hash with ECDSA using a private key
    static std::vector<uint8_t> ecdsaSign(
        const std::vector<uint8_t>& hash,
        const std::vector<uint8_t>& privateKey);

    // Verifies an ECDSA signature against the hash using a public key
    static bool ecdsaVerify(
        const std::vector<uint8_t>& hash,
        const std::vector<uint8_t>& signature,
        const std::vector<uint8_t>& publicKey);
};

} // namespace secure_comm
