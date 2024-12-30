#pragma once // Ensures this header is included once

#include "SecureTypes.hpp" // For EncryptedPackage struct

namespace secure_comm { // Begin namespace secure_comm

class Communication {
public:
    // Packages an encrypted message, signature, nonce, and timestamp into an EncryptedPackage struct
    static EncryptedPackage packageMessage(
        const std::vector<uint8_t>& encryptedData,
        const std::vector<uint8_t>& signature,
        const std::string& nonce,
        uint64_t timestamp);

    // Parses a received EncryptedPackage (in real code, might deserialize from a buffer)
    static EncryptedPackage parseMessage(const EncryptedPackage& pkg);

    // Placeholder networking function to send raw data
    static bool sendData(const std::string& destination, const std::vector<uint8_t>& data);

    // Placeholder networking function to receive raw data
    static std::vector<uint8_t> receiveData();

    // Sends a key renewal request with a new public key
    static bool sendKeyRenewalRequest(const std::string& destination, const std::vector<uint8_t>& newPublicKey);

    // Receives a response containing the peer's new public key
    static std::vector<uint8_t> receiveKeyRenewalResponse();
};

} // namespace secure_comm
