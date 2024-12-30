#pragma once

#include <string>
#include <vector>
#include <string_view>
#include "SecureTypes.hpp"

namespace secure_comm {

class Communication {
public:
    // Main communication methods
    static bool sendSecureMessage(std::string_view destination, std::string_view message);
    static std::string processIncomingMessage(const std::vector<uint8_t>& data);
    
    // Key renewal communication
    static bool sendKeyRenewalRequest(
        std::string_view destination, 
        const std::vector<uint8_t>& newPublicKey);
    static KeyRenewalResponse receiveKeyRenewalResponse();

    // Package handling
    static EncryptedPackage packageMessage(
        const std::vector<uint8_t>& encryptedData,
        const std::vector<uint8_t>& signature,
        std::string_view nonce,
        uint64_t timestamp);

    static EncryptedPackage parseMessage(const std::vector<uint8_t>& data);

private:
    static constexpr size_t MAX_MESSAGE_SIZE = 1024 * 1024; // 1MB
    static constexpr size_t MIN_MESSAGE_SIZE = 64; // Minimum size for header + minimal content
    
    static std::vector<uint8_t> serializePackage(const EncryptedPackage& pkg);
    static bool validatePackage(const EncryptedPackage& pkg);
    static bool sendData(std::string_view destination, const std::vector<uint8_t>& data);
    static std::vector<uint8_t> receiveData();

    // Prevent instantiation
    Communication() = delete;
    ~Communication() = delete;
    Communication(const Communication&) = delete;
    Communication& operator=(const Communication&) = delete;
};

} // namespace secure_comm
