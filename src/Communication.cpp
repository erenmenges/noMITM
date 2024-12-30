#include "Communication.hpp"
#include "Logger.hpp"
#include "NetworkStack.hpp"
#include "KeyManagement.hpp"
#include "Utils.hpp"
#include "Protocol.hpp"
#include <sstream>
#include "Crypto.hpp"
#include <stdexcept>

namespace secure_comm {

namespace {
    // Move constants to anonymous namespace or make them public in class
    constexpr size_t MIN_MESSAGE_SIZE = 64;
    constexpr size_t MAX_MESSAGE_SIZE = 1024 * 1024;

    // Helper function to validate input size
    void validateMessageSize(size_t size) {
        if (size < MIN_MESSAGE_SIZE || 
            size > MAX_MESSAGE_SIZE) {
            throw std::invalid_argument("Invalid message size");
        }
    }

    // Helper function to validate timestamp
    void validateTimestamp(uint64_t timestamp) {
        if (!Utils::validateTimestamp(timestamp)) {
            throw std::invalid_argument("Invalid timestamp");
        }
    }

    void validateSize(size_t size) {
        if (size > MAX_MESSAGE_SIZE) {
            throw std::runtime_error("Message size exceeds maximum allowed");
        }
    }
}

bool Communication::sendSecureMessage(
    std::string_view destination, 
    std::string_view message) 
{
    try {
        validateMessageSize(message.size());

        // Get current keys
        auto currentKeyPair = KeyManagement::getCurrentEphemeralKeyPair();
        auto sessionKey = KeyManagement::getCurrentSessionKey();
        
        if (sessionKey.empty() || currentKeyPair.privateKey.empty()) {
            throw std::runtime_error("Invalid key state");
        }

        // Generate nonce and timestamp
        std::string nonce = Utils::generateNonce();
        uint64_t timestamp = Utils::getCurrentTimestamp();
        
        // Encrypt message
        std::vector<uint8_t> ciphertext = Crypto::aesEncrypt(message, sessionKey);
        
        // Create message hash with all components
        std::vector<uint8_t> messageData;
        messageData.reserve(ciphertext.size() + nonce.size() + sizeof(timestamp));
        messageData.insert(messageData.end(), ciphertext.begin(), ciphertext.end());
        messageData.insert(messageData.end(), nonce.begin(), nonce.end());
        
        const uint8_t* timestampBytes = reinterpret_cast<const uint8_t*>(&timestamp);
        messageData.insert(messageData.end(), 
            timestampBytes, 
            timestampBytes + sizeof(timestamp));
        
        auto hash = Crypto::sha256({
            reinterpret_cast<const char*>(messageData.data()), 
            messageData.size()
        });
        
        // Sign the hash
        auto signature = Crypto::ecdsaSign(hash, currentKeyPair.privateKey);
        
        // Package everything together
        EncryptedPackage pkg;
        pkg.encryptedData = std::move(ciphertext);
        pkg.signature = std::move(signature);
        pkg.nonce = std::move(nonce);
        pkg.timestamp = timestamp;
        
        if (!validatePackage(pkg)) {
            throw std::runtime_error("Package validation failed");
        }
        
        // Serialize and send
        auto serialized = serializePackage(pkg);
        validateMessageSize(serialized.size());
        
        if (!sendData(destination, serialized)) {
            throw std::runtime_error("Failed to send data");
        }
        
        Logger::logEvent(LogLevel::Info, "Secure message sent successfully");
        return true;
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Failed to send secure message: ") + e.what());
        return false;
    }
}

std::string Communication::processIncomingMessage(const std::vector<uint8_t>& data) {
    try {
        validateMessageSize(data.size());
        
        // Parse the incoming package
        auto pkg = parseMessage(data);
        
        if (!validatePackage(pkg)) {
            throw std::runtime_error("Invalid package");
        }
        
        // Validate timestamp
        validateTimestamp(pkg.timestamp);
        
        // Validate nonce
        if (!Utils::validateNonce(pkg.nonce)) {
            throw std::runtime_error("Invalid or reused nonce");
        }
        
        // Verify signature
        std::vector<uint8_t> messageData;
        messageData.reserve(pkg.encryptedData.size() + pkg.nonce.size() + sizeof(pkg.timestamp));
        messageData.insert(messageData.end(), pkg.encryptedData.begin(), pkg.encryptedData.end());
        messageData.insert(messageData.end(), pkg.nonce.begin(), pkg.nonce.end());
        
        const uint8_t* timestampBytes = reinterpret_cast<const uint8_t*>(&pkg.timestamp);
        messageData.insert(messageData.end(), 
            timestampBytes, 
            timestampBytes + sizeof(pkg.timestamp));
        
        auto hash = Crypto::sha256({
            reinterpret_cast<const char*>(messageData.data()), 
            messageData.size()
        });
        
        auto peerPublicKey = KeyManagement::getPeerPublicKey();
        if (!Crypto::ecdsaVerify(hash, pkg.signature, peerPublicKey)) {
            throw std::runtime_error("Signature verification failed");
        }
        
        // Decrypt the message
        auto sessionKey = KeyManagement::getCurrentSessionKey();
        return Crypto::aesDecrypt(pkg.encryptedData, sessionKey);
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Failed to process incoming message: ") + e.what());
        throw;
    }
}

bool Communication::validatePackage(const EncryptedPackage& pkg) {
    return !pkg.encryptedData.empty() && 
           !pkg.signature.empty() && 
           !pkg.nonce.empty() && 
           pkg.timestamp != 0;
}

std::vector<uint8_t> Communication::serializePackage(const EncryptedPackage& pkg) {
    size_t totalSize = sizeof(uint32_t) * 3 + 
                      pkg.encryptedData.size() +
                      pkg.signature.size() +
                      pkg.nonce.size() +
                      sizeof(pkg.timestamp);
                      
    validateSize(totalSize);

    std::vector<uint8_t> serialized;
    serialized.reserve(totalSize);

    // Helper lambda to append size and data
    auto appendWithSize = [&serialized](const auto& data) {
        uint32_t size = static_cast<uint32_t>(data.size());
        serialized.insert(serialized.end(),
            reinterpret_cast<const uint8_t*>(&size),
            reinterpret_cast<const uint8_t*>(&size) + sizeof(size));
        serialized.insert(serialized.end(), data.begin(), data.end());
    };

    // Append all components
    appendWithSize(pkg.encryptedData);
    appendWithSize(pkg.signature);
    appendWithSize(pkg.nonce);
    
    // Append timestamp
    serialized.insert(serialized.end(),
        reinterpret_cast<const uint8_t*>(&pkg.timestamp),
        reinterpret_cast<const uint8_t*>(&pkg.timestamp) + sizeof(pkg.timestamp));

    return serialized;
}

// ... implement other methods with similar security patterns ...

} // namespace secure_comm
