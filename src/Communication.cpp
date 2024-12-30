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
        // Add input validation
        if (destination.empty() || message.empty()) {
            throw std::invalid_argument("Empty destination or message");
        }
        validateMessageSize(message.size());
        
        // Get current session key and keypair
        auto sessionKey = KeyManagement::getCurrentSessionKey();
        auto keyPair = KeyManagement::getCurrentEphemeralKeyPair();
        
        // Encrypt the message
        auto encryptedData = Crypto::aesEncrypt(message, sessionKey);
        
        // Generate nonce and timestamp with validation
        std::string nonce = Utils::generateNonce();
        if (nonce.empty()) {
            throw std::runtime_error("Failed to generate nonce");
        }
        
        uint64_t timestamp = Utils::getCurrentTimestamp();
        if (!Utils::validateTimestamp(timestamp)) {
            throw std::runtime_error("Invalid timestamp generated");
        }
        
        // Create signature data with secure concatenation
        std::vector<uint8_t> signatureData;
        signatureData.reserve(encryptedData.size() + nonce.size() + sizeof(timestamp));
        signatureData.insert(signatureData.end(), encryptedData.begin(), encryptedData.end());
        signatureData.insert(signatureData.end(), nonce.begin(), nonce.end());
        
        const uint8_t* timestampBytes = reinterpret_cast<const uint8_t*>(&timestamp);
        signatureData.insert(signatureData.end(), timestampBytes, timestampBytes + sizeof(timestamp));
        
        // Sign with additional validation
        auto signature = Crypto::ecdsaSign(
            Crypto::sha256({reinterpret_cast<const char*>(signatureData.data()), 
                           signatureData.size()}),
            keyPair.privateKey
        );
        
        if (signature.empty()) {
            throw std::runtime_error("Failed to create signature");
        }
        
        // Package and send with validation
        auto pkg = packageMessage(encryptedData, signature, nonce, timestamp);
        if (!validatePackage(pkg)) {
            throw std::runtime_error("Invalid package created");
        }
        
        auto serialized = serializePackage(pkg);
        if (serialized.empty()) {
            throw std::runtime_error("Failed to serialize package");
        }
        
        return sendData(destination, serialized);
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::MessageSendError,
            std::string("Failed to send secure message: ") + e.what());
        return false;
    }
}

std::string Communication::processIncomingMessage(const std::vector<uint8_t>& data) {
    try {
        // Add input validation
        if (data.empty()) {
            throw std::invalid_argument("Empty data received");
        }
        validateMessageSize(data.size());
        
        // Parse and validate the package with additional checks
        auto pkg = parseMessage(data);
        if (pkg.encryptedData.empty() || pkg.signature.empty() || pkg.nonce.empty()) {
            throw std::runtime_error("Invalid message package: missing components");
        }
        
        if (!validatePackage(pkg)) {
            throw std::runtime_error("Invalid message package");
        }
        
        if (!Utils::validateTimestamp(pkg.timestamp)) {
            throw std::runtime_error("Message timestamp validation failed");
        }
        
        if (!Utils::validateNonce(pkg.nonce)) {
            throw std::runtime_error("Message nonce validation failed");
        }
        
        // Verify signature with peer's public key
        auto peerPublicKey = KeyManagement::getPeerPublicKey();
        
        // Reconstruct signature data securely
        std::vector<uint8_t> signatureData;
        signatureData.reserve(pkg.encryptedData.size() + pkg.nonce.size() + sizeof(pkg.timestamp));
        signatureData.insert(signatureData.end(), 
                           pkg.encryptedData.begin(), pkg.encryptedData.end());
        signatureData.insert(signatureData.end(), pkg.nonce.begin(), pkg.nonce.end());
        
        const uint8_t* timestampBytes = reinterpret_cast<const uint8_t*>(&pkg.timestamp);
        signatureData.insert(signatureData.end(), 
                           timestampBytes, timestampBytes + sizeof(pkg.timestamp));
        
        auto hash = Crypto::sha256({reinterpret_cast<const char*>(signatureData.data()), 
                                  signatureData.size()});
        
        if (!Crypto::ecdsaVerify(hash, pkg.signature, peerPublicKey)) {
            throw std::runtime_error("Invalid message signature");
        }
        
        // Decrypt the message using current session key
        auto sessionKey = KeyManagement::getCurrentSessionKey();
        auto decrypted = Crypto::aesDecrypt(pkg.encryptedData, sessionKey);
        
        if (decrypted.empty()) {
            throw std::runtime_error("Decryption failed");
        }
        
        return decrypted;
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::MessageProcessError,
            std::string("Failed to process incoming message: ") + e.what());
        throw;
    }
}

bool Communication::validatePackage(const EncryptedPackage& pkg) {
    try {
        // Check for empty components
        if (pkg.encryptedData.empty() || pkg.signature.empty() || pkg.nonce.empty()) {
            return false;
        }
        
        // Check sizes
        if (pkg.encryptedData.size() < MIN_MESSAGE_SIZE || 
            pkg.encryptedData.size() > MAX_MESSAGE_SIZE) {
            return false;
        }
        
        // Validate nonce format and expiry
        if (!Utils::validateNonce(pkg.nonce)) {
            return false;
        }
        
        // Validate timestamp
        if (!Utils::validateTimestamp(pkg.timestamp)) {
            return false;
        }
        
        return true;
    }
    catch (...) {
        return false;
    }
}

std::vector<uint8_t> Communication::serializePackage(const EncryptedPackage& pkg) {
    // Validate package components
    if (pkg.encryptedData.empty() || pkg.signature.empty() || pkg.nonce.empty()) {
        throw std::runtime_error("Invalid package: missing components");
    }
    
    // Calculate and validate total size
    size_t totalSize = 
        4 + pkg.encryptedData.size() +  // size + encrypted data
        4 + pkg.signature.size() +       // size + signature
        4 + pkg.nonce.size() +           // size + nonce
        sizeof(uint64_t);                // timestamp
        
    if (totalSize > MAX_MESSAGE_SIZE) {
        throw std::runtime_error("Serialized package would exceed maximum size");
    }
    
    std::vector<uint8_t> serialized;
    serialized.reserve(totalSize);
    
    auto writeSize = [&serialized](uint32_t size) {
        const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&size);
        serialized.insert(serialized.end(), bytes, bytes + sizeof(uint32_t));
    };
    
    // Write encrypted data
    writeSize(static_cast<uint32_t>(pkg.encryptedData.size()));
    serialized.insert(serialized.end(), 
                     pkg.encryptedData.begin(), pkg.encryptedData.end());
    
    // Write signature
    writeSize(static_cast<uint32_t>(pkg.signature.size()));
    serialized.insert(serialized.end(), 
                     pkg.signature.begin(), pkg.signature.end());
    
    // Write nonce
    writeSize(static_cast<uint32_t>(pkg.nonce.size()));
    serialized.insert(serialized.end(), 
                     pkg.nonce.begin(), pkg.nonce.end());
    
    // Write timestamp
    const uint8_t* timestampBytes = reinterpret_cast<const uint8_t*>(&pkg.timestamp);
    serialized.insert(serialized.end(), 
                     timestampBytes, timestampBytes + sizeof(uint64_t));
    
    return serialized;
}

bool Communication::sendKeyRenewalRequest(
    std::string_view destination, 
    const std::vector<uint8_t>& newPublicKey) 
{
    try {
        validateMessageSize(newPublicKey.size());
        
        // Create a special package for key renewal
        auto currentKeyPair = KeyManagement::getCurrentEphemeralKeyPair();
        std::string nonce = Utils::generateNonce();
        uint64_t timestamp = Utils::getCurrentTimestamp();
        
        // Sign the renewal request with current private key
        std::vector<uint8_t> requestData;
        requestData.insert(requestData.end(), newPublicKey.begin(), newPublicKey.end());
        requestData.insert(requestData.end(), nonce.begin(), nonce.end());
        
        const uint8_t* timestampBytes = reinterpret_cast<const uint8_t*>(&timestamp);
        requestData.insert(requestData.end(), timestampBytes, timestampBytes + sizeof(timestamp));
        
        auto signature = Crypto::ecdsaSign(
            Crypto::sha256({reinterpret_cast<const char*>(requestData.data()), requestData.size()}),
            currentKeyPair.privateKey
        );
        
        EncryptedPackage pkg;
        pkg.encryptedData = newPublicKey;  // Not encrypted, just the new public key
        pkg.signature = std::move(signature);
        pkg.nonce = std::move(nonce);
        pkg.timestamp = timestamp;
        
        auto serialized = serializePackage(pkg);
        return sendData(destination, serialized);
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::KeyRenewalError,
            std::string("Failed to send key renewal request: ") + e.what());
        return false;
    }
}

KeyRenewalResponse Communication::receiveKeyRenewalResponse() {
    try {
        auto data = receiveData();
        validateMessageSize(data.size());
        
        auto pkg = parseMessage(data);
        if (!validatePackage(pkg)) {
            throw std::runtime_error("Invalid renewal response package");
        }
        
        validateTimestamp(pkg.timestamp);
        
        // Verify signature with peer's current public key
        auto peerPublicKey = KeyManagement::getPeerPublicKey();
        if (!Crypto::ecdsaVerify(
            Crypto::sha256({reinterpret_cast<const char*>(pkg.encryptedData.data()), 
                           pkg.encryptedData.size()}),
            pkg.signature,
            peerPublicKey)) {
            throw std::runtime_error("Invalid renewal response signature");
        }
        
        return KeyRenewalResponse{
            true,                  // success
            pkg.encryptedData,     // peerPublicKey
            pkg.signature,         // signature
            pkg.nonce,            // nonce
            pkg.timestamp         // timestamp
        };
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::KeyRenewalError,
            std::string("Failed to receive key renewal response: ") + e.what());
        throw;
    }
}

EncryptedPackage Communication::packageMessage(
    const std::vector<uint8_t>& encryptedData,
    const std::vector<uint8_t>& signature,
    std::string_view nonce,
    uint64_t timestamp)
{
    validateMessageSize(encryptedData.size());
    validateMessageSize(signature.size());
    validateTimestamp(timestamp);
    
    EncryptedPackage pkg;
    pkg.encryptedData = encryptedData;
    pkg.signature = signature;
    pkg.nonce = std::string(nonce);
    pkg.timestamp = timestamp;
    
    if (!validatePackage(pkg)) {
        throw std::runtime_error("Invalid package creation");
    }
    
    return pkg;
}

EncryptedPackage Communication::parseMessage(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        throw std::runtime_error("Empty message data");
    }
    
    if (data.size() < MIN_MESSAGE_SIZE) {
        throw std::runtime_error("Message too small");
    }
    
    if (data.size() > MAX_MESSAGE_SIZE) {
        throw std::runtime_error("Message too large");
    }
    
    size_t offset = 0;
    auto readSize = [&data, &offset]() -> uint32_t {
        if (offset + sizeof(uint32_t) > data.size()) {
            throw std::runtime_error("Invalid message format");
        }
        uint32_t size;
        std::memcpy(&size, &data[offset], sizeof(uint32_t));
        offset += sizeof(uint32_t);
        return size;
    };
    
    EncryptedPackage pkg;
    
    // Read encrypted data
    uint32_t encryptedSize = readSize();
    if (offset + encryptedSize > data.size()) {
        throw std::runtime_error("Invalid encrypted data size");
    }
    pkg.encryptedData.assign(data.begin() + offset, data.begin() + offset + encryptedSize);
    offset += encryptedSize;
    
    // Read signature
    uint32_t signatureSize = readSize();
    if (offset + signatureSize > data.size()) {
        throw std::runtime_error("Invalid signature size");
    }
    pkg.signature.assign(data.begin() + offset, data.begin() + offset + signatureSize);
    offset += signatureSize;
    
    // Read nonce
    uint32_t nonceSize = readSize();
    if (offset + nonceSize > data.size()) {
        throw std::runtime_error("Invalid nonce size");
    }
    pkg.nonce.assign(data.begin() + offset, data.begin() + offset + nonceSize);
    offset += nonceSize;
    
    // Read timestamp
    if (offset + sizeof(uint64_t) > data.size()) {
        throw std::runtime_error("Invalid timestamp format");
    }
    std::memcpy(&pkg.timestamp, &data[offset], sizeof(uint64_t));
    
    if (!validatePackage(pkg)) {
        throw std::runtime_error("Invalid parsed package");
    }
    
    return pkg;
}

bool Communication::sendData(std::string_view destination, const std::vector<uint8_t>& data) {
    try {
        return NetworkStack::getInstance().send(std::string(destination), data);
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::NetworkError,
            std::string("Failed to send data: ") + e.what());
        return false;
    }
}

std::vector<uint8_t> Communication::receiveData() {
    try {
        return NetworkStack::getInstance().receive();
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::NetworkError,
            std::string("Failed to receive data: ") + e.what());
        throw;
    }
}

// Private helper method for timestamp validation
void Communication::validateTimestamp(uint64_t timestamp) {
    uint64_t currentTime = Utils::getCurrentTimestamp();
    uint64_t timeDiff = currentTime > timestamp ? 
                        currentTime - timestamp : 
                        timestamp - currentTime;
    
    // Allow 5 minutes time difference
    constexpr uint64_t MAX_TIME_DIFF = 5 * 60 * 1000; // 5 minutes in milliseconds
    
    if (timeDiff > MAX_TIME_DIFF) {
        throw std::runtime_error("Message timestamp outside acceptable range");
    }
}

// Private helper method for message size validation
void Communication::validateMessageSize(size_t size) {
    if (size < MIN_MESSAGE_SIZE || size > MAX_MESSAGE_SIZE) {
        throw std::invalid_argument("Invalid message size");
    }
}

} // namespace secure_comm
