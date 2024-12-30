#include "Communication.hpp" // Include the declaration of Communication
#include "Logger.hpp"        // For logging
#include "NetworkStack.hpp"

namespace secure_comm { // Begin namespace secure_comm

EncryptedPackage Communication::packageMessage(
    const std::vector<uint8_t>& encryptedData,
    const std::vector<uint8_t>& signature,
    const std::string& nonce,
    uint64_t timestamp)
{
    EncryptedPackage pkg;         // Create a new EncryptedPackage
    pkg.encryptedData = encryptedData; // Assign ciphertext
    pkg.signature = signature;         // Assign signature
    pkg.nonce = nonce;                // Assign nonce
    pkg.timestamp = timestamp;        // Assign timestamp
    return pkg;                       // Return the populated structure
}

EncryptedPackage Communication::parseMessage(const EncryptedPackage& pkg) {
    // In real code, you'd parse a serialized buffer. Here, we just return what was passed in.
    return pkg;
}

bool Communication::sendData(const std::string& destination, const std::vector<uint8_t>& data) {
    // Parse destination string (expected format: "host:port")
    size_t colonPos = destination.find(':');
    if (colonPos == std::string::npos) {
        Logger::logError(ErrorCode::ProcessingError, "Invalid destination format");
        return false;
    }

    std::string host = destination.substr(0, colonPos);
    uint16_t port = std::stoi(destination.substr(colonPos + 1));

    // Connect to the destination
    if (!NetworkStack::connect(host, port)) {
        return false;
    }

    // Send the data
    bool result = NetworkStack::sendData(data);

    // Cleanup
    NetworkStack::disconnect();
    return result;
}

std::vector<uint8_t> Communication::receiveData() {
    return NetworkStack::receiveData();
}

bool Communication::sendKeyRenewalRequest(const std::string& destination, const std::vector<uint8_t>& newPublicKey) {
    // In a real application, you'd send a special "renewal request" message with the new public key
    Logger::logEvent(LogLevel::Info, "Sending key renewal request (demo).");
    return true; // Stub success
}

std::vector<uint8_t> Communication::receiveKeyRenewalResponse() {
    // In a real application, you'd wait for a response from the peer
    Logger::logEvent(LogLevel::Info, "Receiving key renewal response (demo).");
    // Return a dummy new public key
    return { 0x99, 0x88, 0x77, 0x66 };
}

} // namespace secure_comm
