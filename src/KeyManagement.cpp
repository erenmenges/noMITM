#include "KeyManagement.hpp" // Include our own header
#include "Logger.hpp"        // For logging
#include "OCSP.hpp"          // For OCSP checking
#include <fstream>           // For file IO
#include <thread>            // For std::thread
#include <chrono>            // For std::chrono::seconds

namespace secure_comm { // Begin namespace secure_comm

// Define the static members
Crypto::ECDHKeyPair KeyManagement::currentEphemeralKeyPair;  // Holds ephemeral key pair
std::vector<uint8_t> KeyManagement::currentSessionKey;        // Holds current session key

bool KeyManagement::loadCertificate(const std::string& filepath, std::string& outPem) {
    // Open the file at 'filepath'
    std::ifstream in(filepath);
    if (!in.is_open()) {
        // If cannot open, log error and return false
        Logger::logError(ErrorCode::CertificateVerificationFailed, "Cannot open certificate file: " + filepath);
        return false;
    }
    // Read the entire file into a string
    std::string pem((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    outPem = pem;
    return true; // Success
}

bool KeyManagement::loadPrivateKey(const std::string& filepath, std::vector<uint8_t>& outKey) {
    // Open the private key file in binary mode
    std::ifstream in(filepath, std::ios::binary);
    if (!in.is_open()) {
        // If cannot open, log error and return false
        Logger::logError(ErrorCode::CertificateVerificationFailed, "Cannot open private key file: " + filepath);
        return false;
    }
    // Read the file contents into a vector<uint8_t>
    outKey.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    return true; // Success
}

bool KeyManagement::verifyCertificate(const std::string& certPem, const std::string& caPem) {
    // In a real system, you would parse, build a cert chain, check trust, etc.
    // For demonstration, we just check if strings are non-empty
    if (certPem.empty() || caPem.empty()) {
        Logger::logError(ErrorCode::CertificateVerificationFailed, "Certificate or CA is empty.");
        return false;
    }
    // Then check revocation with OCSP
    if (!OCSP::checkCertificateRevocation(certPem)) {
        Logger::logError(ErrorCode::CertificateRevoked, "Certificate has been revoked.");
        return false;
    }
    // Otherwise, assume verification succeeded
    Logger::logEvent(LogLevel::Info, "Certificate verified successfully (demo).");
    return true;
}

void KeyManagement::scheduleKeyRenewal(int secondsUntilRenewal) {
    // Start a detached thread that waits and then initiates key renewal
    std::thread([secondsUntilRenewal]() {
        std::this_thread::sleep_for(std::chrono::seconds(secondsUntilRenewal));
        initiateKeyRenewal();
    }).detach(); // Detach so it runs independently
}

void KeyManagement::initiateKeyRenewal() {
    Logger::logEvent(LogLevel::Info, "Initiating key renewal (demo).");
    // Generate a new ephemeral key pair
    auto newEphemeralKP = Crypto::generateEphemeralKeyPair();

    // In real code, we'd send the new public key to the peer
    // e.g., Communication::sendKeyRenewalRequest(...)

    // Store it (for demonstration)
    currentEphemeralKeyPair = newEphemeralKP;
}

void KeyManagement::handleKeyRenewalRequest(const std::vector<uint8_t>& newPublicKey) {
    Logger::logEvent(LogLevel::Info, "Handling key renewal request (demo).");
    // Generate our new ephemeral key
    auto newEphemeralKP = Crypto::generateEphemeralKeyPair();

    // In real code, we would send our new public key back to the peer
    // Then both sides derive a new session key
    auto newSessionKey = Crypto::deriveSessionKey(newPublicKey, newEphemeralKP.privateKey);

    // Store the new session key
    currentSessionKey = newSessionKey;
    Logger::logEvent(LogLevel::Info, "Session key updated successfully (demo).");
}

} // namespace secure_comm
