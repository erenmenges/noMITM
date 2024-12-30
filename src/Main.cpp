#include "Logger.hpp"
#include "Crypto.hpp"
#include "Utils.hpp"
#include "Communication.hpp"
#include "NetworkStack.hpp"
#include <thread>
#include <chrono>

using namespace secure_comm;

// Handler for received messages
void handleMessage(const std::vector<uint8_t>& data) {
    Logger::logEvent(LogLevel::Info, "Received message of size: " + std::to_string(data.size()));
    // Process message here...
}

int main(int argc, char* argv[]) {
    Logger::logEvent(LogLevel::Info, "Secure Comm Demo started.");
    
    // Initialize networking stack
    NetworkStack::initialize();

    // Check if we should run as server or client
    if (argc > 1 && std::string(argv[1]) == "--server") {
        // Run as server
        Logger::logEvent(LogLevel::Info, "Starting server mode...");
        NetworkStack::startServer(8443, handleMessage);
        
        // Keep server running
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    } else {
        // Run as client
        Logger::logEvent(LogLevel::Info, "Starting client mode...");

        // Generate ephemeral keys
        auto clientEphemKP = Crypto::generateEphemeralKeyPair();
        auto serverEphemKP = Crypto::generateEphemeralKeyPair();

        // Derive session key
        auto clientSessionKey = Crypto::deriveSessionKey(serverEphemKP.publicKey, clientEphemKP.privateKey);

        // Create a test message
        std::string message = "Hello from Client to Server!";
        auto ciphertext = Crypto::aesEncrypt(message, clientSessionKey);

        // Create signature
        auto hash = Crypto::sha256(message);
        auto signature = Crypto::ecdsaSign(hash, clientEphemKP.privateKey);
        auto nonce = Utils::generateNonce();
        auto timestamp = Utils::getCurrentTimestamp();

        // Package message
        auto pkg = Communication::packageMessage(ciphertext, signature, nonce, timestamp);

        // Send the message
        Logger::logEvent(LogLevel::Info, "Sending message to server...");
        Communication::sendData("localhost:8443", ciphertext);

        // Wait briefly to ensure message is sent
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Cleanup
    NetworkStack::cleanup();
    Logger::logEvent(LogLevel::Info, "Secure Comm Demo finished.");
    return 0;
}
