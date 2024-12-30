#include "Communication.hpp"
#include "KeyManagement.hpp"
#include "Logger.hpp"
#include "NetworkStack.hpp"
#include "Utils.hpp"
#include <csignal>
#include <thread>
#include <atomic>
#include <chrono>
#include <filesystem>

namespace secure_comm {

namespace {
    std::atomic<bool> shutdownRequested{false};
    std::mutex cleanup_mutex;
    bool cleanup_performed{false};

    void signalHandler(int signum) {
        Logger::logEvent(LogLevel::Info, 
            "Shutdown signal " + std::to_string(signum) + " received");
        shutdownRequested = true;
    }

    struct AckMessage {
        std::vector<uint8_t> messageHash;
        uint64_t timestamp;
        MessageStatus status;

        std::vector<uint8_t> serialize() const {
            // Basic serialization - you may want to implement a more robust version
            std::vector<uint8_t> result;
            result.insert(result.end(), messageHash.begin(), messageHash.end());
            result.insert(result.end(), reinterpret_cast<const uint8_t*>(&timestamp),
                         reinterpret_cast<const uint8_t*>(&timestamp) + sizeof(timestamp));
            result.push_back(static_cast<uint8_t>(status));
            return result;
        }
    };

    void handleSecureMessage(const std::vector<uint8_t>& message) {
        try {
            if (message.empty()) {
                throw std::invalid_argument("Empty message received");
            }

            // Process received message with proper validation
            auto decryptedMsg = Communication::processIncomingMessage(message);
            
            if (!decryptedMsg.empty()) {
                Logger::logEvent(LogLevel::Info, 
                    "Received and processed message successfully");
            }
            
            // Send acknowledgment
            AckMessage ack{
                .messageHash = Utils::computeHash(message),  // Hash of original message
                .timestamp = Utils::getCurrentTimestamp(),
                .status = MessageStatus::Received
            };

            auto response = Communication::packageMessage(
                ack.serialize(),
                KeyManagement::getCurrentEphemeralKeyPair().publicKey,
                Utils::generateNonce(),
                Utils::getCurrentTimestamp()
            );
            
            if (!Communication::sendSecureMessage("response", 
                std::string(response.encryptedData.begin(), response.encryptedData.end()))) {
                throw std::runtime_error("Failed to send acknowledgment");
            }
        }
        catch (const std::exception& e) {
            Logger::logError(ErrorCode::ProcessingError,
                std::string("Failed to handle message: ") + e.what());
        }
    }

    void performCleanup() {
        std::lock_guard<std::mutex> lock(cleanup_mutex);
        if (!cleanup_performed) {
            try {
                KeyManagement::cleanup();
                NetworkStack::cleanup();
                Logger::flush();
                cleanup_performed = true;
                Logger::logEvent(LogLevel::Info, "Cleanup completed successfully");
            }
            catch (const std::exception& e) {
                Logger::logError(ErrorCode::ProcessingError,
                    std::string("Cleanup failed: ") + e.what());
            }
        }
    }
}

} // namespace secure_comm

constexpr uint16_t MIN_PORT = 1024;
constexpr uint16_t MAX_PORT = 65535;

uint16_t validatePort(const char* port_str) {
    try {
        int port = std::stoi(port_str);
        if (port < MIN_PORT || port > MAX_PORT) {
            throw std::runtime_error("Port must be between 1024 and 65535");
        }
        return static_cast<uint16_t>(port);
    }
    catch (const std::exception& e) {
        throw std::runtime_error("Invalid port number");
    }
}

enum class MessageStatus : uint8_t {
    Received = 0,
    Error = 1
};

int main(int argc, char* argv[]) {
    using namespace secure_comm;
    
    try {
        // Set up signal handlers
        std::signal(SIGINT, signalHandler);
        std::signal(SIGTERM, signalHandler);
        
        // Configure logging
        Logger::setLogLevel(LogLevel::Info);
        Logger::setLogFile("secure_comm.log");
        Logger::enableConsoleOutput(true);
        
        Logger::logEvent(LogLevel::Info, "Secure Communication System starting...");
        
        // Parse command line arguments
        bool server_mode = (argc > 1 && std::string(argv[1]) == "--server");
        uint16_t port = (argc > 2) ? validatePort(argv[2]) : 8443;
        
        if (server_mode) {
            Logger::logEvent(LogLevel::Info, "Starting server mode on port " + std::to_string(port));
            
            // Initialize network stack singleton
            auto& network = NetworkStack::getInstance();
            
            // Initialize key management
            if (!KeyManagement::initialize()) {
                throw std::runtime_error("Failed to initialize key management");
            }
            
            // Start message handling loop
            while (!shutdownRequested) {
                try {
                    auto message = network.receive();
                    if (!message.empty()) {
                        handleSecureMessage(message);
                    }
                }
                catch (const std::exception& e) {
                    Logger::logError(ErrorCode::ProcessingError,
                        std::string("Error in message loop: ") + e.what());
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        } else {
            Logger::logEvent(LogLevel::Info, "Starting client mode");
            
            // Initialize network stack singleton
            auto& network = NetworkStack::getInstance();
            
            // Initialize key management
            if (!KeyManagement::initialize()) {
                throw std::runtime_error("Failed to initialize key management");
            }
            
            // Establish secure session
            auto clientKeyPair = KeyManagement::getCurrentEphemeralKeyPair();
            if (!KeyManagement::establishSession(clientKeyPair.publicKey)) {
                throw std::runtime_error("Failed to establish secure session");
            }
            
            // Send test message
            std::string message = "Hello, secure server!";
            if (!Communication::sendSecureMessage("localhost:" + std::to_string(port), message)) {
                throw std::runtime_error("Failed to send secure message");
            }
            
            Logger::logEvent(LogLevel::Info, "Message sent successfully");
        }
        
        performCleanup();
        return 0;
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Fatal error: ") + e.what());
        performCleanup();
        return 1;
    }
}
