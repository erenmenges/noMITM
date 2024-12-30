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
            auto response = Communication::packageMessage(
                std::vector<uint8_t>(decryptedMsg.begin(), decryptedMsg.end()),
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
        
        // Initialize systems with proper error handling
        if (!NetworkStack::initialize()) {
            throw std::runtime_error("Failed to initialize network stack");
        }
        
        if (!KeyManagement::initialize()) {
            throw std::runtime_error("Failed to initialize key management");
        }
        
        // Parse command line arguments
        bool server_mode = (argc > 1 && std::string(argv[1]) == "--server");
        uint16_t port = (argc > 2) ? validatePort(argv[2]) : 8443;
        
        if (server_mode) {
            Logger::logEvent(LogLevel::Info, "Starting server mode on port " + std::to_string(port));
            
            if (!NetworkStack::startServer(port, handleSecureMessage)) {
                throw std::runtime_error("Failed to start server");
            }
            
            // Schedule key renewal with proper interval
            KeyManagement::scheduleKeyRenewal(std::chrono::hours(1));
            
            // Main server loop with proper shutdown handling
            while (!shutdownRequested) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        } else {
            Logger::logEvent(LogLevel::Info, "Starting client mode");
            
            // Establish secure session with proper key handling
            auto clientKeyPair = KeyManagement::getCurrentEphemeralKeyPair();
            if (!KeyManagement::establishSession(clientKeyPair.publicKey)) {
                throw std::runtime_error("Failed to establish secure session");
            }
            
            // Send test message with proper validation
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
