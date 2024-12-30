#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <string_view>
#include <chrono>

namespace secure_comm {

class NetworkStack {
public:
    static bool initialize();
    static void cleanup();
    
    // Server operations
    static bool startServer(uint16_t port, 
        std::function<void(const std::vector<uint8_t>&)> messageHandler);
    static void stopServer();
    
    // Client operations
    static bool connect(std::string_view host, uint16_t port);
    static void disconnect();
    static bool sendData(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> receiveData(
        std::chrono::milliseconds timeout = std::chrono::milliseconds(1000));

private:
    // Constants
    static constexpr size_t INITIAL_BUFFER_SIZE = 1024;
    static constexpr size_t MAX_BUFFER_SIZE = 1024 * 1024; // 1MB max message size
    static constexpr int MAX_CONNECTIONS = 10;
    static constexpr int SOCKET_TIMEOUT_MS = 1000;
    
    struct Message {
        std::vector<uint8_t> data;
        uint32_t expected_size;
        bool header_received;
        std::chrono::system_clock::time_point last_activity;
        
        Message() : expected_size(0), header_received(false),
                   last_activity(std::chrono::system_clock::now()) {}
    };
    
    // Static member variables
    static std::atomic<bool> running_;
    static std::atomic<int> server_socket_;
    static std::atomic<int> client_socket_;
    static std::atomic<bool> is_server_;
    static std::thread server_thread_;
    static std::map<int, Message> incomplete_messages_;
    static std::vector<uint8_t> read_buffer_;
    static std::function<void(const std::vector<uint8_t>&)> message_handler_;
    static std::mutex network_mutex_;
    static std::mutex message_mutex_;
    
    // Private methods
    static void serverLoop();
    static void handleClient(int client_socket, 
        std::function<void(const std::vector<uint8_t>&)> messageHandler);
    static bool setSocketOptions(int socket);
    static bool validateMessageSize(size_t size);
    static void cleanupSocket(std::atomic<int>& socket);
    static void cleanupSocket(int socket);
    static void cleanupInactiveConnections();
    
    // Prevent instantiation
    NetworkStack() = delete;
    ~NetworkStack() = delete;
    NetworkStack(const NetworkStack&) = delete;
    NetworkStack& operator=(const NetworkStack&) = delete;
};

} // namespace secure_comm 