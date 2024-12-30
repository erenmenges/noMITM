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
    static NetworkStack& getInstance() {
        static NetworkStack instance;
        return instance;
    }

    bool initialize();
    bool startServer(uint16_t port, std::function<void(const std::vector<uint8_t>&)> messageHandler);
    bool connect(std::string_view host, uint16_t port);
    bool sendData(const std::vector<uint8_t>& data);
    static void cleanup();

private:
    struct Message {
        std::vector<uint8_t> data;
        size_t expected_size = 0;
        bool header_received = false;
        std::chrono::system_clock::time_point last_activity;
    };

    static void serverLoop();
    static void handleClient(int client_socket, std::function<void(const std::vector<uint8_t>&)> messageHandler);
    static bool setSocketOptions(int socket);
    static void cleanupSocket(int socket);
    static void cleanupInactiveConnections();
    static bool validateMessageSize(size_t size);

    NetworkStack() = default;
    ~NetworkStack() = default;
    NetworkStack(const NetworkStack&) = delete;
    NetworkStack& operator=(const NetworkStack&) = delete;

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
};

// Constants
constexpr size_t INITIAL_BUFFER_SIZE = 4096;
constexpr int SOCKET_TIMEOUT_MS = 5000;

} // namespace secure_comm 