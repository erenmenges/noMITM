#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace secure_comm {

class NetworkStack {
public:
    // Initialize networking stack
    static void initialize();
    
    // Cleanup networking stack
    static void cleanup();

    // Server operations
    static void startServer(uint16_t port, 
        std::function<void(const std::vector<uint8_t>&)> messageHandler);
    static void stopServer();

    // Client operations
    static bool connect(const std::string& host, uint16_t port);
    static void disconnect();
    
    // Send/receive operations
    static bool sendData(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> receiveData();

private:
    static int server_socket_;
    static int client_socket_;
    static bool is_server_;
    static bool running_;
    static std::vector<uint8_t> read_buffer_;
    
    static void handleClient(int client_socket, 
        std::function<void(const std::vector<uint8_t>&)> messageHandler);
};

} // namespace secure_comm 