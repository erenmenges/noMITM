#include "NetworkStack.hpp"
#include "Logger.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <thread>
#include <cstring>

namespace secure_comm {

// Initialize static members
int NetworkStack::server_socket_ = -1;
int NetworkStack::client_socket_ = -1;
bool NetworkStack::is_server_ = false;
bool NetworkStack::running_ = false;
std::vector<uint8_t> NetworkStack::read_buffer_(1024); // 1KB buffer

void NetworkStack::initialize() {
    // Nothing specific needed for initialization with raw sockets
    Logger::logEvent(LogLevel::Info, "Network stack initialized");
}

void NetworkStack::cleanup() {
    if (client_socket_ != -1) {
        close(client_socket_);
        client_socket_ = -1;
    }
    if (server_socket_ != -1) {
        close(server_socket_);
        server_socket_ = -1;
    }
    running_ = false;
    Logger::logEvent(LogLevel::Info, "Network stack cleaned up");
}

void NetworkStack::startServer(uint16_t port, 
    std::function<void(const std::vector<uint8_t>&)> messageHandler) {
    
    try {
        is_server_ = true;
        running_ = true;

        // Create socket
        server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket_ == -1) {
            throw std::runtime_error("Failed to create socket");
        }

        // Set socket options
        int opt = 1;
        if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            throw std::runtime_error("Failed to set socket options");
        }

        // Bind socket
        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);

        if (bind(server_socket_, (struct sockaddr*)&address, sizeof(address)) < 0) {
            throw std::runtime_error("Failed to bind socket");
        }

        // Listen for connections
        if (listen(server_socket_, 3) < 0) {
            throw std::runtime_error("Failed to listen");
        }

        // Start accepting connections in a separate thread
        std::thread([this, messageHandler]() {
            while (running_) {
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                
                int new_socket = accept(server_socket_, 
                    (struct sockaddr*)&client_addr, &addr_len);
                
                if (new_socket >= 0) {
                    // Handle client in a new thread
                    std::thread(&NetworkStack::handleClient, 
                        new_socket, messageHandler).detach();
                }
            }
        }).detach();

        Logger::logEvent(LogLevel::Info, "Server started on port " + std::to_string(port));
    }
    catch (const std::exception& e) {
        Logger::logEvent(LogLevel::Error, "Server error: " + std::string(e.what()));
        running_ = false;
        cleanup();
    }
}

void NetworkStack::handleClient(int client_socket, 
    std::function<void(const std::vector<uint8_t>&)> messageHandler) {
    
    std::vector<uint8_t> buffer(1024);
    
    while (running_) {
        ssize_t bytes_read = recv(client_socket, buffer.data(), buffer.size(), 0);
        
        if (bytes_read > 0) {
            std::vector<uint8_t> received_data(buffer.begin(), 
                buffer.begin() + bytes_read);
            messageHandler(received_data);
        }
        else if (bytes_read <= 0) {
            break; // Connection closed or error
        }
    }
    
    close(client_socket);
}

void NetworkStack::stopServer() {
    if (is_server_ && running_) {
        cleanup();
        Logger::logEvent(LogLevel::Info, "Server stopped");
    }
}

bool NetworkStack::connect(const std::string& host, uint16_t port) {
    try {
        // Create socket
        client_socket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (client_socket_ == -1) {
            throw std::runtime_error("Failed to create socket");
        }

        // Resolve hostname
        struct hostent* server = gethostbyname(host.c_str());
        if (server == nullptr) {
            throw std::runtime_error("Failed to resolve hostname");
        }

        // Prepare the sockaddr_in structure
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        memcpy(&server_addr.sin_addr.s_addr, server->h_addr, server->h_length);
        server_addr.sin_port = htons(port);

        // Connect to server
        if (::connect(client_socket_, (struct sockaddr*)&server_addr, 
            sizeof(server_addr)) < 0) {
            throw std::runtime_error("Connection failed");
        }

        Logger::logEvent(LogLevel::Info, 
            "Connected to " + host + ":" + std::to_string(port));
        return true;
    }
    catch (const std::exception& e) {
        Logger::logEvent(LogLevel::Error, 
            "Connection error: " + std::string(e.what()));
        cleanup();
        return false;
    }
}

void NetworkStack::disconnect() {
    if (client_socket_ != -1) {
        close(client_socket_);
        client_socket_ = -1;
        Logger::logEvent(LogLevel::Info, "Disconnected from remote host");
    }
}

bool NetworkStack::sendData(const std::vector<uint8_t>& data) {
    if (client_socket_ == -1) {
        Logger::logEvent(LogLevel::Error, "Cannot send data: Not connected");
        return false;
    }

    try {
        ssize_t bytes_sent = send(client_socket_, data.data(), data.size(), 0);
        if (bytes_sent < 0) {
            throw std::runtime_error("Send failed");
        }
        Logger::logEvent(LogLevel::Info, 
            "Sent " + std::to_string(bytes_sent) + " bytes");
        return true;
    }
    catch (const std::exception& e) {
        Logger::logEvent(LogLevel::Error, 
            "Send error: " + std::string(e.what()));
        return false;
    }
}

std::vector<uint8_t> NetworkStack::receiveData() {
    if (client_socket_ == -1) {
        Logger::logEvent(LogLevel::Error, "Cannot receive data: Not connected");
        return {};
    }

    try {
        ssize_t bytes_received = recv(client_socket_, 
            read_buffer_.data(), read_buffer_.size(), 0);
        
        if (bytes_received > 0) {
            Logger::logEvent(LogLevel::Info, 
                "Received " + std::to_string(bytes_received) + " bytes");
            return std::vector<uint8_t>(read_buffer_.begin(), 
                read_buffer_.begin() + bytes_received);
        }
        return {};
    }
    catch (const std::exception& e) {
        Logger::logEvent(LogLevel::Error, 
            "Receive error: " + std::string(e.what()));
        return {};
    }
}

} // namespace secure_comm 