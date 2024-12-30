#include "NetworkStack.hpp"
#include "Logger.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <string.h>
#include <openssl/ssl.h>

namespace secure_comm {

namespace {
    constexpr int POLL_TIMEOUT = 1000; // 1 second timeout for poll
    constexpr size_t MAX_CONNECTIONS = 10;
}

constexpr size_t MAX_BUFFER_SIZE = 1024; // Define MAX_BUFFER_SIZE if not already defined

// Initialize static member variables
std::atomic<bool> NetworkStack::running_{false};           // Flag indicating if network stack is running
std::atomic<int> NetworkStack::server_socket_{-1};         // Server socket file descriptor
std::atomic<int> NetworkStack::client_socket_{-1};         // Client socket file descriptor
std::atomic<bool> NetworkStack::is_server_{false};         // Flag indicating if instance is server
std::thread NetworkStack::server_thread_;                  // Thread for handling server operations
std::map<int, NetworkStack::Message> NetworkStack::incomplete_messages_; // Buffer for partial messages
std::vector<uint8_t> NetworkStack::read_buffer_(INITIAL_BUFFER_SIZE);   // Buffer for reading data
std::function<void(const std::vector<uint8_t>&)> NetworkStack::message_handler_; // Callback for message handling
std::mutex NetworkStack::network_mutex_;                   // Mutex for network operations
std::mutex NetworkStack::message_mutex_;                   // Mutex for message handling

bool NetworkStack::initialize() {
    try {
        // Lock network operations during initialization
        std::lock_guard<std::mutex> lock(network_mutex_);
        
        // Clear and resize the read buffer if it's not empty
        if (!read_buffer_.empty()) {
            read_buffer_.clear();
        }
        read_buffer_.reserve(INITIAL_BUFFER_SIZE);
        
        // Initialize OpenSSL library components
        SSL_library_init();              // Initialize SSL library
        SSL_load_error_strings();        // Load SSL error strings
        OpenSSL_add_all_algorithms();    // Load all available algorithms
        
        return true;
    }
    catch (const std::exception& e) {
        // Log any initialization errors and cleanup
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Failed to initialize network stack: ") + e.what());
        cleanup();
        return false;
    }
}

bool NetworkStack::setSocketOptions(int socket) {
    // Validate socket descriptor
    if (socket < 0) return false;

    // Create timeout structure for socket operations
    struct timeval tv;
    tv.tv_sec = SOCKET_TIMEOUT_MS / 1000;        // Convert milliseconds to seconds
    tv.tv_usec = (SOCKET_TIMEOUT_MS % 1000) * 1000;  // Remaining milliseconds to microseconds
    
    // Set receive and send timeouts for the socket
    if (setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        return false;
    }

    // Get current socket flags
    int flags = fcntl(socket, F_GETFL, 0);
    // Set socket to non-blocking mode while preserving existing flags
    if (flags < 0 || fcntl(socket, F_SETFL, flags | O_NONBLOCK) < 0) {
        return false;
    }

    // Enable TCP keepalive to detect dead connections
    int keepalive = 1;
    if (setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive)) < 0) {
        return false;
    }

    return true;
}

bool NetworkStack::startServer(uint16_t port,
    std::function<void(const std::vector<uint8_t>&)> messageHandler)
{
    try {
        // Ensure thread safety during server initialization
        std::lock_guard<std::mutex> lock(network_mutex_);
        
        // Check if server is already running
        if (running_.load() || server_socket_.load() >= 0) {
            throw std::runtime_error("Server already running");
        }

        // Create TCP socket
        int server_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (server_sock < 0) {
            throw std::runtime_error("Failed to create server socket");
        }

        // Configure socket options (timeouts, non-blocking, keepalive)
        if (!setSocketOptions(server_sock)) {
            close(server_sock);
            throw std::runtime_error("Failed to set socket options");
        }

        // Enable immediate address reuse after server shutdown
        int reuse = 1;
        if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            close(server_sock);
            throw std::runtime_error("Failed to set SO_REUSEADDR");
        }

        // Prepare server address structure
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));     // Clear structure
        server_addr.sin_family = AF_INET;                 // IPv4
        server_addr.sin_addr.s_addr = INADDR_ANY;         // Listen on all interfaces
        server_addr.sin_port = htons(port);               // Set port in network byte order

        // Bind socket to address and port
        if (bind(server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(server_sock);
            throw std::runtime_error("Failed to bind server socket");
        }

        // Start listening for incoming connections
        if (listen(server_sock, MAX_CONNECTIONS) < 0) {
            close(server_sock);
            throw std::runtime_error("Failed to listen on server socket");
        }

        // Store server configuration
        server_socket_ = server_sock;           // Save socket descriptor
        message_handler_ = messageHandler;      // Save message callback
        is_server_ = true;                     // Mark as server mode
        running_ = true;                       // Set running flag

        // Start server thread
        server_thread_ = std::thread(&NetworkStack::serverLoop);
        
        Logger::logEvent(LogLevel::Info, "Server started successfully");
        return true;

    } catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Failed to start server: ") + e.what());
        return false;
    }
}

void NetworkStack::serverLoop() {
    try {
        while (running_) {
            std::vector<pollfd> poll_fds;
            
            {
                std::lock_guard<std::mutex> lock(network_mutex_);
                poll_fds.push_back({server_socket_.load(), POLLIN, 0});
                
                for (const auto& [client_fd, _] : incomplete_messages_) {
                    poll_fds.push_back({client_fd, POLLIN, 0});
                }
            }

            int poll_result = poll(poll_fds.data(), poll_fds.size(), POLL_TIMEOUT);
            if (poll_result < 0) {
                if (errno != EINTR) {
                    throw std::runtime_error("Poll failed: " + std::string(strerror(errno)));
                }
                continue;
            }

            // Handle new connections
            if (poll_fds[0].revents & POLLIN) {
                struct sockaddr_in client_addr;
                socklen_t addr_len = sizeof(client_addr);
                
                int client_sock = accept(server_socket_.load(), 
                    (struct sockaddr*)&client_addr, &addr_len);
                
                if (client_sock >= 0) {
                    if (!setSocketOptions(client_sock)) {
                        close(client_sock);
                        Logger::logEvent(LogLevel::Warning, 
                            "Failed to set options for client socket");
                        continue;
                    }

                    std::lock_guard<std::mutex> lock(message_mutex_);
                    incomplete_messages_[client_sock] = Message();
                    Logger::logEvent(LogLevel::Info, "New client connected");
                }
            }

            // Handle client data
            for (size_t i = 1; i < poll_fds.size(); ++i) {
                if (poll_fds[i].revents & (POLLIN | POLLHUP)) {
                    handleClient(poll_fds[i].fd, message_handler_);
                }
            }

            cleanupInactiveConnections();
        }
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Server loop failed: ") + e.what());
    }
}

void NetworkStack::handleClient(int client_socket, 
    std::function<void(const std::vector<uint8_t>&)> messageHandler)
{
    try {
        std::vector<uint8_t> buffer(INITIAL_BUFFER_SIZE);
        ssize_t bytes_read = recv(client_socket, buffer.data(), buffer.size(), 0);

        if (bytes_read <= 0) {
            if (bytes_read == 0 || errno != EAGAIN) {
                cleanupSocket(client_socket);
            }
            return;
        }

        std::lock_guard<std::mutex> lock(message_mutex_);
        auto& message = incomplete_messages_[client_socket];
        message.last_activity = std::chrono::system_clock::now();

        if (!message.header_received) {
            if (bytes_read < sizeof(uint32_t)) {
                return;
            }

            message.expected_size = *reinterpret_cast<uint32_t*>(buffer.data());
            if (!validateMessageSize(message.expected_size)) {
                cleanupSocket(client_socket);
                return;
            }

            message.header_received = true;
            message.data.reserve(message.expected_size);
            message.data.insert(message.data.end(), 
                buffer.begin() + sizeof(uint32_t),
                buffer.begin() + bytes_read);
        } else {
            message.data.insert(message.data.end(), 
                buffer.begin(), 
                buffer.begin() + bytes_read);
        }

        if (message.data.size() >= message.expected_size) {
            messageHandler(message.data);
            incomplete_messages_.erase(client_socket);
        }
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Failed to handle client: ") + e.what());
        cleanupSocket(client_socket);
    }
}

bool NetworkStack::connect(std::string_view host, uint16_t port) {
    try {
        std::lock_guard<std::mutex> lock(network_mutex_);
        
        if (client_socket_.load() >= 0) {
            throw std::runtime_error("Already connected");
        }

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            throw std::runtime_error("Failed to create client socket");
        }

        if (!setSocketOptions(sock)) {
            close(sock);
            throw std::runtime_error("Failed to set socket options");
        }

        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, host.data(), &server_addr.sin_addr) <= 0) {
            close(sock);
            throw std::runtime_error("Invalid address");
        }

        if (::connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(sock);
            throw std::runtime_error("Connection failed");
        }

        client_socket_ = sock;
        running_ = true;
        Logger::logEvent(LogLevel::Info, "Connected to server successfully");
        return true;
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Failed to connect: ") + e.what());
        return false;
    }
}

bool NetworkStack::sendData(const std::vector<uint8_t>& data) {
    try {
        if (!validateMessageSize(data.size())) {
            throw std::runtime_error("Invalid message size");
        }

        std::lock_guard<std::mutex> lock(network_mutex_);
        int socket = is_server_ ? server_socket_.load() : client_socket_.load();
        
        if (socket < 0) {
            throw std::runtime_error("Not connected");
        }

        // Send size header
        uint32_t size = static_cast<uint32_t>(data.size());
        if (send(socket, &size, sizeof(size), 0) != sizeof(size)) {
            throw std::runtime_error("Failed to send message size");
        }

        // Send data
        size_t total_sent = 0;
        while (total_sent < data.size()) {
            ssize_t sent = send(socket, 
                data.data() + total_sent, 
                data.size() - total_sent, 
                0);
            
            if (sent <= 0) {
                if (errno != EAGAIN) {
                    throw std::runtime_error("Send failed");
                }
                continue;
            }
            
            total_sent += sent;
        }

        return true;
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Failed to send data: ") + e.what());
        return false;
    }
}

void NetworkStack::cleanupSocket(int socket) {
    if (socket >= 0) {
        close(socket);
    }
}

void NetworkStack::cleanupInactiveConnections() {
    std::lock_guard<std::mutex> lock(message_mutex_);
    auto now = std::chrono::system_clock::now();
    
    for (auto it = incomplete_messages_.begin(); it != incomplete_messages_.end();) {
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(
            now - it->second.last_activity).count();
            
        if (duration > SOCKET_TIMEOUT_MS / 1000) {
            cleanupSocket(it->first);
            it = incomplete_messages_.erase(it);
        } else {
            ++it;
        }
    }
}

void NetworkStack::cleanup() {
    running_ = false;
    
    if (server_thread_.joinable()) {
        server_thread_.join();
    }

    std::lock_guard<std::mutex> lock(network_mutex_);
    
    cleanupSocket(server_socket_);
    cleanupSocket(client_socket_);
    
    {
        std::lock_guard<std::mutex> msg_lock(message_mutex_);
        for (auto& [socket, _] : incomplete_messages_) {
            cleanupSocket(socket);
        }
        incomplete_messages_.clear();
    }
    
    is_server_ = false;
    Logger::logEvent(LogLevel::Info, "Network stack cleaned up successfully");
}

bool NetworkStack::validateMessageSize(size_t size) {
    return size > 0 && size <= MAX_BUFFER_SIZE;
}

void NetworkStack::startClientReceiveThread() {
    if (!client_receive_thread_.joinable()) {
        client_receive_thread_ = std::thread([this]() {
            std::vector<uint8_t> buffer(INITIAL_BUFFER_SIZE);
            
            while (running_) {
                try {
                    ssize_t bytes_read = recv(client_socket_.load(), 
                        buffer.data(), buffer.size(), 0);
                        
                    if (bytes_read > 0) {
                        std::lock_guard<std::mutex> lock(message_mutex_);
                        auto& message = incomplete_messages_[client_socket_.load()];
                        message.last_activity = std::chrono::system_clock::now();
                        
                        if (!message.header_received) {
                            if (bytes_read >= sizeof(uint32_t)) {
                                message.expected_size = *reinterpret_cast<uint32_t*>(buffer.data());
                                message.header_received = true;
                                message.data.insert(message.data.end(),
                                    buffer.begin() + sizeof(uint32_t),
                                    buffer.begin() + bytes_read);
                            }
                        } else {
                            message.data.insert(message.data.end(),
                                buffer.begin(), buffer.begin() + bytes_read);
                        }
                        
                        if (message.data.size() >= message.expected_size) {
                            if (message_handler_) {
                                message_handler_(message.data);
                            }
                            incomplete_messages_.erase(client_socket_.load());
                        }
                    }
                }
                catch (const std::exception& e) {
                    Logger::logError(ErrorCode::NetworkError,
                        std::string("Client receive error: ") + e.what());
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
    }
}

} // namespace secure_comm 