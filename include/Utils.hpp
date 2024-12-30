#pragma once

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include <unordered_map>
#include <shared_mutex>

namespace secure_comm {

class Utils {
public:
    static constexpr auto NONCE_EXPIRY_TIME = std::chrono::hours(24);
    
    // Nonce management
    static std::string generateNonce();
    static bool validateNonce(const std::string& nonce);
    
    // Timestamp utilities
    static uint64_t getCurrentTimestamp();
    static bool validateTimestamp(uint64_t timestamp);
    
private:
    static constexpr size_t NONCE_SIZE = 32; // 256 bits
    static constexpr std::chrono::seconds TIMESTAMP_TOLERANCE{300}; // 5 minutes
    
    static std::shared_mutex nonce_mutex_;
    static std::unordered_map<std::string, std::chrono::system_clock::time_point> used_nonces_;
};

} // namespace secure_comm
