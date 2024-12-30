#pragma once // Ensures this header is only included once

#include <string>   // For std::string
#include <chrono>   // For time utilities
#include <cstdint>  // For fixed-width integer types

namespace secure_comm { // Begin namespace secure_comm

class Utils {
public:
    static std::string generateNonce();          // Generates a random nonce as a string
    static uint64_t getCurrentTimestamp();       // Retrieves the current Unix timestamp in seconds

    // Validates that the provided nonce is unique/not used before
    static bool validateNonce(const std::string& nonce);

    // Validates that the provided timestamp is within an acceptable time window
    static bool validateTimestamp(uint64_t timestamp);
};

} // namespace secure_comm
