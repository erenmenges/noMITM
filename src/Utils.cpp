#include "Utils.hpp"            // Include the header for function declarations
#include <random>               // For generating random numbers
#include <unordered_set>        // For storing used nonces

namespace secure_comm { // Begin namespace secure_comm

namespace {
    // A static/global in-memory store of used nonces; real code might store this differently
    std::unordered_set<std::string> g_usedNonces; 
}

std::string Utils::generateNonce() {
    // Create a static 64-bit Mersenne Twister engine seeded with a random device
    static std::mt19937_64 rng{std::random_device{}()};
    // Create a uniform distribution over the full range of uint64_t
    static std::uniform_int_distribution<uint64_t> dist;

    // Generate a random 64-bit number
    auto randomValue = dist(rng);
    // Convert to string (very simplistic nonce)
    auto nonce = std::to_string(randomValue);
    return nonce;
}

uint64_t Utils::getCurrentTimestamp() {
    using namespace std::chrono; // Bring chrono types into scope
    // Get current time from system_clock and convert to a duration since epoch
    auto now = system_clock::now().time_since_epoch();
    // Convert duration to seconds (integer)
    return static_cast<uint64_t>(duration_cast<seconds>(now).count());
}

bool Utils::validateNonce(const std::string& nonce) {
    // Check if this nonce was already used
    if (g_usedNonces.find(nonce) != g_usedNonces.end()) {
        return false; // If found, it's invalid
    }
    // Otherwise, record it as used
    g_usedNonces.insert(nonce);
    return true; // Valid if not previously used
}

bool Utils::validateTimestamp(uint64_t timestamp) {
    // We'll allow a ±5 minute skew
    const uint64_t ALLOWED_SKEW = 300; // 300 seconds = 5 minutes
    uint64_t now = getCurrentTimestamp(); // Current time

    // If timestamp is too far in the past
    if (timestamp + ALLOWED_SKEW < now) 
        return false;
    // If timestamp is too far in the future
    if (timestamp > now + ALLOWED_SKEW) 
        return false;

    return true; // Otherwise valid
}

} // namespace secure_comm
