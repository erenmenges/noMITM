#pragma once

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <unordered_map>
#include "Crypto.hpp"
#include "SecureTypes.hpp"

namespace secure_comm {

class KeyManagement {
public:
    static bool initialize();
    static void cleanup();
    
    // Session management
    static bool establishSession(const std::vector<uint8_t>& peerPublicKey);
    static const ECDHKeyPair& getCurrentEphemeralKeyPair();
    static const std::vector<uint8_t>& getCurrentSessionKey();
    static const std::vector<uint8_t>& getPeerPublicKey();
    
    // Key renewal
    static void scheduleKeyRenewal(std::chrono::seconds interval);
    static bool performKeyRenewal();
    
private:
    static bool verifyKeyRenewalResponse(const KeyRenewalResponse& response);
    static void renewalThread(std::chrono::seconds interval);
    static void secureErase(std::vector<uint8_t>& data);

    // Constants
    static constexpr std::chrono::minutes MAX_KEY_AGE{60};
    static constexpr std::chrono::seconds MIN_RENEWAL_INTERVAL{60};
    
    // Static member variables
    static std::mutex renewal_mutex_;
    static std::condition_variable renewal_cv_;
    static bool renewal_in_progress_;
    static std::atomic<bool> shutdown_requested_;
    static std::thread renewal_thread_;
    
    static std::mutex key_mutex_;
    static ECDHKeyPair current_ephemeral_keypair_;
    static std::vector<uint8_t> current_session_key_;
    static std::vector<uint8_t> peer_public_key_;
    static std::atomic<bool> session_established_;
    static std::chrono::system_clock::time_point last_renewal_;
    
    static std::unordered_map<std::string, std::vector<uint8_t>> cached_certificates_;
    static std::mutex cert_cache_mutex_;
};

} // namespace secure_comm
