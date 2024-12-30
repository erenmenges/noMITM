#include <openssl/crypto.h>
#include "KeyManagement.hpp"
#include "Crypto.hpp"
#include "Logger.hpp"
#include "OCSP.hpp"
#include <algorithm>
#include "Utils.hpp"
#include "Communication.hpp"

namespace secure_comm {

// Static member initializations
std::mutex KeyManagement::renewal_mutex_;
std::condition_variable KeyManagement::renewal_cv_;
bool KeyManagement::renewal_in_progress_ = false;
std::atomic<bool> KeyManagement::shutdown_requested_{false};
std::thread KeyManagement::renewal_thread_;

std::mutex KeyManagement::key_mutex_;
ECDHKeyPair KeyManagement::current_ephemeral_keypair_;
std::vector<uint8_t> KeyManagement::current_session_key_;
std::vector<uint8_t> KeyManagement::peer_public_key_;
std::atomic<bool> KeyManagement::session_established_{false};
std::chrono::system_clock::time_point KeyManagement::last_renewal_;

std::unordered_map<std::string, std::vector<uint8_t>> KeyManagement::cached_certificates_;
std::mutex KeyManagement::cert_cache_mutex_;

class RenewalLockGuard {
public:
    RenewalLockGuard(std::mutex& mutex, bool& flag) 
        : mutex_(mutex), flag_(flag) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (flag_) throw std::runtime_error("Renewal already in progress");
        flag_ = true;
    }
    ~RenewalLockGuard() {
        std::lock_guard<std::mutex> lock(mutex_);
        flag_ = false;
    }
private:
    std::mutex& mutex_;
    bool& flag_;
};

void KeyManagement::secureErase(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
        data.shrink_to_fit();
    }
}

bool KeyManagement::initialize() {
    try {
        std::lock_guard<std::mutex> lock(key_mutex_);
        current_ephemeral_keypair_ = Crypto::generateEphemeralKeyPair();
        last_renewal_ = std::chrono::system_clock::now();
        Logger::logEvent(LogLevel::Security, "Initial ephemeral key pair generated");
        return true;
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Failed to initialize key management: ") + e.what());
        return false;
    }
}

void KeyManagement::scheduleKeyRenewal(std::chrono::seconds interval) {
    if (interval < MIN_RENEWAL_INTERVAL) {
        throw std::invalid_argument("Renewal interval too short");
    }

    {
        std::lock_guard<std::mutex> lock(renewal_mutex_);
        if (renewal_thread_.joinable()) {
            shutdown_requested_ = true;
            renewal_cv_.notify_all();
            renewal_thread_.join();
        }
        
        shutdown_requested_ = false;
        renewal_thread_ = std::thread(&KeyManagement::renewalThread, interval);
    }
}

void KeyManagement::renewalThread(std::chrono::seconds interval) {
    while (!shutdown_requested_) {
        {
            std::unique_lock<std::mutex> lock(renewal_mutex_);
            if (renewal_cv_.wait_for(lock, interval, 
                []{ return shutdown_requested_.load(); })) {
                break;
            }
        }
        
        if (!shutdown_requested_) {
            try {
                performKeyRenewal();
            }
            catch (const std::exception& e) {
                Logger::logError(ErrorCode::KeyRenewalFailed,
                    std::string("Scheduled key renewal failed: ") + e.what());
            }
        }
    }
}

bool KeyManagement::performKeyRenewal() {
    std::unique_lock<std::mutex> renewal_lock(renewal_mutex_);
    if (renewal_in_progress_) {
        return false;
    }
    renewal_in_progress_ = true;
    
    try {
        // Generate new ephemeral key pair
        auto newKeyPair = Crypto::generateEphemeralKeyPair();
        
        // Create and send key renewal message
        if (!Communication::sendKeyRenewalRequest("peer_address", newKeyPair.publicKey)) {
            throw std::runtime_error("Failed to send key renewal request");
        }
        
        // Wait for response with timeout
        auto response = Communication::receiveKeyRenewalResponse();
        if (!response.success) {
            throw std::runtime_error("Key renewal request was rejected");
        }
        
        // Verify response and update keys
        if (verifyKeyRenewalResponse(response)) {
            std::lock_guard<std::mutex> key_lock(key_mutex_);
            
            // Secure replacement of old keys
            secureErase(current_ephemeral_keypair_.privateKey);
            secureErase(current_ephemeral_keypair_.publicKey);
            
            current_ephemeral_keypair_ = std::move(newKeyPair);
            
            // Derive new session key
            auto newSessionKey = Crypto::deriveSessionKey(
                response.peerPublicKey,
                current_ephemeral_keypair_.privateKey);
            
            secureErase(current_session_key_);
            current_session_key_ = std::move(newSessionKey);
            
            last_renewal_ = std::chrono::system_clock::now();
            
            Logger::logEvent(LogLevel::Security, "Key renewal completed successfully");
            renewal_in_progress_ = false;
            renewal_cv_.notify_all();
            return true;
        }
        
        throw std::runtime_error("Failed to verify key renewal response");
    }
    catch (const std::exception& e) {
        renewal_in_progress_ = false;
        renewal_cv_.notify_all();
        Logger::logError(ErrorCode::KeyRenewalFailed,
            std::string("Key renewal failed: ") + e.what());
        return false;
    }
}

bool KeyManagement::establishSession(const std::vector<uint8_t>& peerPublicKey) {
    try {
        if (peerPublicKey.empty()) {
            throw std::invalid_argument("Invalid peer public key");
        }

        std::lock_guard<std::mutex> lock(key_mutex_);
        
        // Store peer's public key
        peer_public_key_ = peerPublicKey;
        
        // Derive session key
        current_session_key_ = Crypto::deriveSessionKey(
            peer_public_key_,
            current_ephemeral_keypair_.privateKey);
        
        if (current_session_key_.empty()) {
            throw std::runtime_error("Failed to derive session key");
        }
        
        session_established_ = true;
        Logger::logEvent(LogLevel::Security, "Secure session established");
        return true;
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Failed to establish session: ") + e.what());
        return false;
    }
}

const ECDHKeyPair& KeyManagement::getCurrentEphemeralKeyPair() {
    std::lock_guard<std::mutex> lock(key_mutex_);
    if (current_ephemeral_keypair_.privateKey.empty() || 
        current_ephemeral_keypair_.publicKey.empty()) {
        throw std::runtime_error("No ephemeral key pair available");
    }
    return current_ephemeral_keypair_;
}

const std::vector<uint8_t>& KeyManagement::getCurrentSessionKey() {
    std::lock_guard<std::mutex> lock(key_mutex_);
    if (!session_established_) {
        throw std::runtime_error("No session established");
    }
    if (current_session_key_.empty()) {
        throw std::runtime_error("Invalid session key state");
    }
    return current_session_key_;
}

const std::vector<uint8_t>& KeyManagement::getPeerPublicKey() {
    std::lock_guard<std::mutex> lock(key_mutex_);
    if (!session_established_) {
        throw std::runtime_error("No session established");
    }
    if (peer_public_key_.empty()) {
        throw std::runtime_error("Invalid peer public key state");
    }
    return peer_public_key_;
}

void KeyManagement::cleanup() {
    {
        std::lock_guard<std::mutex> lock(renewal_mutex_);
        shutdown_requested_ = true;
        renewal_cv_.notify_all();
        
        if (renewal_thread_.joinable()) {
            renewal_thread_.join();
        }
    }

    {
        std::lock_guard<std::mutex> lock(key_mutex_);
        
        // Secure erasure of all sensitive data
        secureErase(current_ephemeral_keypair_.privateKey);
        secureErase(current_ephemeral_keypair_.publicKey);
        secureErase(current_session_key_);
        secureErase(peer_public_key_);
        
        session_established_ = false;
    }

    {
        std::lock_guard<std::mutex> lock(cert_cache_mutex_);
        for (auto& cert : cached_certificates_) {
            secureErase(cert.second);
        }
        cached_certificates_.clear();
    }

    Logger::logEvent(LogLevel::Security, "Key management cleaned up successfully");
}

bool KeyManagement::verifyKeyRenewalResponse(const KeyRenewalResponse& response) {
    try {
        if (!response.success || response.peerPublicKey.empty()) {
            return false;
        }

        std::lock_guard<std::mutex> lock(key_mutex_);
        
        // Verify the signature using the current peer public key
        std::vector<uint8_t> messageData;
        messageData.reserve(response.peerPublicKey.size() + response.nonce.size() + 
                          sizeof(response.timestamp));
        
        messageData.insert(messageData.end(), 
            response.peerPublicKey.begin(), 
            response.peerPublicKey.end());
        messageData.insert(messageData.end(), 
            response.nonce.begin(), 
            response.nonce.end());
        
        const uint8_t* timestampBytes = reinterpret_cast<const uint8_t*>(&response.timestamp);
        messageData.insert(messageData.end(), 
            timestampBytes, 
            timestampBytes + sizeof(response.timestamp));
        
        auto hash = Crypto::sha256({
            reinterpret_cast<const char*>(messageData.data()), 
            messageData.size()
        });
        
        if (!Crypto::ecdsaVerify(hash, response.signature, peer_public_key_)) {
            Logger::logEvent(LogLevel::Warning, "Key renewal response signature verification failed");
            return false;
        }

        // Verify timestamp
        auto now = std::chrono::system_clock::now();
        auto response_time = std::chrono::system_clock::from_time_t(response.timestamp);
        if (std::abs(std::chrono::duration_cast<std::chrono::seconds>(
            now - response_time).count()) > 300) { // 5 minutes tolerance
            Logger::logEvent(LogLevel::Warning, "Key renewal response timestamp out of bounds");
            return false;
        }

        // Verify nonce
        if (!secure_comm::Utils::validateNonce(response.nonce)) {
            Logger::logEvent(LogLevel::Warning, "Key renewal response nonce validation failed");
            return false;
        }

        Logger::logEvent(LogLevel::Security, "Key renewal response verified successfully");
        return true;
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Key renewal response verification failed: ") + e.what());
        return false;
    }
}

} // namespace secure_comm
