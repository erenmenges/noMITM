#include "Utils.hpp"
#include "Logger.hpp"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

namespace secure_comm {

// Static member initializations
std::shared_mutex Utils::nonce_mutex_;
std::unordered_map<std::string, std::chrono::system_clock::time_point> Utils::used_nonces_;

namespace {
    // Helper function to encode binary data as base64
    std::string base64Encode(const std::vector<uint8_t>& data) {
        BIO* b64 = BIO_new(BIO_f_base64());
        BIO* bmem = BIO_new(BIO_s_mem());
        if (!b64 || !bmem) {
            BIO_free_all(b64);  // Will handle null safely
            BIO_free_all(bmem); // Will handle null safely
            throw std::runtime_error("Failed to create BIO objects");
        }
        
        BIO* bio = BIO_push(b64, bmem);
        if (!bio) {
            BIO_free_all(b64);
            BIO_free_all(bmem);
            throw std::runtime_error("Failed to push BIO objects");
        }
        
        BIO_write(bio, data.data(), data.size());
        BIO_flush(bio);
        BUF_MEM* bptr;
        BIO_get_mem_ptr(bio, &bptr);
        std::string result(bptr->data, bptr->length);
        BIO_free_all(bio);
        return result;
    }
    
    void cleanupExpiredNonces(std::unordered_map<std::string, std::chrono::system_clock::time_point>& nonces) {
        auto now = std::chrono::system_clock::now();
        for (auto it = nonces.begin(); it != nonces.end();) {
            if (now - it->second > Utils::NONCE_EXPIRY_TIME) {
                it = nonces.erase(it);
            } else {
                ++it;
            }
        }
    }
}

// Method implementations
std::string Utils::generateNonce() {
    try {
        std::vector<uint8_t> random_bytes(NONCE_SIZE);
        if (RAND_bytes(random_bytes.data(), NONCE_SIZE) != 1) {
            throw std::runtime_error("Failed to generate random bytes for nonce");
        }
        
        // Encode as base64 to make it URL-safe
        std::string nonce = base64Encode(random_bytes);
        
        // Remove any base64 padding characters
        while (!nonce.empty() && nonce.back() == '=') {
            nonce.pop_back();
        }
        
        // Store nonce with current timestamp
        {
            std::unique_lock<std::shared_mutex> lock(nonce_mutex_);
            // Periodically cleanup expired nonces
            if (used_nonces_.size() > 1000) { // Arbitrary threshold
                cleanupExpiredNonces(used_nonces_);
            }
            used_nonces_[nonce] = std::chrono::system_clock::now();
        }
        
        return nonce;
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::ProcessingError,
            std::string("Failed to generate nonce: ") + e.what());
        throw;
    }
}

bool Utils::validateNonce(const std::string& nonce) {
    try {
        std::unique_lock<std::shared_mutex> lock(nonce_mutex_);
        
        auto now = std::chrono::system_clock::now();
        bool found = false;
        bool expired = false;
        
        // Constant-time comparison
        for (const auto& [stored_nonce, timestamp] : used_nonces_) {
            bool matches = (stored_nonce.length() == nonce.length());
            size_t len = stored_nonce.length();
            for (size_t i = 0; i < len; i++) {
                matches &= (stored_nonce[i] == nonce[i]);
            }
            if (matches) {
                found = true;
                expired = (now - timestamp > NONCE_EXPIRY_TIME);
                break;
            }
        }
        
        if (!found) return false;
        if (expired) {
            used_nonces_.erase(nonce);
            return false;
        }
        return true;
    }
    catch (...) {
        return false;
    }
}

uint64_t Utils::getCurrentTimestamp() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

bool Utils::validateTimestamp(uint64_t timestamp) {
    auto now = getCurrentTimestamp();
    auto difference = std::abs(static_cast<int64_t>(now - timestamp));
    
    return difference <= TIMESTAMP_TOLERANCE.count();
}

} // namespace secure_comm
