#pragma once // Ensures this header is included only once during compilation

#include <string>  // Provides the std::string type
#include <vector>  // Provides the std::vector container
#include <cstdint> // Provides fixed-width integer types like uint64_t

namespace secure_comm { // Begin namespace secure_comm to group related functionality

// Error codes for the secure communication library
enum class ErrorCode {
    None = 0,
    CertificateVerificationFailed,
    CertificateRevoked,
    InvalidNonce,
    InvalidTimestamp,
    InvalidSignature,
    KeyRenewalFailed,
    DecryptionFailed,
    ProcessingError,
    NetworkError,
    SecurityError,
    InvalidParameter,
    ResourceError
};

// Converts an ErrorCode to a human-readable string
inline const char* toString(ErrorCode code) {
    switch (code) {
        case ErrorCode::None: 
            return "No error"; // If no error
        case ErrorCode::CertificateVerificationFailed: 
            return "Certificate Verification Failed"; // If certificate verification fails
        case ErrorCode::CertificateRevoked: 
            return "Certificate Revoked"; // If the certificate is revoked
        case ErrorCode::InvalidNonce: 
            return "Invalid Nonce"; // If the nonce is invalid or already used
        case ErrorCode::InvalidTimestamp: 
            return "Invalid Timestamp"; // If the timestamp is out of acceptable range
        case ErrorCode::InvalidSignature: 
            return "Invalid Signature"; // If signature verification fails
        case ErrorCode::KeyRenewalFailed: 
            return "Key Renewal Failed"; // If session key renewal fails
        case ErrorCode::DecryptionFailed: 
            return "Decryption Failed"; // If an error occurs during AES decrypt
        case ErrorCode::ProcessingError: 
            return "Processing Error"; // If a general error happened in processing
        case ErrorCode::NetworkError: 
            return "Network Error"; // If a network error occurred
        case ErrorCode::SecurityError: 
            return "Security Error"; // If a security error occurred
        case ErrorCode::InvalidParameter: 
            return "Invalid Parameter"; // If an invalid parameter was provided
        case ErrorCode::ResourceError: 
            return "Resource Error"; // If a resource error occurred
        default: 
            return "Unknown error"; // Catch-all for unhandled error codes
    }
}

// Structure for key pairs
struct KeyPair {
    std::vector<uint8_t> privateKey;
    std::vector<uint8_t> publicKey;
};

// Structure for encrypted messages
struct EncryptedPackage {
    std::vector<uint8_t> encryptedData;
    std::vector<uint8_t> signature;
    std::string nonce;
    uint64_t timestamp;
};

// Structure for session information
struct SessionInfo {
    std::vector<uint8_t> sessionKey;
    uint64_t establishedAt;
    uint64_t expiresAt;
    bool isValid;
};

// Constants for security parameters
struct SecurityParameters {
    static constexpr size_t MIN_KEY_SIZE = 256;
    static constexpr size_t MAX_MESSAGE_SIZE = 1024 * 1024; // 1MB
    static constexpr uint32_t MAX_SESSION_DURATION = 3600;  // 1 hour
    static constexpr uint32_t NONCE_TIMEOUT = 300;         // 5 minutes
    static constexpr uint32_t TIMESTAMP_TOLERANCE = 300;    // 5 minutes
};

// Message types for protocol communication
enum class MessageType : uint8_t {
    Data = 0,
    KeyRenewal = 1,
    SessionEstablishment = 2,
    Error = 3,
    Heartbeat = 4,
    Acknowledgment = 5
};

struct KeyRenewalResponse {
    bool success;
    std::vector<uint8_t> peerPublicKey;
    std::vector<uint8_t> signature;
    std::string nonce;
    uint64_t timestamp;
};

} // namespace secure_comm
