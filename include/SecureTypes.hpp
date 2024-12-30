#pragma once // Ensures this header is included only once during compilation

#include <string>  // Provides the std::string type
#include <vector>  // Provides the std::vector container
#include <cstdint> // Provides fixed-width integer types like uint64_t

namespace secure_comm { // Begin namespace secure_comm to group related functionality

// Enumerates possible error codes that can occur in the secure communication library
enum class ErrorCode {
    None = 0,                          // No error occurred
    CertificateVerificationFailed,     // Certificate failed verification
    CertificateRevoked,               // Certificate is revoked (OCSP check failed)
    InvalidNonce,                      // Nonce is invalid or has been used before
    InvalidTimestamp,                  // Timestamp is outside the acceptable range
    InvalidSignature,                  // Signature verification failed
    KeyRenewalFailed,                  // Failed to renew session key
    DecryptionFailed,                  // An error occurred during decryption
    ProcessingError,                   // A general processing error occurred
    // ... more as needed
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
        default: 
            return "Unknown error"; // Catch-all for unhandled error codes
    }
}

// A struct representing an encrypted package that includes the ciphertext, signature, etc.
struct EncryptedPackage {
    std::vector<uint8_t> encryptedData;  // The AES-encrypted message data
    std::vector<uint8_t> signature;      // ECDSA signature bytes
    std::string nonce;                   // A unique nonce for replay protection
    uint64_t timestamp;                  // Timestamp to check message freshness
};

} // namespace secure_comm
