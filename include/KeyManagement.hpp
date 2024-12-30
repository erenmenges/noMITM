#pragma once // Ensures this header is only included once

#include <string>         // For std::string
#include <vector>         // For std::vector
#include "Crypto.hpp"     // For Crypto::ECDHKeyPair

namespace secure_comm { // Begin namespace secure_comm

class KeyManagement {
public:
    // Loads a certificate from a PEM file into a string
    static bool loadCertificate(const std::string& filepath, std::string& outPem);

    // Loads a private key from a file into a vector of bytes
    static bool loadPrivateKey(const std::string& filepath, std::vector<uint8_t>& outKey);

    // Validates the certificate against a CA certificate chain
    static bool verifyCertificate(const std::string& certPem, const std::string& caPem);

    // Schedules a key renewal in 'secondsUntilRenewal' seconds
    static void scheduleKeyRenewal(int secondsUntilRenewal);

    // Initiates a key renewal immediately
    static void initiateKeyRenewal();

    // Handles an incoming key renewal request with the new public key from the peer
    static void handleKeyRenewalRequest(const std::vector<uint8_t>& newPublicKey);

    // Stores the current ephemeral key pair (for ECDH)
    static Crypto::ECDHKeyPair currentEphemeralKeyPair;

    // Stores the current session key
    static std::vector<uint8_t> currentSessionKey;
};

} // namespace secure_comm
