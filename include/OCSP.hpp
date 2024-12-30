#pragma once // Ensures this header is included only once

#include <string> // For std::string
#include <vector>
#include <chrono>

namespace secure_comm { // Begin namespace secure_comm

/**
 * A placeholder interface for OCSP checking.
 * In a real implementation, you would integrate OpenSSL or another library
 * to perform Online Certificate Status Protocol checks.
 */
class OCSP {
public:
    // Returns true if the certificate is not revoked according to OCSP.
    static bool checkCertificateRevocation(
        const std::string& certificatePem,
        const std::string& issuerCertificatePem,
        std::chrono::seconds timeout = std::chrono::seconds(10)
    );

private:
    static constexpr size_t MAX_RESPONSE_SIZE = 32768; // 32KB
    static constexpr int OCSP_VALID = 0;
    static constexpr int OCSP_REVOKED = 1;
    static constexpr int OCSP_UNKNOWN = 2;
};

} // namespace secure_comm
