#pragma once // Ensures this header is included only once

#include <string> // For std::string

namespace secure_comm { // Begin namespace secure_comm

/**
 * A placeholder interface for OCSP checking.
 * In a real implementation, you would integrate OpenSSL or another library
 * to perform Online Certificate Status Protocol checks.
 */
class OCSP {
public:
    // Returns true if the certificate is not revoked according to OCSP.
    static bool checkCertificateRevocation(const std::string& certificatePem);
};

} // namespace secure_comm
