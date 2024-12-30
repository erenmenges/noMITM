#include "OCSP.hpp"
#include "Logger.hpp"
#include <openssl/ocsp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <curl/curl.h>
#include <stdexcept>
#include <memory>

namespace secure_comm {

namespace {
    // RAII wrapper for OpenSSL BIO
    struct BIODeleter {
        void operator()(BIO* bio) { BIO_free_all(bio); }
    };
    using BIOPtr = std::unique_ptr<BIO, BIODeleter>;

    // Helper function to handle OpenSSL errors
    std::string getOpenSSLError() {
        BIOPtr bio(BIO_new(BIO_s_mem()));
        ERR_print_errors(bio.get());
        char* buf = nullptr;
        size_t len = BIO_get_mem_data(bio.get(), &buf);
        return std::string(buf, len);
    }

    // CURL write callback
    size_t writeCallback(void* contents, size_t size, size_t nmemb, std::vector<unsigned char>* userp) {
        size_t realsize = size * nmemb;
        try {
            userp->insert(userp->end(), (unsigned char*)contents, (unsigned char*)contents + realsize);
            return realsize;
        } catch(const std::bad_alloc& e) {
            return 0;
        }
    }

    // Send OCSP request using CURL
    std::vector<unsigned char> sendOCSPRequest(
        const std::string& url,
        const unsigned char* request,
        size_t request_len,
        std::chrono::seconds timeout
    ) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            throw std::runtime_error("Failed to initialize CURL");
        }

        std::vector<unsigned char> response;
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/ocsp-request");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request_len);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout.count());

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            throw std::runtime_error(std::string("CURL request failed: ") + curl_easy_strerror(res));
        }

        return response;
    }
}

bool OCSP::checkCertificateRevocation(
    const std::string& certificatePem,
    const std::string& issuerCertificatePem,
    std::chrono::seconds timeout
) {
    try {
        // Parse the certificate and issuer certificate
        BIOPtr certBio(BIO_new_mem_buf(certificatePem.c_str(), -1));
        BIOPtr issuerBio(BIO_new_mem_buf(issuerCertificatePem.c_str(), -1));
        
        if (!certBio || !issuerBio) {
            throw std::runtime_error("Failed to create certificate BIOs");
        }

        std::unique_ptr<X509, decltype(&X509_free)> cert(
            PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr),
            X509_free);
        std::unique_ptr<X509, decltype(&X509_free)> issuerCert(
            PEM_read_bio_X509(issuerBio.get(), nullptr, nullptr, nullptr),
            X509_free);

        if (!cert || !issuerCert) {
            throw std::runtime_error("Failed to parse certificates: " + getOpenSSLError());
        }

        // Get OCSP URI from certificate
        STACK_OF(OPENSSL_STRING)* ocspUrls = X509_get1_ocsp(cert.get());
        if (!ocspUrls || sk_OPENSSL_STRING_num(ocspUrls) == 0) {
            if (ocspUrls) X509_email_free(ocspUrls);
            throw std::runtime_error("No OCSP responder URL found in certificate");
        }

        std::string ocspUrl(sk_OPENSSL_STRING_value(ocspUrls, 0));

        // Create OCSP request
        OCSP_REQUEST* req = OCSP_REQUEST_new();
        if (!req) {
            if (ocspUrls) X509_email_free(ocspUrls);
            throw std::runtime_error("Failed to create OCSP request");
        }

        // Add certificate ID to request
        OCSP_CERTID* certId = OCSP_cert_to_id(EVP_sha1(), cert.get(), issuerCert.get());
        if (!certId || !OCSP_request_add0_id(req, certId)) {
            OCSP_REQUEST_free(req);
            if (ocspUrls) X509_email_free(ocspUrls);
            throw std::runtime_error("Failed to add certificate ID to request");
        }

        // Convert request to DER format
        unsigned char* requestDer = nullptr;
        int requestDerLen = i2d_OCSP_REQUEST(req, &requestDer);
        if (requestDerLen <= 0) {
            OCSP_REQUEST_free(req);
            if (ocspUrls) X509_email_free(ocspUrls);
            throw std::runtime_error("Failed to encode OCSP request");
        }

        // Send request and get response
        std::vector<unsigned char> responseData;
        try {
            responseData = sendOCSPRequest(ocspUrl, requestDer, requestDerLen, timeout);
        } catch (...) {
            OPENSSL_free(requestDer);
            OCSP_REQUEST_free(req);
            if (ocspUrls) X509_email_free(ocspUrls);
            throw;
        }
        OPENSSL_free(requestDer);

        // Parse response
        const unsigned char* p = responseData.data();
        OCSP_RESPONSE* resp = d2i_OCSP_RESPONSE(nullptr, &p, responseData.size());
        if (!resp) {
            OCSP_REQUEST_free(req);
            if (ocspUrls) X509_email_free(ocspUrls);
            throw std::runtime_error("Failed to parse OCSP response");
        }

        // Check response status
        int resp_status = OCSP_response_status(resp);
        if (resp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
            OCSP_RESPONSE_free(resp);
            OCSP_REQUEST_free(req);
            if (ocspUrls) X509_email_free(ocspUrls);
            throw std::runtime_error("OCSP response status error: " + std::to_string(resp_status));
        }

        // Verify response
        OCSP_BASICRESP* basic = OCSP_response_get1_basic(resp);
        if (!basic) {
            OCSP_RESPONSE_free(resp);
            OCSP_REQUEST_free(req);
            if (ocspUrls) X509_email_free(ocspUrls);
            throw std::runtime_error("Failed to get basic OCSP response");
        }

        int status, reason;
        ASN1_GENERALIZEDTIME *revtime = nullptr, *thisupd = nullptr, *nextupd = nullptr;
        if (!OCSP_resp_find_status(basic, certId, &status, &reason, &revtime, &thisupd, &nextupd)) {
            OCSP_BASICRESP_free(basic);
            OCSP_RESPONSE_free(resp);
            OCSP_REQUEST_free(req);
            if (ocspUrls) X509_email_free(ocspUrls);
            throw std::runtime_error("Failed to find certificate status");
        }

        // Cleanup
        OCSP_BASICRESP_free(basic);
        OCSP_RESPONSE_free(resp);
        OCSP_REQUEST_free(req);
        if (ocspUrls) X509_email_free(ocspUrls);

        return (status == V_OCSP_CERTSTATUS_GOOD);
    }
    catch (const std::exception& e) {
        Logger::logError(ErrorCode::CertificateVerificationFailed,
            std::string("OCSP check failed: ") + e.what());
        return false;
    }
}

} // namespace secure_comm
