#include "Logger.hpp"             // Include the header for Logger declarations
#include <iostream>               // For std::cerr output
#include <chrono>                 // For timing functions
#include <ctime>                  // For std::time_t, localtime, etc.

namespace secure_comm { // Begin namespace secure_comm

// Helper function to get a human-readable time string
static std::string currentTimeString() {
    // Get current time as a system_clock::time_point
    auto now = std::chrono::system_clock::now();
    // Convert to time_t
    auto now_c = std::chrono::system_clock::to_time_t(now);
    // Convert to a human-readable C-string. std::ctime() adds a newline at the end.
    return std::ctime(&now_c);
}

void Logger::logEvent(LogLevel level, const std::string& message) {
    // Determine a prefix based on the log level
    std::string prefix;
    switch (level) {
        case LogLevel::Info:     prefix = "[INFO]    "; break;
        case LogLevel::Warning:  prefix = "[WARNING] "; break;
        case LogLevel::Error:    prefix = "[ERROR]   "; break;
        case LogLevel::Security: prefix = "[SECURITY]"; break;
    }

    // Write to stderr with the prefix, current time, and message
    std::cerr << prefix << " " << currentTimeString() << " " << message << std::endl;
}

void Logger::logError(ErrorCode code, const std::string& details) {
    // Output error information: prefix, time, error code, and detail string
    std::cerr << "[ERROR] " << currentTimeString()
              << " Code: " << toString(code)
              << " Details: " << details
              << std::endl;
}

} // namespace secure_comm
