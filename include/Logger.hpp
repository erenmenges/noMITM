#pragma once // Ensures this header is included only once

#include <string>           // For std::string
#include "SecureTypes.hpp"  // For ErrorCode

namespace secure_comm { // Begin namespace secure_comm

// Enumerates different log levels we can use
enum class LogLevel {
    Info,      // Informational messages
    Warning,   // Warnings
    Error,     // Errors
    Security   // Security-related events
};

class Logger {
public:
    // Logs a generic event with a given log level and message
    static void logEvent(LogLevel level, const std::string& message);

    // Logs an error with a specific error code and additional details
    static void logError(ErrorCode code, const std::string& details);
};

} // namespace secure_comm
