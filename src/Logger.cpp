#include "Logger.hpp"
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <filesystem>

namespace secure_comm {

// Static member initialization
std::mutex Logger::log_mutex_;
LogLevel Logger::min_log_level_ = LogLevel::Info;
std::string Logger::log_file_path_;
bool Logger::console_output_enabled_ = true;

namespace {
    std::string currentTimeString() {
        try {
            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) % 1000;

            std::stringstream ss;
            std::tm tm_buf;
            
            #ifdef _WIN32
                localtime_s(&tm_buf, &time);
            #else
                localtime_r(&time, &tm_buf);
            #endif
            
            ss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S")
               << '.' << std::setfill('0') << std::setw(3) << ms.count();
            return ss.str();
        }
        catch (const std::exception& e) {
            return "TIME_ERROR";
        }
    }

    std::string levelToString(LogLevel level) {
        switch (level) {
            case LogLevel::Debug:    return "[DEBUG]   ";
            case LogLevel::Info:     return "[INFO]    ";
            case LogLevel::Warning:  return "[WARNING] ";
            case LogLevel::Error:    return "[ERROR]   ";
            case LogLevel::Security: return "[SECURITY]";
            case LogLevel::Fatal:    return "[FATAL]   ";
            default:                 return "[UNKNOWN] ";
        }
    }

    std::string errorToString(ErrorCode code) {
        switch (code) {
            case ErrorCode::None:
                return "None";
            case ErrorCode::CertificateVerificationFailed:
                return "CertificateVerificationFailed";
            case ErrorCode::CertificateRevoked:
                return "CertificateRevoked";
            case ErrorCode::InvalidNonce:
                return "InvalidNonce";
            case ErrorCode::InvalidTimestamp:
                return "InvalidTimestamp";
            case ErrorCode::InvalidSignature:
                return "InvalidSignature";
            case ErrorCode::KeyRenewalFailed:
                return "KeyRenewalFailed";
            case ErrorCode::DecryptionFailed:
                return "DecryptionFailed";
            case ErrorCode::ProcessingError:
                return "ProcessingError";
            default:
                return "Unknown";
        }
    }
}

void Logger::logEvent(LogLevel level, std::string_view message) {
    if (level < min_log_level_) {
        return;
    }

    try {
        std::string timestamp = currentTimeString();
        std::string levelStr = levelToString(level);
        
        std::string fullMessage = 
            levelStr + " " + timestamp + " " + std::string(message) + "\n";
        
        std::lock_guard<std::mutex> lock(log_mutex_);
        
        if (console_output_enabled_) {
            std::cerr << fullMessage << std::flush;
        }
        
        if (!log_file_path_.empty()) {
            writeToFile(fullMessage);
        }
    }
    catch (const std::exception& e) {
        // Fallback logging to stderr in case of errors
        std::cerr << "[LOGGING_ERROR] Failed to log message: " << e.what() << std::endl;
    }
}

void Logger::logError(ErrorCode code, std::string_view details) {
    try {
        std::string timestamp = currentTimeString();
        std::string errorStr = errorToString(code);
        
        std::string fullMessage = 
            "[ERROR]    " + timestamp + " Code: " + errorStr + 
            " Details: " + std::string(details) + "\n";
        
        std::lock_guard<std::mutex> lock(log_mutex_);
        
        if (console_output_enabled_) {
            std::cerr << fullMessage << std::flush;
        }
        
        if (!log_file_path_.empty()) {
            writeToFile(fullMessage);
        }
    }
    catch (const std::exception& e) {
        // Fallback logging to stderr in case of errors
        std::cerr << "[LOGGING_ERROR] Failed to log error: " << e.what() << std::endl;
    }
}

void Logger::writeToFile(std::string_view message) {
    try {
        std::ofstream file(log_file_path_, std::ios::app);
        if (file.is_open()) {
            file << message;
            file.flush();
        }
    }
    catch (const std::exception&) {
        // If file logging fails, try to log to console as fallback
        if (console_output_enabled_) {
            std::cerr << "[FILE_ERROR] Failed to write to log file: " << message;
        }
    }
}

void Logger::setLogLevel(LogLevel minLevel) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    min_log_level_ = minLevel;
}

void Logger::setLogFile(std::string_view path) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    log_file_path_ = path;
}

void Logger::enableConsoleOutput(bool enable) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    console_output_enabled_ = enable;
}

void Logger::flush() {
    std::lock_guard<std::mutex> lock(log_mutex_);
    std::cerr.flush();
    if (!log_file_path_.empty()) {
        std::ofstream file(log_file_path_, std::ios::app);
        if (file.is_open()) {
            file.flush();
        }
    }
}

} // namespace secure_comm
