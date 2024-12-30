#pragma once

#include <string>
#include <mutex>
#include <string_view>
#include "SecureTypes.hpp"

namespace secure_comm {

enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error,
    Security,
    Fatal
};

class Logger {
public:
    static void logEvent(LogLevel level, std::string_view message);
    static void logError(ErrorCode code, std::string_view details);

    static void setLogLevel(LogLevel minLevel);
    static void setLogFile(std::string_view path);
    static void enableConsoleOutput(bool enable);

    static void flush();

private:
    static std::mutex log_mutex_;
    static LogLevel min_log_level_;
    static std::string log_file_path_;
    static bool console_output_enabled_;

    static std::string getTimestamp();
    static std::string levelToString(LogLevel level);
    static std::string errorToString(ErrorCode code);
    static void writeToFile(std::string_view message);

    Logger() = delete;
    ~Logger() = delete;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
};

} // namespace secure_comm
