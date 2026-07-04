#pragma once
#include "naleystogramm-core/types.h"
#include <string>
#include <vector>
#include <functional>
#include <utility>
#include <cstdint>
#include <mutex>
#include <fstream>

// ── Logger ──────────────────────────────────────────────────────────────────
// Путь к файлу:
//   Windows: %LOCALAPPDATA%\naleystogramm\debug.log
//   Linux:   ~/.cache/naleystogramm/debug.log
// Формат записи: [2026-02-21 12:34:56.789] [INFO] [NETWORK] Сообщение
//
class Logger {
public:
    static Logger& instance();

    void init();

    void debug  (LogComponent comp, const std::string& message);
    void info   (LogComponent comp, const std::string& message);
    void warning(LogComponent comp, const std::string& message);
    void error  (LogComponent comp, const std::string& message);

    void log(LogLevel level, LogComponent comp, const std::string& message);

    void setVerbose(bool enabled);
    [[nodiscard]] bool isVerbose() const { return m_verbose; }

    [[nodiscard]] std::string logFilePath() const { return m_filePath; }

    void clearLog();

    [[nodiscard]] std::vector<LogEntry> recentEntries(int count = 100) const;

    // ── Listener API (вместо Qt-сигналов) ────────────────────────────────
    using Token = uint32_t;
    // Вызывается на потоке вызова Logger::log().
    // Из UI: обернуть в QMetaObject::invokeMethod(..., Qt::QueuedConnection).
    Token subscribe  (std::function<void(const LogEntry&)> fn);
    void  unsubscribe(Token t);

    Token subscribeClear  (std::function<void()> fn);
    void  unsubscribeClear(Token t);

private:
    Logger();
    ~Logger();

    void initFilePath();
    void rotateIfNeeded();
    void writeToFile(const LogEntry& entry);
    std::string formatEntry(const LogEntry& entry) const;
    static const char* levelToString     (LogLevel     level);
    static const char* componentToString (LogComponent comp);

    std::string   m_filePath;
    std::ofstream m_file;
    mutable std::mutex m_mutex;
    bool m_verbose{false};

    std::vector<LogEntry> m_recentEntries;
    static constexpr int     kMaxRecentEntries = 1000;
    static constexpr int64_t kMaxFileSize      = 5LL * 1024 * 1024;

    std::vector<std::pair<Token, std::function<void(const LogEntry&)>>> m_entryListeners;
    std::vector<std::pair<Token, std::function<void()>>>                m_clearListeners;
    Token m_nextToken{0};
};

// Удобные макросы для логирования (принимают std::string или const char*)
#define LOG_DEBUG(comp, msg)   Logger::instance().debug  (LogComponent::comp, msg)
#define LOG_INFO(comp, msg)    Logger::instance().info   (LogComponent::comp, msg)
#define LOG_WARNING(comp, msg) Logger::instance().warning(LogComponent::comp, msg)
#define LOG_ERROR(comp, msg)   Logger::instance().error  (LogComponent::comp, msg)
