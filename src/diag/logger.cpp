#include "naleystogramm-core/diag/logger.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <chrono>
#include <regex>
#include <filesystem>
#include <algorithm>

#ifdef _WIN32
static void safe_localtime(const std::time_t* tp, struct tm* out) { localtime_s(out, tp); }
#else
static void safe_localtime(const std::time_t* tp, struct tm* out) { localtime_r(tp, out); }
#endif

static constexpr const char* kLogFileName = "debug.log";

// ── Helpers ─────────────────────────────────────────────────────────────────

static int64_t currentEpochMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string epochMsToString(int64_t ms) {
    const std::time_t t = static_cast<std::time_t>(ms / 1000);
    const int frac = static_cast<int>(ms % 1000);
    struct tm tm_info {};
    safe_localtime(&t, &tm_info);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    char result[40];
    std::snprintf(result, sizeof(result), "%s.%03d", buf, frac);
    return std::string(result);
}

static std::string currentIsoTimestamp() {
    const auto now = std::chrono::system_clock::now();
    const std::time_t t = std::chrono::system_clock::to_time_t(now);
    struct tm tm_info {};
    safe_localtime(&t, &tm_info);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_info);
    return std::string(buf);
}

static std::string xdgDir(const char* envVar, const char* fallback) {
    const char* val = std::getenv(envVar);
    if (val && *val) return std::string(val);
    const char* home = std::getenv("HOME");
    return std::string(home ? home : "/tmp") + fallback;
}

// ── Singleton ───────────────────────────────────────────────────────────────

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

Logger::Logger() {
    initFilePath();
}

Logger::~Logger() {
    if (m_file.is_open())
        m_file.close();
}

// ── Инициализация ───────────────────────────────────────────────────────────

void Logger::initFilePath() {
#ifdef _WIN32
    const char* local = std::getenv("LOCALAPPDATA");
    m_filePath = std::string(local ? local : "C:\\ProgramData") +
                 "\\naleystogramm\\" + kLogFileName;
#else
    m_filePath = xdgDir("XDG_CACHE_HOME", "/.cache") +
                 "/naleystogramm/" + kLogFileName;
#endif
}

void Logger::init() {
    std::lock_guard<std::mutex> lock(m_mutex);
    rotateIfNeeded();

    m_file.open(m_filePath, std::ios::out | std::ios::app);
    if (!m_file.is_open()) {
        std::fprintf(stderr, "[Logger] Cannot open log file: %s\n", m_filePath.c_str());
        return;
    }

    std::fprintf(stderr, "[Logger] Log file: %s\n", m_filePath.c_str());

    m_file << "\n"
           << "========================================\n"
           << "  Session started: " << currentIsoTimestamp() << "\n"
           << "========================================\n";
    m_file.flush();
}

// ── Ротация файла ───────────────────────────────────────────────────────────

void Logger::rotateIfNeeded() {
    std::error_code ec;
    const auto size = std::filesystem::file_size(m_filePath, ec);
    if (ec || size <= static_cast<uintmax_t>(kMaxFileSize)) return;

    const std::string backup = m_filePath + ".old";
    std::filesystem::remove(backup, ec);
    std::filesystem::rename(m_filePath, backup, ec);
    std::fprintf(stderr, "[Logger] Rotated log file (%llu bytes)\n",
                 static_cast<unsigned long long>(size));
}

// ── Методы логирования ──────────────────────────────────────────────────────

void Logger::debug(LogComponent comp, const std::string& message) {
    if (!m_verbose) return;
    log(LogLevel::Debug, comp, message);
}

void Logger::info(LogComponent comp, const std::string& message) {
    log(LogLevel::Info, comp, message);
}

void Logger::warning(LogComponent comp, const std::string& message) {
    log(LogLevel::Warning, comp, message);
}

void Logger::error(LogComponent comp, const std::string& message) {
    log(LogLevel::Error, comp, message);
}

static std::string sanitizeMessage(LogComponent comp, const std::string& msg) {
    if (comp != LogComponent::Crypto) return msg;
    static const std::regex kHexPattern("[0-9a-fA-F]{64,}");
    return std::regex_replace(msg, kHexPattern, "[REDACTED]");
}

void Logger::log(LogLevel level, LogComponent comp, const std::string& message) {
    const std::string safeMessage = sanitizeMessage(comp, message);

    LogEntry entry{
        .timestamp = currentEpochMs(),
        .level     = level,
        .component = comp,
        .message   = safeMessage
    };

    writeToFile(entry);

    std::vector<std::pair<Token, std::function<void(const LogEntry&)>>> snapshot;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_recentEntries.push_back(entry);
        while (static_cast<int>(m_recentEntries.size()) > kMaxRecentEntries)
            m_recentEntries.erase(m_recentEntries.begin());
        snapshot = m_entryListeners;
    }

    for (auto& [tok, fn] : snapshot)
        fn(entry);

    std::fprintf(stderr, "[%s][%s] %s\n",
                 levelToString(level),
                 componentToString(comp),
                 safeMessage.c_str());
}

// ── Запись в файл ───────────────────────────────────────────────────────────

void Logger::writeToFile(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (!m_file.is_open()) return;
    m_file << formatEntry(entry) << "\n";
    m_file.flush();
}

std::string Logger::formatEntry(const LogEntry& entry) const {
    // "[2026-02-21 12:34:56.789] [INFO   ] [NETWORK] msg"
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%-7s", levelToString(entry.level));
    return "[" + epochMsToString(entry.timestamp) + "] [" +
           std::string(buf) + "] [" +
           componentToString(entry.component) + "] " +
           entry.message;
}

// ── Вспомогательные методы ──────────────────────────────────────────────────

const char* Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::Debug:   return "DEBUG";
        case LogLevel::Info:    return "INFO";
        case LogLevel::Warning: return "WARN";
        case LogLevel::Error:   return "ERROR";
    }
    return "UNKNOWN";
}

const char* Logger::componentToString(LogComponent comp) {
    switch (comp) {
        case LogComponent::Network:      return "NETWORK";
        case LogComponent::FileTransfer: return "FILETRANSFER";
        case LogComponent::Crypto:       return "CRYPTO";
        case LogComponent::Storage:      return "STORAGE";
        case LogComponent::UI:           return "UI";
        case LogComponent::General:      return "GENERAL";
    }
    return "UNKNOWN";
}

void Logger::setVerbose(bool enabled) {
    m_verbose = enabled;
    info(LogComponent::General,
         std::string("Verbose logging ") + (enabled ? "enabled" : "disabled"));
}

// ── clearLog ────────────────────────────────────────────────────────────────

void Logger::clearLog() {
    std::vector<std::pair<Token, std::function<void()>>> snapshot;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_recentEntries.clear();

        if (m_file.is_open()) {
            m_file.close();
            m_file.open(m_filePath, std::ios::out | std::ios::trunc);
            if (m_file.is_open()) {
                m_file << "========================================\n"
                       << "  Log cleared: " << currentIsoTimestamp() << "\n"
                       << "========================================\n";
                m_file.flush();
            }
        }
        snapshot = m_clearListeners;
    }
    for (auto& [tok, fn] : snapshot)
        fn();
}

// ── recentEntries ───────────────────────────────────────────────────────────

std::vector<LogEntry> Logger::recentEntries(int count) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (count >= static_cast<int>(m_recentEntries.size()))
        return m_recentEntries;
    const int start = static_cast<int>(m_recentEntries.size()) - count;
    return std::vector<LogEntry>(m_recentEntries.begin() + start,
                                 m_recentEntries.end());
}

// ── Subscribe / Unsubscribe ─────────────────────────────────────────────────

Logger::Token Logger::subscribe(std::function<void(const LogEntry&)> fn) {
    std::lock_guard<std::mutex> lock(m_mutex);
    Token t = m_nextToken++;
    m_entryListeners.emplace_back(t, std::move(fn));
    return t;
}

void Logger::unsubscribe(Token t) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_entryListeners.erase(
        std::remove_if(m_entryListeners.begin(), m_entryListeners.end(),
                       [t](const auto& p){ return p.first == t; }),
        m_entryListeners.end());
}

Logger::Token Logger::subscribeClear(std::function<void()> fn) {
    std::lock_guard<std::mutex> lock(m_mutex);
    Token t = m_nextToken++;
    m_clearListeners.emplace_back(t, std::move(fn));
    return t;
}

void Logger::unsubscribeClear(Token t) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_clearListeners.erase(
        std::remove_if(m_clearListeners.begin(), m_clearListeners.end(),
                       [t](const auto& p){ return p.first == t; }),
        m_clearListeners.end());
}
