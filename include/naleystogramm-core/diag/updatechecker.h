#pragma once
#include "naleystogramm-core/types.h"
#include <string>
#include <vector>
#include <functional>
#include <utility>
#include <mutex>
#include <atomic>
#include <cstdint>

// ── UpdateChecker ──────────────────────────────────────────────────────────
// Проверяет новую версию через GitHub Releases API (libcurl).
// Callbacks вызываются на рабочем потоке — bridge-слой должен
// перепоставить на Qt-поток через QMetaObject::invokeMethod.
//
// Использование:
//   UpdateChecker uc;
//   uc.subscribeUpdateAvailable([](const UpdateInfo& i){ ... });
//   uc.checkInBackground();

class UpdateChecker {
public:
    static constexpr const char* kGitHubOwner   = "Xomel45";
    static constexpr const char* kGitHubRepo    = "naleystogramm";
    static constexpr const char* kCurrentVersion = APP_VERSION;

    UpdateChecker();
    ~UpdateChecker();

    // Тихая проверка — пропускает если проверяли менее 6 часов назад
    void checkInBackground();
    // Явная проверка из UI — всегда делает запрос
    void checkNow();

    [[nodiscard]] const char* currentVersion() const { return kCurrentVersion; }
    // Возвращает ISO-timestamp последней проверки или "" если не проверяли
    [[nodiscard]] std::string lastChecked() const;
    [[nodiscard]] UpdateInfo  cachedResult() const;

    // ── Listener API (вместо Qt-сигналов) ────────────────────────────────
    using Token = uint32_t;
    Token subscribeUpdateAvailable (std::function<void(const UpdateInfo&)>  fn);
    Token subscribeNoUpdate        (std::function<void(const std::string&)> fn);
    Token subscribeCheckFailed     (std::function<void(const std::string&)> fn);
    Token subscribeCheckStarted    (std::function<void()>                   fn);
    void  unsubscribe(Token t);

private:
    void doCheck();
    static bool isNewerVersion(const std::string& remote, const std::string& local);

    void notifyAvailable  (const UpdateInfo& info);
    void notifyNoUpdate   (const std::string& ver);
    void notifyFailed     (const std::string& err);
    void notifyStarted    ();

    UpdateInfo              m_cached;
    std::atomic<bool>       m_alive{true};   // false when destructor starts
    mutable std::mutex      m_mutex;         // protects m_cached and listener vectors
    Token                   m_nextToken{0};

    std::vector<std::pair<Token, std::function<void(const UpdateInfo&)>>>  m_onAvailable;
    std::vector<std::pair<Token, std::function<void(const std::string&)>>> m_onNoUpdate;
    std::vector<std::pair<Token, std::function<void(const std::string&)>>> m_onFailed;
    std::vector<std::pair<Token, std::function<void()>>>                   m_onStarted;
};
