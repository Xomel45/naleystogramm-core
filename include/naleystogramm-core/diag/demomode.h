#pragma once
#include <string>
#include <functional>
#include <vector>
#include <utility>
#include <cstdint>

// ── DemoMode ───────────────────────────────────────────────────────────────
// Режим презентации — UI показывает заглушки вместо реальных данных.
// Сетевой слой НЕ затрагивается: реальные UUID/имя/IP уходят собеседнику.
// Только визуальная маскировка для скриншотов и демо.

class DemoMode {
public:
    static DemoMode& instance();

    [[nodiscard]] bool enabled() const { return m_enabled; }
    void setEnabled(bool on);

    [[nodiscard]] std::string displayName(const std::string& real) const;
    [[nodiscard]] std::string uuid(const std::string& real)        const;
    [[nodiscard]] std::string ip(const std::string& real)          const;
    [[nodiscard]] uint16_t    port(uint16_t real)                  const;

    static constexpr const char* kDemoName = "User-0000";
    static constexpr const char* kDemoUuid = "00000000-0000-0000-0000-000000000000";
    static constexpr const char* kDemoIp   = "0.0.0.0";
    static constexpr uint16_t    kDemoPort = 0;

    // Подписка/отписка на изменение состояния (замена Qt-сигнала).
    using Token = uint32_t;
    Token subscribe(std::function<void(bool)> fn);
    void  unsubscribe(Token t);

private:
    DemoMode() = default;
    bool m_enabled{false};
    std::vector<std::pair<Token, std::function<void(bool)>>> m_listeners;
    Token m_nextToken{0};
};
