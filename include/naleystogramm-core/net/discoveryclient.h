#pragma once
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

// ── DiscoveryClient ──────────────────────────────────────────────────────────
// Клиент discovery-сервера (naleystogramm-server, --mode discovery) через
// libcurl, по аналогии с GroupManager. Все HTTP-запросы — блокирующие, в
// отдельном detached std::thread, результат — через listener-callback.
// Серверы друг с другом не общаются — это не федерация, просто способ узнать
// актуальные uuid/ip/port собеседника по его "домашнему" серверу.
//
// Поиск (lookup) не требует аккаунта. Регистрация/heartbeat/update/unregister —
// для собственного аккаунта на сервере (чтобы другие могли найти нас по имени).
class DiscoveryClient {
public:
    struct LookupResult {
        std::string username;
        std::string uuid;
        std::string pubkey; // base64 X25519 — не верифицируется против хендшейка (TOFU, как и при ручном добавлении)
        std::string ip;
        uint16_t    port{0};
    };

    struct RegisterResult {
        std::string host;
        uint16_t    port{0};
        std::string username;
        std::string token; // Bearer-токен для /update, /heartbeat, /unregister
    };

    struct DiscoveryEvent {
        std::function<void(const LookupResult&)> onLookupSuccess;
        std::function<void(const std::string& host, const std::string& username,
                            const std::string& error)> onLookupError;

        std::function<void(const RegisterResult&)> onRegisterSuccess;
        std::function<void(const std::string& host, const std::string& username,
                            const std::string& error)> onRegisterError;

        std::function<void(const std::string& host)> onUpdateOk;
        std::function<void(const std::string& host, const std::string& error)> onUpdateError;

        std::function<void(const std::string& host)> onHeartbeatOk;
        std::function<void(const std::string& host, const std::string& error)> onHeartbeatError;

        std::function<void(const std::string& host)> onUnregisterSuccess;
        std::function<void(const std::string& host, const std::string& error)> onUnregisterError;
    };

    DiscoveryClient() = default;

    // host — без схемы ("myserver.example" или "1.2.3.4")
    void lookup(const std::string& host, uint16_t discoveryPort, const std::string& username);

    // Зарегистрировать аккаунт на сервере. email/inviteCode/clientVersion — пустая
    // строка если поле не нужно (сервер сам решит, обязательно оно или нет).
    void registerAccount(const std::string& host, uint16_t discoveryPort,
                          const std::string& username, const std::string& uuid,
                          const std::string& pubkeyBase64, const std::string& ip,
                          uint16_t advertisedPort, const std::string& email,
                          const std::string& inviteCode, const std::string& clientVersion);

    // Обновить ip:port присутствия (при смене адреса). token — из RegisterResult.
    void updatePresence(const std::string& host, uint16_t discoveryPort, const std::string& token,
                         const std::string& ip, uint16_t advertisedPort);

    // Подтвердить online-статус — звать периодически, пока зарегистрированы.
    void heartbeat(const std::string& host, uint16_t discoveryPort, const std::string& token);

    // Удалить аккаунт с сервера.
    void unregisterAccount(const std::string& host, uint16_t discoveryPort, const std::string& token);

    using Token = uint32_t;
    Token addListener(DiscoveryEvent ev);
    void removeListener(Token t);

private:
    template<typename Fn>
    void fire(Fn&& invoke) const {
        std::vector<std::pair<Token, DiscoveryEvent>> snap;
        { std::lock_guard<std::mutex> lk(m_listenerMutex); snap = m_listeners; }
        for (auto& [tok, ev] : snap) invoke(ev);
    }

    mutable std::mutex m_listenerMutex;
    std::vector<std::pair<Token, DiscoveryEvent>> m_listeners;
    Token m_nextToken{0};
};
