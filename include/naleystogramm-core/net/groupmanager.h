#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>
#include "naleystogramm-core/types.h"
#include "naleystogramm-crypto/bytes.h"

class StorageManager;

// ── GroupManager ────────────────────────────────────────────────────────────
// Группы и каналы: HTTP join/leave/info + WebSocket чат через libcurl
// (CURLOPT_CONNECT_ONLY + curl_ws_recv/curl_ws_send). AES-256-GCM шифрование
// сообщений общим групповым ключом, ECIES для передачи ключа при вступлении.
class GroupManager {
public:
    struct GroupEvent {
        std::function<void(const Group&)> onGroupJoined;
        std::function<void(const std::string& groupId)> onGroupLeft;
        std::function<void(const std::string& groupId)> onWsConnected;
        std::function<void(const std::string& groupId)> onWsDisconnected;
        std::function<void(const GroupMessage&)> onMessageReceived;
        std::function<void(const std::string& groupId, const std::string& username,
                            const std::string& role)> onMemberJoined;
        std::function<void(const std::string& groupId, const std::string& username)> onMemberLeft;
        std::function<void(const std::string& groupId,
                            const std::vector<GroupMessage>&)> onHistoryLoaded;
        std::function<void(const std::string& serverUrl, const std::string& error)> onJoinError;
    };

    explicit GroupManager(StorageManager* storage);
    ~GroupManager();

    GroupManager(const GroupManager&) = delete;
    GroupManager& operator=(const GroupManager&) = delete;

    // Вступить в группу/канал на сервере (HTTP join + WS)
    void joinGroup(const std::string& serverUrl, const std::string& username);

    // Покинуть группу (HTTP leave + закрыть WS)
    void leaveGroup(const std::string& groupId);

    // Подключить WS для уже сохранённой группы
    void connectGroup(const Group& g);

    // Загрузить все сохранённые группы из БД и установить WS-соединения
    void loadSavedGroups();

    // Отправить зашифрованное сообщение в группу
    bool sendMessage(const std::string& groupId, const std::string& text);

    // Список всех загруженных групп
    [[nodiscard]] std::vector<Group> groups() const;
    [[nodiscard]] Group groupById(const std::string& id) const;

    using Token = uint32_t;
    Token addListener(GroupEvent ev);
    void removeListener(Token t);

private:
    struct Conn;

    template<typename Fn>
    void fire(Fn&& invoke) const {
        std::vector<std::pair<Token, GroupEvent>> snap;
        { std::lock_guard<std::mutex> lk(m_listenerMutex); snap = m_listeners; }
        for (auto& [tok, ev] : snap) invoke(ev);
    }

    void wsThreadFunc(const std::string& groupId, Conn* conn);
    void handleWsFrame(const std::string& groupId, const std::string& text);

    // Encrypt plaintext with group AES key → base64(nonce+ct+tag)
    [[nodiscard]] static std::string encryptGroupMsg(const Bytes& key, const std::string& text);
    // Decrypt base64(nonce+ct+tag) → plaintext
    [[nodiscard]] static std::string decryptGroupMsg(const Bytes& key, const std::string& base64);

    StorageManager* m_storage;
    mutable std::mutex m_mutex;
    std::unordered_map<std::string, std::unique_ptr<Conn>> m_conns; // groupId → Conn

    mutable std::mutex m_listenerMutex;
    std::vector<std::pair<Token, GroupEvent>> m_listeners;
    Token m_nextToken{0};
};
