#pragma once
// Чистые типы данных — передаются между core и UI.
// Не содержит сервисных классов (QObject, сигналов, методов).
// Не зависит от Qt — только std C++.
// UI-код включает src/ui/qt_bridge.h для конвертаций std ↔ Qt.
#include <string>
#include <vector>
#include <cstdint>

// ── Контакт ──────────────────────────────────────────────────────────────────
struct Contact {
    std::string          uuid;
    std::string          name;
    std::string          ip;
    uint16_t             port{0};
    std::vector<uint8_t> identityKey;
    std::string          avatarHash {};
    std::string          avatarPath {};
    bool                 isBlocked {false};
    bool                 isMuted   {false};
    int64_t              lastSeen  {0};    // epoch ms; 0 = never
    std::string          systemInfoJson {};
    std::string          birthday       {};   // ISO date "yyyy-MM-dd" or empty
    std::string          versionCreated {"0.1.0"};
};

// ── Сообщение ─────────────────────────────────────────────────────────────────
struct Message {
    int64_t              id{0};
    std::string          peerUuid;
    bool                 outgoing{false};
    std::string          text;
    std::string          fileName;
    int64_t              fileSize{0};
    std::vector<uint8_t> ciphertext;
    int64_t              timestamp{0};    // epoch ms; 0 = not set
    bool                 delivered{false};
    bool                 isVoice{false};
    int                  voiceDurationMs{0};
    std::string          versionCreated {"0.1.0"};
};

// ── Логирование ───────────────────────────────────────────────────────────────
enum class LogLevel {
    Debug,
    Info,
    Warning,
    Error
};

enum class LogComponent {
    Network,
    FileTransfer,
    Crypto,
    Storage,
    UI,
    General
};

struct LogEntry {
    int64_t      timestamp{0};   // epoch ms
    LogLevel     level;
    LogComponent component;
    std::string  message;
};

// ── Прогресс передачи файла ──────────────────────────────────────────────────
struct TransferProgress {
    std::string  id;
    std::string  fileName;
    int64_t      bytesTransferred{0};
    int64_t      totalBytes{0};
    double       speedBytesPerSec{0.0};
    int          etaSeconds{0};
    int          percent{0};
    bool         outgoing{false};
};

// ── Группа / Канал ────────────────────────────────────────────────────────────
enum class GroupType {
    Group,
    Channel
};

struct Group {
    std::string          id;              // server URL — уникальный идентификатор
    std::string          name;
    GroupType            type{GroupType::Group};
    std::string          serverUrl;
    std::string          username;        // наш username на этом сервере
    std::string          token;           // auth token (хранится зашифрованным в DB)
    std::vector<uint8_t> groupKey;        // расшифрованный AES-256 ключ (32 байта)
    std::vector<uint8_t> localPrivKey;    // ephemeral X25519 privkey для этой группы
    std::vector<uint8_t> localPubKey;     // ephemeral X25519 pubkey
    bool                 isAdmin{false};
    int64_t              joinedAt{0};     // epoch ms
};

struct GroupMessage {
    int64_t     id{0};
    std::string groupId;         // = serverUrl
    std::string sender;          // username отправителя
    std::string text;            // расшифрованный текст
    int64_t     ts{0};           // unix timestamp ms
    bool        outgoing{false};
};

// Наш аккаунт на discovery-сервере (naleystogramm-server, --mode discovery).
// Один аккаунт на клиента — регистрация на новом сервере перезаписывает старую запись.
struct DiscoveryAccount {
    std::string host;
    uint16_t    port{0};
    std::string username;
    std::string token;        // auth token (хранится зашифрованным в DB)
    int64_t     registeredAt{0}; // epoch ms

    [[nodiscard]] bool isEmpty() const noexcept { return host.empty() || username.empty(); }
};

// ── Информация об обновлении ─────────────────────────────────────────────────
struct UpdateInfo {
    std::string version;
    std::string url;         // HTML-страница релиза
    std::string notes;
    std::string downloadUrl; // прямая ссылка на пакет (пусто — только HTML-страница)
    std::string assetName;   // имя файла (определяет тип пакета)
    bool        available{false};
};
