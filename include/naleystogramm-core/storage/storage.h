#pragma once
#include "naleystogramm-core/types.h"
#include <vector>
#include <cstdint>
#include <string>

struct sqlite3;   // opaque — не тянем sqlite3.h в заголовок

class StorageManager {
public:
    StorageManager();
    ~StorageManager();

    bool open();

    // Contacts
    [[nodiscard]] bool addContact(const Contact& c);
    [[nodiscard]] bool updateContactAddress(const std::string& uuid, const std::string& ip, uint16_t port);
    [[nodiscard]] bool updateContactKey(const std::string& uuid, const std::vector<uint8_t>& identityKey);
    [[nodiscard]] bool updateAvatar(const std::string& uuid, const std::string& hash, const std::string& path);
    [[nodiscard]] bool updateContactName(const std::string& uuid, const std::string& name);
    [[nodiscard]] bool updateContactSystemInfo(const std::string& uuid, const std::string& infoJson);
    [[nodiscard]] bool updateContactBirthday(const std::string& uuid, const std::string& birthday);
    [[nodiscard]] bool blockContact(const std::string& uuid, bool blocked);
    [[nodiscard]] bool setContactMuted(const std::string& uuid, bool muted);
    bool               updateLastSeen(const std::string& uuid);
    [[nodiscard]] Contact              getContact(const std::string& uuid) const;
    [[nodiscard]] std::vector<Contact> allContacts() const;
    [[nodiscard]] bool deleteContact(const std::string& uuid);
    [[nodiscard]] bool isUuidBlocked(const std::string& uuid) const;
    [[nodiscard]] bool clearMessages(const std::string& uuid);

    // Messages
    [[nodiscard]] int64_t              saveMessage(const Message& msg);
    [[nodiscard]] std::vector<Message> getMessages(const std::string& peerUuid,
                                                   int limit = 50, int offset = 0) const;
    [[nodiscard]] bool        markDelivered(int64_t msgId);
    [[nodiscard]] std::string lastMessageText(const std::string& peerUuid) const;
    [[nodiscard]] int64_t     lastMessageTime(const std::string& peerUuid) const;  // epoch ms; 0 = none

    // Groups & Channels
    [[nodiscard]] bool saveGroup(const Group& g);
    [[nodiscard]] bool updateGroupToken(const std::string& groupId, const std::string& token);
    [[nodiscard]] bool updateGroupKey(const std::string& groupId, const std::vector<uint8_t>& key);
    [[nodiscard]] bool updateGroupName(const std::string& groupId, const std::string& name);
    [[nodiscard]] bool setGroupAdmin(const std::string& groupId, bool isAdmin);
    [[nodiscard]] Group              getGroup(const std::string& groupId) const;
    [[nodiscard]] std::vector<Group> allGroups() const;
    [[nodiscard]] bool deleteGroup(const std::string& groupId);

    // Group Messages
    [[nodiscard]] int64_t                   saveGroupMessage(const GroupMessage& msg);
    [[nodiscard]] std::vector<GroupMessage> getGroupMessages(const std::string& groupId,
                                                             int limit = 50, int offset = 0) const;
    [[nodiscard]] std::string lastGroupMessageText(const std::string& groupId) const;

    // Discovery account — наша регистрация на discovery-сервере (один аккаунт на клиента)
    [[nodiscard]] bool             saveDiscoveryAccount(const DiscoveryAccount& a);
    [[nodiscard]] DiscoveryAccount getDiscoveryAccount() const; // пусто (isEmpty()) если не зарегистрированы
    [[nodiscard]] bool             clearDiscoveryAccount();

private:
    void migrate();
    bool hasColumn(const char* table, const char* col) const;

    sqlite3* m_db{nullptr};
};
