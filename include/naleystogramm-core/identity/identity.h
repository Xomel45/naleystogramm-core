#pragma once
#include <string>
#include <optional>
#include <cstdint>

struct PeerInfo {
    std::string name;
    std::string uuid;
    std::string ip;
    uint16_t    port{0};

    [[nodiscard]] bool operator==(const PeerInfo& o) const noexcept {
        return uuid == o.uuid;
    }
};

// "username@discovery-server.example[:port]" — поиск контакта на чужом
// discovery-сервере (naleystogramm-server), в отличие от ручного PeerInfo.
struct DiscoveryAddress {
    std::string username;
    std::string host;
    uint16_t    port{0};
};

class Identity {
public:
    static Identity& instance();

    // Load from disk or generate on first launch
    void load();
    void save() const;

    [[nodiscard]] std::string uuid()        const { return m_uuid; }
    [[nodiscard]] std::string displayName() const { return m_name; }
    void setDisplayName(const std::string& name);

    // "UUID@IP:Port" — share this with contacts
    [[nodiscard]] std::string connectionString(const std::string& externalIp, uint16_t port) const;

    // Parse a connection string received from a contact
    static std::optional<PeerInfo> parseConnectionString(const std::string& str);

    // Parse "username@discovery-server.example[:port]" — returns nullopt if the
    // part before '@' is a valid UUID (that's parseConnectionString's job instead)
    static std::optional<DiscoveryAddress> parseDiscoveryAddress(const std::string& str);

    // "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" — accepts upper and lower case hex
    static bool isValidUuid(const std::string& uuid);

    // Default port for naleystogramm-server in --mode discovery
    static constexpr uint16_t kDefaultDiscoveryPort = 47822;

private:
    Identity() = default;
    std::string m_filePath;
    std::string m_uuid;
    std::string m_name;
};
