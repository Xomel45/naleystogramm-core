#pragma once
#include "naleystogramm-core/identity/device_pairing.h"
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <filesystem>

// Уровень конфиденциальности
enum class PrivacyLevel : int {
    Everyone     = 0,
    ContactsOnly = 1,
    Nobody       = 2,
};

// Режим проброса портов
enum class PortForwardingMode : int {
    UpnpAuto     = 0,
    Manual       = 1,
    Disabled     = 2,
    ClientServer = 3,
    OpenPort     = 4,
};

// ── SessionManager ─────────────────────────────────────────────────────────────
class SessionManager {
public:
    static SessionManager& instance();

    void load();
    void save();

    [[nodiscard]] std::string filePath() const { return m_filePath; }

    // ── Identity ──────────────────────────────────────────────────────────
    [[nodiscard]] std::string uuid()        const { return m_uuid; }
    [[nodiscard]] std::string displayName() const { return m_displayName; }
    [[nodiscard]] std::string bio()         const { return m_bio; }
    [[nodiscard]] std::string birthday()    const { return m_birthday; }
    void setUuid(const std::string& uuid);
    void setDisplayName(const std::string& name);
    void setBio(const std::string& b);
    void setBirthday(const std::string& d);

    // ── Network ───────────────────────────────────────────────────────────
    [[nodiscard]] uint16_t    port()        const { return m_port; }
    [[nodiscard]] std::string bindIp()      const { return m_bindIp; }
    void setPort(uint16_t port);
    void setBindIp(const std::string& ip);

    // ── UI ────────────────────────────────────────────────────────────────
    [[nodiscard]] std::string theme()          const { return m_theme; }
    [[nodiscard]] std::string language()       const { return m_language; }
    [[nodiscard]] bool        demoMode()       const { return m_demoMode; }
    [[nodiscard]] int         leftPanelWidth() const { return m_leftPanelWidth; }
    [[nodiscard]] bool        enterSends()     const { return m_enterSends; }
    void setTheme(const std::string& theme);
    void setLanguage(const std::string& lang);
    void setDemoMode(bool on);
    void setLeftPanelWidth(int w);
    void setEnterSends(bool on);

    // ── Updates ───────────────────────────────────────────────────────────
    [[nodiscard]] std::string lastUpdateCheck()  const { return m_lastUpdateCheck; }
    [[nodiscard]] bool        autoCheckUpdates() const { return m_autoCheckUpdates; }
    void setLastUpdateCheck(const std::string& iso);
    void setAutoCheckUpdates(bool on);

    // ── Port Forwarding ───────────────────────────────────────────────────
    [[nodiscard]] PortForwardingMode portForwardingMode() const { return m_portForwardingMode; }
    [[nodiscard]] std::string        manualPublicIp()     const { return m_manualPublicIp; }
    [[nodiscard]] uint16_t           manualPublicPort()   const { return m_manualPublicPort; }
    void setPortForwardingMode(PortForwardingMode mode);
    void setManualPublicIp(const std::string& ip);
    void setManualPublicPort(uint16_t port);

    // ── Relay ─────────────────────────────────────────────────────────────
    [[nodiscard]] std::string relayServerIp()  const { return m_relayServerIp; }
    [[nodiscard]] uint16_t    relayTcpPort()   const { return m_relayTcpPort; }
    [[nodiscard]] uint16_t    relayUdpPort()   const { return m_relayUdpPort; }
    void setRelayServerIp(const std::string& ip);
    void setRelayTcpPort(uint16_t port);
    void setRelayUdpPort(uint16_t port);

    // ── Security ──────────────────────────────────────────────────────────
    [[nodiscard]] bool remoteShellEnabled() const { return m_remoteShellEnabled; }
    void setRemoteShellEnabled(bool on);

    // ── Privacy ───────────────────────────────────────────────────────────
    [[nodiscard]] PrivacyLevel privacyMessages() const { return m_privacyMessages; }
    [[nodiscard]] PrivacyLevel privacyFiles()    const { return m_privacyFiles;    }
    [[nodiscard]] PrivacyLevel privacyCalls()    const { return m_privacyCalls;    }
    [[nodiscard]] PrivacyLevel privacyVoice()    const { return m_privacyVoice;    }
    [[nodiscard]] PrivacyLevel privacyAvatar()   const { return m_privacyAvatar;   }
    [[nodiscard]] PrivacyLevel privacyShell()    const { return m_privacyShell;    }
    void setPrivacyMessages(PrivacyLevel v);
    void setPrivacyFiles   (PrivacyLevel v);
    void setPrivacyCalls   (PrivacyLevel v);
    void setPrivacyVoice   (PrivacyLevel v);
    void setPrivacyAvatar  (PrivacyLevel v);
    void setPrivacyShell   (PrivacyLevel v);

    // ── Avatar ────────────────────────────────────────────────────────────
    [[nodiscard]] std::string avatarPath() const { return m_avatarPath; }
    void setAvatarPath(const std::string& path);

    // SHA-256 hex of file; empty if file is not readable
    [[nodiscard]] static std::string computeAvatarHash(const std::string& filePath);

    // Create all required app directories (call once at startup before Logger/Storage/KeyProtector)
    static void ensureDirectories();

    // ── Linked devices ────────────────────────────────────────────────────
    [[nodiscard]] std::vector<LinkedDevice> linkedDevices() const { return m_linkedDevices; }
    void addLinkedDevice(const LinkedDevice& dev);
    void removeLinkedDevice(const std::string& uuid);
    [[nodiscard]] bool isLinkedDevice(const std::string& uuid) const;
    [[nodiscard]] std::optional<LinkedDevice> linkedDevice(const std::string& uuid) const;

private:
    SessionManager();

    void initFilePath();
    void generateIdentityIfNeeded();
    void scheduleSave();

    std::string m_filePath;

    // Identity
    std::string m_uuid;
    std::string m_displayName {"User"};
    std::string m_bio;
    std::string m_birthday;

    // Network
    uint16_t    m_port   {47821};
    std::string m_bindIp;

    // UI
    std::string m_theme          {"dark"};
    std::string m_language       {"ru"};
    bool        m_demoMode       {false};
    int         m_leftPanelWidth {320};
    bool        m_enterSends     {true};

    // Updates
    std::string m_lastUpdateCheck;
    bool        m_autoCheckUpdates {true};

    // Port Forwarding
    PortForwardingMode m_portForwardingMode {PortForwardingMode::UpnpAuto};
    std::string        m_manualPublicIp;
    uint16_t           m_manualPublicPort {47821};

    // Relay
    std::string m_relayServerIp;
    uint16_t    m_relayTcpPort {47822};
    uint16_t    m_relayUdpPort {47823};

    // Security
    bool m_remoteShellEnabled {false};

    // Privacy
    PrivacyLevel m_privacyMessages {PrivacyLevel::Everyone};
    PrivacyLevel m_privacyFiles    {PrivacyLevel::Everyone};
    PrivacyLevel m_privacyCalls    {PrivacyLevel::Everyone};
    PrivacyLevel m_privacyVoice    {PrivacyLevel::Everyone};
    PrivacyLevel m_privacyAvatar   {PrivacyLevel::Everyone};
    PrivacyLevel m_privacyShell    {PrivacyLevel::ContactsOnly};

    // Avatar
    std::string m_avatarPath;

    // Linked devices
    std::vector<LinkedDevice> m_linkedDevices;
};
