#include "naleystogramm-core/storage/sessionmanager.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <openssl/rand.h>
#include <filesystem>
#include <openssl/evp.h>

#ifndef APP_VERSION
#  define APP_VERSION "unknown"
#endif

static constexpr const char* kFileName = "session.json";

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::string xdgDir(const char* envVar, const char* fallback) {
    const char* val = std::getenv(envVar);
    if (val && *val) return std::string(val);
    const char* home = std::getenv("HOME");
    return std::string(home ? home : "/tmp") + fallback;
}

static std::string generateUuid() {
    unsigned char b[16];
    RAND_bytes(b, 16);
    b[6] = (b[6] & 0x0Fu) | 0x40u;  // version 4
    b[8] = (b[8] & 0x3Fu) | 0x80u;  // variant 1
    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7],
        b[8],b[9], b[10],b[11],b[12],b[13],b[14],b[15]);
    return buf;
}

// ── Singleton ─────────────────────────────────────────────────────────────────

SessionManager& SessionManager::instance() {
    static SessionManager inst;
    return inst;
}

SessionManager::SessionManager() {
    initFilePath();
}

// ── Path init ─────────────────────────────────────────────────────────────────

void SessionManager::initFilePath() {
#ifdef _WIN32
    const char* local = std::getenv("LOCALAPPDATA");
    std::string base = std::string(local ? local : "C:\\ProgramData") + "\\naleystogramm";
#else
    std::string base = xdgDir("XDG_CACHE_HOME", "/.cache") + "/naleystogramm";
#endif
    std::filesystem::create_directories(base);
    m_filePath = base + "/" + kFileName;
    std::fprintf(stderr, "[Session] Config File Located\n");
}

// ── Load ──────────────────────────────────────────────────────────────────────

void SessionManager::load() {
    std::ifstream f(m_filePath);
    if (!f.is_open()) {
        std::fprintf(stderr, "[Session] No session.json — creating new\n");
        generateIdentityIfNeeded();
        save();
        return;
    }

    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    f.close();

    nlohmann::json obj;
    try {
        obj = nlohmann::json::parse(content);
    } catch (...) {
        std::fprintf(stderr, "[Session] session.json is malformed — resetting\n");
        generateIdentityIfNeeded();
        save();
        return;
    }

    if (!obj.is_object()) {
        std::fprintf(stderr, "[Session] session.json is not an object — resetting\n");
        generateIdentityIfNeeded();
        save();
        return;
    }

    // Identity
    if (obj.contains("identity") && obj["identity"].is_object()) {
        const auto& id = obj["identity"];
        m_uuid        = id.value("uuid",        std::string{});
        m_displayName = id.value("name",        std::string{"User"});
        m_bio         = id.value("bio",         std::string{});
        m_birthday    = id.value("birthday",    std::string{});
        m_avatarPath  = id.value("avatarPath",  std::string{});
    }

    // Network
    if (obj.contains("network") && obj["network"].is_object()) {
        const auto& net = obj["network"];
        m_port               = static_cast<uint16_t>(net.value("port",               47821));
        m_bindIp             = net.value("bindIp",             std::string{});
        m_portForwardingMode = static_cast<PortForwardingMode>(
            net.value("portForwardingMode", static_cast<int>(PortForwardingMode::UpnpAuto)));
        m_manualPublicIp     = net.value("manualPublicIp",     std::string{});
        m_manualPublicPort   = static_cast<uint16_t>(net.value("manualPublicPort",   47821));
        m_relayServerIp      = net.value("relayServerIp",      std::string{});
        m_relayTcpPort       = static_cast<uint16_t>(net.value("relayTcpPort",       47822));
        m_relayUdpPort       = static_cast<uint16_t>(net.value("relayUdpPort",       47823));
    }

    // UI
    if (obj.contains("ui") && obj["ui"].is_object()) {
        const auto& ui = obj["ui"];
        m_theme          = ui.value("theme",          std::string{"dark"});
        m_language       = ui.value("language",       std::string{"ru"});
        m_demoMode       = ui.value("demoMode",       false);
        m_leftPanelWidth = ui.value("leftPanelWidth", 320);
        m_enterSends     = ui.value("enterSends",     true);
    }

    // Updates
    if (obj.contains("updates") && obj["updates"].is_object()) {
        const auto& upd = obj["updates"];
        m_lastUpdateCheck  = upd.value("lastChecked", std::string{});
        m_autoCheckUpdates = upd.value("autoCheck",   true);
    }

    // Security
    if (obj.contains("security") && obj["security"].is_object()) {
        m_remoteShellEnabled = obj["security"].value("remoteShell", false);
    }

    // Privacy
    if (obj.contains("privacy") && obj["privacy"].is_object()) {
        const auto& prv = obj["privacy"];
        auto pl = [&](const char* key, PrivacyLevel def) {
            return static_cast<PrivacyLevel>(
                prv.value(key, static_cast<int>(def)));
        };
        m_privacyMessages = pl("messages", PrivacyLevel::Everyone);
        m_privacyFiles    = pl("files",    PrivacyLevel::Everyone);
        m_privacyCalls    = pl("calls",    PrivacyLevel::Everyone);
        m_privacyVoice    = pl("voice",    PrivacyLevel::Everyone);
        m_privacyAvatar   = pl("avatar",   PrivacyLevel::Everyone);
        m_privacyShell    = pl("shell",    PrivacyLevel::ContactsOnly);
    }

    // Linked devices
    m_linkedDevices.clear();
    if (obj.contains("linkedDevices") && obj["linkedDevices"].is_array()) {
        for (const auto& v : obj["linkedDevices"])
            m_linkedDevices.push_back(LinkedDevice::fromJson(v));
    }

    generateIdentityIfNeeded();
    std::fprintf(stderr, "[Session] Session Loaded\n");
}

// ── Save ──────────────────────────────────────────────────────────────────────

void SessionManager::save() {
    // Metadata: ISO-8601 timestamp without Qt
    std::time_t now = std::time(nullptr);
    char tsbuf[32];
    std::strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%dT%H:%M:%S", std::gmtime(&now));

    nlohmann::json devArr = nlohmann::json::array();
    for (const auto& d : m_linkedDevices)
        devArr.push_back(d.toJson());

    nlohmann::json root = {
        {"identity", {
            {"uuid",       m_uuid},
            {"name",       m_displayName},
            {"bio",        m_bio},
            {"birthday",   m_birthday},
            {"avatarPath", m_avatarPath},
        }},
        {"network", {
            {"port",               static_cast<int>(m_port)},
            {"bindIp",             m_bindIp},
            {"portForwardingMode", static_cast<int>(m_portForwardingMode)},
            {"manualPublicIp",     m_manualPublicIp},
            {"manualPublicPort",   static_cast<int>(m_manualPublicPort)},
            {"relayServerIp",      m_relayServerIp},
            {"relayTcpPort",       static_cast<int>(m_relayTcpPort)},
            {"relayUdpPort",       static_cast<int>(m_relayUdpPort)},
        }},
        {"ui", {
            {"theme",          m_theme},
            {"language",       m_language},
            {"demoMode",       m_demoMode},
            {"leftPanelWidth", m_leftPanelWidth},
            {"enterSends",     m_enterSends},
        }},
        {"updates", {
            {"lastChecked", m_lastUpdateCheck},
            {"autoCheck",   m_autoCheckUpdates},
        }},
        {"security", {
            {"remoteShell", m_remoteShellEnabled},
        }},
        {"privacy", {
            {"messages", static_cast<int>(m_privacyMessages)},
            {"files",    static_cast<int>(m_privacyFiles)},
            {"calls",    static_cast<int>(m_privacyCalls)},
            {"voice",    static_cast<int>(m_privacyVoice)},
            {"avatar",   static_cast<int>(m_privacyAvatar)},
            {"shell",    static_cast<int>(m_privacyShell)},
        }},
        {"meta", {
            {"version", APP_VERSION},
            {"savedAt", std::string(tsbuf)},
        }},
        {"linkedDevices", devArr},
    };

    std::ofstream f(m_filePath, std::ios::out | std::ios::trunc);
    if (!f.is_open()) {
        std::fprintf(stderr, "[Session] Cannot write %s\n", m_filePath.c_str());
        return;
    }
    f << root.dump(4);
    f.close();
    std::fprintf(stderr, "[Session] Session Saved\n");
}

// ── Identity generation ───────────────────────────────────────────────────────

void SessionManager::generateIdentityIfNeeded() {
    if (m_uuid.empty()) {
        m_uuid = generateUuid();
        std::fprintf(stderr, "[Session] Identity Generated\n");
    }
    if (m_displayName.empty())
        m_displayName = "User";
}

// ── Immediate save (replaces debounced QTimer) ────────────────────────────────

void SessionManager::scheduleSave() {
    save();
}

// ── Setters ───────────────────────────────────────────────────────────────────

void SessionManager::setUuid(const std::string& uuid)          { m_uuid = uuid;              scheduleSave(); }
void SessionManager::setDisplayName(const std::string& name)   { m_displayName = name;       scheduleSave(); }
void SessionManager::setBio(const std::string& b)              { m_bio = b;                  scheduleSave(); }
void SessionManager::setBirthday(const std::string& d)         { m_birthday = d;             scheduleSave(); }
void SessionManager::setPort(uint16_t port)                    { m_port = port;              scheduleSave(); }
void SessionManager::setBindIp(const std::string& ip)          { m_bindIp = ip;              scheduleSave(); }
void SessionManager::setTheme(const std::string& theme)        { m_theme = theme;            scheduleSave(); }
void SessionManager::setLanguage(const std::string& lang)      { m_language = lang;          scheduleSave(); }
void SessionManager::setDemoMode(bool on)                      { m_demoMode = on;            scheduleSave(); }
void SessionManager::setLeftPanelWidth(int w)                  { m_leftPanelWidth = w;       scheduleSave(); }
void SessionManager::setEnterSends(bool on)                    { m_enterSends = on;          scheduleSave(); }
void SessionManager::setLastUpdateCheck(const std::string& iso){ m_lastUpdateCheck = iso;    scheduleSave(); }
void SessionManager::setAutoCheckUpdates(bool on)              { m_autoCheckUpdates = on;    scheduleSave(); }

void SessionManager::setPortForwardingMode(PortForwardingMode mode) {
    m_portForwardingMode = mode;
    scheduleSave();
}

void SessionManager::setManualPublicIp(const std::string& ip)  { m_manualPublicIp = ip;      scheduleSave(); }
void SessionManager::setManualPublicPort(uint16_t port)        { m_manualPublicPort = port;  scheduleSave(); }
void SessionManager::setRelayServerIp(const std::string& ip)   { m_relayServerIp = ip;       scheduleSave(); }
void SessionManager::setRelayTcpPort(uint16_t port)            { m_relayTcpPort = port;      scheduleSave(); }
void SessionManager::setRelayUdpPort(uint16_t port)            { m_relayUdpPort = port;      scheduleSave(); }

void SessionManager::setRemoteShellEnabled(bool on)            { m_remoteShellEnabled = on;  scheduleSave(); }

void SessionManager::setPrivacyMessages(PrivacyLevel v) { m_privacyMessages = v; scheduleSave(); }
void SessionManager::setPrivacyFiles   (PrivacyLevel v) { m_privacyFiles    = v; scheduleSave(); }
void SessionManager::setPrivacyCalls   (PrivacyLevel v) { m_privacyCalls    = v; scheduleSave(); }
void SessionManager::setPrivacyVoice   (PrivacyLevel v) { m_privacyVoice    = v; scheduleSave(); }
void SessionManager::setPrivacyAvatar  (PrivacyLevel v) { m_privacyAvatar   = v; scheduleSave(); }
void SessionManager::setPrivacyShell   (PrivacyLevel v) { m_privacyShell    = v; scheduleSave(); }

void SessionManager::setAvatarPath(const std::string& path)   { m_avatarPath = path;         scheduleSave(); }

// ── computeAvatarHash ─────────────────────────────────────────────────────────

std::string SessionManager::computeAvatarHash(const std::string& filePath) {
    std::ifstream f(filePath, std::ios::binary);
    if (!f.is_open()) return {};

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

    char buf[8192];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0)
        EVP_DigestUpdate(ctx, buf, static_cast<size_t>(f.gcount()));

    unsigned char digest[32];
    unsigned int  len = 0;
    EVP_DigestFinal_ex(ctx, digest, &len);
    EVP_MD_CTX_free(ctx);

    char hex[65];
    for (unsigned i = 0; i < len; ++i)
        std::snprintf(hex + i * 2, 3, "%02x", digest[i]);
    hex[64] = '\0';
    return hex;
}

// ── ensureDirectories ─────────────────────────────────────────────────────────

void SessionManager::ensureDirectories() {
#ifdef _WIN32
    const char* local = std::getenv("LOCALAPPDATA");
    std::string base = std::string(local ? local : "C:\\ProgramData") + "\\naleystogramm";
    const std::pair<const char*, std::string> dirs[] = {
        { "Config",  base },
        { "Avatars", base + "\\avatars" },
        { "Logs",    base + "\\logs"    },
        { "Keys",    base + "\\keys"    },
    };
#else
    std::string cache  = xdgDir("XDG_CACHE_HOME",  "/.cache")              + "/naleystogramm";
    std::string config = xdgDir("XDG_CONFIG_HOME", "/.config")             + "/naleystogramm";
    std::string data   = xdgDir("XDG_DATA_HOME",   "/.local/share")        + "/naleystogramm";
    const std::pair<const char*, std::string> dirs[] = {
        { "Config",  config          },
        { "Avatars", cache + "/avatars" },
        { "Logs",    data  + "/logs" },
        { "Keys",    data  + "/keys" },
    };
#endif

    for (const auto& [label, path] : dirs) {
        std::error_code ec;
        std::filesystem::create_directories(path, ec);
        if (!ec)
            std::fprintf(stderr, "[Session] Directory Ready: %s\n", label);
        else
            std::fprintf(stderr, "[Session] Directory Creation Failed: %s — %s\n",
                         label, ec.message().c_str());
    }
}

// ── Linked devices ────────────────────────────────────────────────────────────

void SessionManager::addLinkedDevice(const LinkedDevice& dev) {
    for (auto& d : m_linkedDevices) {
        if (d.uuid == dev.uuid) { d = dev; scheduleSave(); return; }
    }
    m_linkedDevices.push_back(dev);
    scheduleSave();
}

void SessionManager::removeLinkedDevice(const std::string& uuid) {
    auto before = m_linkedDevices.size();
    m_linkedDevices.erase(
        std::remove_if(m_linkedDevices.begin(), m_linkedDevices.end(),
                       [&](const LinkedDevice& d){ return d.uuid == uuid; }),
        m_linkedDevices.end());
    if (m_linkedDevices.size() != before) scheduleSave();
}

bool SessionManager::isLinkedDevice(const std::string& uuid) const {
    return std::any_of(m_linkedDevices.cbegin(), m_linkedDevices.cend(),
                       [&](const LinkedDevice& d){ return d.uuid == uuid; });
}

std::optional<LinkedDevice> SessionManager::linkedDevice(const std::string& uuid) const {
    for (const auto& d : m_linkedDevices)
        if (d.uuid == uuid) return d;
    return std::nullopt;
}
