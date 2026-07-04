#pragma once
#include "naleystogramm-core/types.h"
#include "naleystogramm-core/identity/identity.h"
#include "naleystogramm-core/net/upnp.h"
#include <nlohmann/json.hpp>
#include <asio.hpp>
#include <memory>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <vector>
#include <utility>
#include <atomic>

// ── Состояние подключения ─────────────────────────────────────────────────────

enum class ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting
};

// ── Пир ───────────────────────────────────────────────────────────────────────

struct PeerConnection {
    std::string uuid           {};
    std::string name           {};
    std::string ip             {};
    uint16_t    port           {0};
    uint16_t    serverPort     {0};

    std::shared_ptr<asio::ip::tcp::socket> socket;
    std::string readBuf{};

    ConnectionState state             {ConnectionState::Disconnected};
    int             reconnectAttempts {0};
    int64_t         lastActivity      {0};   // epoch ms

    std::shared_ptr<asio::steady_timer> pingTimer{};
    std::shared_ptr<asio::steady_timer> pongTimeoutTimer{};
    std::chrono::steady_clock::time_point pingStart {};
    bool            awaitingPong      {false};

    // Rate limiting
    std::chrono::steady_clock::time_point rateWindowStart {};
    bool     rateWindowValid {false};
    uint32_t rateCount       {0};

    int64_t     latencyMs      {-1};
    int64_t     connectedSince {0};  // epoch ms
    std::string systemInfoJson {};
    std::string avatarHash     {};
    std::string birthday       {};
    std::string helloName      {};
    std::string helloVersion   {};
    bool        isLinkedDevice {false};
    std::string pendingPairCode{};
    // UUID we expect in HANDSHAKE_ACK; empty for device-pairing flows (verified by OTP instead)
    std::string expectedUuid   {};
};

// ── Публичная информация о пире ───────────────────────────────────────────────

struct PeerPublicInfo {
    std::string     name;
    std::string     ip;
    uint16_t        serverPort     {0};
    ConnectionState state          {ConnectionState::Disconnected};
    int64_t         latencyMs      {-1};
    int64_t         connectedSince {0};  // epoch ms
    std::string     systemInfoJson {};
    std::string     avatarHash     {};
    std::string     birthday       {};
};

// ── NetworkEvent (callbacks вместо Qt-сигналов) ───────────────────────────────
// Вызываются на io_context-потоке. Bridge-слой должен перепоставить
// на Qt-поток через QMetaObject::invokeMethod(..., Qt::QueuedConnection).
// Незаполненные поля оставлять nullptr.

struct NetworkEvent {
    std::function<void(const std::string& ip, uint16_t port, bool upnpOk)> onReady;
    std::function<void(const std::string& ip)>                              onExternalIp;
    std::function<void(bool ok)>                                            onUpnpResult;
    std::function<void(bool open)>                                          onOpenPortResult;
    std::function<void()>                                                   onRelayConnected;
    std::function<void()>                                                   onRelayDisconnected;
    std::function<void(const std::string& uuid,
                       const std::string& name,
                       const std::string& ip)>                              onIncomingRequest;
    std::function<void(const std::string& uuid,
                       const nlohmann::json& msg)>                          onMessage;
    std::function<void(const std::string& uuid,
                       const std::string& name)>                            onPeerConnected;
    std::function<void(const std::string& uuid)>                            onPeerDisconnected;
    std::function<void(const std::string& uuid,
                       const std::string& name)>                            onNameUpdated;
    std::function<void(const std::string& uuid,
                       const std::string& name,
                       bool isPrimary)>                                      onDeviceLinked;
    std::function<void(const std::string& uuid)>                            onPeerInfoUpdated;
    std::function<void(const std::string& uuid,
                       ConnectionState state)>                               onStateChanged;
    std::function<void(const std::string& msg)>                             onLog;
    std::function<void(const std::string& msg)>                             onError;
};

// ── NetworkManager ────────────────────────────────────────────────────────────

class NetworkManager {
public:
    NetworkManager();
    ~NetworkManager();

    void init();

    [[nodiscard]] std::string externalIp()     const noexcept { return m_externalIp; }
    [[nodiscard]] uint16_t    localPort()      const noexcept { return m_localPort; }
    [[nodiscard]] uint16_t    advertisedPort() const noexcept {
        return m_advertisedPort ? m_advertisedPort : m_localPort;
    }
    [[nodiscard]] bool        upnpMapped()     const noexcept { return m_upnpMapped; }

    // Доступ к io_context для подсистем, которым нужны asio::steady_timer
    // (например, CallManager).
    [[nodiscard]] asio::io_context& ioContext() { return m_io; }

    static constexpr uint16_t kDefaultPort = 47821;

    [[nodiscard]] static std::string detectLocalLanIp();

    // Публичные методы — thread-safe через asio::post()
    void connectToPeer   (const PeerInfo& peer);
    void connectToDevice (const std::string& host, uint16_t port, const std::string& code);
    void relayToLinkedDevices(const std::string& exceptUuid, const nlohmann::json& frame);
    [[nodiscard]] std::string primaryDeviceUuid() const;
    void retryUpnp();
    void checkOpenPort();
    void broadcastProfileUpdate(const std::string& name);
    void acceptIncoming  (const std::string& peerUuid);
    void rejectIncoming  (const std::string& peerUuid);
    void sendFrame       (const std::string& peerUuid, const nlohmann::json& obj);
    bool isOnline        (const std::string& uuid) const;
    [[nodiscard]] PeerPublicInfo   getPeerInfo      (const std::string& uuid) const;
    [[nodiscard]] ConnectionState  connectionState  (const std::string& uuid) const;
    void setVerboseLogging(bool enabled);
    [[nodiscard]] bool verboseLogging() const { return m_verboseLogging; }

    // ── Listener API ─────────────────────────────────────────────────────
    using Token = uint32_t;
    Token addListener   (NetworkEvent ev);
    void  removeListener(Token t);

private:
    // Called once UpnpMapper completes (thread-safe via asio::post)
    void notifyUpnpResult(bool ok);

    // ── Asio ─────────────────────────────────────────────────────────────────
    asio::io_context    m_io;
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> m_work;
    asio::ip::tcp::acceptor m_acceptor;
    std::thread         m_ioThread;

    // ── Listener storage ─────────────────────────────────────────────────────
    mutable std::mutex  m_listenerMutex;
    std::vector<std::pair<Token, NetworkEvent>> m_listeners;
    Token               m_nextToken{0};

    // ── Peer state (accessed only on io_context thread) ───────────────────────
    std::unordered_map<std::string, PeerConnection>  m_peers;
    std::unordered_map<std::string, PeerConnection>  m_pending;

    struct PeerReconnectInfo { std::string name, ip; uint16_t port{0}; };
    std::unordered_map<std::string, PeerReconnectInfo>                  m_reconnectInfo;

    struct IpBanRecord {
        int     failures    {0};
        int64_t firstFailMs {0};
        int64_t bannedUntil {0};  // epoch ms; 0 = not banned
    };
    std::unordered_map<std::string, IpBanRecord> m_ipBanRecords;
    std::unordered_map<std::string, int>                                m_reconnectAttempts;
    std::unordered_map<std::string, std::shared_ptr<asio::steady_timer>> m_reconnectTimers;
    std::unordered_map<std::string, std::queue<nlohmann::json>>         m_messageQueues;

    // ── Network params ────────────────────────────────────────────────────────
    std::string  m_externalIp;
    uint16_t     m_localPort      {47821};
    uint16_t     m_advertisedPort {0};
    bool         m_upnpMapped     {false};
    bool         m_verboseLogging {false};

    // ── Relay ─────────────────────────────────────────────────────────────────
    std::shared_ptr<asio::ip::tcp::socket>       m_relaySocket;
    std::string                                  m_relayReadBuf;
    bool                                         m_relayRegistered    {false};
    std::unordered_set<std::string>              m_relayPeers;
    std::shared_ptr<asio::steady_timer>          m_relayReconnectTimer;
    std::shared_ptr<asio::steady_timer>          m_upnpRefreshTimer;
    std::unique_ptr<UpnpMapper>                  m_upnpMapper;

    // ── Internal methods ──────────────────────────────────────────────────────
    void startServer();
    void startAccept();
    void startAsyncRead    (const std::string& peerId, bool isPending);
    void startRelayRead    ();
    void handleDisconnect  (const std::string& uuid);

    void discoverExternalIp();
    void tryUpnp();
    void connectToRelay();
    void sendViaRelay      (const std::string& targetUuid, const nlohmann::json& obj);
    void handleRelayFrame  (const std::string& fromUuid, const nlohmann::json& innerObj);
    void handleFrame       (PeerConnection& peer, const nlohmann::json& obj);
    void sendClientHello    (asio::ip::tcp::socket& sock);
    void sendHandshake      (asio::ip::tcp::socket& sock);
    void sendUuidChallenge  (asio::ip::tcp::socket& sock, const std::string& expectedUuid);
    void recordUuidFailure  (const std::string& ip);
    void tryParseFrames    (PeerConnection& conn, bool isPending);
    void log               (const std::string& message, bool forceVerbose = false);
    void scheduleReconnect (const std::string& uuid);
    void attemptReconnect  (const std::string& uuid);
    void resetReconnectState(const std::string& uuid);
    int  calculateBackoffMs(int attempts) const;
    void startKeepalive    (const std::string& uuid);
    void stopKeepalive     (const std::string& uuid);
    void schedulePing      (const std::string& uuid);
    void sendPing          (const std::string& uuid);
    void handlePing        (PeerConnection& peer, const nlohmann::json& obj);
    void handlePong        (PeerConnection& peer, const nlohmann::json& obj);
    void drainMessageQueue (const std::string& uuid);

    // Helper: notify all listeners (must not hold m_listenerMutex)
    // Named "fire" to avoid collision with Qt's "emit" macro.
    template<typename Fn>
    void fire(Fn&& invoke) const {
        std::vector<std::pair<Token, NetworkEvent>> snap;
        {
            std::lock_guard<std::mutex> lk(m_listenerMutex);
            snap = m_listeners;
        }
        for (auto& [tok, ev] : snap)
            invoke(ev);
    }

    // ── Constants ─────────────────────────────────────────────────────────────
    static constexpr int     kConnectionTimeout    = 10000;
    static constexpr int     kMaxReconnectDelay    = 30000;
    static constexpr int     kPingInterval         = 30000;
    static constexpr int     kPongTimeout          = 10000;
    static constexpr int     kMaxReconnectAttempts = 50;
    static constexpr int     kMaxQueueSize         = 100;
    static constexpr int     kMaxBufferSize        = 16 * 1024 * 1024;
    static constexpr uint32_t kMaxFramesPerSecond  = 200;
    static constexpr const char* kMinPeerVersion   = "0.8.1.1";
    static constexpr int     kUpnpRefreshIntervalMs = 30 * 60 * 1000;
};
