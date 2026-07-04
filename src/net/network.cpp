#include "naleystogramm-core/net/network.h"
#include "naleystogramm-core/identity/identity.h"
#include "naleystogramm-core/diag/versionutils.h"
#include "naleystogramm-core/identity/device_pairing.h"
#include "naleystogramm-core/diag/systeminfo.h"
#include "naleystogramm-core/storage/sessionmanager.h"
#include <nlohmann/json.hpp>
#include <asio.hpp>
#include <cmath>
#include <ctime>
#include <chrono>
#include <algorithm>
#include <random>
#include <string>
#include <memory>
#include <functional>
#include <future>
#ifdef HAVE_CURL
#  include <curl/curl.h>
#endif
#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <iphlpapi.h>
#else
#  include <ifaddrs.h>
#  include <net/if.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#endif

// ── Helpers ───────────────────────────────────────────────────────────────────

static int64_t currentEpochMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string generateUuid() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    uint64_t hi = dist(gen);
    uint64_t lo = dist(gen);
    hi = (hi & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;  // version 4
    lo = (lo & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;  // variant 10xx
    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%08x-%04x-%04x-%04x-%012llx",
        static_cast<uint32_t>(hi >> 32),
        static_cast<uint16_t>(hi >> 16),
        static_cast<uint16_t>(hi),
        static_cast<uint16_t>(lo >> 48),
        static_cast<unsigned long long>(lo & 0x0000FFFFFFFFFFFFULL));
    return std::string(buf);
}

#ifdef HAVE_CURL
static size_t curlWrite(void* ptr, size_t size, size_t nmemb, std::string* out) {
    const size_t chunk = size * nmemb;
    // Защита от OOM: безлимитное тело ответа не должно исчерпать память.
    static constexpr size_t kMaxResponse = 8 * 1024 * 1024;
    if (out->size() + chunk > kMaxResponse) return 0;
    out->append(static_cast<char*>(ptr), chunk);
    return chunk;
}
#endif

static void writeFrame(asio::ip::tcp::socket& sock, const nlohmann::json& obj) {
    const std::string data = obj.dump() + "\n";
    std::error_code ec;
    asio::write(sock, asio::buffer(data), ec);
}

static std::string sanitizeCtrl(const std::string& s, std::size_t maxLen = 256) {
    std::string r;
    r.reserve(std::min(s.size(), maxLen));
    for (unsigned char c : s) {
        if (r.size() >= maxLen) break;
        if (c >= 0x20 && c != 0x7F) r.push_back(static_cast<char>(c));
    }
    // trim trailing spaces
    while (!r.empty() && r.back() == ' ') r.pop_back();
    return r;
}

static constexpr int     kMaxUuidFailures  = 5;
static constexpr int64_t kBanDurationMs    = 30LL * 60 * 1000;  // 30 minutes

// ── Constructor / Destructor ──────────────────────────────────────────────────

NetworkManager::NetworkManager()
    : m_work(std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
          asio::make_work_guard(m_io)))
    , m_acceptor(m_io)
{
    m_ioThread = std::thread([this]() { m_io.run(); });
}

NetworkManager::~NetworkManager() {
    // Close acceptor from this thread; io_context handles the error gracefully
    {
        std::error_code ec;
        m_acceptor.close(ec);
    }

    // Cancel timers and close sockets on io_context thread, then wait
    std::promise<void> done;
    auto fut = done.get_future();
    asio::post(m_io, [this, &done]() mutable {
        for (auto& [uuid, peer] : m_peers) {
            if (peer.pingTimer)        peer.pingTimer->cancel();
            if (peer.pongTimeoutTimer) peer.pongTimeoutTimer->cancel();
            if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
        }
        for (auto& [uuid, timer] : m_reconnectTimers) timer->cancel();
        if (m_relayReconnectTimer) m_relayReconnectTimer->cancel();
        if (m_upnpRefreshTimer)    m_upnpRefreshTimer->cancel();
        if (m_relaySocket) { std::error_code ec; m_relaySocket->close(ec); }
        done.set_value();
    });
    fut.wait();

    m_work.reset();
    if (m_ioThread.joinable()) m_ioThread.join();
}

// ── Listener API ──────────────────────────────────────────────────────────────

NetworkManager::Token NetworkManager::addListener(NetworkEvent ev) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    Token t = m_nextToken++;
    m_listeners.emplace_back(t, std::move(ev));
    return t;
}

void NetworkManager::removeListener(Token t) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    m_listeners.erase(
        std::remove_if(m_listeners.begin(), m_listeners.end(),
                       [t](const auto& p){ return p.first == t; }),
        m_listeners.end());
}

// ── Logging ───────────────────────────────────────────────────────────────────

void NetworkManager::log(const std::string& message, bool forceVerbose) {
    std::fprintf(stderr, "[Network] %s\n", message.c_str());
    if (m_verboseLogging || forceVerbose) {
        fire([&message](NetworkEvent& ev) {
            if (ev.onLog) ev.onLog(message);
        });
    }
}

void NetworkManager::setVerboseLogging(bool enabled) {
    asio::post(m_io, [this, enabled]() {
        m_verboseLogging = enabled;
        log(std::string("Verbose logging ") + (enabled ? "enabled" : "disabled"), true);
    });
}

// ── Read-only getters (benign race — display only) ─────────────────────────────

ConnectionState NetworkManager::connectionState(const std::string& uuid) const {
    const auto it = m_peers.find(uuid);
    return (it != m_peers.end()) ? it->second.state : ConnectionState::Disconnected;
}

PeerPublicInfo NetworkManager::getPeerInfo(const std::string& uuid) const {
    const auto it = m_peers.find(uuid);
    if (it == m_peers.end()) return {};
    const auto& p = it->second;
    return PeerPublicInfo{
        .name           = p.name,
        .ip             = p.ip,
        .serverPort     = p.serverPort,
        .state          = p.state,
        .latencyMs      = p.latencyMs,
        .connectedSince = p.connectedSince,
        .systemInfoJson = p.systemInfoJson,
        .avatarHash     = p.avatarHash,
        .birthday       = p.birthday,
    };
}

bool NetworkManager::isOnline(const std::string& uuid) const {
    return m_peers.count(uuid) > 0;
}

// ── detectLocalLanIp ──────────────────────────────────────────────────────────

std::string NetworkManager::detectLocalLanIp() {
    static const std::vector<std::string> kVpnPfx {
        "tun","tap","wg","utun","ppp","vpn","veth","docker","virbr","br-"
    };
    auto isVpn = [&](const std::string& name) {
        for (const auto& p : kVpnPfx)
            if (name.rfind(p, 0) == 0) return true;
        return false;
    };

    std::string best192, best10, other;

#ifdef _WIN32
    ULONG bufLen = 16000;
    auto buf = std::make_unique<char[]>(bufLen);
    auto* pAddrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.get());
    if (GetAdaptersAddresses(AF_INET,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
            nullptr, pAddrs, &bufLen) != ERROR_SUCCESS)
        return {};
    for (auto* a = pAddrs; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp ||
            a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        char n[512] = {};
        WideCharToMultiByte(CP_UTF8,0,a->FriendlyName,-1,n,sizeof(n),nullptr,nullptr);
        std::string sname = n;
        std::transform(sname.begin(), sname.end(), sname.begin(), ::tolower);
        if (isVpn(sname)) continue;
        for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next) {
            if (ua->Address.lpSockaddr->sa_family != AF_INET) continue;
            char ipbuf[INET_ADDRSTRLEN];
            const auto* sin = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
            inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf));
            const std::string ip = ipbuf;
            if      (ip.rfind("192.168.",0)==0 && best192.empty()) best192 = ip;
            else if (ip.rfind("10.",0)==0       && best10.empty())  best10  = ip;
            else if (other.empty())                                   other   = ip;
        }
    }
#else
    struct ifaddrs* ifap = nullptr;
    if (::getifaddrs(&ifap) != 0) return {};
    for (auto* ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_RUNNING)) continue;
        if (ifa->ifa_flags & IFF_LOOPBACK) continue;
        const std::string sname = ifa->ifa_name ? ifa->ifa_name : "";
        if (isVpn(sname)) continue;
        char ipbuf[INET_ADDRSTRLEN];
        const auto* sin = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
        inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf));
        const std::string ip = ipbuf;
        if      (ip.rfind("192.168.",0)==0 && best192.empty()) best192 = ip;
        else if (ip.rfind("10.",0)==0       && best10.empty())  best10  = ip;
        else if (other.empty())                                   other   = ip;
    }
    ::freeifaddrs(ifap);
#endif

    return !best192.empty() ? best192 : !best10.empty() ? best10 : other;
}

// ── init / startServer / startAccept ─────────────────────────────────────────

void NetworkManager::init() {
    asio::post(m_io, [this]() {
        startServer();
        m_advertisedPort = m_localPort;

        const auto mode = SessionManager::instance().portForwardingMode();

        if (mode == PortForwardingMode::Manual) {
            m_externalIp     = SessionManager::instance().manualPublicIp();
            const uint16_t manPort = SessionManager::instance().manualPublicPort();
            m_advertisedPort = (manPort > 0) ? manPort : m_localPort;
            log("Режим Manual: " + m_externalIp + ":" + std::to_string(m_advertisedPort));
            if (!m_externalIp.empty())
                fire([this](NetworkEvent& ev){ if(ev.onExternalIp) ev.onExternalIp(m_externalIp); });
            fire([this](NetworkEvent& ev){ if(ev.onReady) ev.onReady(m_externalIp, m_advertisedPort, false); });

        } else if (mode == PortForwardingMode::Disabled) {
            m_externalIp     = detectLocalLanIp();
            m_advertisedPort = m_localPort;
            log("Режим Disabled: " + m_externalIp + ":" + std::to_string(m_advertisedPort));
            fire([this](NetworkEvent& ev){ if(ev.onExternalIp) ev.onExternalIp(m_externalIp); });
            fire([this](NetworkEvent& ev){ if(ev.onReady) ev.onReady(m_externalIp, m_advertisedPort, false); });

        } else if (mode == PortForwardingMode::ClientServer) {
            m_externalIp     = {};
            m_advertisedPort = m_localPort;
            log("Режим Client-Server: подключаемся к ретранслятору");
            connectToRelay();
            fire([this](NetworkEvent& ev){ if(ev.onReady) ev.onReady(m_externalIp, m_advertisedPort, false); });

        } else if (mode == PortForwardingMode::OpenPort) {
            const uint16_t manPort = SessionManager::instance().manualPublicPort();
            m_advertisedPort = (manPort > 0) ? manPort : m_localPort;
            log("Режим OpenPort: порт " + std::to_string(m_advertisedPort) + ", ищем внешний IP");
            discoverExternalIp();

        } else {
            // UpnpAuto — default
            tryUpnp();
            discoverExternalIp();
        }
    });
}

void NetworkManager::startServer() {
    const uint16_t configured = SessionManager::instance().port();
    uint16_t port = configured;
    std::error_code ec;

    while (true) {
        m_acceptor.open(asio::ip::tcp::v4(), ec);
        if (!ec) {
            m_acceptor.set_option(asio::ip::tcp::acceptor::reuse_address(true), ec);
            m_acceptor.bind(asio::ip::tcp::endpoint(asio::ip::tcp::v4(), port), ec);
        }
        if (!ec) { m_acceptor.listen(asio::socket_base::max_listen_connections, ec); }
        if (!ec) break;

        std::error_code closeEc;
        m_acceptor.close(closeEc);
        if (++port > configured + 20) {
            fire([&](NetworkEvent& ev){
                if (ev.onError) ev.onError("Cannot bind to any port near " + std::to_string(configured));
            });
            return;
        }
    }
    m_localPort = port;
    log("Listening on port " + std::to_string(port));
    startAccept();
}

void NetworkManager::startAccept() {
    auto sock = std::make_shared<asio::ip::tcp::socket>(m_io);
    m_acceptor.async_accept(*sock, [this, sock](std::error_code ec) {
        if (ec) return;
        startAccept();

        const std::string tempId = generateUuid();
        m_pending[tempId] = PeerConnection{
            .uuid   = tempId,
            .ip     = sock->remote_endpoint().address().to_string(),
            .socket = sock,
        };
        startAsyncRead(tempId, true);
    });
}

// ── Асинхронное чтение ────────────────────────────────────────────────────────

void NetworkManager::startAsyncRead(const std::string& peerId, bool isPending) {
    PeerConnection* connPtr = nullptr;
    if (isPending) {
        auto it = m_pending.find(peerId);
        if (it == m_pending.end()) return;
        connPtr = &it->second;
    } else {
        auto it = m_peers.find(peerId);
        if (it == m_peers.end()) return;
        connPtr = &it->second;
    }
    if (!connPtr->socket) return;

    auto sock     = connPtr->socket;
    auto stageBuf = std::make_shared<std::array<char, 8192>>();

    sock->async_read_some(asio::buffer(*stageBuf),
        [this, peerId, isPending, sock, stageBuf](std::error_code ec, std::size_t n) {
            if (ec) {
                if (isPending) {
                    m_pending.erase(peerId);
                } else {
                    handleDisconnect(peerId);
                }
                return;
            }

            PeerConnection* conn = nullptr;
            if (isPending) {
                auto it = m_pending.find(peerId);
                if (it == m_pending.end()) return;
                conn = &it->second;
            } else {
                auto it = m_peers.find(peerId);
                if (it == m_peers.end()) return;
                conn = &it->second;
            }

            if (static_cast<int>(conn->readBuf.size() + n) > kMaxBufferSize) {
                log("DoS: буфер пира " + conn->ip + " превысил " +
                    std::to_string(kMaxBufferSize / (1024*1024)) + " МБ — отключаем", true);
                std::error_code closeEc;
                sock->close(closeEc);
                return;
            }
            conn->readBuf.append(stageBuf->data(), n);
            tryParseFrames(*conn, isPending);

            startAsyncRead(peerId, isPending);
        });
}

// ── Разбор фреймов ────────────────────────────────────────────────────────────

void NetworkManager::tryParseFrames(PeerConnection& conn, bool /*isPending*/) {
    static constexpr int kMaxFrameSize = 1 * 1024 * 1024;

    while (true) {
        const auto nl = conn.readBuf.find('\n');
        if (nl == std::string::npos) break;

        const std::string rawFrame(conn.readBuf.data(), nl);
        conn.readBuf.erase(0, nl + 1);

        if (static_cast<int>(rawFrame.size()) > kMaxFrameSize) {
            log("Большой фрейм " + std::to_string(rawFrame.size()) +
                " байт от " + conn.ip + " — отброшен", true);
            continue;
        }

        const auto doc = nlohmann::json::parse(rawFrame, nullptr, false);
        if (!doc.is_discarded() && doc.is_object())
            handleFrame(conn, doc);
    }
}

// ── Отключение ────────────────────────────────────────────────────────────────

void NetworkManager::handleDisconnect(const std::string& uuid) {
    auto it = m_peers.find(uuid);
    if (it == m_peers.end()) return;

    const std::string name = it->second.name;
    log("Disconnected from " + name, true);

    stopKeepalive(uuid);

    if (it->second.socket) {
        std::error_code ec;
        it->second.socket->close(ec);
    }
    m_peers.erase(it);

    fire([&uuid](NetworkEvent& ev){ if(ev.onPeerDisconnected) ev.onPeerDisconnected(uuid); });
    fire([&uuid](NetworkEvent& ev){ if(ev.onStateChanged) ev.onStateChanged(uuid, ConnectionState::Disconnected); });

    if (m_reconnectInfo.count(uuid))
        scheduleReconnect(uuid);
}

// ── Внешний IP ────────────────────────────────────────────────────────────────

void NetworkManager::discoverExternalIp() {
#ifndef HAVE_CURL
    fire([this](NetworkEvent& ev){ if(ev.onReady) ev.onReady(m_externalIp, m_advertisedPort, m_upnpMapped); });
    return;
#else
    std::thread([this]() {
        static constexpr const char* kIpSources[] = {
            "https://api.ipify.org?format=json",
            "http://api.ipify.org?format=json",
            "http://ip4.seeip.org/json",
            "http://ifconfig.me/ip",
        };
        std::string body;
        CURL* curl = curl_easy_init();
        if (curl) {
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curlWrite);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &body);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT,        8L);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_USERAGENT,      "naleystogramm/" APP_VERSION);
            for (const char* url : kIpSources) {
                body.clear();
                curl_easy_setopt(curl, CURLOPT_URL, url);
                const CURLcode rc = curl_easy_perform(curl);
                if (rc != CURLE_OK) {
                    log(std::string("discoverExternalIp [") + url + "]: " + curl_easy_strerror(rc), true);
                    continue;
                }
                if (!body.empty()) break;
            }
            curl_easy_cleanup(curl);
        }

        asio::post(m_io, [this, body]() {
            const auto isValidIp = [](const std::string& s) {
                if (s.empty()) return false;
                // IPv6 minimal check
                if (s.find(':') != std::string::npos) {
                    for (char c : s)
                        if (!std::isalnum(static_cast<unsigned char>(c)) && c != ':') return false;
                    return true;
                }
                // IPv4
                int parts = 0; int val = 0; bool inNum = false;
                for (char c : s) {
                    if (std::isdigit(static_cast<unsigned char>(c))) {
                        val = val * 10 + (c - '0');
                        inNum = true;
                    } else if (c == '.' && inNum) {
                        if (val > 255) return false;
                        ++parts; val = 0; inNum = false;
                    } else return false;
                }
                return inNum && parts == 3 && val <= 255;
            };

            // trim whitespace from raw body
            std::string ip;
            {
                const auto s = body.find_first_not_of(" \t\r\n");
                const auto e = body.find_last_not_of(" \t\r\n");
                const std::string trimmed = (s != std::string::npos) ? body.substr(s, e - s + 1) : std::string{};
                const auto doc = nlohmann::json::parse(trimmed, nullptr, false);
                if (!doc.is_discarded() && doc.is_object())
                    ip = doc.value("ip", std::string{});
                else
                    ip = trimmed;  // plain-text response (e.g. ifconfig.me)
            }

            if (!isValidIp(ip)) {
                log("Невалидный внешний IP: '" + ip + "'", true);
            } else {
                m_externalIp = ip;
                log("External IP: " + ip);
                fire([this](NetworkEvent& ev){ if(ev.onExternalIp) ev.onExternalIp(m_externalIp); });
            }
            fire([this](NetworkEvent& ev){ if(ev.onReady) ev.onReady(m_externalIp, m_advertisedPort, m_upnpMapped); });
        });
    }).detach();
#endif
}

// ── UPnP ──────────────────────────────────────────────────────────────────────

void NetworkManager::tryUpnp() {
    log("UPnP: запускаем маппинг порта " + std::to_string(m_localPort) + "...");
    if (!m_upnpMapper) {
        m_upnpMapper = std::make_unique<UpnpMapper>(m_io,
            [this](const std::string& msg, bool important) { log("[UPnP] " + msg, important); });
    }
    const std::string localIp = detectLocalLanIp();
    m_upnpMapper->mapPort(m_localPort, localIp, [this](bool ok) { notifyUpnpResult(ok); });
}

void NetworkManager::notifyUpnpResult(bool ok) {
    asio::post(m_io, [this, ok]() {
        m_upnpMapped = ok;
        if (ok) {
            log("UPnP: маппинг успешен");
            if (!m_upnpRefreshTimer)
                m_upnpRefreshTimer = std::make_shared<asio::steady_timer>(m_io);

            auto scheduleRefresh = std::make_shared<std::function<void()>>();
            *scheduleRefresh = [this, scheduleRefresh]() {
                m_upnpRefreshTimer->expires_after(std::chrono::milliseconds(kUpnpRefreshIntervalMs));
                m_upnpRefreshTimer->async_wait([this, scheduleRefresh](std::error_code ec) {
                    if (ec) return;
                    if (SessionManager::instance().portForwardingMode() != PortForwardingMode::UpnpAuto) return;
                    log("UPnP: refresh — повторный маппинг порта " + std::to_string(m_localPort));
                    tryUpnp();
                });
            };
            (*scheduleRefresh)();
        } else {
            log("UPnP: маппинг провалился");
        }
        fire([ok](NetworkEvent& ev){ if(ev.onUpnpResult) ev.onUpnpResult(ok); });
    });
}

void NetworkManager::retryUpnp() {
    asio::post(m_io, [this]() {
        if (SessionManager::instance().portForwardingMode() != PortForwardingMode::UpnpAuto) {
            log("retryUpnp: пропускаем (не UpnpAuto)");
            return;
        }
        log("retryUpnp: повторный маппинг порта " + std::to_string(m_localPort));
        m_upnpMapped = false;
        tryUpnp();
    });
}

void NetworkManager::checkOpenPort() {
    asio::post(m_io, [this]() {
        if (m_externalIp.empty() || m_advertisedPort == 0) {
            fire([](NetworkEvent& ev){ if(ev.onOpenPortResult) ev.onOpenPortResult(false); });
            return;
        }
        std::error_code ec;
        const auto addr = asio::ip::make_address(m_externalIp, ec);
        if (ec) {
            fire([](NetworkEvent& ev){ if(ev.onOpenPortResult) ev.onOpenPortResult(false); });
            return;
        }

        auto sock  = std::make_shared<asio::ip::tcp::socket>(m_io);
        auto timer = std::make_shared<asio::steady_timer>(m_io);

        timer->expires_after(std::chrono::seconds(5));
        timer->async_wait([sock, timer](std::error_code) {
            std::error_code ce; sock->cancel(ce);
        });

        const uint16_t port = m_advertisedPort;
        sock->async_connect({addr, port},
            [this, sock, timer](std::error_code ec) {
                timer->cancel();
                std::error_code ce; sock->close(ce);
                const bool open = !ec;
                fire([open](NetworkEvent& ev){ if(ev.onOpenPortResult) ev.onOpenPortResult(open); });
            });
    });
}

// ── Ретранслятор ──────────────────────────────────────────────────────────────

void NetworkManager::connectToRelay() {
    const std::string relayIp  = SessionManager::instance().relayServerIp();
    const uint16_t    relayTcp = SessionManager::instance().relayTcpPort();

    if (relayIp.empty()) {
        log("Relay: IP сервера не задан");
        return;
    }

    if (m_relayReconnectTimer) m_relayReconnectTimer->cancel();

    if (m_relaySocket) {
        std::error_code ec; m_relaySocket->close(ec);
    }
    m_relaySocket     = std::make_shared<asio::ip::tcp::socket>(m_io);
    m_relayReadBuf.clear();
    m_relayRegistered = false;

    std::error_code ec;
    const auto addr = asio::ip::make_address(relayIp, ec);
    if (ec) { log("Relay: невалидный IP '" + relayIp + "'"); return; }

    log("Relay: подключаемся к " + relayIp + ":" + std::to_string(relayTcp));

    m_relaySocket->async_connect({addr, relayTcp},
        [this](std::error_code ec) {
            if (ec) {
                log("Relay: ошибка подключения: " + ec.message());
                if (!m_relayReconnectTimer)
                    m_relayReconnectTimer = std::make_shared<asio::steady_timer>(m_io);
                m_relayReconnectTimer->expires_after(std::chrono::seconds(5));
                m_relayReconnectTimer->async_wait([this](std::error_code e) {
                    if (!e) connectToRelay();
                });
                return;
            }
            nlohmann::json reg;
            reg["type"] = "RELAY_REGISTER";
            reg["uuid"] = Identity::instance().uuid();
            writeFrame(*m_relaySocket, reg);
            startRelayRead();
        });
}

void NetworkManager::startRelayRead() {
    if (!m_relaySocket || !m_relaySocket->is_open()) return;

    auto sock     = m_relaySocket;
    auto stageBuf = std::make_shared<std::array<char, 8192>>();

    sock->async_read_some(asio::buffer(*stageBuf),
        [this, sock, stageBuf](std::error_code ec, std::size_t n) {
            if (ec) {
                m_relayRegistered = false;
                log("Relay: соединение разорвано: " + ec.message());
                fire([](NetworkEvent& ev){ if(ev.onRelayDisconnected) ev.onRelayDisconnected(); });

                if (!m_relayReconnectTimer)
                    m_relayReconnectTimer = std::make_shared<asio::steady_timer>(m_io);
                m_relayReconnectTimer->expires_after(std::chrono::seconds(5));
                m_relayReconnectTimer->async_wait([this](std::error_code e) {
                    if (!e) connectToRelay();
                });
                return;
            }

            if (static_cast<int>(m_relayReadBuf.size() + n) > kMaxBufferSize) {
                log("Relay: буфер переполнен — сбрасываем");
                m_relayReadBuf.clear();
                std::error_code ce; sock->close(ce);
                return;
            }
            m_relayReadBuf.append(stageBuf->data(), n);

            while (true) {
                const auto nl = m_relayReadBuf.find('\n');
                if (nl == std::string::npos) break;
                const std::string rawFrame(m_relayReadBuf.data(), nl);
                m_relayReadBuf.erase(0, nl + 1);

                const auto obj = nlohmann::json::parse(rawFrame, nullptr, false);
                if (obj.is_discarded() || !obj.is_object()) continue;

                const std::string t = obj.value("type", std::string{});

                if (t == "RELAY_REGISTERED") {
                    m_relayRegistered = true;
                    log("Relay: зарегистрированы");
                    fire([](NetworkEvent& ev){ if(ev.onRelayConnected) ev.onRelayConnected(); });

                } else if (t == "RELAY_MSG") {
                    const std::string fromUuid = obj.value("from", std::string{});
                    if (obj.contains("data") && obj["data"].is_object() && !fromUuid.empty())
                        handleRelayFrame(fromUuid, obj["data"]);

                } else if (t == "RELAY_PEER_OFFLINE") {
                    const std::string peerUuid = obj.value("uuid", std::string{});
                    log("Relay: пир " + peerUuid + " недоступен");
                    if (m_peers.count(peerUuid)) {
                        stopKeepalive(peerUuid);
                        m_relayPeers.erase(peerUuid);
                        m_peers.erase(peerUuid);
                        fire([&peerUuid](NetworkEvent& ev){
                            if(ev.onPeerDisconnected) ev.onPeerDisconnected(peerUuid);
                            if(ev.onStateChanged)     ev.onStateChanged(peerUuid, ConnectionState::Disconnected);
                        });
                    }

                } else if (t == "RELAY_ERROR") {
                    log("Relay error: " + obj.value("msg", std::string{}));
                }
            }

            startRelayRead();
        });
}

void NetworkManager::sendViaRelay(const std::string& targetUuid, const nlohmann::json& obj) {
    if (!m_relaySocket || !m_relaySocket->is_open() || !m_relayRegistered) {
        log("sendViaRelay: ретранслятор недоступен — [" +
            obj.value("type", "?") + "] отброшен", true);
        return;
    }
    nlohmann::json wrapper;
    wrapper["type"] = "RELAY_MSG";
    wrapper["to"]   = targetUuid;
    wrapper["data"] = obj;
    writeFrame(*m_relaySocket, wrapper);
    log("Relay: [" + obj.value("type", "?") + "] → " + targetUuid);
}

void NetworkManager::handleRelayFrame(const std::string& fromUuid, const nlohmann::json& innerObj) {
    if (m_peers.count(fromUuid)) {
        handleFrame(m_peers[fromUuid], innerObj);
        return;
    }
    if (!m_pending.count(fromUuid)) {
        m_pending[fromUuid] = PeerConnection{
            .uuid   = fromUuid,
            .ip     = SessionManager::instance().relayServerIp(),
            .socket = nullptr,
        };
    }
    handleFrame(m_pending[fromUuid], innerObj);
}

// ── Broadcast / profile ───────────────────────────────────────────────────────

void NetworkManager::broadcastProfileUpdate(const std::string& name) {
    asio::post(m_io, [this, name]() {
        nlohmann::json msg;
        msg["type"] = "PROFILE_UPDATE";
        msg["name"] = name;
        for (auto& [uuid, peer] : m_peers)
            sendFrame(uuid, msg);
        log("PROFILE_UPDATE → " + std::to_string(m_peers.size()) + " пирам: \"" + name + "\"", true);
    });
}

// ── Исходящее подключение ─────────────────────────────────────────────────────

void NetworkManager::connectToPeer(const PeerInfo& peer) {
    asio::post(m_io, [this, peer]() {
        auto it = m_peers.find(peer.uuid);
        if (it != m_peers.end()) {
            const auto st = it->second.state;
            if (st == ConnectionState::Connected || st == ConnectionState::Connecting) {
                log("Уже подключены к " + peer.name + " — пропускаем", true);
                return;
            }
        }

        // Relay-режим: сразу через ретранслятор
        if (SessionManager::instance().portForwardingMode() == PortForwardingMode::ClientServer) {
            m_reconnectInfo[peer.uuid] = { peer.name, peer.ip, peer.port };
            m_peers[peer.uuid] = PeerConnection{
                .uuid           = peer.uuid,
                .name           = peer.name,
                .ip             = peer.ip,
                .port           = peer.port,
                .socket         = nullptr,
                .state          = ConnectionState::Connecting,
                .connectedSince = currentEpochMs(),
                .expectedUuid   = peer.uuid,
            };
            m_relayPeers.insert(peer.uuid);
            fire([&peer](NetworkEvent& ev){
                if(ev.onStateChanged) ev.onStateChanged(peer.uuid, ConnectionState::Connecting);
            });

            if (m_relayRegistered) {
                const auto& id = Identity::instance();
                const std::string avatarPath = SessionManager::instance().avatarPath();
                const std::string avatarHash = avatarPath.empty() ? std::string{}
                    : SessionManager::computeAvatarHash(avatarPath);
                nlohmann::json hs;
                hs["type"]       = "HANDSHAKE";
                hs["uuid"]       = id.uuid();
                hs["name"]       = id.displayName();
                hs["port"]       = static_cast<int>(m_localPort);
                hs["systemInfo"] = SystemInfo::instance().toJsonForHandshake(m_externalIp);
                hs["avatarHash"] = avatarHash;
                hs["birthday"]   = SessionManager::instance().birthday();
                hs["version"]    = APP_VERSION;
                sendViaRelay(peer.uuid, hs);
                log("Relay: HANDSHAKE → " + peer.name);
            } else {
                log("connectToPeer via relay: ретранслятор не подключён");
            }
            return;
        }

        log("Connecting to " + peer.name + " (" + peer.ip + ":" + std::to_string(peer.port) + ")...", true);
        m_reconnectInfo[peer.uuid] = { peer.name, peer.ip, peer.port };

        std::error_code ec;
        const auto addr = asio::ip::make_address(peer.ip, ec);
        if (ec) {
            scheduleReconnect(peer.uuid);
            return;
        }

        auto sock  = std::make_shared<asio::ip::tcp::socket>(m_io);
        auto timer = std::make_shared<asio::steady_timer>(m_io);

        fire([&peer](NetworkEvent& ev){
            if(ev.onStateChanged) ev.onStateChanged(peer.uuid, ConnectionState::Connecting);
        });

        timer->expires_after(std::chrono::milliseconds(kConnectionTimeout));
        timer->async_wait([this, sock, peer](std::error_code ec) {
            if (ec) return;
            log("Connection timeout to " + peer.name, true);
            std::error_code ce; sock->cancel(ce);
        });

        sock->async_connect({addr, peer.port},
            [this, sock, timer, peer](std::error_code ec) {
                timer->cancel();

                if (ec) {
                    if (ec != asio::error::operation_aborted)
                        log("Ошибка подключения к " + peer.name + ": " + ec.message(), true);
                    scheduleReconnect(peer.uuid);
                    return;
                }

                // Дубликат: входящее сработало быстрее
                auto existIt = m_peers.find(peer.uuid);
                if (existIt != m_peers.end() &&
                    existIt->second.state == ConnectionState::Connected) {
                    log("Дублирующий исходящий сокет к " + peer.name + " — закрываем", true);
                    std::error_code ce; sock->close(ce);
                    return;
                }

                log("Connected to " + peer.name + " (" + peer.ip + ":" + std::to_string(peer.port) + ")", true);

                m_peers[peer.uuid] = PeerConnection{
                    .uuid           = peer.uuid,
                    .name           = peer.name,
                    .ip             = peer.ip,
                    .port           = peer.port,
                    .socket         = sock,
                    .state          = ConnectionState::Connected,
                    .lastActivity   = currentEpochMs(),
                    .connectedSince = currentEpochMs(),
                    .expectedUuid   = peer.uuid,
                };
                resetReconnectState(peer.uuid);

                sendClientHello(*sock);
                log("CLIENT_HELLO → " + peer.name);

                startKeepalive(peer.uuid);
                fire([&peer](NetworkEvent& ev){
                    if(ev.onStateChanged) ev.onStateChanged(peer.uuid, ConnectionState::Connected);
                });
                startAsyncRead(peer.uuid, false);
            });
    });
}

// ── Device pairing: вторичный → главный ──────────────────────────────────────

void NetworkManager::connectToDevice(const std::string& host, uint16_t port, const std::string& code) {
    asio::post(m_io, [this, host, port, code]() {
        log("Подключаемся к главному устройству " + host + ":" + std::to_string(port) + "...", true);

        std::error_code ec;
        const auto addr = asio::ip::make_address(host, ec);
        if (ec) {
            fire([&host](NetworkEvent& ev){
                if (ev.onError) ev.onError("Невалидный адрес: " + host);
            });
            return;
        }

        auto sock   = std::make_shared<asio::ip::tcp::socket>(m_io);
        const std::string tempId = generateUuid();

        m_peers[tempId] = PeerConnection{
            .uuid            = tempId,
            .ip              = host,
            .port            = port,
            .socket          = sock,
            .state           = ConnectionState::Connecting,
            .connectedSince  = currentEpochMs(),
            .pendingPairCode = code,
        };

        sock->async_connect({addr, port},
            [this, sock, tempId, host, port](std::error_code ec) {
                if (ec) {
                    log("Ошибка подключения к главному устройству: " + ec.message(), true);
                    fire([&ec](NetworkEvent& ev){
                        if (ev.onError) ev.onError("Не удалось подключиться к главному устройству: " + ec.message());
                    });
                    m_peers.erase(tempId);
                    return;
                }
                auto it = m_peers.find(tempId);
                if (it == m_peers.end()) return;
                auto& conn = it->second;
                conn.state        = ConnectionState::Connected;
                conn.lastActivity = currentEpochMs();

                sendClientHello(*sock);
                log("CLIENT_HELLO → главное устройство " + host + ":" + std::to_string(port));
                startAsyncRead(tempId, false);
            });
    });
}

// ── Multi-device relay helpers ────────────────────────────────────────────────

void NetworkManager::relayToLinkedDevices(const std::string& exceptUuid, const nlohmann::json& frame) {
    asio::post(m_io, [this, exceptUuid, frame]() {
        for (auto& [uuid, peer] : m_peers)
            if (peer.isLinkedDevice && uuid != exceptUuid)
                sendFrame(uuid, frame);
    });
}

std::string NetworkManager::primaryDeviceUuid() const {
    for (auto& [uuid, peer] : m_peers) {
        if (!peer.isLinkedDevice) continue;
        const auto dev = SessionManager::instance().linkedDevice(uuid);
        if (dev.has_value() && dev->isPrimary)
            return uuid;
    }
    return {};
}

// ── handleFrame ───────────────────────────────────────────────────────────────

void NetworkManager::handleFrame(PeerConnection& peer, const nlohmann::json& obj) {
    // Rate limiting
    const auto now = std::chrono::steady_clock::now();
    if (!peer.rateWindowValid) {
        peer.rateWindowStart = now;
        peer.rateWindowValid = true;
        peer.rateCount = 0;
    } else if (std::chrono::duration_cast<std::chrono::milliseconds>(
                   now - peer.rateWindowStart).count() >= 1000) {
        peer.rateWindowStart = now;
        peer.rateCount = 0;
    }
    if (++peer.rateCount > kMaxFramesPerSecond) {
        const std::string tag = peer.name.empty() ? peer.ip : peer.name;
        log("Rate limit: " + tag + " превысил " + std::to_string(kMaxFramesPerSecond) + " фреймов/сек — разрываем", true);
        if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
        return;
    }

    // IP ban check
    {
        const auto bit = m_ipBanRecords.find(peer.ip);
        if (bit != m_ipBanRecords.end() && bit->second.bannedUntil > currentEpochMs()) {
            const int64_t secLeft = (bit->second.bannedUntil - currentEpochMs()) / 1000;
            log("IP " + peer.ip + " забанен ещё " + std::to_string(secLeft) + " сек — разрываем", true);
            if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
            return;
        }
    }

    const std::string type = obj.value("type", std::string{});
    peer.lastActivity = currentEpochMs();

    if (type == "CLIENT_HELLO") {
        const std::string peerVersion = obj.value("version", std::string{});
        const std::string peerName    = sanitizeCtrl(obj.value("name", std::string{}));
        log("CLIENT_HELLO от " + peer.ip + ": «" + peerName + "», версия " + peerVersion, true);

        peer.helloName      = peerName;
        peer.helloVersion   = peerVersion;
        peer.isLinkedDevice = (obj.value("role", std::string{}) == "DEVICE");

        if (VersionUtils::compare(peerVersion, kMinPeerVersion) < 0) {
            log("CLIENT_HELLO отклонён от " + peer.ip + ": версия " + peerVersion +
                " < минимальной " + kMinPeerVersion, true);
            if (peer.socket) {
                nlohmann::json reject;
                reject["type"]       = "VERSION_REJECT";
                reject["minVersion"] = kMinPeerVersion;
                reject["ourVersion"] = APP_VERSION;
                writeFrame(*peer.socket, reject);
                auto sock = peer.socket;
                auto t = std::make_shared<asio::steady_timer>(m_io);
                t->expires_after(std::chrono::milliseconds(200));
                t->async_wait([sock, t](std::error_code) {
                    std::error_code ec; sock->close(ec);
                });
            }
            return;
        }

        nlohmann::json hello;
        hello["type"]    = "SERVER_HELLO";
        hello["version"] = APP_VERSION;
        hello["name"]    = Identity::instance().displayName();
        if (peer.socket) writeFrame(*peer.socket, hello);
        log("SERVER_HELLO → " + peer.ip + " «" + peerName + "»");
        return;
    }

    if (type == "SERVER_HELLO") {
        const std::string peerVersion = obj.value("version", std::string{});
        const std::string peerName    = sanitizeCtrl(obj.value("name", std::string{}));
        log("SERVER_HELLO от " + peer.ip + ": «" + peerName + "», версия " + peerVersion, true);

        peer.helloName    = peerName;
        peer.helloVersion = peerVersion;

        if (VersionUtils::compare(peerVersion, kMinPeerVersion) < 0) {
            log("SERVER_HELLO: версия " + peerVersion + " < минимальной " + kMinPeerVersion + " — разрываем", true);
            if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
            return;
        }

        if (!peer.expectedUuid.empty()) {
            log("SERVER_HELLO OK — UUID_CHALLENGE → «" + peerName + "»");
            if (peer.socket) sendUuidChallenge(*peer.socket, peer.expectedUuid);
        } else {
            log("SERVER_HELLO OK — отправляем HANDSHAKE → «" + peerName + "»");
            if (peer.socket) sendHandshake(*peer.socket);
        }
        return;
    }

    if (type == "VERSION_REJECT") {
        const std::string minVer = obj.value("minVersion", std::string{});
        log("VERSION_REJECT от " + peer.ip + ": требуется ≥ " + minVer, true);
        fire([&minVer](NetworkEvent& ev){
            if (ev.onError) ev.onError("Несовместимая версия: требуется ≥ " + minVer);
        });
        if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
        return;
    }

    // ── Device pairing ────────────────────────────────────────────────────────

    if (type == "DEVICE_PAIR_REQUEST") {
        const std::string code    = obj.value("code", std::string{});
        const std::string devUuid = obj.value("uuid", std::string{});
        const std::string devName = sanitizeCtrl(obj.value("name", std::string{}));

        if (devUuid.empty()) {
            if (peer.socket) writeFrame(*peer.socket, DevicePairing::makePairReject("invalid_uuid"));
            return;
        }
        if (!DevicePairing::validateAndConsume(code)) {
            const std::string reason = DevicePairing::currentCode().empty() ? "expired" : "invalid_code";
            // Неверный код спаривания считаем как неудачную попытку аутентификации:
            // тот же счётчик/бан по IP, что и для UUID — закрывает брутфорс 6-значного OTP.
            if (reason == "invalid_code") recordUuidFailure(peer.ip);
            if (peer.socket) writeFrame(*peer.socket, DevicePairing::makePairReject(reason));
            return;
        }

        LinkedDevice dev;
        dev.uuid      = devUuid;
        dev.name      = devName;
        dev.isPrimary = false;
        dev.linkedAt  = currentEpochMs();
        SessionManager::instance().addLinkedDevice(dev);
        peer.isLinkedDevice = true;

        if (peer.socket)
            writeFrame(*peer.socket, DevicePairing::makePairAccept(
                Identity::instance().uuid(), Identity::instance().displayName()));

        fire([&devUuid, &devName](NetworkEvent& ev){
            if (ev.onDeviceLinked) ev.onDeviceLinked(devUuid, devName, false);
        });
        return;
    }

    if (type == "DEVICE_PAIR_ACCEPT") {
        const std::string primUuid = obj.value("uuid", std::string{});
        const std::string primName = sanitizeCtrl(obj.value("name", std::string{}));
        if (primUuid.empty()) { log("DEVICE_PAIR_ACCEPT: невалидный UUID", true); return; }

        LinkedDevice dev;
        dev.uuid      = primUuid;
        dev.name      = primName;
        dev.isPrimary = true;
        dev.linkedAt  = currentEpochMs();
        SessionManager::instance().addLinkedDevice(dev);
        peer.isLinkedDevice = true;

        fire([&primUuid, &primName](NetworkEvent& ev){
            if (ev.onDeviceLinked) ev.onDeviceLinked(primUuid, primName, true);
        });
        return;
    }

    if (type == "DEVICE_PAIR_REJECT") {
        const std::string reason = obj.value("reason", std::string{});
        const std::string msg =
            (reason == "invalid_code") ? "Привязка отклонена: неверный код" :
            (reason == "expired")      ? "Привязка отклонена: код устарел"   :
            (reason == "invalid_uuid") ? "Привязка отклонена: невалидный UUID" :
            "Привязка отклонена: " + reason;
        fire([&msg](NetworkEvent& ev){ if (ev.onError) ev.onError(msg); });
        if (peer.socket) {
            std::error_code ec;
            peer.socket->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            peer.socket->close(ec);
        }
        return;
    }

    if (type == "UUID_CHALLENGE") {
        const std::string challenged = obj.value("uuid", std::string{});
        const bool isOurs = (challenged == Identity::instance().uuid());
        if (!isOurs) {
            recordUuidFailure(peer.ip);
        }
        nlohmann::json resp;
        resp["type"]      = "UUID_RESPONSE";
        resp["confirmed"] = isOurs;
        if (peer.socket) writeFrame(*peer.socket, resp);
        if (!isOurs) {
            if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
        }
        return;
    }

    if (type == "UUID_RESPONSE") {
        if (!obj.value("confirmed", false)) {
            log("UUID_RESPONSE: пир " + peer.ip + " отклонил UUID — закрываем", true);
            if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
            return;
        }
        log("UUID_RESPONSE: пир " + peer.ip + " подтвердил UUID — отправляем HANDSHAKE");
        if (peer.socket) sendHandshake(*peer.socket);
        return;
    }

    if (type == "HANDSHAKE") {
        const std::string parsedUuid = obj.value("uuid", std::string{});
        if (!Identity::isValidUuid(parsedUuid)) {
            log("HANDSHAKE: невалидный UUID от " + peer.ip, true);
            if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
            return;
        }

        const std::string peerVersion = obj.value("version", std::string{});
        if (VersionUtils::compare(peerVersion, kMinPeerVersion) < 0) {
            log("HANDSHAKE отклонён от " + peer.ip + ": версия " + peerVersion + " < " + kMinPeerVersion, true);
            if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
            return;
        }

        peer.uuid       = parsedUuid;
        peer.name       = sanitizeCtrl(obj.value("name", std::string{}));
        peer.serverPort = static_cast<uint16_t>(obj.value("port", 0));
        peer.avatarHash = obj.value("avatarHash", std::string{});
        peer.birthday   = obj.value("birthday", std::string{}).substr(0, 10);

        if (obj.contains("systemInfo") && obj["systemInfo"].is_object()) {
            const std::string sysJson = obj["systemInfo"].dump();
            if (sysJson.size() <= 4096) peer.systemInfoJson = sysJson;
        }

        log("HANDSHAKE от " + peer.name + " (порт " + std::to_string(peer.serverPort) + ")");

        // Tie-breaking: если взаимный connect — закрываем входящее при UUID > пира
        if (peer.socket && m_reconnectInfo.count(parsedUuid)) {
            if (Identity::instance().uuid() > parsedUuid) {
                log("Tie-breaking: UUID > " + peer.name + " — закрываем входящее", true);
                auto sock = peer.socket;
                asio::post(m_io, [sock]() { std::error_code ec; sock->close(ec); });
                return;
            }
        }

        fire([&parsedUuid, &peer](NetworkEvent& ev){
            if (ev.onIncomingRequest) ev.onIncomingRequest(parsedUuid, peer.name, peer.ip);
            if (ev.onPeerInfoUpdated) ev.onPeerInfoUpdated(parsedUuid);
        });
        return;
    }

    if (type == "HANDSHAKE_ACK") {
        if (obj.value("accepted", false)) {
            const std::string peerVersionAck = obj.value("version", std::string{});
            if (VersionUtils::compare(peerVersionAck, kMinPeerVersion) < 0) {
                log("HANDSHAKE_ACK отклонён от " + peer.ip + ": версия " + peerVersionAck + " < " + kMinPeerVersion, true);
                if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
                return;
            }

            const std::string confirmedUuid = obj.value("uuid", std::string{});
            // sanitizeCtrl обязателен: имя логируется и уходит в UI — иначе пир
            // может внедрить терминальные ESC-последовательности / управляющие
            // символы (как и в ветке HANDSHAKE выше).
            const std::string confirmedName = sanitizeCtrl(obj.value("name", std::string{}));

            if (!Identity::isValidUuid(confirmedUuid)) {
                log("HANDSHAKE_ACK: невалидный UUID от " + peer.ip, true);
                if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
                return;
            }
            if (!peer.expectedUuid.empty() && confirmedUuid != peer.expectedUuid) {
                log("HANDSHAKE_ACK: UUID mismatch от " + peer.ip
                    + " (ожидали " + peer.expectedUuid + ", получили " + confirmedUuid + ")", true);
                if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
                return;
            }

            auto existIt = m_peers.find(confirmedUuid);
            if (existIt != m_peers.end() &&
                existIt->second.state == ConnectionState::Connected &&
                existIt->second.socket != peer.socket) {
                log("HANDSHAKE_ACK: дублирующее соединение к " + confirmedName + " — закрываем", true);
                if (peer.socket) { std::error_code ec; peer.socket->close(ec); }
                return;
            }

            peer.uuid = confirmedUuid;
            peer.name = confirmedName;

            if (obj.contains("systemInfo") && obj["systemInfo"].is_object()) {
                const std::string sysJson = obj["systemInfo"].dump();
                if (sysJson.size() <= 4096) peer.systemInfoJson = sysJson;
            }
            peer.avatarHash = obj.value("avatarHash", std::string{});
            peer.birthday   = obj.value("birthday", std::string{}).substr(0, 10);

            fire([&confirmedUuid, &confirmedName](NetworkEvent& ev){
                if (ev.onPeerConnected) ev.onPeerConnected(confirmedUuid, confirmedName);
            });

            if (!peer.pendingPairCode.empty()) {
                const auto& id = Identity::instance();
                if (peer.socket) writeFrame(*peer.socket, DevicePairing::makePairRequest(
                    id.uuid(), id.displayName(), peer.pendingPairCode));
                peer.pendingPairCode.clear();
            }
            drainMessageQueue(peer.uuid);
        } else {
            log("HANDSHAKE_ACK отклонён от " + peer.name);
            fire([&peer](NetworkEvent& ev){
                if (ev.onError) ev.onError("Подключение отклонено: " + peer.name);
            });
            if (peer.socket) {
                std::error_code ec;
                peer.socket->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
                peer.socket->close(ec);
            }
        }
        return;
    }

    if (type == "PING") { handlePing(peer, obj); return; }
    if (type == "PONG") { handlePong(peer, obj); return; }

    if (type == "PROFILE_UPDATE") {
        const std::string newName = sanitizeCtrl(obj.value("name", std::string{}));
        if (!newName.empty() && newName != peer.name) {
            log("PROFILE_UPDATE от " + peer.name + ": «" + newName + "»");
            peer.name = newName;
            fire([&peer, &newName](NetworkEvent& ev){
                if (ev.onNameUpdated) ev.onNameUpdated(peer.uuid, newName);
            });
        }
        return;
    }

    // All other frames go to message handler
    const std::string uuid = peer.uuid;
    fire([&uuid, &obj](NetworkEvent& ev){
        if (ev.onMessage) ev.onMessage(uuid, obj);
    });
}

// ── sendClientHello / sendHandshake ───────────────────────────────────────────

void NetworkManager::sendClientHello(asio::ip::tcp::socket& sock) {
    const auto& devices = SessionManager::instance().linkedDevices();
    const bool actingAsDevice = std::any_of(devices.cbegin(), devices.cend(),
        [](const LinkedDevice& d) { return d.isPrimary; });

    nlohmann::json obj;
    obj["type"]    = "CLIENT_HELLO";
    obj["version"] = APP_VERSION;
    obj["name"]    = Identity::instance().displayName();
    if (actingAsDevice) obj["role"] = "DEVICE";
    writeFrame(sock, obj);
}

void NetworkManager::sendHandshake(asio::ip::tcp::socket& sock) {
    const auto& id = Identity::instance();
    const std::string avatarPath = SessionManager::instance().avatarPath();
    const std::string avatarHash = avatarPath.empty() ? std::string{}
        : SessionManager::computeAvatarHash(avatarPath);

    nlohmann::json obj;
    obj["type"]       = "HANDSHAKE";
    obj["uuid"]       = id.uuid();
    obj["name"]       = id.displayName();
    obj["port"]       = static_cast<int>(m_advertisedPort ? m_advertisedPort : m_localPort);
    obj["systemInfo"] = SystemInfo::instance().toJsonForHandshake(m_externalIp);
    obj["avatarHash"] = avatarHash;
    obj["birthday"]   = SessionManager::instance().birthday();
    obj["version"]    = APP_VERSION;
    writeFrame(sock, obj);
}

void NetworkManager::sendUuidChallenge(asio::ip::tcp::socket& sock, const std::string& expectedUuid) {
    nlohmann::json obj;
    obj["type"] = "UUID_CHALLENGE";
    obj["uuid"] = expectedUuid;
    writeFrame(sock, obj);
}

void NetworkManager::recordUuidFailure(const std::string& ip) {
    const int64_t now = currentEpochMs();
    auto& rec = m_ipBanRecords[ip];

    if (rec.bannedUntil > 0 && rec.bannedUntil <= now) {
        // Previous ban expired — reset counter
        rec = IpBanRecord{};
    }

    if (rec.firstFailMs == 0) rec.firstFailMs = now;
    ++rec.failures;

    if (rec.failures >= kMaxUuidFailures) {
        rec.bannedUntil = now + kBanDurationMs;
        log("IP " + ip + " забанен на 30 минут после "
            + std::to_string(rec.failures) + " неверных UUID", true);
    } else {
        log("IP " + ip + " — неверный UUID ("
            + std::to_string(rec.failures) + "/" + std::to_string(kMaxUuidFailures) + ")", true);
    }
}

// ── sendFrame ─────────────────────────────────────────────────────────────────

void NetworkManager::sendFrame(const std::string& peerUuid, const nlohmann::json& obj) {
    asio::post(m_io, [this, peerUuid, obj]() {
        if (m_relayPeers.count(peerUuid)) {
            sendViaRelay(peerUuid, obj);
            return;
        }

        auto it = m_peers.find(peerUuid);
        if (it == m_peers.end() || !it->second.socket || !it->second.socket->is_open()) {
            const std::string typeHint = obj.value("type", "?");
            auto& q = m_messageQueues[peerUuid];
            if (static_cast<int>(q.size()) < kMaxQueueSize) {
                q.push(obj);
                log("sendFrame: [" + typeHint + "] в очередь (" +
                    std::to_string(q.size()) + "/" + std::to_string(kMaxQueueSize) + ")", true);
            } else {
                log("sendFrame: очередь переполнена, [" + typeHint + "] отброшен", true);
            }
            return;
        }

        auto& peer = it->second;
        const std::string frame = obj.dump() + "\n";
        std::error_code ec;
        const auto written = asio::write(*peer.socket, asio::buffer(frame), ec);

        if (ec || written != frame.size()) {
            log("sendFrame: ОШИБКА записи пиру " + peer.name + " — в очередь", true);
            auto& q = m_messageQueues[peerUuid];
            if (static_cast<int>(q.size()) < kMaxQueueSize)
                q.push(obj);
        } else {
            log("sendFrame: [" + obj.value("type", "?") + "] → " + peer.name +
                " (" + std::to_string(written) + " байт)");
            peer.lastActivity = currentEpochMs();
        }
    });
}

void NetworkManager::drainMessageQueue(const std::string& uuid) {
    auto qit = m_messageQueues.find(uuid);
    if (qit == m_messageQueues.end() || qit->second.empty()) return;

    const std::size_t count = qit->second.size();
    log("Выгружаем " + std::to_string(count) + " сообщений из очереди → " + uuid, true);

    auto pending = std::move(qit->second);
    m_messageQueues.erase(qit);
    while (!pending.empty()) {
        sendFrame(uuid, pending.front());
        pending.pop();
    }
}

// ── acceptIncoming / rejectIncoming ──────────────────────────────────────────

void NetworkManager::acceptIncoming(const std::string& peerUuid) {
    asio::post(m_io, [this, peerUuid]() {
        auto eit = m_peers.find(peerUuid);
        if (eit != m_peers.end() && eit->second.state == ConnectionState::Connected) {
            log("Дублирующее входящее от " + peerUuid + " — уже подключены, отклоняем", true);
            rejectIncoming(peerUuid);
            return;
        }

        for (auto it = m_pending.begin(); it != m_pending.end(); ++it) {
            if (it->second.uuid != peerUuid) continue;

            auto conn = it->second;
            m_pending.erase(it);

            conn.state             = ConnectionState::Connected;
            conn.lastActivity      = currentEpochMs();
            conn.connectedSince    = currentEpochMs();
            conn.reconnectAttempts = 0;

            m_peers[peerUuid] = conn;
            m_reconnectInfo[peerUuid] = { conn.name, conn.ip, conn.serverPort };

            const auto& id = Identity::instance();
            const std::string avatarPath = SessionManager::instance().avatarPath();
            const std::string avatarHash = avatarPath.empty() ? std::string{}
                : SessionManager::computeAvatarHash(avatarPath);

            nlohmann::json ack;
            ack["type"]       = "HANDSHAKE_ACK";
            ack["accepted"]   = true;
            ack["uuid"]       = id.uuid();
            ack["name"]       = id.displayName();
            ack["systemInfo"] = SystemInfo::instance().toJsonForHandshake(m_externalIp);
            ack["avatarHash"] = avatarHash;
            ack["birthday"]   = SessionManager::instance().birthday();
            ack["version"]    = APP_VERSION;

            if (conn.socket) {
                writeFrame(*conn.socket, ack);
            } else {
                m_relayPeers.insert(peerUuid);
                sendViaRelay(peerUuid, ack);
            }

            log("Принято подключение от " + conn.name + " (порт " + std::to_string(conn.serverPort) + ")");

            if (conn.socket) {
                startKeepalive(peerUuid);
                startAsyncRead(peerUuid, false);
            }

            fire([&peerUuid, &conn](NetworkEvent& ev){
                if (ev.onPeerConnected)  ev.onPeerConnected(peerUuid, conn.name);
                if (ev.onStateChanged)   ev.onStateChanged(peerUuid, ConnectionState::Connected);
            });
            drainMessageQueue(peerUuid);
            return;
        }
    });
}

void NetworkManager::rejectIncoming(const std::string& peerUuid) {
    asio::post(m_io, [this, peerUuid]() {
        for (auto it = m_pending.begin(); it != m_pending.end(); ++it) {
            if (it->second.uuid != peerUuid) continue;

            nlohmann::json ack;
            ack["type"]     = "HANDSHAKE_ACK";
            ack["accepted"] = false;
            auto* sockPtr = it->second.socket.get();

            if (sockPtr && sockPtr->is_open()) {
                writeFrame(*sockPtr, ack);
                auto sock  = it->second.socket;
                auto timer = std::make_shared<asio::steady_timer>(m_io);
                timer->expires_after(std::chrono::milliseconds(500));
                timer->async_wait([sock, timer](std::error_code) {
                    std::error_code ec;
                    sock->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
                    sock->close(ec);
                });
            } else {
                sendViaRelay(peerUuid, ack);
            }
            m_pending.erase(it);
            return;
        }
    });
}

// ── Переподключение ───────────────────────────────────────────────────────────

int NetworkManager::calculateBackoffMs(int attempts) const {
    const int base = 1000;
    const int delay = base * static_cast<int>(std::pow(2.0, std::min(attempts, 5)));
    return std::min(delay, kMaxReconnectDelay);
}

void NetworkManager::scheduleReconnect(const std::string& uuid) {
    if (!m_reconnectInfo.count(uuid)) {
        log("Нет информации для переподключения к " + uuid);
        return;
    }

    const int attempts = m_reconnectAttempts.count(uuid) ? m_reconnectAttempts[uuid] : 0;
    if (attempts >= kMaxReconnectAttempts) {
        log("Превышен лимит попыток (" + std::to_string(attempts) +
            ") для " + m_reconnectInfo[uuid].name, true);
        fire([&attempts](NetworkEvent& ev){
            if (ev.onError) ev.onError("Не удалось переподключиться после " + std::to_string(attempts) + " попыток");
        });
        m_reconnectInfo.erase(uuid);
        m_reconnectAttempts.erase(uuid);
        m_messageQueues.erase(uuid);
        return;
    }

    const int delayMs = calculateBackoffMs(attempts);
    log("Переподключение к " + m_reconnectInfo[uuid].name + " через " +
        std::to_string(delayMs) + "мс (попытка " + std::to_string(attempts+1) +
        "/" + std::to_string(kMaxReconnectAttempts) + ")", true);

    fire([&uuid](NetworkEvent& ev){
        if (ev.onStateChanged) ev.onStateChanged(uuid, ConnectionState::Reconnecting);
    });

    auto rit = m_reconnectTimers.find(uuid);
    if (rit != m_reconnectTimers.end()) rit->second->cancel();

    auto timer = std::make_shared<asio::steady_timer>(m_io);
    timer->expires_after(std::chrono::milliseconds(delayMs));
    timer->async_wait([this, uuid, timer](std::error_code ec) {
        m_reconnectTimers.erase(uuid);
        if (!ec) attemptReconnect(uuid);
    });
    m_reconnectTimers[uuid] = timer;
}

void NetworkManager::attemptReconnect(const std::string& uuid) {
    if (!m_reconnectInfo.count(uuid)) return;
    const auto& info = m_reconnectInfo[uuid];
    m_reconnectAttempts[uuid] = (m_reconnectAttempts.count(uuid) ? m_reconnectAttempts[uuid] : 0) + 1;

    log("Попытка переподключения к " + info.name + " (" + info.ip + ":" +
        std::to_string(info.port) + "), #" + std::to_string(m_reconnectAttempts[uuid]), true);

    PeerInfo peer;
    peer.uuid = uuid;
    peer.name = info.name;
    peer.ip   = info.ip;
    peer.port = info.port;
    connectToPeer(peer);
}

void NetworkManager::resetReconnectState(const std::string& uuid) {
    m_reconnectAttempts.erase(uuid);
    auto rit = m_reconnectTimers.find(uuid);
    if (rit != m_reconnectTimers.end()) {
        rit->second->cancel();
        m_reconnectTimers.erase(rit);
    }
    auto pit = m_peers.find(uuid);
    if (pit != m_peers.end())
        pit->second.reconnectAttempts = 0;
}

// ── Keepalive (PING/PONG) ─────────────────────────────────────────────────────

void NetworkManager::startKeepalive(const std::string& uuid) {
    auto it = m_peers.find(uuid);
    if (it == m_peers.end()) return;
    auto& peer = it->second;

    peer.pingTimer = std::make_shared<asio::steady_timer>(m_io);
    log("Keepalive started for " + peer.name);

    asio::post(m_io, [this, uuid]() { sendPing(uuid); });
    schedulePing(uuid);
}

void NetworkManager::schedulePing(const std::string& uuid) {
    auto it = m_peers.find(uuid);
    if (it == m_peers.end() || !it->second.pingTimer) return;
    auto timer = it->second.pingTimer;

    timer->expires_after(std::chrono::milliseconds(kPingInterval));
    timer->async_wait([this, uuid, timer](std::error_code ec) {
        auto it2 = m_peers.find(uuid);
        if (ec || it2 == m_peers.end() || it2->second.pingTimer != timer) return;
        sendPing(uuid);
        schedulePing(uuid);
    });
}

void NetworkManager::stopKeepalive(const std::string& uuid) {
    auto it = m_peers.find(uuid);
    if (it == m_peers.end()) return;
    auto& peer = it->second;
    if (peer.pingTimer)        { peer.pingTimer->cancel();        peer.pingTimer.reset(); }
    if (peer.pongTimeoutTimer) { peer.pongTimeoutTimer->cancel(); peer.pongTimeoutTimer.reset(); }
    peer.awaitingPong = false;
}

void NetworkManager::sendPing(const std::string& uuid) {
    auto it = m_peers.find(uuid);
    if (it == m_peers.end()) return;
    auto& peer = it->second;

    if (peer.awaitingPong) {
        log("PING к " + peer.name + " пропущен — ожидаем PONG");
        return;
    }
    if (!peer.socket || !peer.socket->is_open()) {
        log("Нет сокета для PING к " + peer.name);
        return;
    }

    nlohmann::json ping;
    ping["type"] = "PING";
    ping["ts"]   = currentEpochMs();
    writeFrame(*peer.socket, ping);
    peer.awaitingPong = true;
    peer.pingStart    = std::chrono::steady_clock::now();
    log("PING → " + peer.name);

    if (!peer.pongTimeoutTimer)
        peer.pongTimeoutTimer = std::make_shared<asio::steady_timer>(m_io);

    peer.pongTimeoutTimer->expires_after(std::chrono::milliseconds(kPongTimeout));
    peer.pongTimeoutTimer->async_wait([this, uuid](std::error_code ec) {
        if (ec) return;
        auto it2 = m_peers.find(uuid);
        if (it2 == m_peers.end()) return;
        auto& p = it2->second;
        if (p.awaitingPong) {
            log("PONG таймаут от " + p.name + " — соединение мёртво", true);
            if (p.socket) { std::error_code ce; p.socket->close(ce); }
        }
    });
}

void NetworkManager::handlePing(PeerConnection& peer, const nlohmann::json& /*obj*/) {
    nlohmann::json pong;
    pong["type"] = "PONG";
    pong["ts"]   = currentEpochMs();
    if (peer.socket && peer.socket->is_open()) {
        writeFrame(*peer.socket, pong);
        log("PONG → " + peer.name);
    }
    peer.lastActivity = currentEpochMs();
}

void NetworkManager::handlePong(PeerConnection& peer, const nlohmann::json& /*obj*/) {
    peer.awaitingPong = false;
    peer.lastActivity = currentEpochMs();
    if (peer.pongTimeoutTimer) peer.pongTimeoutTimer->cancel();

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - peer.pingStart).count();
    peer.latencyMs = static_cast<int64_t>(elapsed);
    log("PONG от " + peer.name + " (" + std::to_string(peer.latencyMs) + " мс)");
}
