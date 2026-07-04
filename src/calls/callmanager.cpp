#include "naleystogramm-core/calls/callmanager.h"
#include "naleystogramm-core/net/network.h"
#include "naleystogramm-core/storage/sessionmanager.h"
#include "naleystogramm-core/identity/identity.h"
#include "naleystogramm-crypto/e2e.h"
#include <openssl/rand.h>
#include <cstdio>
#include <random>

// ── UUID v4 (как в network.cpp — независимая копия, чтобы не тянуть
//    приватные хелперы NetworkManager) ─────────────────────────────────────────
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

// Таймаут ожидания CALL_ACCEPT от вызываемого пира — см. CallManager::kCallTimeoutMs

// ── Конструктор / деструктор ─────────────────────────────────────────────────

CallManager::CallManager(NetworkManager* net, E2EManager* e2e)
    : m_net(net), m_e2e(e2e)
{
}

CallManager::~CallManager() {
    endCall();
    std::lock_guard<std::mutex> lk(m_mutex);
    cancelTimers();
}

void CallManager::setMediaEngine(IMediaEngine* media) {
    m_media = media;
    if (m_media) {
        m_media->setErrorCallback([this](const std::string& msg) {
            fire([&msg](const CallEvent& ev) { if (ev.onCallError) ev.onCallError(msg); });
        });
    }
}

// ── setState / state ─────────────────────────────────────────────────────────

void CallManager::setState(CallState s) {
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (m_state == s) return;
        m_state = s;
    }
    fire([s](const CallEvent& ev) { if (ev.onStateChanged) ev.onStateChanged(s); });
}

CallManager::CallState CallManager::state() const {
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_state;
}

bool CallManager::isCallActive() const {
    return state() == CallState::InCall;
}

std::string CallManager::activePeer() const {
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_peerUuid;
}

// ── cancelTimers (вызывается с захваченным m_mutex) ──────────────────────────

void CallManager::cancelTimers() {
    ++m_generation;
    if (m_callTimeout) { m_callTimeout->cancel(); m_callTimeout.reset(); }
    if (m_endedTimer)  { m_endedTimer->cancel();  m_endedTimer.reset(); }
}

// ── resetState ───────────────────────────────────────────────────────────────

void CallManager::resetState() {
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        cancelTimers();
        m_callId.clear();
        m_peerUuid.clear();
        m_peerIp.clear();
        m_pendingCallerUdpPort = 0;
        m_pendingMediaSalt.clear();
        m_state = CallState::Idle;
    }
    fire([](const CallEvent& ev) { if (ev.onStateChanged) ev.onStateChanged(CallState::Idle); });
}

// ── initiateCall ─────────────────────────────────────────────────────────────

void CallManager::initiateCall(const std::string& peerUuid, const std::string& peerIp) {
    if (state() != CallState::Idle) {
        fire([](const CallEvent& ev) { if (ev.onCallError) ev.onCallError("Уже идёт звонок"); });
        return;
    }
    if (!m_e2e->hasSession(peerUuid)) {
        fire([](const CallEvent& ev) {
            if (ev.onCallError) ev.onCallError("Нет E2E сессии с пиром — невозможно выполнить звонок");
        });
        return;
    }

    // Генерируем 8-байтовый salt для деривации медиа-ключа
    Bytes salt(8);
    RAND_bytes(salt.data(), static_cast<int>(salt.size()));

    const std::string callId = generateUuid();

    if (!m_media) {
        fire([](const CallEvent& ev) { if (ev.onCallError) ev.onCallError("MediaEngine недоступен"); });
        return;
    }

    // Bind-only "пробный" запуск MediaEngine — нужен только чтобы убедиться,
    // что Opus/Multimedia доступны (ошибка прилетит через onCallError).
    if (!m_media->startCall("127.0.0.1", 0, Bytes(32, 0))) {
        return; // ошибка уже сообщена через MediaEngine::setErrorCallback
    }
    m_media->endCall();

    // Узнаём свободный UDP-порт через временный bind-only сокет
    // (отдельный io_context — чтобы не трогать поток NetworkManager).
    asio::io_context tmpIo;
    asio::ip::udp::socket tmpSock(tmpIo);
    std::error_code ec;
    tmpSock.open(asio::ip::udp::v4(), ec);
    if (!ec) tmpSock.bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0), ec);
    uint16_t localUdpPort = 0;
    if (!ec) localUdpPort = tmpSock.local_endpoint().port();
    tmpSock.close();
    if (ec) {
        fire([](const CallEvent& ev) { if (ev.onCallError) ev.onCallError("Не удалось открыть UDP порт для звонка"); });
        return;
    }

    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_peerUuid         = peerUuid;
        m_peerIp           = peerIp;
        m_callId           = callId;
        m_pendingMediaSalt = salt;
        m_state            = CallState::Calling;
    }
    fire([](const CallEvent& ev) { if (ev.onStateChanged) ev.onStateChanged(CallState::Calling); });

    // Таймаут: если через 30 с не получим CALL_ACCEPT — отменяем
    {
        auto timer = std::make_shared<asio::steady_timer>(m_net->ioContext());
        timer->expires_after(std::chrono::milliseconds(kCallTimeoutMs));
        int gen;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            m_callTimeout = timer;
            gen = m_generation;
        }
        timer->async_wait([this, gen, timer](const std::error_code& tec) {
            if (tec) return; // отменён
            std::string peer;
            {
                std::lock_guard<std::mutex> lk(m_mutex);
                if (gen != m_generation) return;
                peer = m_peerUuid;
            }
            std::fprintf(stderr, "[CallManager] Таймаут ожидания CALL_ACCEPT\n");
            resetState();
            fire([&peer](const CallEvent& ev) { if (ev.onCallRejected) ev.onCallRejected(peer, "timeout"); });
        });
    }

    // Отправляем CALL_INVITE через TCP
    nlohmann::json invite;
    invite["type"]         = "CALL_INVITE";
    invite["callId"]       = callId;
    invite["udpPort"]      = static_cast<int>(localUdpPort);
    invite["codecs"]       = nlohmann::json::array({"opus"});
    invite["mediaKeySalt"] = bytesToHex(salt);
    m_net->sendFrame(peerUuid, invite);

    std::fprintf(stderr, "[CallManager] CALL_INVITE отправлен, callId=%s, udpPort=%d\n",
                  callId.c_str(), static_cast<int>(localUdpPort));
}

// ── acceptCall ────────────────────────────────────────────────────────────────

void CallManager::acceptCall(const std::string& callId) {
    std::string peerUuid, peerIp;
    uint16_t    callerUdpPort = 0;
    Bytes       salt;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (m_state == CallState::Ringing && m_callId == callId) {
            peerUuid      = m_peerUuid;
            peerIp        = m_peerIp;
            callerUdpPort = m_pendingCallerUdpPort;
            salt          = m_pendingMediaSalt;
        }
    }
    if (peerUuid.empty()) {
        const std::string msg = "Нет входящего звонка с callId: " + callId;
        fire([&msg](const CallEvent& ev) { if (ev.onCallError) ev.onCallError(msg); });
        return;
    }
    if (!m_media) {
        fire([](const CallEvent& ev) { if (ev.onCallError) ev.onCallError("MediaEngine недоступен"); });
        return;
    }

    startMedia(peerIp, callerUdpPort, callId, salt);
    if (!m_media->isInCall()) return; // startMedia уже сообщил об ошибке

    // Сообщаем наш UDP порт вызывающей стороне
    nlohmann::json accept;
    accept["type"]    = "CALL_ACCEPT";
    accept["callId"]  = callId;
    accept["udpPort"] = static_cast<int>(m_media->localUdpPort());
    m_net->sendFrame(peerUuid, accept);

    setState(CallState::InCall);
    fire([&peerUuid](const CallEvent& ev) { if (ev.onCallAccepted) ev.onCallAccepted(peerUuid); });

    std::fprintf(stderr, "[CallManager] Звонок принят, наш UDP порт=%d\n", m_media->localUdpPort());
}

// ── rejectCall ────────────────────────────────────────────────────────────────

void CallManager::rejectCall(const std::string& callId, const std::string& reason) {
    std::string peerUuid;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (m_state != CallState::Ringing || m_callId != callId) return;
        peerUuid = m_peerUuid;
    }

    nlohmann::json reject;
    reject["type"]   = "CALL_REJECT";
    reject["callId"] = callId;
    reject["reason"] = reason;
    m_net->sendFrame(peerUuid, reject);

    std::fprintf(stderr, "[CallManager] Звонок отклонён: %s\n", reason.c_str());
    resetState();
}

// ── endCall ───────────────────────────────────────────────────────────────────

void CallManager::endCall() {
    std::string peerUuid, callId;
    bool wasActive = false;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (m_state == CallState::Idle) return;
        peerUuid   = m_peerUuid;
        callId     = m_callId;
        wasActive  = (m_state == CallState::InCall ||
                      m_state == CallState::Calling ||
                      m_state == CallState::Ringing);
    }

    if (wasActive && !callId.empty() && !peerUuid.empty()) {
        nlohmann::json end;
        end["type"]   = "CALL_END";
        end["callId"] = callId;
        m_net->sendFrame(peerUuid, end);
    }

    if (m_media) m_media->endCall();
    setState(CallState::Ended);
    if (!peerUuid.empty())
        fire([&peerUuid](const CallEvent& ev) { if (ev.onCallEnded) ev.onCallEnded(peerUuid); });

    // Переход Ended → Idle через 1 с (чтобы UI успел показать "Звонок завершён")
    auto timer = std::make_shared<asio::steady_timer>(m_net->ioContext());
    timer->expires_after(std::chrono::milliseconds(1000));
    int gen;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_endedTimer = timer;
        gen = m_generation;
    }
    timer->async_wait([this, gen, timer](const std::error_code& tec) {
        if (tec) return; // отменён
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            if (gen != m_generation) return;
        }
        resetState();
    });
}

// ── handleSignaling ────────────────────────────────────────────────────────────

void CallManager::handleSignaling(const std::string& from, const nlohmann::json& msg) {
    const std::string type   = msg.value("type", std::string());
    const std::string callId = msg.value("callId", std::string());

    if (type == "CALL_INVITE") {
        if (state() != CallState::Idle) {
            // Уже в звонке — отклоняем
            nlohmann::json reject;
            reject["type"]   = "CALL_REJECT";
            reject["callId"] = callId;
            reject["reason"] = "busy";
            m_net->sendFrame(from, reject);
            return;
        }

        const auto callerUdpPort = static_cast<uint16_t>(msg.value("udpPort", 0));
        const Bytes salt = bytesFromHex(msg.value("mediaKeySalt", std::string()));

        // Получаем IP/имя пира из NetworkManager
        const auto peerInfo = m_net->getPeerInfo(from);

        {
            std::lock_guard<std::mutex> lk(m_mutex);
            m_peerUuid             = from;
            m_callId               = callId;
            m_pendingCallerUdpPort = callerUdpPort;
            m_pendingMediaSalt     = salt;
            m_peerIp               = peerInfo.ip;
            m_state                = CallState::Ringing;
        }
        fire([](const CallEvent& ev) { if (ev.onStateChanged) ev.onStateChanged(CallState::Ringing); });
        fire([&](const CallEvent& ev) {
            if (ev.onIncomingCall) ev.onIncomingCall(from, peerInfo.name, callId);
        });

    } else if (type == "CALL_ACCEPT") {
        std::string peerIp;
        Bytes       salt;
        bool        valid = false;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            if (m_state == CallState::Calling && m_callId == callId) {
                valid  = true;
                peerIp = m_peerIp;
                salt   = m_pendingMediaSalt;
                cancelTimers(); // останавливаем таймаут 30 с
            }
        }
        if (!valid) return;

        if (!m_media) return;
        const auto peerUdpPort = static_cast<uint16_t>(msg.value("udpPort", 0));
        startMedia(peerIp, peerUdpPort, callId, salt);
        if (!m_media->isInCall()) return;

        setState(CallState::InCall);
        fire([&from](const CallEvent& ev) { if (ev.onCallAccepted) ev.onCallAccepted(from); });

        std::fprintf(stderr, "[CallManager] CALL_ACCEPT получен, peerUdpPort=%d\n",
                      static_cast<int>(peerUdpPort));

    } else if (type == "CALL_REJECT") {
        std::string peerUuid;
        bool        valid = false;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            if (m_state == CallState::Calling && m_callId == callId) {
                valid    = true;
                peerUuid = m_peerUuid;
            }
        }
        if (!valid) return;

        const std::string reason = msg.value("reason", std::string());
        std::fprintf(stderr, "[CallManager] Звонок отклонён пиром: %s\n", reason.c_str());

        resetState();
        fire([&](const CallEvent& ev) { if (ev.onCallRejected) ev.onCallRejected(peerUuid, reason); });

    } else if (type == "CALL_END") {
        std::string peerUuid;
        bool        valid = false;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            if ((m_state == CallState::InCall || m_state == CallState::Ringing ||
                 m_state == CallState::Calling) && m_callId == callId) {
                valid    = true;
                peerUuid = m_peerUuid;
            }
        }
        if (!valid) return;

        std::fprintf(stderr, "[CallManager] CALL_END получен от пира\n");
        if (m_media) m_media->endCall();

        setState(CallState::Ended);
        fire([&](const CallEvent& ev) { if (ev.onCallEnded) ev.onCallEnded(peerUuid); });

        auto timer = std::make_shared<asio::steady_timer>(m_net->ioContext());
        timer->expires_after(std::chrono::milliseconds(1000));
        int gen;
        {
            std::lock_guard<std::mutex> lk(m_mutex);
            m_endedTimer = timer;
            gen = m_generation;
        }
        timer->async_wait([this, gen, timer](const std::error_code& tec) {
            if (tec) return;
            {
                std::lock_guard<std::mutex> lk(m_mutex);
                if (gen != m_generation) return;
            }
            resetState();
        });
    }
}

// ── startMedia ────────────────────────────────────────────────────────────────

void CallManager::startMedia(const std::string& peerIp, uint16_t peerUdpPort,
                              const std::string& callId, const Bytes& salt)
{
    if (!m_media) return;

    std::string peerUuid;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        peerUuid = m_peerUuid;
    }

    if (!m_e2e->hasSession(peerUuid)) {
        fire([](const CallEvent& ev) { if (ev.onCallError) ev.onCallError("Нет E2E сессии — медиа не может быть запущено"); });
        resetState();
        return;
    }

    const Bytes mediaKey = m_e2e->snapshotMediaKey(peerUuid, callId, salt);
    if (mediaKey.empty()) {
        fire([](const CallEvent& ev) { if (ev.onCallError) ev.onCallError("Не удалось вывести медиа-ключ"); });
        resetState();
        return;
    }

    // В режиме Client-Server — включаем UDP-ретрансляцию до startCall()
    if (SessionManager::instance().portForwardingMode() == PortForwardingMode::ClientServer) {
        const std::string relayIp  = SessionManager::instance().relayServerIp();
        const uint16_t    relayUdp = SessionManager::instance().relayUdpPort();
        const std::string myUuid   = Identity::instance().uuid();
        m_media->enableUdpRelay(relayIp, relayUdp, myUuid, peerUuid);
    }

    if (!m_media->startCall(peerIp, peerUdpPort, mediaKey)) {
        // ошибка уже сообщена через MediaEngine::setErrorCallback
        resetState();
        return;
    }
    std::fprintf(stderr, "[CallManager] MediaEngine запущен, peerUdpPort=%d\n",
                  static_cast<int>(peerUdpPort));
}

// ── Listener API ──────────────────────────────────────────────────────────────

CallManager::Token CallManager::addListener(CallEvent ev) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    Token t = m_nextToken++;
    m_listeners.emplace_back(t, std::move(ev));
    return t;
}

void CallManager::removeListener(Token t) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    m_listeners.erase(
        std::remove_if(m_listeners.begin(), m_listeners.end(),
                       [t](const auto& p) { return p.first == t; }),
        m_listeners.end());
}
