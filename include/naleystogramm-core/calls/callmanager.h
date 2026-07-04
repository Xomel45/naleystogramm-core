#pragma once
#include "naleystogramm-core/calls/imediaengine.h"
#include "naleystogramm-crypto/bytes.h"
#include <asio.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <utility>
#include <vector>

class NetworkManager;
class E2EManager;

// ── CallManager ────────────────────────────────────────────────────────────────
// Машина состояний голосового звонка + обработка сигналинга (CALL_INVITE/ACCEPT/REJECT/END).
//
// Диаграмма состояний:
//   Idle → Calling  (мы отправили CALL_INVITE)
//   Idle → Ringing  (получили CALL_INVITE от пира)
//   Calling → InCall  (получили CALL_ACCEPT)
//   Calling → Idle    (получили CALL_REJECT или таймаут 30 с)
//   Ringing → InCall  (мы отправили CALL_ACCEPT)
//   Ringing → Idle    (мы отклонили или пир отменил)
//   InCall  → Ended   (получили/отправили CALL_END или пир отключился)
//   Ended   → Idle    (автоматически через 1 с)

class CallManager {
public:
    enum class CallState { Idle, Calling, Ringing, InCall, Ended };

    // Callbacks вместо Qt-сигналов. Вызываются на потоке io_context
    // (NetworkManager::ioContext()) или непосредственно из вызвавшего потока —
    // подписчик из UI должен перепоставить на Qt-поток через
    // QMetaObject::invokeMethod(..., Qt::QueuedConnection).
    struct CallEvent {
        std::function<void(const std::string& fromUuid,
                            const std::string& callerName,
                            const std::string& callId)>     onIncomingCall;
        std::function<void(const std::string& peerUuid)>    onCallAccepted;
        std::function<void(const std::string& peerUuid,
                            const std::string& reason)>      onCallRejected;
        std::function<void(const std::string& peerUuid)>    onCallEnded;
        std::function<void(const std::string& msg)>         onCallError;
        std::function<void(CallState state)>                onStateChanged;
    };

    CallManager(NetworkManager* net, E2EManager* e2e);
    ~CallManager();

    // ── Исходящий звонок ──────────────────────────────────────────────────────
    // Создаёт callId, отправляет CALL_INVITE через TCP, запускает таймаут 30 с.
    void initiateCall(const std::string& peerUuid, const std::string& peerIp);

    // ── Принять входящий звонок ───────────────────────────────────────────────
    // Отправляет CALL_ACCEPT, запускает MediaEngine.
    void acceptCall(const std::string& callId);

    // ── Отклонить входящий звонок ─────────────────────────────────────────────
    void rejectCall(const std::string& callId, const std::string& reason = "declined");

    // ── Завершить текущий звонок ──────────────────────────────────────────────
    void endCall();

    // ── Обработчик сигналинговых сообщений ───────────────────────────────────
    // Вызывается из MainWindow::onMessageReceived для CALL_* типов.
    void handleSignaling(const std::string& from, const nlohmann::json& msg);

    [[nodiscard]] CallState     state() const;
    [[nodiscard]] bool          isCallActive() const;
    [[nodiscard]] std::string   activePeer() const;

    // Платформенная реализация звонка (Qt-адаптер на desktop, JNI на Android).
    // Не владеет объектом — вызывающая сторона (UI-слой) держит его живым
    // не короче времени жизни CallManager. В CLI-режиме не вызывается —
    // m_media остаётся nullptr, initiateCall/acceptCall тогда не работают.
    void setMediaEngine(IMediaEngine* media);

    // ── Listener API ─────────────────────────────────────────────────────────
    using Token = uint32_t;
    Token addListener   (CallEvent ev);
    void  removeListener(Token t);

private:
    void setState(CallState s);
    // Запустить MediaEngine после согласования параметров
    void startMedia(const std::string& peerIp, uint16_t peerUdpPort,
                    const std::string& callId, const Bytes& salt);
    // Очистить состояние и вернуться в Idle
    void resetState();
    // Отменить активные таймеры (повышает m_generation, чтобы устаревшие
    // колбэки таймеров игнорировались)
    void cancelTimers();

    // Helper: уведомить всех подписчиков (не должен держать m_listenerMutex)
    template<typename Fn>
    void fire(Fn&& invoke) const {
        std::vector<std::pair<Token, CallEvent>> snap;
        {
            std::lock_guard<std::mutex> lk(m_listenerMutex);
            snap = m_listeners;
        }
        for (auto& [tok, ev] : snap)
            invoke(ev);
    }

    NetworkManager* m_net   {nullptr};
    E2EManager*     m_e2e   {nullptr};
    IMediaEngine*   m_media {nullptr};

    mutable std::mutex m_mutex;
    CallState    m_state   {CallState::Idle};
    std::string  m_callId;
    std::string  m_peerUuid;
    std::string  m_peerIp;

    // Отбрасывает устаревшие колбэки таймеров после resetState()/повторного звонка
    int m_generation {0};
    std::shared_ptr<asio::steady_timer> m_callTimeout; // 30 с без CALL_ACCEPT → Idle
    std::shared_ptr<asio::steady_timer> m_endedTimer;  // Ended → Idle через 1 с

    // Данные входящего приглашения (ждут acceptCall/rejectCall)
    uint16_t     m_pendingCallerUdpPort {0};
    Bytes        m_pendingMediaSalt;

    mutable std::mutex m_listenerMutex;
    std::vector<std::pair<Token, CallEvent>> m_listeners;
    Token        m_nextToken{0};

    static constexpr int kCallTimeoutMs = 30000;
};
