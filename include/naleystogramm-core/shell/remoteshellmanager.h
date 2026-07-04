#pragma once
#include "naleystogramm-crypto/bytes.h"
#include "naleystogramm-core/shell/shellprocess.h"
#include <asio.hpp>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

class NetworkManager;
class E2EManager;

// ── RemoteShellManager ────────────────────────────────────────────────────────
// Управляет сессиями удалённого шелла через существующий E2E-зашифрованный канал.
//
// Протокол (незашифрованный сигналинг):
//   Initiator → Receiver:  SHELL_REQUEST           {type, sessionId}
//   Receiver  → Initiator: SHELL_CHALLENGE          {type, sessionId}
//   Initiator → Receiver:  SHELL_CHALLENGE_RESPONSE {type, sessionId, password}
//   Receiver  → Initiator: SHELL_ACCEPT             {type, sessionId}
//   Receiver  → Initiator: SHELL_REJECT             {type, sessionId, reason}
//   Either    → Either:    SHELL_KILL               {type, sessionId, reason}
//
// При получении SHELL_REQUEST получатель автоматически генерирует одноразовый
// пароль (OTP) и показывает его в своём окне. Инициатор должен ввести пароль,
// который ему сообщает получатель вне полосы (голосом, чатом). Только при
// совпадении — запускается шелл.
//
// Данные шелла (E2E-зашифрованы через Double Ratchet):
//   SHELL_DATA  ← {shell_type, session, data:<base64>}   stdout/stderr получателя
//   SHELL_INPUT → {shell_type, session, data:<base64>}   stdin инициатора

class RemoteShellManager {
public:
    enum class Role { Initiator, Receiver };

    // Callbacks вместо Qt-сигналов. Вызываются на потоке io_context
    // (NetworkManager::ioContext()) или непосредственно из вызвавшего потока —
    // подписчик из UI должен перепоставить на Qt-поток через
    // QMetaObject::invokeMethod(..., Qt::QueuedConnection).
    struct ShellEvent {
        // Receiver: входящий запрос — показать OTP в окне получателя
        std::function<void(const std::string& sessionId, const std::string& peerUuid,
                            const std::string& peerName, const std::string& otp)> onChallengeGenerated;
        // Initiator: нужно ввести пароль (который виден у получателя)
        std::function<void(const std::string& sessionId, const std::string& peerUuid,
                            const std::string& peerName)> onPasswordRequired;
        // Initiator: пароль принят, шелл запущен
        std::function<void(const std::string& sessionId, const std::string& peerUuid,
                            const std::string& peerName)> onAccepted;
        // Receiver: шелл-процесс успешно запущен (OTP-диалог можно закрыть, монитор — показать)
        std::function<void(const std::string& sessionId)> onSessionStarted;
        // Initiator: запрос отклонён (неверный пароль или явный отказ)
        std::function<void(const std::string& sessionId, const std::string& reason)> onRejected;
        // Данные stdout/stderr от удалённого шелла → ShellWindow инициатора
        std::function<void(const std::string& sessionId, const Bytes& data)> onDataReceived;
        // Команда от инициатора → ShellMonitor получателя (для отображения)
        std::function<void(const std::string& sessionId, const Bytes& data)> onInputMonitored;
        // Сессия завершена (с любой стороны)
        std::function<void(const std::string& sessionId, const std::string& reason)> onSessionEnded;
        // Обнаружена попытка эскалации привилегий — сессия уже уничтожена
        std::function<void(const std::string& sessionId)> onPrivilegeEscalationDetected;
    };

    RemoteShellManager(NetworkManager* net, E2EManager* e2e);
    ~RemoteShellManager();

    // Инициатор: запросить шелл-сессию у пира.
    // Отказывает немедленно если уже есть активная сессия.
    void requestShell(const std::string& peerUuid);

    // Получатель: явно отклонить запрос (нажата кнопка «Отклонить» в UI).
    void rejectRequest(const std::string& sessionId,
                       const std::string& reason = "declined");

    // Инициатор: ответить на OTP-запрос.
    // Вызывается после того как пользователь ввёл пароль в диалоге.
    void respondToChallenge(const std::string& sessionId, const std::string& password);

    // Инициатор: отправить данные в stdin удалённого процесса.
    void sendInput(const std::string& sessionId, const Bytes& data);

    // Любая сторона: завершить сессию
    void killSession(const std::string& sessionId,
                     const std::string& reason = "terminated");

    // Обработчик незашифрованного сигналинга (все SHELL_* типы).
    // Вызывается из MainWindow::onMessageReceived.
    void handleSignaling(const std::string& from, const nlohmann::json& msg);

    // Обработчик расшифрованных данных шелла (outer type SHELL_DATA / SHELL_INPUT).
    void handleDecryptedData(const std::string& from, const Bytes& plaintext);

    // ── Listener API ─────────────────────────────────────────────────────────
    using Token = uint32_t;
    Token addListener   (ShellEvent ev);
    void  removeListener(Token t);

private:
    static bool        hasForbiddenPattern(const Bytes& input);
    static std::string generateOtp();

    void sendEncrypted(const std::string& peerUuid,
                       const nlohmann::json& innerObj,
                       const std::string& outerType);

    // Вызывается с захваченным m_mutex
    void spawnProcess(const std::string& sessionId);
    // Вызывается с захваченным m_mutex
    void cleanupSession(const std::string& sessionId);
    // Вызывается с захваченным m_mutex
    void resetInactivityTimer(const std::string& sessionId);

    struct SessionData {
        Role        role;
        std::string peerUuid;
        std::string peerName;
        std::string otp;                              // OTP (только у Receiver, до верификации)
        std::unique_ptr<ShellProcess>       process;  // только у Receiver после принятия
        std::shared_ptr<asio::steady_timer> inactivityTimer;
        int         timerGeneration{0};
    };

    // Helper: уведомить всех подписчиков (не должен держать m_listenerMutex)
    template<typename Fn>
    void fire(Fn&& invoke) const {
        std::vector<std::pair<Token, ShellEvent>> snap;
        {
            std::lock_guard<std::mutex> lk(m_listenerMutex);
            snap = m_listeners;
        }
        for (auto& [tok, ev] : snap)
            invoke(ev);
    }

    NetworkManager* m_net {nullptr};
    E2EManager*     m_e2e {nullptr};

    // Защищает m_sessions: публичные методы вызываются с Qt-потока,
    // продолжения spawnProcess/таймеров — через asio::post на io-потоке.
    // Recursive — внутренние методы вызывают друг друга с уже захваченным мьютексом.
    mutable std::recursive_mutex m_mutex;
    std::unordered_map<std::string, SessionData> m_sessions;

    // Флаг уничтожения объекта — проверяется в колбэках из потоков чтения
    // ShellProcess и продолжениях asio::post после возможного удаления менеджера.
    std::shared_ptr<std::atomic<bool>> m_destroyed;

    mutable std::mutex m_listenerMutex;
    std::vector<std::pair<Token, ShellEvent>> m_listeners;
    Token m_nextToken{0};

    static constexpr int kMaxConcurrentSessions = 1;
    static constexpr int kSessionTimeoutMs      = 30 * 60 * 1000; // 30 минут
    static constexpr int kOtpLength             = 6;
};
