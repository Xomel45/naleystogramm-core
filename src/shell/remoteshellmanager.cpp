#include "naleystogramm-core/shell/remoteshellmanager.h"
#include "naleystogramm-core/net/network.h"
#include "naleystogramm-crypto/e2e.h"
#include <algorithm>
#include <cstdio>
#include <openssl/rand.h>
#include <random>
#include <regex>

// ── UUID v4 (как в callmanager.cpp — независимая копия, чтобы не тянуть
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

// ── Конструктор / деструктор ──────────────────────────────────────────────────

RemoteShellManager::RemoteShellManager(NetworkManager* net, E2EManager* e2e)
    : m_net(net), m_e2e(e2e), m_destroyed(std::make_shared<std::atomic<bool>>(false))
{}

RemoteShellManager::~RemoteShellManager() {
    *m_destroyed = true;
    std::lock_guard<std::recursive_mutex> lk(m_mutex);
    for (auto& [id, sd] : m_sessions) {
        if (sd.inactivityTimer) sd.inactivityTimer->cancel();
        sd.process.reset(); // ShellProcess::~ShellProcess() вызывает kill()
    }
    m_sessions.clear();
}

// ── Инициатор: запросить шелл ─────────────────────────────────────────────────

void RemoteShellManager::requestShell(const std::string& peerUuid) {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);

    // Допускается не более одной одновременной сессии
    if (m_sessions.size() >= kMaxConcurrentSessions) {
        std::fprintf(stderr, "[Shell] Отказ: уже есть активная сессия (максимум %d)\n",
                      kMaxConcurrentSessions);
        fire([](ShellEvent& ev) { if (ev.onRejected) ev.onRejected(std::string{}, "max_sessions"); });
        return;
    }

    const std::string sessionId = generateUuid();
    const std::string peerName  = m_net->getPeerInfo(peerUuid).name;

    SessionData sd;
    sd.role     = Role::Initiator;
    sd.peerUuid = peerUuid;
    sd.peerName = peerName;
    m_sessions.emplace(sessionId, std::move(sd));

    m_net->sendFrame(peerUuid, nlohmann::json{
        {"type",      "SHELL_REQUEST"},
        {"sessionId", sessionId},
    });

    std::fprintf(stderr, "[Shell] Запрошен шелл у %s, сессия=%s\n",
                  peerUuid.substr(0, 8).c_str(), sessionId.substr(0, 8).c_str());
}

// ── Получатель: явно отклонить запрос ────────────────────────────────────────

void RemoteShellManager::rejectRequest(const std::string& sessionId,
                                        const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);
    auto it = m_sessions.find(sessionId);
    if (it == m_sessions.end()) return;

    m_net->sendFrame(it->second.peerUuid, nlohmann::json{
        {"type",      "SHELL_REJECT"},
        {"sessionId", sessionId},
        {"reason",    reason},
    });

    cleanupSession(sessionId);

    std::fprintf(stderr, "[Shell] Сессия %s отклонена: %s\n",
                  sessionId.substr(0, 8).c_str(), reason.c_str());
}

// ── Инициатор: ответить на OTP-запрос ────────────────────────────────────────

void RemoteShellManager::respondToChallenge(const std::string& sessionId,
                                             const std::string& password) {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);
    auto it = m_sessions.find(sessionId);
    if (it == m_sessions.end() || it->second.role != Role::Initiator) return;

    m_net->sendFrame(it->second.peerUuid, nlohmann::json{
        {"type",      "SHELL_CHALLENGE_RESPONSE"},
        {"sessionId", sessionId},
        {"password",  password},
    });

    std::fprintf(stderr, "[Shell] Отправлен ответ на OTP-запрос, сессия=%s\n",
                  sessionId.substr(0, 8).c_str());
}

// ── Инициатор: отправить ввод ─────────────────────────────────────────────────

void RemoteShellManager::sendInput(const std::string& sessionId, const Bytes& data) {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);
    auto it = m_sessions.find(sessionId);
    if (it == m_sessions.end() || it->second.role != Role::Initiator) return;

    // ══ КРИТИЧЕСКАЯ ПРОВЕРКА БЕЗОПАСНОСТИ ════════════════════════════════════
    if (hasForbiddenPattern(data)) {
        std::fprintf(stderr, "[Shell][SECURITY] ЭСКАЛАЦИЯ ПРИВИЛЕГИЙ! Сессия %s уничтожена.\n",
                      sessionId.substr(0, 8).c_str());
        killSession(sessionId, "privilege_escalation");
        fire([&sessionId](ShellEvent& ev) {
            if (ev.onPrivilegeEscalationDetected) ev.onPrivilegeEscalationDetected(sessionId);
        });
        return;
    }
    // ═════════════════════════════════════════════════════════════════════════

    resetInactivityTimer(sessionId);

    sendEncrypted(it->second.peerUuid,
        nlohmann::json{
            {"shell_type", "SHELL_INPUT"},
            {"session",    sessionId},
            {"data",       bytesToBase64(data)},
        },
        "SHELL_INPUT"
    );
}

// ── Завершить сессию ──────────────────────────────────────────────────────────

void RemoteShellManager::killSession(const std::string& sessionId,
                                      const std::string& reason) {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);
    auto it = m_sessions.find(sessionId);
    if (it == m_sessions.end()) return;

    m_net->sendFrame(it->second.peerUuid, nlohmann::json{
        {"type",      "SHELL_KILL"},
        {"sessionId", sessionId},
        {"reason",    reason},
    });

    cleanupSession(sessionId);
    fire([&](ShellEvent& ev) { if (ev.onSessionEnded) ev.onSessionEnded(sessionId, reason); });
}

// ── Обработчик незашифрованного сигналинга ────────────────────────────────────

void RemoteShellManager::handleSignaling(const std::string& from, const nlohmann::json& msg) {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);
    const std::string type      = msg.value("type", std::string());
    const std::string sessionId = msg.value("sessionId", std::string());

    // ── SHELL_REQUEST: от инициатора к получателю ─────────────────────────────
    if (type == "SHELL_REQUEST") {
        // Не допускаем более одной одновременной сессии
        if (m_sessions.size() >= kMaxConcurrentSessions) {
            std::fprintf(stderr, "[Shell] Входящий SHELL_REQUEST отклонён: занято (сессий=%zu)\n",
                          m_sessions.size());
            m_net->sendFrame(from, nlohmann::json{
                {"type",      "SHELL_REJECT"},
                {"sessionId", sessionId},
                {"reason",    "busy"},
            });
            return;
        }

        const std::string peerName = m_net->getPeerInfo(from).name;
        const std::string otp      = generateOtp();

        SessionData sd;
        sd.role     = Role::Receiver;
        sd.peerUuid = from;
        sd.peerName = peerName;
        sd.otp      = otp;
        m_sessions.emplace(sessionId, std::move(sd));

        // Сообщаем инициатору что ждём ответа на OTP-запрос
        m_net->sendFrame(from, nlohmann::json{
            {"type",      "SHELL_CHALLENGE"},
            {"sessionId", sessionId},
        });

        std::fprintf(stderr, "[Shell] Входящий запрос от %s, сессия=%s — OTP сгенерирован\n",
                      from.substr(0, 8).c_str(), sessionId.substr(0, 8).c_str());

        // Показываем OTP в окне получателя — пользователь сообщает его инициатору
        fire([&](ShellEvent& ev) {
            if (ev.onChallengeGenerated) ev.onChallengeGenerated(sessionId, from, peerName, otp);
        });

    // ── SHELL_CHALLENGE: от получателя к инициатору ───────────────────────────
    } else if (type == "SHELL_CHALLENGE") {
        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end() || it->second.role != Role::Initiator) return;

        std::fprintf(stderr, "[Shell] Получен OTP-запрос, сессия=%s — ожидаем ввод пароля\n",
                      sessionId.substr(0, 8).c_str());

        // Просим инициатора ввести пароль, который виден у получателя
        const std::string peerName = it->second.peerName;
        fire([&](ShellEvent& ev) {
            if (ev.onPasswordRequired) ev.onPasswordRequired(sessionId, from, peerName);
        });

    // ── SHELL_CHALLENGE_RESPONSE: от инициатора к получателю ─────────────────
    } else if (type == "SHELL_CHALLENGE_RESPONSE") {
        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end() || it->second.role != Role::Receiver) return;

        const std::string entered = msg.value("password", std::string());

        // Константное по времени сравнение OTP — не даём измерять совпадение
        // по префиксу через тайминг.
        bool otpMatch = !entered.empty() && !it->second.otp.empty() &&
                        entered.size() == it->second.otp.size();
        if (otpMatch) {
            unsigned diff = 0;
            for (std::size_t i = 0; i < entered.size(); ++i)
                diff |= static_cast<unsigned>(entered[i] ^ it->second.otp[i]);
            otpMatch = (diff == 0);
        }
        if (!otpMatch) {
            std::fprintf(stderr, "[Shell][SECURITY] Неверный OTP для сессии %s — шелл отклонён\n",
                          sessionId.substr(0, 8).c_str());

            m_net->sendFrame(from, nlohmann::json{
                {"type",      "SHELL_REJECT"},
                {"sessionId", sessionId},
                {"reason",    "wrong_password"},
            });

            cleanupSession(sessionId);
            return;
        }

        // Пароль верный — запускаем шелл и подтверждаем инициатору
        it->second.otp.clear(); // одноразовый: сразу обнуляем

        m_net->sendFrame(from, nlohmann::json{
            {"type",      "SHELL_ACCEPT"},
            {"sessionId", sessionId},
        });

        spawnProcess(sessionId);

        std::fprintf(stderr, "[Shell] OTP верный, сессия=%s — шелл запускается\n",
                      sessionId.substr(0, 8).c_str());

    // ── SHELL_ACCEPT: от получателя к инициатору ─────────────────────────────
    } else if (type == "SHELL_ACCEPT") {
        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end() || it->second.role != Role::Initiator) return;

        resetInactivityTimer(sessionId);

        std::fprintf(stderr, "[Shell] Шелл принят пиром, сессия=%s\n",
                      sessionId.substr(0, 8).c_str());

        const std::string peerName = it->second.peerName;
        fire([&](ShellEvent& ev) { if (ev.onAccepted) ev.onAccepted(sessionId, from, peerName); });

    // ── SHELL_REJECT: от получателя к инициатору ─────────────────────────────
    } else if (type == "SHELL_REJECT") {
        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end()) return;

        const std::string reason = msg.value("reason", std::string("declined"));
        cleanupSession(sessionId);

        std::fprintf(stderr, "[Shell] Запрос шелла отклонён: %s\n", reason.c_str());

        fire([&](ShellEvent& ev) { if (ev.onRejected) ev.onRejected(sessionId, reason); });

    // ── SHELL_KILL: завершение с любой стороны ────────────────────────────────
    } else if (type == "SHELL_KILL") {
        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end()) return;

        const std::string reason = msg.value("reason", std::string("terminated"));

        std::fprintf(stderr, "[Shell] Получен SHELL_KILL: сессия=%s причина=%s\n",
                      sessionId.substr(0, 8).c_str(), reason.c_str());

        cleanupSession(sessionId);
        fire([&](ShellEvent& ev) { if (ev.onSessionEnded) ev.onSessionEnded(sessionId, reason); });
    }
}

// ── Обработчик расшифрованных данных SHELL_DATA / SHELL_INPUT ─────────────────

void RemoteShellManager::handleDecryptedData(const std::string& from, const Bytes& plaintext) {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);

    const auto inner = nlohmann::json::parse(plaintext.begin(), plaintext.end(), nullptr, false);
    if (inner.is_discarded()) return;

    const std::string shellType = inner.value("shell_type", std::string());
    const std::string sessionId = inner.value("session", std::string());
    const Bytes       data      = bytesFromBase64(inner.value("data", std::string()));

    if (shellType == "SHELL_DATA") {
        // stdout/stderr от удалённого шелла → отображаем в ShellWindow инициатора
        resetInactivityTimer(sessionId);
        fire([&](ShellEvent& ev) { if (ev.onDataReceived) ev.onDataReceived(sessionId, data); });

    } else if (shellType == "SHELL_INPUT") {
        auto it = m_sessions.find(sessionId);
        if (it == m_sessions.end() || it->second.role != Role::Receiver || !it->second.process) {
            std::fprintf(stderr, "[Shell] SHELL_INPUT: нет активного процесса для сессии %s\n",
                          sessionId.substr(0, 8).c_str());
            return;
        }

        // ══ ВТОРИЧНАЯ ПРОВЕРКА БЕЗОПАСНОСТИ (defence in depth) ═══════════════
        if (hasForbiddenPattern(data)) {
            std::fprintf(stderr, "[Shell][SECURITY] ЭСКАЛАЦИЯ (получатель): сессия %s уничтожена\n",
                          sessionId.substr(0, 8).c_str());

            m_net->sendFrame(from, nlohmann::json{
                {"type",      "SHELL_KILL"},
                {"sessionId", sessionId},
                {"reason",    "privilege_escalation"},
            });

            cleanupSession(sessionId);
            fire([&](ShellEvent& ev) { if (ev.onSessionEnded) ev.onSessionEnded(sessionId, "privilege_escalation"); });
            return;
        }
        // ═════════════════════════════════════════════════════════════════════

        resetInactivityTimer(sessionId);
        fire([&](ShellEvent& ev) { if (ev.onInputMonitored) ev.onInputMonitored(sessionId, data); });

        Bytes cmd = data;
        if (cmd.empty() || cmd.back() != '\n') cmd.push_back('\n');
        it->second.process->write(cmd);
    }
}

// ── Проверка на эскалацию привилегий ─────────────────────────────────────────

bool RemoteShellManager::hasForbiddenPattern(const Bytes& input) {
    static const std::vector<std::regex> kPatterns = {
        // sudo / su / pkexec / doas / runas / gsudo как самостоятельные слова
        std::regex(R"(\b(sudo|su|pkexec|doas|runas|gsudo)\b)",
                   std::regex::ECMAScript | std::regex::icase),
        // Полные пути к sudo/su (обход $PATH)
        std::regex(R"(/usr(/local)?/bin/(sudo|su|pkexec|doas))"),
        // env-bypass: env sudo, env -i sudo, env VAR=x sudo и т.д.
        std::regex(R"(\benv\b[^|&;]*\b(sudo|su|pkexec)\b)"),
        // chmod +s / chmod 4xxx / chmod 6xxx (setuid / setgid бит)
        std::regex(R"(\bchmod\b[^|&;]*[+\-][sS]|\bchmod\s+[46][0-7]{3}\b)"),
        // setcap, newuidmap, newgidmap, nsenter (namespace / capabilities)
        std::regex(R"(\b(setcap|newuidmap|newgidmap|nsenter)\b)"),
        // chown root — смена владельца на root
        std::regex(R"(\bchown\s+(root[: ]|0[: ]))",
                   std::regex::ECMAScript | std::regex::icase),
        // Запись в /etc/passwd, /etc/shadow, /etc/sudoers, /etc/crontab и др.
        std::regex(R"(>{1,2}\s*/etc/(passwd|shadow|sudoers|crontab|cron\.\S*|hosts|ld\.so\.(conf|preload)))",
                   std::regex::ECMAScript | std::regex::icase),
        // tee в /etc/
        std::regex(R"(\btee\b[^|&;]*/etc/)"),
        // Python/Perl/Ruby setuid one-liners
        std::regex(R"(\b(python[23]?|perl|ruby)\b[^|&;]*\b(setuid|setgid)\s*\()"),
        // LD_PRELOAD / LD_LIBRARY_PATH инъекция
        std::regex(R"(\bLD_(PRELOAD|LIBRARY_PATH)\s*=)"),
        // Чтение физической памяти ядра
        std::regex(R"(/dev/(mem|kmem|port)\b)"),
        // PowerShell RunAs (Windows)
        std::regex(R"(Start-Process\s+\S*\s+-Verb\s+RunAs)",
                   std::regex::ECMAScript | std::regex::icase),
        // crontab -e / at now (инъекция cron)
        std::regex(R"(\bcrontab\s+-e|\bat\s+now\b)"),
    };

    const std::string str(input.begin(), input.end());
    for (const auto& pat : kPatterns) {
        if (std::regex_search(str, pat))
            return true;
    }
    return false;
}

// ── Генерация одноразового пароля ─────────────────────────────────────────────

std::string RemoteShellManager::generateOtp() {
    // Исключаем визуально похожие символы: 0/O, 1/I, B/8 и т.д.
    static const std::string kChars = "ACDEFGHJKLMNPQRTUVWXYZ2346789";
    const std::size_t n = kChars.size();
    // Rejection sampling — избегаем modulo bias
    const uint8_t limit = static_cast<uint8_t>(256 - (256 % n));

    std::string otp;
    otp.reserve(kOtpLength);
    while (otp.size() < static_cast<std::size_t>(kOtpLength)) {
        uint8_t b;
        if (RAND_bytes(&b, 1) != 1)
            continue;
        if (b < limit)
            otp += kChars[b % n];
    }
    return otp;
}

// ── Отправка зашифрованных данных ─────────────────────────────────────────────

void RemoteShellManager::sendEncrypted(const std::string& peerUuid,
                                        const nlohmann::json& innerObj,
                                        const std::string& outerType) {
    if (!m_e2e->hasSession(peerUuid)) {
        std::fprintf(stderr, "[Shell] Нет E2E-сессии для %s — данные шелла не отправлены\n",
                      peerUuid.substr(0, 8).c_str());
        return;
    }

    const std::string innerJson = innerObj.dump();
    nlohmann::json env = m_e2e->encrypt(peerUuid, sv2bytes(innerJson));
    if (env.empty()) return;

    // decrypt() не использует поле type — подмена безопасна
    env["type"] = outerType;
    m_net->sendFrame(peerUuid, env);
}

// ── Запуск шелл-процесса ──────────────────────────────────────────────────────

void RemoteShellManager::spawnProcess(const std::string& sessionId) {
    auto it = m_sessions.find(sessionId);
    if (it == m_sessions.end()) return;

    SessionData& sd = it->second;
    const std::string peerUuid = sd.peerUuid;

    auto proc = std::make_unique<ShellProcess>();
    const bool ok = proc->start(
        // onOutput
        [this, sessionId, peerUuid, destroyed = m_destroyed](const Bytes& out) {
            asio::post(m_net->ioContext(), [this, sessionId, peerUuid, out, destroyed]() {
                if (*destroyed) return;
                std::lock_guard<std::recursive_mutex> lk(m_mutex);
                auto sit = m_sessions.find(sessionId);
                if (sit == m_sessions.end()) return;
                resetInactivityTimer(sessionId);
                sendEncrypted(peerUuid, nlohmann::json{
                    {"shell_type", "SHELL_DATA"},
                    {"session",    sessionId},
                    {"data",       bytesToBase64(out)},
                }, "SHELL_DATA");
            });
        },
        // onExit
        [this, sessionId, peerUuid, destroyed = m_destroyed]() {
            asio::post(m_net->ioContext(), [this, sessionId, peerUuid, destroyed]() {
                if (*destroyed) return;
                std::lock_guard<std::recursive_mutex> lk(m_mutex);
                auto sit = m_sessions.find(sessionId);
                if (sit == m_sessions.end()) return;

                std::fprintf(stderr, "[Shell] Шелл-процесс завершился, сессия=%s\n",
                              sessionId.substr(0, 8).c_str());

                m_net->sendFrame(peerUuid, nlohmann::json{
                    {"type",      "SHELL_KILL"},
                    {"sessionId", sessionId},
                    {"reason",    "process_exited"},
                });
                cleanupSession(sessionId);
                fire([&](ShellEvent& ev) { if (ev.onSessionEnded) ev.onSessionEnded(sessionId, "process_exited"); });
            });
        });

    if (!ok) {
        std::fprintf(stderr, "[Shell] Не удалось запустить шелл\n");
        m_net->sendFrame(peerUuid, nlohmann::json{
            {"type",      "SHELL_KILL"},
            {"sessionId", sessionId},
            {"reason",    "spawn_failed"},
        });
        m_sessions.erase(it);
        fire([&](ShellEvent& ev) { if (ev.onSessionEnded) ev.onSessionEnded(sessionId, "spawn_failed"); });
        return;
    }

    sd.process         = std::move(proc);
    sd.inactivityTimer = std::make_shared<asio::steady_timer>(m_net->ioContext());
    resetInactivityTimer(sessionId); // запускает первый таймаут бездействия

    std::fprintf(stderr, "[Shell] Шелл-процесс запущен, сессия=%s, таймаут=%d мин\n",
                  sessionId.substr(0, 8).c_str(), kSessionTimeoutMs / 60000);

    fire([&](ShellEvent& ev) { if (ev.onSessionStarted) ev.onSessionStarted(sessionId); });
}

// ── Сброс таймера бездействия ─────────────────────────────────────────────────

void RemoteShellManager::resetInactivityTimer(const std::string& sessionId) {
    auto it = m_sessions.find(sessionId);
    if (it == m_sessions.end() || !it->second.inactivityTimer) return;

    SessionData& sd = it->second;
    ++sd.timerGeneration;
    const int gen = sd.timerGeneration;

    sd.inactivityTimer->expires_after(std::chrono::milliseconds(kSessionTimeoutMs));
    sd.inactivityTimer->async_wait([this, sessionId, gen, destroyed = m_destroyed](const std::error_code& ec) {
        if (*destroyed || ec) return; // ec=operation_aborted при rearm/отмене
        std::lock_guard<std::recursive_mutex> lk(m_mutex);
        auto sit = m_sessions.find(sessionId);
        if (sit == m_sessions.end() || sit->second.timerGeneration != gen) return;

        std::fprintf(stderr, "[Shell] Таймаут бездействия: сессия %s завершена\n",
                      sessionId.substr(0, 8).c_str());

        const std::string peerUuid = sit->second.peerUuid;
        m_net->sendFrame(peerUuid, nlohmann::json{
            {"type",      "SHELL_KILL"},
            {"sessionId", sessionId},
            {"reason",    "timeout"},
        });
        cleanupSession(sessionId);
        fire([&](ShellEvent& ev) { if (ev.onSessionEnded) ev.onSessionEnded(sessionId, "timeout"); });
    });
}

// ── Очистка сессии ────────────────────────────────────────────────────────────

void RemoteShellManager::cleanupSession(const std::string& sessionId) {
    auto it = m_sessions.find(sessionId);
    if (it == m_sessions.end()) return;

    if (it->second.inactivityTimer) {
        it->second.inactivityTimer->cancel();
        it->second.inactivityTimer.reset();
    }
    it->second.process.reset(); // ShellProcess::~ShellProcess() вызывает kill()

    m_sessions.erase(it);
}

// ── Listener API ──────────────────────────────────────────────────────────────

RemoteShellManager::Token RemoteShellManager::addListener(ShellEvent ev) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    Token t = m_nextToken++;
    m_listeners.emplace_back(t, std::move(ev));
    return t;
}

void RemoteShellManager::removeListener(Token t) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    m_listeners.erase(
        std::remove_if(m_listeners.begin(), m_listeners.end(),
                       [t](const auto& p) { return p.first == t; }),
        m_listeners.end());
}
