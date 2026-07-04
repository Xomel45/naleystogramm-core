#pragma once
#include "naleystogramm-crypto/bytes.h"
#include <atomic>
#include <functional>
#include <thread>

// Кросс-платформенный запуск интерактивного шелла (bash/zsh/sh на Linux,
// powershell.exe на Windows) с merged stdout+stderr, без PTY — аналог
// QProcess с MergedChannels. Чтение вывода — в выделенном потоке.
class ShellProcess {
public:
    using OutputCallback = std::function<void(const Bytes&)>;
    using ExitCallback   = std::function<void()>;

    ShellProcess() = default;
    ~ShellProcess();

    ShellProcess(const ShellProcess&)            = delete;
    ShellProcess& operator=(const ShellProcess&) = delete;

    // Запускает шелл. onOutput/onExit вызываются из отдельного потока чтения —
    // переданные колбэки должны быть thread-safe (использовать asio::post
    // для перехода на нужный поток). Возвращает false при ошибке запуска.
    bool start(OutputCallback onOutput, ExitCallback onExit);

    // Записать данные в stdin процесса (блокирующий write).
    bool write(const Bytes& data);

    // Принудительно завершить процесс; поток чтения детачится сам.
    void kill();

    [[nodiscard]] bool isRunning() const { return m_running; }

private:
#ifdef _WIN32
    void* m_hProcess   {nullptr};
    void* m_hStdinWrite{nullptr};
#else
    long long m_pid    {-1};
    int       m_stdinFd{-1};
#endif
    std::thread       m_readerThread;
    std::atomic<bool> m_running{false};
};
