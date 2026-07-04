#include "naleystogramm-core/shell/shellprocess.h"
#include <cstdio>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <cerrno>
#  include <cstring>
#  include <filesystem>
#  include <signal.h>
#  include <sys/wait.h>
#  include <unistd.h>
extern char** environ;
#endif

ShellProcess::~ShellProcess() {
    if (m_running) kill();
}

#ifdef _WIN32

// ── Windows: CreatePipe + CreateProcessW (powershell.exe) ────────────────────

bool ShellProcess::start(OutputCallback onOutput, ExitCallback onExit) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength              = sizeof(sa);
    sa.bInheritHandle       = TRUE;
    sa.lpSecurityDescriptor = nullptr;

    HANDLE stdoutRead = nullptr, stdoutWrite = nullptr;
    HANDLE stdinRead  = nullptr, stdinWrite  = nullptr;

    if (!CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0)) {
        std::fprintf(stderr, "[ShellProcess] CreatePipe(stdout) failed: %lu\n", GetLastError());
        return false;
    }
    if (!SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(stdoutRead); CloseHandle(stdoutWrite);
        return false;
    }
    if (!CreatePipe(&stdinRead, &stdinWrite, &sa, 0)) {
        std::fprintf(stderr, "[ShellProcess] CreatePipe(stdin) failed: %lu\n", GetLastError());
        CloseHandle(stdoutRead); CloseHandle(stdoutWrite);
        return false;
    }
    if (!SetHandleInformation(stdinWrite, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(stdoutRead); CloseHandle(stdoutWrite);
        CloseHandle(stdinRead);  CloseHandle(stdinWrite);
        return false;
    }

    STARTUPINFOW si{};
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = stdoutWrite;
    si.hStdError  = stdoutWrite;
    si.hStdInput  = stdinRead;

    PROCESS_INFORMATION pi{};
    std::wstring cmdLine = L"powershell.exe -NoLogo -NoExit -NonInteractive";

    const BOOL ok = CreateProcessW(nullptr, cmdLine.data(), nullptr, nullptr, TRUE,
                                    CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

    // Дочерние концы пайпов больше не нужны в родителе
    CloseHandle(stdoutWrite);
    CloseHandle(stdinRead);

    if (!ok) {
        std::fprintf(stderr, "[ShellProcess] CreateProcessW failed: %lu\n", GetLastError());
        CloseHandle(stdoutRead);
        CloseHandle(stdinWrite);
        return false;
    }

    CloseHandle(pi.hThread);

    m_hProcess    = pi.hProcess;
    m_hStdinWrite = stdinWrite;
    m_running     = true;

    HANDLE outRead = stdoutRead;
    HANDLE hProc   = pi.hProcess;
    m_readerThread = std::thread([outRead, hProc, onOutput, onExit]() {
        char buf[4096];
        for (;;) {
            DWORD n = 0;
            const BOOL rok = ReadFile(outRead, buf, sizeof(buf), &n, nullptr);
            if (!rok || n == 0) break;
            onOutput(Bytes(buf, buf + n));
        }
        WaitForSingleObject(hProc, INFINITE);
        CloseHandle(outRead);
        CloseHandle(hProc);
        onExit();
    });

    return true;
}

bool ShellProcess::write(const Bytes& data) {
    if (!m_hStdinWrite) return false;
    DWORD written = 0;
    return WriteFile(static_cast<HANDLE>(m_hStdinWrite), data.data(),
                      static_cast<DWORD>(data.size()), &written, nullptr) != 0;
}

void ShellProcess::kill() {
    if (m_hProcess) {
        TerminateProcess(static_cast<HANDLE>(m_hProcess), 1);
        m_hProcess = nullptr;
    }
    if (m_hStdinWrite) {
        CloseHandle(static_cast<HANDLE>(m_hStdinWrite));
        m_hStdinWrite = nullptr;
    }
    if (m_readerThread.joinable())
        m_readerThread.detach();
    m_running = false;
}

#else

// ── POSIX: pipe + fork + execve (bash/zsh/sh) ────────────────────────────────

bool ShellProcess::start(OutputCallback onOutput, ExitCallback onExit) {
    int inPipe[2];
    int outPipe[2];
    if (::pipe(inPipe) != 0) {
        std::fprintf(stderr, "[ShellProcess] pipe() failed: %s\n", std::strerror(errno));
        return false;
    }
    if (::pipe(outPipe) != 0) {
        std::fprintf(stderr, "[ShellProcess] pipe() failed: %s\n", std::strerror(errno));
        ::close(inPipe[0]); ::close(inPipe[1]);
        return false;
    }

    std::string shell = "/bin/bash";
    if (!std::filesystem::exists(shell)) {
        shell = "/bin/zsh";
        if (!std::filesystem::exists(shell))
            shell = "/bin/sh";
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        std::fprintf(stderr, "[ShellProcess] fork() failed: %s\n", std::strerror(errno));
        ::close(inPipe[0]);  ::close(inPipe[1]);
        ::close(outPipe[0]); ::close(outPipe[1]);
        return false;
    }

    if (pid == 0) {
        // ── Дочерний процесс ──────────────────────────────────────────────
        ::dup2(inPipe[0],  STDIN_FILENO);
        ::dup2(outPipe[1], STDOUT_FILENO);
        ::dup2(outPipe[1], STDERR_FILENO);
        ::close(inPipe[0]);  ::close(inPipe[1]);
        ::close(outPipe[0]); ::close(outPipe[1]);

        char* argv[] = { const_cast<char*>(shell.c_str()), nullptr };
        ::execve(shell.c_str(), argv, environ);
        _exit(127); // execve не вернулась — ошибка запуска
    }

    // ── Родительский процесс ─────────────────────────────────────────────────
    ::close(inPipe[0]);
    ::close(outPipe[1]);

    m_pid     = pid;
    m_stdinFd = inPipe[1];
    m_running = true;

    const int outFd = outPipe[0];
    m_readerThread = std::thread([outFd, pid, onOutput, onExit]() {
        char buf[4096];
        for (;;) {
            const ssize_t n = ::read(outFd, buf, sizeof(buf));
            if (n > 0) {
                onOutput(Bytes(buf, buf + n));
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            break; // EOF или ошибка чтения
        }
        int status = 0;
        ::waitpid(pid, &status, 0);
        ::close(outFd);
        onExit();
    });

    return true;
}

bool ShellProcess::write(const Bytes& data) {
    if (m_stdinFd < 0) return false;
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::write(m_stdinFd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

void ShellProcess::kill() {
    if (m_pid > 0) {
        ::kill(static_cast<pid_t>(m_pid), SIGKILL);
        m_pid = -1;
    }
    if (m_stdinFd >= 0) {
        ::close(m_stdinFd);
        m_stdinFd = -1;
    }
    if (m_readerThread.joinable())
        m_readerThread.detach();
    m_running = false;
}

#endif
