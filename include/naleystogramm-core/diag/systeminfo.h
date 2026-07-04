#pragma once
#include <string>
#include <nlohmann/json.hpp>

// ── SystemInfo ────────────────────────────────────────────────────────────────
// Синглтон. Собирает статическую информацию об аппаратуре и ОС один раз
// при запуске (collect()). Результат передаётся собеседнику в HANDSHAKE
// и отображается в ContactProfileDialog.
//
// Поддерживаемые платформы:
//   Linux  — /proc/cpuinfo, /proc/meminfo, /etc/os-release
//   Other  — compile-time arch macros

class SystemInfo {
public:
    static SystemInfo& instance();

    void collect();

    [[nodiscard]] std::string deviceType() const { return m_deviceType; }
    [[nodiscard]] std::string cpuModel()   const { return m_cpuModel;   }
    [[nodiscard]] std::string ramAmount()  const { return m_ramAmount;  }
    [[nodiscard]] std::string osName()     const { return m_osName;     }

    [[nodiscard]] nlohmann::json toJson() const;
    [[nodiscard]] nlohmann::json toJsonForHandshake(const std::string& externalIp) const;

private:
    SystemInfo() = default;
    void collectLinux();
    void collectFallback();

    std::string m_deviceType{"PC"};
    std::string m_cpuModel;
    std::string m_ramAmount;
    std::string m_osName;
};
