#include "naleystogramm-core/diag/systeminfo.h"
#include <fstream>
#include <sstream>
#include <cstring>
#include <cmath>
#include <cstdio>
#include <algorithm>

#ifdef __linux__
#  include <sys/utsname.h>
#endif
#ifdef _WIN32
#  include <windows.h>
#endif

static std::string sysinfo_trim(std::string s) {
    const auto* ws = " \t\r\n";
    s.erase(0, s.find_first_not_of(ws));
    const auto last = s.find_last_not_of(ws);
    if (last != std::string::npos) s.erase(last + 1);
    return s;
}

static void sysinfo_removeAll(std::string& s, std::string_view sub) {
    for (std::size_t p; (p = s.find(sub)) != std::string::npos; )
        s.erase(p, sub.size());
}

static std::string sysinfo_simplified(std::string s) {
    bool inSpace = false;
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == ' ' || c == '\t') {
            if (!inSpace) { out += ' '; inSpace = true; }
        } else {
            out += c;
            inSpace = false;
        }
    }
    return sysinfo_trim(out);
}

SystemInfo& SystemInfo::instance() {
    static SystemInfo inst;
    return inst;
}

void SystemInfo::collect() {
#ifdef __linux__
    collectLinux();
    {
        std::ifstream f("/etc/os-release");
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("PRETTY_NAME=", 0) == 0) {
                std::string name = line.substr(12);
                if (!name.empty() && name.front() == '"') name = name.substr(1);
                if (!name.empty() && name.back() == '"') name.pop_back();
                m_osName = sysinfo_trim(name);
                break;
            }
        }
    }
    if (m_osName.empty()) {
        struct utsname uts{};
        uname(&uts);
        m_osName = std::string(uts.sysname) + " " + uts.release;
    }
#else
    collectFallback();
#  ifdef _WIN32
    OSVERSIONINFOW ovi{};
    ovi.dwOSVersionInfoSize = sizeof(ovi);
    GetVersionExW(&ovi);
    m_osName = "Windows " + std::to_string(ovi.dwMajorVersion)
             + "." + std::to_string(ovi.dwMinorVersion);
#  else
    m_osName = "Unknown OS";
#  endif
#endif
    fprintf(stderr, "[SystemInfo] type=%s cpu=%s ram=%s os=%s\n",
            m_deviceType.c_str(), m_cpuModel.c_str(),
            m_ramAmount.c_str(), m_osName.c_str());
}

#ifdef __linux__
void SystemInfo::collectLinux() {
    m_deviceType = "PC";

    {
        std::ifstream f("/proc/cpuinfo");
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("model name", 0) == 0) {
                const auto colon = line.find(':');
                if (colon != std::string::npos) {
                    std::string cpu = line.substr(colon + 1);
                    sysinfo_removeAll(cpu, "(R)");
                    sysinfo_removeAll(cpu, "(TM)");
                    sysinfo_removeAll(cpu, " CPU");
                    m_cpuModel = sysinfo_simplified(cpu);
                }
                break;
            }
        }
    }

    if (m_cpuModel.empty()) {
        struct utsname uts{};
        uname(&uts);
        m_cpuModel = uts.machine;
    }

    {
        std::ifstream f("/proc/meminfo");
        std::string line;
        while (std::getline(f, line)) {
            if (line.rfind("MemTotal:", 0) == 0) {
                std::istringstream ss(line);
                std::string key;
                long long kb = 0;
                ss >> key >> kb;
                const double gb = static_cast<double>(kb) / (1024.0 * 1024.0);
                const int rounded = static_cast<int>(std::round(gb));
                char buf[32];
                if (std::abs(gb - rounded) < 0.1)
                    std::snprintf(buf, sizeof(buf), "%d GB", rounded);
                else
                    std::snprintf(buf, sizeof(buf), "%.1f GB", gb);
                m_ramAmount = buf;
                break;
            }
        }
    }

    if (m_ramAmount.empty()) {
        m_ramAmount = "неизвестно";
    }
}
#endif // __linux__

void SystemInfo::collectFallback() {
    m_deviceType = "PC";
#if defined(__x86_64__) || defined(_M_X64)
    m_cpuModel = "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    m_cpuModel = "arm64";
#elif defined(__arm__) || defined(_M_ARM)
    m_cpuModel = "arm";
#else
    m_cpuModel = "unknown";
#endif
    m_ramAmount = "неизвестно";
}

nlohmann::json SystemInfo::toJson() const {
    return {
        {"deviceType", m_deviceType},
        {"cpuModel",   m_cpuModel},
        {"ramAmount",  m_ramAmount},
        {"osName",     m_osName},
    };
}

nlohmann::json SystemInfo::toJsonForHandshake(const std::string& externalIp) const {
    nlohmann::json obj = toJson();
    if (externalIp.empty() || externalIp == "0.0.0.0") {
        obj["cpuModel"]   = "Ким Чен-Танк";
        obj["deviceType"] = "Secret Bunker";
        obj["ramAmount"]  = "Unlimited Nuclear Power";
    }
    return obj;
}
