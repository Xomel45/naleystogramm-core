#pragma once
#include <asio.hpp>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

// UPnP IGD маппер через SSDP + SOAP. Qt-free (asio + std::regex).
// Поддерживает: до 3 попыток обнаружения IGD, привязку SSDP к LAN-интерфейсу,
// подробное логирование через переданный logFn.
class UpnpMapper {
public:
    UpnpMapper(asio::io_context& io,
               std::function<void(const std::string& msg, bool important)> logFn);

    // localIp — LAN IP, к которому привязывается SSDP (см. NetworkManager::detectLocalLanIp()).
    // onResult вызывается ровно один раз на самый последний запуск mapPort().
    void mapPort(uint16_t port, const std::string& localIp,
                  std::function<void(bool)> onResult);

private:
    struct ParsedUrl {
        std::string host;
        uint16_t    port {80};
        std::string path {"/"};
    };
    struct HttpResponse {
        bool        ok {false};
        int         status {0};
        std::string body;
        std::string error;
    };

    void discover(int generation);
    void fetchControlUrl(int generation, const std::string& location);
    void addPortMapping(int generation, const ParsedUrl& controlUrl, const std::string& serviceType);

    void httpRequest(const ParsedUrl& url, const std::string& method,
                      const std::string& body,
                      const std::vector<std::pair<std::string, std::string>>& headers,
                      std::function<void(HttpResponse)> cb);

    static ParsedUrl    parseUrl(const std::string& url);
    static std::string  soapRequest(const std::string& action, const std::string& body,
                                     const std::string& serviceType);

    void log(const std::string& msg, bool important = false) const;
    void finish(int generation, bool ok);

    asio::io_context& m_io;
    std::function<void(const std::string&, bool)> m_logFn;

    uint16_t    m_port {0};
    std::string m_localIp;
    int         m_retryCount {0};
    int         m_generation {0};
    std::function<void(bool)> m_onResult;

    static constexpr int kUpnpTimeoutMs = 5000;  // Таймаут одной попытки/запроса (мс)
    static constexpr int kMaxRetries    = 3;     // Макс. число попыток обнаружения SSDP
    static constexpr int kRetryDelayMs  = 2000;  // Пауза между попытками (мс)
};
