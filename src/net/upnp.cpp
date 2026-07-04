#include "naleystogramm-core/net/upnp.h"
#include <algorithm>
#include <array>
#include <cctype>
#include <regex>

namespace {

std::string trim(const std::string& s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// Тело HTTP-ответа с Transfer-Encoding: chunked → разворачиваем в обычные байты.
std::string dechunk(const std::string& in) {
    std::string out;
    std::size_t pos = 0;
    while (pos < in.size()) {
        const auto lineEnd = in.find("\r\n", pos);
        if (lineEnd == std::string::npos) break;
        const std::string sizeHex = in.substr(pos, lineEnd - pos);
        std::size_t chunkSize = 0;
        try { chunkSize = std::stoul(sizeHex, nullptr, 16); } catch (...) { break; }
        if (chunkSize == 0) break;
        const std::size_t dataStart = lineEnd + 2;
        if (dataStart + chunkSize > in.size()) break;
        out.append(in, dataStart, chunkSize);
        pos = dataStart + chunkSize + 2;  // пропускаем завершающий \r\n чанка
    }
    return out;
}

} // namespace

UpnpMapper::UpnpMapper(asio::io_context& io,
                       std::function<void(const std::string&, bool)> logFn)
    : m_io(io), m_logFn(std::move(logFn)) {}

void UpnpMapper::log(const std::string& msg, bool important) const {
    if (m_logFn) m_logFn(msg, important);
}

void UpnpMapper::finish(int generation, bool ok) {
    if (generation != m_generation) return;
    if (m_onResult) m_onResult(ok);
}

void UpnpMapper::mapPort(uint16_t port, const std::string& localIp,
                          std::function<void(bool)> onResult) {
    ++m_generation;
    m_port       = port;
    m_localIp    = localIp;
    m_retryCount = 0;
    m_onResult   = std::move(onResult);
    discover(m_generation);
}

// ── SSDP discovery ────────────────────────────────────────────────────────

void UpnpMapper::discover(int generation) {
    if (generation != m_generation) return;

    log("[1/4 SSDP] Попытка обнаружения IGD " + std::to_string(m_retryCount + 1) + "/" +
        std::to_string(kMaxRetries) + " (localIp=" + (m_localIp.empty() ? "?" : m_localIp) + ")");

    auto sock = std::make_shared<asio::ip::udp::socket>(m_io);
    std::error_code ec;
    sock->open(asio::ip::udp::v4(), ec);
    if (!ec) sock->set_option(asio::ip::udp::socket::reuse_address(true), ec);

    bool bound = false;
    if (!ec && !m_localIp.empty()) {
        std::error_code addrEc;
        const auto addr = asio::ip::make_address(m_localIp, addrEc);
        if (!addrEc) {
            sock->bind(asio::ip::udp::endpoint(addr, 0), ec);
            if (!ec) {
                bound = true;
            } else {
                log("[1/4 SSDP] Не удалось привязать UDP к " + m_localIp + ": " + ec.message() +
                    " — пробуем Any", true);
            }
        }
    }
    if (!bound) {
        ec.clear();
        sock->bind(asio::ip::udp::endpoint(asio::ip::udp::v4(), 0), ec);
    }
    if (ec) {
        log("[1/4 SSDP] Привязка UDP провалилась: " + ec.message() + " — SSDP невозможен", true);
        finish(generation, false);
        return;
    }

    {
        std::error_code epEc;
        const auto ep = sock->local_endpoint(epEc);
        if (!epEc)
            log("[1/4 SSDP] Привязан к " + ep.address().to_string() + ":" + std::to_string(ep.port()) +
                (bound ? "" : " (Any, fallback)"));
    }

    static const std::string kSsdp =
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        "MX: 2\r\n"
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
        "\r\n";

    std::error_code sendEc;
    const asio::ip::udp::endpoint dest(asio::ip::make_address("239.255.255.250"), 1900);
    const std::size_t sent = sock->send_to(asio::buffer(kSsdp), dest, 0, sendEc);
    if (sendEc || sent != kSsdp.size()) {
        log("[1/4 SSDP] Ошибка отправки M-SEARCH: " + sendEc.message(), true);
    } else {
        log("[1/4 SSDP] M-SEARCH отправлен на 239.255.255.250:1900 (" + std::to_string(sent) +
            " байт), ожидаем ответ " + std::to_string(kUpnpTimeoutMs) + " мс...");
    }

    auto buf    = std::make_shared<std::array<char, 4096>>();
    auto sender = std::make_shared<asio::ip::udp::endpoint>();
    auto timer  = std::make_shared<asio::steady_timer>(m_io);
    auto done   = std::make_shared<bool>(false);

    sock->async_receive_from(asio::buffer(*buf), *sender,
        [this, sock, buf, sender, timer, done, generation](std::error_code recvEc, std::size_t n) {
            if (*done) return;
            *done = true;
            timer->cancel();

            if (generation != m_generation) return;

            if (recvEc) {
                log("[1/4 SSDP] Ошибка приёма UDP: " + recvEc.message(), true);
                finish(generation, false);
                return;
            }

            const std::string data(buf->data(), n);
            log("[1/4 SSDP] Ответ получен от " + sender->address().to_string() + ":" +
                std::to_string(sender->port()) + " (" + std::to_string(n) + " байт)");

            static const std::regex re(R"(LOCATION:\s*(http://[^\r\n]+))", std::regex::icase);
            std::smatch m;
            if (!std::regex_search(data, m, re)) {
                log("[1/4 SSDP] LOCATION заголовок не найден.\n"
                    "  Ответ роутера:\n" + data + "\n"
                    "  Вероятная причина: роутер ответил, но не является IGD "
                    "(нет WANIPConnection/WANPPPConnection).", true);
                finish(generation, false);
                return;
            }

            const std::string location = trim(m[1].str());
            log("[1/4 SSDP] IGD обнаружен: " + location);
            fetchControlUrl(generation, location);
        });

    timer->expires_after(std::chrono::milliseconds(kUpnpTimeoutMs));
    timer->async_wait([this, sock, done, generation](std::error_code tec) {
        if (tec || *done) return;
        *done = true;
        std::error_code cec;
        sock->cancel(cec);

        if (generation != m_generation) return;

        if (m_retryCount + 1 < kMaxRetries) {
            ++m_retryCount;
            log("[1/4 SSDP] Таймаут (" + std::to_string(kUpnpTimeoutMs) + " мс) — роутер не ответил на "
                "M-SEARCH. Повтор через " + std::to_string(kRetryDelayMs) + " мс (попытка " +
                std::to_string(m_retryCount + 1) + "/" + std::to_string(kMaxRetries) + ").\n"
                "  Возможные причины: UPnP отключён на роутере, мультикаст "
                "239.255.255.250 блокируется, интерфейс " + (m_localIp.empty() ? "?" : m_localIp) +
                " не видит роутер.", true);

            auto retryTimer = std::make_shared<asio::steady_timer>(m_io);
            retryTimer->expires_after(std::chrono::milliseconds(kRetryDelayMs));
            retryTimer->async_wait([this, retryTimer, generation](std::error_code) {
                discover(generation);
            });
        } else {
            log("[1/4 SSDP] IGD не найден после " + std::to_string(kMaxRetries) + " попыток.\n"
                "  Что делать:\n"
                "  1. Зайти в панель роутера → включить UPnP/IGD\n"
                "  2. Или переключить режим на «Разблокированный порт» "
                "и пробросить порт вручную\n"
                "  3. Или использовать режим «Ретранслятор»", true);
            finish(generation, false);
        }
    });
}

// Загружаем XML-описание IGD для поиска controlURL WANIPConnection/WANPPPConnection
void UpnpMapper::fetchControlUrl(int generation, const std::string& location) {
    if (generation != m_generation) return;

    log("[2/4 Describe] Загружаем описание IGD: " + location);

    const ParsedUrl url = parseUrl(location);
    httpRequest(url, "GET", "", {}, [this, generation, url, location](HttpResponse resp) {
        if (generation != m_generation) return;

        if (!resp.ok) {
            log("[2/4 Describe] Ошибка загрузки XML-описания IGD:\n"
                "  URL: " + location + "\n"
                "  Ошибка: " + resp.error + " (HTTP " + std::to_string(resp.status) + ")", true);
            finish(generation, false);
            return;
        }

        const std::string& xml = resp.body;
        log("[2/4 Describe] XML получен (" + std::to_string(xml.size()) + " байт)");

        // Ищем controlURL для WANIPConnection или WANPPPConnection;
        // захватываем "IP" / "PPP" чтобы передать правильный SOAPAction.
        static const std::regex re(
            R"(<serviceType>urn:schemas-upnp-org:service:WAN(IP|PPP)Connection:1</serviceType>[\s\S]*?<controlURL>([^<]+)</controlURL>)");
        std::smatch m;
        if (!std::regex_search(xml, m, re)) {
            // Показываем доступные serviceType чтобы понять что поддерживает роутер
            static const std::regex reServices(R"(<serviceType>([^<]+)</serviceType>)");
            std::vector<std::string> services;
            for (auto it = std::sregex_iterator(xml.begin(), xml.end(), reServices);
                 it != std::sregex_iterator(); ++it) {
                services.push_back(trim((*it)[1].str()));
            }
            std::string joined;
            for (std::size_t i = 0; i < services.size(); ++i) {
                if (i) joined += ", ";
                joined += services[i];
            }
            log("[2/4 Describe] controlURL не найден.\n"
                "  Нужен: WANIPConnection:1 или WANPPPConnection:1\n"
                "  Найдено в XML (" + std::to_string(services.size()) + " сервисов): " + joined + "\n"
                "  Вероятно, роутер не поддерживает UPnP IGD v1.", true);
            finish(generation, false);
            return;
        }

        // group 1 = "IP" или "PPP", group 2 = controlURL
        const std::string serviceType = "WAN" + m[1].str() + "Connection";
        const std::string ctrl = trim(m[2].str());

        // Строим control URL (если relative path — дополняем хостом/портом из base location)
        ParsedUrl ctrlUrl;
        if (ctrl.rfind("http", 0) == 0) {
            ctrlUrl = parseUrl(ctrl);
        } else {
            ctrlUrl      = url;
            ctrlUrl.path = ctrl.empty() || ctrl.front() == '/' ? ctrl : "/" + ctrl;
        }

        log("[2/4 Describe] Service: " + serviceType + ", Control URL: http://" + ctrlUrl.host + ":" +
            std::to_string(ctrlUrl.port) + ctrlUrl.path);
        addPortMapping(generation, ctrlUrl, serviceType);
    });
}

// ── SOAP: AddPortMapping ──────────────────────────────────────────────────

void UpnpMapper::addPortMapping(int generation, const ParsedUrl& controlUrl,
                                  const std::string& serviceType) {
    if (generation != m_generation) return;

    const std::string body =
        "<NewRemoteHost></NewRemoteHost>"
        "<NewExternalPort>" + std::to_string(m_port) + "</NewExternalPort>"
        "<NewProtocol>TCP</NewProtocol>"
        "<NewInternalPort>" + std::to_string(m_port) + "</NewInternalPort>"
        "<NewInternalClient>" + m_localIp + "</NewInternalClient>"
        "<NewEnabled>1</NewEnabled>"
        "<NewPortMappingDescription>naleystogramm</NewPortMappingDescription>"
        "<NewLeaseDuration>0</NewLeaseDuration>";

    const std::string soap = soapRequest("AddPortMapping", body, serviceType);

    log("[3/4 SOAP] AddPortMapping: порт " + std::to_string(m_port) + " → " + m_localIp + "\n"
        "  Control URL: http://" + controlUrl.host + ":" + std::to_string(controlUrl.port) + controlUrl.path);

    const std::vector<std::pair<std::string, std::string>> headers {
        {"Content-Type", "text/xml; charset=\"utf-8\""},
        {"SOAPAction", "\"urn:schemas-upnp-org:service:" + serviceType + ":1#AddPortMapping\""},
    };

    httpRequest(controlUrl, "POST", soap, headers,
        [this, generation, port = m_port](HttpResponse resp) {
            if (generation != m_generation) return;

            if (resp.ok) {
                log("[3/4 SOAP] AddPortMapping OK (HTTP " + std::to_string(resp.status) + ") — "
                    "порт " + std::to_string(port) + " проброшен успешно", true);
            } else {
                static const std::regex reCode(R"(<errorCode>(\d+)</errorCode>)");
                static const std::regex reDesc(R"(<errorDescription>([^<]+)</errorDescription>)");
                std::smatch mCode, mDesc;
                const std::string upnpCode = std::regex_search(resp.body, mCode, reCode) ? mCode[1].str() : "?";
                const std::string upnpDesc = std::regex_search(resp.body, mDesc, reDesc) ? trim(mDesc[1].str()) : "нет";

                // Расшифровка кодов ошибок IGD (UPnP Forum WANIPConnection:1 spec)
                std::string hint;
                if (upnpCode == "718")
                    hint = "порт уже занят другим приложением (ConflictInMappingEntry)";
                else if (upnpCode == "725")
                    hint = "роутер принимает только постоянные маппинги (OnlyPermanentLeasesSupported) — "
                           "уже используем LeaseDuration=0, возможна несовместимость прошивки";
                else if (upnpCode == "501")
                    hint = "действие не поддерживается роутером (ActionFailed)";
                else if (upnpCode == "606")
                    hint = "доступ запрещён роутером (Unauthorized)";

                log("[3/4 SOAP] AddPortMapping провалился:\n"
                    "  HTTP статус: " + std::to_string(resp.status) + "\n"
                    "  SOAP ошибка: " + upnpCode + " (" + upnpDesc + ")" +
                    (hint.empty() ? "" : "\n  Подсказка: " + hint) + "\n"
                    "  Тело ответа: " + resp.body, true);
            }

            finish(generation, resp.ok);
        });
}

std::string UpnpMapper::soapRequest(const std::string& action, const std::string& body,
                                     const std::string& serviceType) {
    return
        "<?xml version=\"1.0\"?>"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
        "<s:Body>"
        "<u:" + action + " xmlns:u=\"urn:schemas-upnp-org:service:" + serviceType + ":1\">"
        + body +
        "</u:" + action + ">"
        "</s:Body>"
        "</s:Envelope>";
}

// ── URL parsing ────────────────────────────────────────────────────────────

UpnpMapper::ParsedUrl UpnpMapper::parseUrl(const std::string& url) {
    ParsedUrl r;
    std::string rest = url;

    const auto schemePos = rest.find("://");
    if (schemePos != std::string::npos) rest = rest.substr(schemePos + 3);

    const auto slashPos = rest.find('/');
    const std::string hostPort = (slashPos == std::string::npos) ? rest : rest.substr(0, slashPos);
    r.path = (slashPos == std::string::npos) ? "/" : rest.substr(slashPos);

    const auto colonPos = hostPort.find(':');
    if (colonPos != std::string::npos) {
        r.host = hostPort.substr(0, colonPos);
        try { r.port = static_cast<uint16_t>(std::stoi(hostPort.substr(colonPos + 1))); }
        catch (...) { r.port = 80; }
    } else {
        r.host = hostPort;
        r.port = 80;
    }
    return r;
}

// ── HTTP/1.1 minimal client (GET/POST, Connection: close) ─────────────────

void UpnpMapper::httpRequest(const ParsedUrl& url, const std::string& method,
                              const std::string& body,
                              const std::vector<std::pair<std::string, std::string>>& headers,
                              std::function<void(HttpResponse)> cb) {
    auto resolver = std::make_shared<asio::ip::tcp::resolver>(m_io);
    auto sock     = std::make_shared<asio::ip::tcp::socket>(m_io);
    auto timer    = std::make_shared<asio::steady_timer>(m_io);
    auto done     = std::make_shared<bool>(false);
    auto cbPtr    = std::make_shared<std::function<void(HttpResponse)>>(std::move(cb));

    auto finishReq = std::make_shared<std::function<void(HttpResponse)>>();
    *finishReq = [done, timer, sock, cbPtr](HttpResponse r) {
        if (*done) return;
        *done = true;
        timer->cancel();
        std::error_code ec; sock->close(ec);
        (*cbPtr)(std::move(r));
    };

    timer->expires_after(std::chrono::milliseconds(kUpnpTimeoutMs));
    timer->async_wait([done, sock](std::error_code tec) {
        if (tec || *done) return;
        std::error_code cec; sock->cancel(cec);
    });

    std::string requestStr = method + " " + url.path + " HTTP/1.1\r\n" +
        "Host: " + url.host + ":" + std::to_string(url.port) + "\r\n" +
        "Connection: close\r\n";
    if (!body.empty())
        requestStr += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    for (const auto& [k, v] : headers)
        requestStr += k + ": " + v + "\r\n";
    requestStr += "\r\n" + body;

    auto reqBuf = std::make_shared<std::string>(std::move(requestStr));

    resolver->async_resolve(url.host, std::to_string(url.port),
        [this, resolver, sock, timer, done, finishReq, reqBuf]
        (std::error_code ec, const asio::ip::tcp::resolver::results_type& results) {
            if (*done) return;
            if (ec) { (*finishReq)({false, 0, "", "resolve: " + ec.message()}); return; }

            asio::async_connect(*sock, results,
                [this, sock, timer, done, finishReq, reqBuf]
                (std::error_code cec, const asio::ip::tcp::endpoint&) {
                    if (*done) return;
                    if (cec) { (*finishReq)({false, 0, "", "connect: " + cec.message()}); return; }

                    asio::async_write(*sock, asio::buffer(*reqBuf),
                        [this, sock, timer, done, finishReq]
                        (std::error_code wec, std::size_t) {
                            if (*done) return;
                            if (wec) { (*finishReq)({false, 0, "", "write: " + wec.message()}); return; }

                            auto respBuf = std::make_shared<asio::streambuf>();
                            asio::async_read(*sock, *respBuf, asio::transfer_all(),
                                [this, sock, timer, done, finishReq, respBuf]
                                (std::error_code rec, std::size_t) {
                                    if (*done) return;
                                    // EOF (сервер закрыл соединение после ответа) — нормальное завершение.
                                    if (rec && rec != asio::error::eof) {
                                        (*finishReq)({false, 0, "", "read: " + rec.message()});
                                        return;
                                    }

                                    const std::string raw(
                                        asio::buffers_begin(respBuf->data()),
                                        asio::buffers_end(respBuf->data()));

                                    const auto headerEnd = raw.find("\r\n\r\n");
                                    if (headerEnd == std::string::npos) {
                                        (*finishReq)({false, 0, "", "пустой или некорректный HTTP-ответ"});
                                        return;
                                    }

                                    const std::string headerPart = raw.substr(0, headerEnd);
                                    std::string bodyPart = raw.substr(headerEnd + 4);

                                    HttpResponse resp;
                                    const auto firstLineEnd = headerPart.find("\r\n");
                                    const std::string statusLine = headerPart.substr(0, firstLineEnd);
                                    const auto sp1 = statusLine.find(' ');
                                    if (sp1 != std::string::npos) {
                                        const auto sp2 = statusLine.find(' ', sp1 + 1);
                                        const std::string codeStr = statusLine.substr(
                                            sp1 + 1, sp2 == std::string::npos ? std::string::npos : sp2 - sp1 - 1);
                                        try { resp.status = std::stoi(codeStr); } catch (...) { resp.status = 0; }
                                    }

                                    std::string headersLower = headerPart;
                                    std::transform(headersLower.begin(), headersLower.end(),
                                                    headersLower.begin(),
                                                    [](unsigned char c) { return std::tolower(c); });
                                    if (headersLower.find("transfer-encoding: chunked") != std::string::npos)
                                        bodyPart = dechunk(bodyPart);

                                    resp.body = std::move(bodyPart);
                                    if (resp.status >= 200 && resp.status < 300) resp.ok = true;
                                    else resp.error = "HTTP " + std::to_string(resp.status);

                                    (*finishReq)(std::move(resp));
                                });
                        });
                });
        });
}
