#include "naleystogramm-core/net/discoveryclient.h"
#include <algorithm>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include <thread>

namespace {

size_t curlWrite(void* ptr, size_t size, size_t nmemb, std::string* out) {
    const size_t chunk = size * nmemb;
    // Защита от OOM: сервер (или MITM по plain HTTP) не должен забивать память
    // безлимитным телом. Возврат значения ≠ chunk прерывает передачу.
    static constexpr size_t kMaxResponse = 8 * 1024 * 1024;
    if (out->size() + chunk > kMaxResponse) return 0;
    out->append(static_cast<char*>(ptr), chunk);
    return chunk;
}

// Блокирующий HTTP-запрос (вызывать только из отдельного потока).
bool httpRequest(const std::string& method, const std::string& url, const std::string& body,
                  const std::vector<std::pair<std::string, std::string>>& extraHeaders,
                  std::string& outBody, long& outCode) {
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &outBody);

    struct curl_slist* hdrs = nullptr;
    if (method == "POST" || method == "PUT") hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    for (const auto& [k, v] : extraHeaders) hdrs = curl_slist_append(hdrs, (k + ": " + v).c_str());
    if (hdrs) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    } else if (method == "PUT") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    } else if (method == "DELETE") {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    }

    const CURLcode rc = curl_easy_perform(curl);
    if (hdrs) curl_slist_free_all(hdrs);
    if (rc != CURLE_OK) {
        curl_easy_cleanup(curl);
        return false;
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &outCode);
    curl_easy_cleanup(curl);
    return true;
}

// Достаёт поле "error" из JSON-ответа сервера ({"error": "...", "detail": "..."}),
// иначе — общее сообщение по HTTP-коду.
std::string extractError(const std::string& body, long code) {
    const auto obj = nlohmann::json::parse(body, nullptr, false);
    if (!obj.is_discarded() && obj.contains("error") && obj["error"].is_string())
        return obj["error"].get<std::string>();
    return "server error (HTTP " + std::to_string(code) + ")";
}

} // namespace

DiscoveryClient::Token DiscoveryClient::addListener(DiscoveryEvent ev) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    const Token t = m_nextToken++;
    m_listeners.emplace_back(t, std::move(ev));
    return t;
}

void DiscoveryClient::removeListener(Token t) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    m_listeners.erase(
        std::remove_if(m_listeners.begin(), m_listeners.end(),
                        [t](const auto& p) { return p.first == t; }),
        m_listeners.end());
}

void DiscoveryClient::lookup(const std::string& host, uint16_t discoveryPort, const std::string& username) {
    std::thread([this, host, discoveryPort, username]() {
        const std::string url =
            "http://" + host + ":" + std::to_string(discoveryPort) + "/lookup/" + username;

        std::string body;
        long code = 0;
        if (!httpRequest("GET", url, "", {}, body, code)) {
            fire([&](DiscoveryEvent& ev) {
                if (ev.onLookupError) ev.onLookupError(host, username, "request_failed");
            });
            return;
        }
        if (code == 404) {
            fire([&](DiscoveryEvent& ev) {
                if (ev.onLookupError) ev.onLookupError(host, username, "user_not_found");
            });
            return;
        }
        if (code / 100 != 2) {
            fire([&](DiscoveryEvent& ev) {
                if (ev.onLookupError) ev.onLookupError(host, username, extractError(body, code));
            });
            return;
        }

        const auto obj = nlohmann::json::parse(body, nullptr, false);
        if (obj.is_discarded()) {
            fire([&](DiscoveryEvent& ev) {
                if (ev.onLookupError) ev.onLookupError(host, username, "invalid response");
            });
            return;
        }

        LookupResult r;
        r.username = obj.value("username", username);
        r.uuid     = obj.value("uuid", "");
        r.pubkey   = obj.value("pubkey", "");
        r.ip       = obj.value("ip", "");
        r.port     = static_cast<uint16_t>(obj.value("port", 0));

        if (r.uuid.empty() || r.ip.empty() || r.port == 0) {
            fire([&](DiscoveryEvent& ev) {
                if (ev.onLookupError) ev.onLookupError(host, username, "server did not return uuid/ip/port");
            });
            return;
        }

        fire([&](DiscoveryEvent& ev) { if (ev.onLookupSuccess) ev.onLookupSuccess(r); });
    }).detach();
}

void DiscoveryClient::registerAccount(const std::string& host, uint16_t discoveryPort,
                                       const std::string& username, const std::string& uuid,
                                       const std::string& pubkeyBase64, const std::string& ip,
                                       uint16_t advertisedPort, const std::string& email,
                                       const std::string& inviteCode, const std::string& clientVersion) {
    std::thread([this, host, discoveryPort, username, uuid, pubkeyBase64, ip, advertisedPort,
                 email, inviteCode, clientVersion]() {
        const std::string url = "http://" + host + ":" + std::to_string(discoveryPort) + "/register";

        nlohmann::json req{
            {"username", username},
            {"uuid",     uuid},
            {"pubkey",   pubkeyBase64},
            {"ip",       ip},
            {"port",     advertisedPort},
        };
        if (!email.empty())         req["email"]          = email;
        if (!inviteCode.empty())    req["invite_code"]    = inviteCode;
        if (!clientVersion.empty()) req["client_version"]  = clientVersion;

        std::string body;
        long code = 0;
        if (!httpRequest("POST", url, req.dump(), {}, body, code)) {
            fire([&](DiscoveryEvent& ev) {
                if (ev.onRegisterError) ev.onRegisterError(host, username, "request_failed");
            });
            return;
        }
        if (code != 201) {
            const std::string err = extractError(body, code);
            fire([&](DiscoveryEvent& ev) {
                if (ev.onRegisterError) ev.onRegisterError(host, username, err);
            });
            return;
        }

        const auto obj = nlohmann::json::parse(body, nullptr, false);
        if (obj.is_discarded() || !obj.contains("token")) {
            fire([&](DiscoveryEvent& ev) {
                if (ev.onRegisterError) ev.onRegisterError(host, username, "invalid response");
            });
            return;
        }

        RegisterResult r;
        r.host     = host;
        r.port     = discoveryPort;
        r.username = obj.value("username", username);
        r.token    = obj.value("token", "");

        fire([&](DiscoveryEvent& ev) { if (ev.onRegisterSuccess) ev.onRegisterSuccess(r); });
    }).detach();
}

void DiscoveryClient::updatePresence(const std::string& host, uint16_t discoveryPort, const std::string& token,
                                      const std::string& ip, uint16_t advertisedPort) {
    std::thread([this, host, discoveryPort, token, ip, advertisedPort]() {
        const std::string url = "http://" + host + ":" + std::to_string(discoveryPort) + "/update";
        const nlohmann::json req{{"ip", ip}, {"port", advertisedPort}};

        std::string body;
        long code = 0;
        const bool ok = httpRequest("PUT", url, req.dump(), {{"Authorization", "Bearer " + token}}, body, code);
        if (!ok || code / 100 != 2) {
            const std::string err = ok ? extractError(body, code) : "request_failed";
            fire([&](DiscoveryEvent& ev) {
                if (ev.onUpdateError) ev.onUpdateError(host, err);
            });
            return;
        }
        fire([&](DiscoveryEvent& ev) { if (ev.onUpdateOk) ev.onUpdateOk(host); });
    }).detach();
}

void DiscoveryClient::heartbeat(const std::string& host, uint16_t discoveryPort, const std::string& token) {
    std::thread([this, host, discoveryPort, token]() {
        const std::string url = "http://" + host + ":" + std::to_string(discoveryPort) + "/heartbeat";

        std::string body;
        long code = 0;
        const bool ok = httpRequest("POST", url, "", {{"Authorization", "Bearer " + token}}, body, code);
        if (!ok || code / 100 != 2) {
            const std::string err = ok ? extractError(body, code) : "request_failed";
            fire([&](DiscoveryEvent& ev) {
                if (ev.onHeartbeatError) ev.onHeartbeatError(host, err);
            });
            return;
        }
        fire([&](DiscoveryEvent& ev) { if (ev.onHeartbeatOk) ev.onHeartbeatOk(host); });
    }).detach();
}

void DiscoveryClient::unregisterAccount(const std::string& host, uint16_t discoveryPort, const std::string& token) {
    std::thread([this, host, discoveryPort, token]() {
        const std::string url = "http://" + host + ":" + std::to_string(discoveryPort) + "/unregister";

        std::string body;
        long code = 0;
        const bool ok = httpRequest("DELETE", url, "", {{"Authorization", "Bearer " + token}}, body, code);
        if (!ok || code / 100 != 2) {
            const std::string err = ok ? extractError(body, code) : "request_failed";
            fire([&](DiscoveryEvent& ev) {
                if (ev.onUnregisterError) ev.onUnregisterError(host, err);
            });
            return;
        }
        fire([&](DiscoveryEvent& ev) { if (ev.onUnregisterSuccess) ev.onUnregisterSuccess(host); });
    }).detach();
}
