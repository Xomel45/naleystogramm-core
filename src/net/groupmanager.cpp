#include "naleystogramm-core/net/groupmanager.h"
#include "naleystogramm-core/storage/storage.h"
#include "naleystogramm-crypto/x3dh.h"
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <thread>

#if defined(_WIN32)
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <sys/time.h>
#endif

namespace {

constexpr int kMaxReconnAttempts = 10;
constexpr int kReconnBaseMs = 2000;

int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

std::string toWs(const std::string& url) {
    if (url.rfind("https://", 0) == 0) return "wss://" + url.substr(8);
    if (url.rfind("http://", 0) == 0)  return "ws://"  + url.substr(7);
    return url;
}

void interruptibleSleep(std::atomic<bool>& stop, int ms) {
    while (ms > 0 && !stop.load()) {
        const int chunk = std::min(ms, 100);
        std::this_thread::sleep_for(std::chrono::milliseconds(chunk));
        ms -= chunk;
    }
}

void setRecvTimeout(curl_socket_t sock, int ms) {
#if defined(_WIN32)
    DWORD timeout = static_cast<DWORD>(ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

size_t curlWrite(void* ptr, size_t size, size_t nmemb, std::string* out) {
    const size_t chunk = size * nmemb;
    // Защита от OOM: безлимитное тело ответа не должно исчерпать память.
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
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &outBody);

    struct curl_slist* hdrs = nullptr;
    if (method == "POST") hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    for (const auto& [k, v] : extraHeaders) hdrs = curl_slist_append(hdrs, (k + ": " + v).c_str());
    if (hdrs) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

    if (method == "POST") {
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

} // namespace

// ── Conn ──────────────────────────────────────────────────────────────────────

struct GroupManager::Conn {
    Group info;
    std::thread wsThread;
    std::atomic<bool> stopRequested{false};
    std::atomic<bool> connected{false};
    std::mutex curlMutex;   // защищает curl + send/recv от гонки между потоками
    CURL* curl{nullptr};
    int reconnAttempts{0};
};

GroupManager::GroupManager(StorageManager* storage) : m_storage(storage) {}

GroupManager::~GroupManager() {
    std::vector<Conn*> conns;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        for (auto& [id, c] : m_conns) {
            c->stopRequested = true;
            conns.push_back(c.get());
        }
    }
    for (auto* c : conns) {
        if (c->wsThread.joinable()) c->wsThread.join();
    }
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

std::string GroupManager::encryptGroupMsg(const Bytes& key, const std::string& text) {
    if (key.size() != 32) return {};
    const Bytes plain = sv2bytes(text);

    Bytes nonce(12);
    RAND_bytes(nonce.data(), 12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};
    Bytes ct(plain.size());
    Bytes tag(16);
    int len = 0;

    bool ok = true;
    ok = ok && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) > 0;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) > 0;
    ok = ok && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) > 0;
    ok = ok && EVP_EncryptUpdate(ctx, ct.data(), &len, plain.data(),
                                  static_cast<int>(plain.size())) > 0;
    int fin = 0;
    ok = ok && EVP_EncryptFinal_ex(ctx, ct.data() + len, &fin) > 0;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) > 0;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return {};
    ct.resize(static_cast<size_t>(len + fin));

    // Формат: nonce(12) + ciphertext + tag(16)
    return bytesToBase64(nonce + ct + tag);
}

std::string GroupManager::decryptGroupMsg(const Bytes& key, const std::string& base64) {
    if (key.size() != 32) return {};
    const Bytes blob = bytesFromBase64(base64);
    if (blob.size() < 12 + 16) return {};

    const Bytes nonce = bytesLeft(blob, 12);
    const Bytes tag   = bytesRight(blob, 16);
    const Bytes ct    = bytesMid(blob, 12, blob.size() - 12 - 16);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};
    Bytes plain(ct.size());
    int len = 0, fin = 0;
    bool ok = true;

    ok = ok && EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) > 0;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) > 0;
    ok = ok && EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) > 0;
    ok = ok && EVP_DecryptUpdate(ctx, plain.data(), &len, ct.data(),
                                  static_cast<int>(ct.size())) > 0;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                    const_cast<uint8_t*>(tag.data())) > 0;
    ok = ok && EVP_DecryptFinal_ex(ctx, plain.data() + len, &fin) > 0;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        fprintf(stderr, "[GroupManager] decryptGroupMsg: GCM auth failed\n");
        return {};
    }
    plain.resize(static_cast<size_t>(len + fin));
    return std::string(plain.begin(), plain.end());
}

// ── Join ──────────────────────────────────────────────────────────────────────

void GroupManager::joinGroup(const std::string& serverUrl, const std::string& username) {
    Bytes privKey, pubKey;
    if (!X3DH::generateX25519(privKey, pubKey)) {
        fire([&](GroupEvent& ev) { if (ev.onJoinError) ev.onJoinError(serverUrl, "keygen failed"); });
        return;
    }

    std::thread([this, serverUrl, username, privKey, pubKey]() {
        const nlohmann::json joinBody{
            {"username", username},
            {"pubkey", bytesToBase64(pubKey)}
        };

        std::string respBody;
        long httpCode = 0;
        if (!httpRequest("POST", serverUrl + "/group/join", joinBody.dump(), {}, respBody, httpCode)
            || httpCode / 100 != 2) {
            fire([&](GroupEvent& ev) {
                if (ev.onJoinError) ev.onJoinError(serverUrl, "join request failed (HTTP " + std::to_string(httpCode) + ")");
            });
            return;
        }

        const auto obj = nlohmann::json::parse(respBody, nullptr, false);
        if (obj.is_discarded()) {
            fire([&](GroupEvent& ev) { if (ev.onJoinError) ev.onJoinError(serverUrl, "invalid join response"); });
            return;
        }
        const std::string token     = obj.value("token", "");
        const std::string keyEncB64 = obj.value("group_key_enc", "");
        const std::string role      = obj.value("role", "member");

        const Bytes groupKey = X3DH::eciesDecrypt(privKey, bytesFromBase64(keyEncB64));
        if (groupKey.size() != 32) {
            fprintf(stderr, "[GroupManager] ECIES decrypt failed for group_key_enc\n");
            fire([&](GroupEvent& ev) { if (ev.onJoinError) ev.onJoinError(serverUrl, "key decryption failed"); });
            return;
        }

        std::string infoBody;
        long infoCode = 0;
        httpRequest("GET", serverUrl + "/info", "", {}, infoBody, infoCode);
        const auto info = nlohmann::json::parse(infoBody, nullptr, false);

        Group g;
        g.id        = serverUrl;
        g.name      = (!info.is_discarded()) ? info.value("name", serverUrl) : serverUrl;
        g.type      = (!info.is_discarded() && info.value("broadcast_only", false))
                           ? GroupType::Channel : GroupType::Group;
        g.serverUrl = serverUrl;
        g.username  = username;
        g.token     = token;
        g.groupKey     = groupKey;
        g.localPrivKey = privKey;
        g.localPubKey  = pubKey;
        g.isAdmin   = (role == "owner" || role == "admin");
        g.joinedAt  = nowMs();

        if (!m_storage->saveGroup(g)) {
            fprintf(stderr, "[GroupManager] saveGroup failed for %s\n", serverUrl.c_str());
        }

        fire([&](GroupEvent& ev) { if (ev.onGroupJoined) ev.onGroupJoined(g); });
        connectGroup(g);
    }).detach();
}

// ── Leave ─────────────────────────────────────────────────────────────────────

void GroupManager::leaveGroup(const std::string& groupId) {
    Conn* conn = nullptr;
    Group g;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        auto it = m_conns.find(groupId);
        if (it == m_conns.end()) return;
        conn = it->second.get();
        g = conn->info;
        conn->stopRequested = true;
    }
    if (conn->wsThread.joinable()) conn->wsThread.join();
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_conns.erase(groupId);
    }

    std::thread([url = g.serverUrl, token = g.token]() {
        std::string body;
        long code = 0;
        httpRequest("DELETE", url + "/group/leave", "", {{"Authorization", "Bearer " + token}}, body, code);
    }).detach();

    if (!m_storage->deleteGroup(groupId)) {
        fprintf(stderr, "[GroupManager] deleteGroup failed for %s\n", groupId.c_str());
    }
    fire([&](GroupEvent& ev) { if (ev.onGroupLeft) ev.onGroupLeft(groupId); });
}

// ── Connect WS ───────────────────────────────────────────────────────────────

void GroupManager::connectGroup(const Group& g) {
    Conn* conn = nullptr;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        auto it = m_conns.find(g.id);
        if (it != m_conns.end()) {
            it->second->info = g;
            return;
        }
        auto c = std::make_unique<Conn>();
        c->info = g;
        conn = c.get();
        m_conns.emplace(g.id, std::move(c));
    }
    conn->wsThread = std::thread(&GroupManager::wsThreadFunc, this, g.id, conn);
}

void GroupManager::wsThreadFunc(const std::string& groupId, Conn* conn) {
    for (;;) {
        if (conn->stopRequested.load()) return;

        CURL* curl = curl_easy_init();
        if (curl) {
            const std::string wsUrl = toWs(conn->info.serverUrl) + "/group/ws?token=" + conn->info.token;
            curl_easy_setopt(curl, CURLOPT_URL, wsUrl.c_str());
            curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
        }

        if (!curl || curl_easy_perform(curl) != CURLE_OK) {
            if (curl) curl_easy_cleanup(curl);
            if (conn->stopRequested.load()) return;
            if (++conn->reconnAttempts > kMaxReconnAttempts) {
                fprintf(stderr, "[GroupManager] превышено число попыток реконнекта для %s\n", groupId.c_str());
                return;
            }
            interruptibleSleep(conn->stopRequested, kReconnBaseMs << std::min(conn->reconnAttempts, 5));
            continue;
        }

        curl_socket_t sock = CURL_SOCKET_BAD;
        curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sock);
        if (sock != CURL_SOCKET_BAD) setRecvTimeout(sock, 200);

        {
            std::lock_guard<std::mutex> lk(conn->curlMutex);
            conn->curl = curl;
        }
        conn->reconnAttempts = 0;
        conn->connected = true;
        fire([&](GroupEvent& ev) { if (ev.onWsConnected) ev.onWsConnected(groupId); });

        std::string msgBuf;
        std::vector<char> buf(8192);
        while (!conn->stopRequested.load()) {
            const curl_ws_frame* meta = nullptr;
            size_t nread = 0;
            CURLcode res;
            {
                std::lock_guard<std::mutex> lk(conn->curlMutex);
                res = curl_ws_recv(curl, buf.data(), buf.size(), &nread, &meta);
            }
            if (res == CURLE_AGAIN) continue;
            if (res != CURLE_OK) break;
            if (meta && (meta->flags & CURLWS_CLOSE)) break;
            msgBuf.append(buf.data(), nread);
            if (meta && meta->bytesleft == 0) {
                if (meta->flags & CURLWS_TEXT) handleWsFrame(groupId, msgBuf);
                msgBuf.clear();
            }
        }

        {
            std::lock_guard<std::mutex> lk(conn->curlMutex);
            conn->curl = nullptr;
        }
        conn->connected = false;
        curl_easy_cleanup(curl);
        fire([&](GroupEvent& ev) { if (ev.onWsDisconnected) ev.onWsDisconnected(groupId); });

        if (conn->stopRequested.load()) return;
        if (++conn->reconnAttempts > kMaxReconnAttempts) {
            fprintf(stderr, "[GroupManager] превышено число попыток реконнекта для %s\n", groupId.c_str());
            return;
        }
        interruptibleSleep(conn->stopRequested, kReconnBaseMs << std::min(conn->reconnAttempts, 5));
    }
}

// ── WS message handler ────────────────────────────────────────────────────────

void GroupManager::handleWsFrame(const std::string& groupId, const std::string& raw) {
    const auto obj = nlohmann::json::parse(raw, nullptr, false);
    if (obj.is_discarded()) return;
    const std::string type = obj.value("type", "");

    Bytes key;
    std::string username;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        auto it = m_conns.find(groupId);
        if (it == m_conns.end()) return;
        key = it->second->info.groupKey;
        username = it->second->info.username;
    }

    if (type == "history") {
        std::vector<GroupMessage> hist;
        for (const auto& mv : obj.value("messages", nlohmann::json::array())) {
            const std::string decrypted = decryptGroupMsg(key, mv.value("data", ""));
            if (decrypted.empty()) continue;
            const std::string sender = mv.value("sender", "");
            GroupMessage gm;
            gm.groupId  = groupId;
            gm.sender   = sender;
            gm.text     = decrypted;
            gm.ts       = mv.value("ts", int64_t{0});
            gm.outgoing = (sender == username);
            (void)m_storage->saveGroupMessage(gm);
            hist.push_back(gm);
        }
        fire([&](GroupEvent& ev) { if (ev.onHistoryLoaded) ev.onHistoryLoaded(groupId, hist); });

    } else if (type == "msg") {
        const std::string sender = obj.value("sender", "");
        const std::string decrypted = decryptGroupMsg(key, obj.value("data", ""));
        if (decrypted.empty()) return;

        GroupMessage gm;
        gm.groupId  = groupId;
        gm.sender   = sender;
        gm.text     = decrypted;
        gm.ts       = obj.value("ts", nowMs());
        gm.outgoing = (sender == username);
        (void)m_storage->saveGroupMessage(gm);
        fire([&](GroupEvent& ev) { if (ev.onMessageReceived) ev.onMessageReceived(gm); });

    } else if (type == "join") {
        const std::string user = obj.value("username", "");
        const std::string role = obj.value("role", "member");
        fire([&](GroupEvent& ev) { if (ev.onMemberJoined) ev.onMemberJoined(groupId, user, role); });

    } else if (type == "leave") {
        const std::string user = obj.value("username", "");
        fire([&](GroupEvent& ev) { if (ev.onMemberLeft) ev.onMemberLeft(groupId, user); });
    }
}

// ── Send ──────────────────────────────────────────────────────────────────────

bool GroupManager::sendMessage(const std::string& groupId, const std::string& text) {
    Conn* conn = nullptr;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        auto it = m_conns.find(groupId);
        if (it == m_conns.end() || !it->second->connected.load()) return false;
        conn = it->second.get();
    }

    const std::string encrypted = encryptGroupMsg(conn->info.groupKey, text);
    if (encrypted.empty()) return false;

    const nlohmann::json frame{{"type", "msg"}, {"data", encrypted}};
    const std::string payload = frame.dump();

    std::lock_guard<std::mutex> lk(conn->curlMutex);
    if (!conn->curl) return false;
    size_t sent = 0;
    return curl_ws_send(conn->curl, payload.data(), payload.size(), &sent, 0, CURLWS_TEXT) == CURLE_OK;
}

// ── Load saved groups ─────────────────────────────────────────────────────────

void GroupManager::loadSavedGroups() {
    const auto saved = m_storage->allGroups();
    for (const Group& g : saved) {
        if (g.token.empty() || g.groupKey.size() != 32) continue;
        connectGroup(g);
        fprintf(stderr, "[GroupManager] Загружена группа %s\n", g.name.c_str());
    }
}

std::vector<Group> GroupManager::groups() const {
    std::lock_guard<std::mutex> lk(m_mutex);
    std::vector<Group> list;
    list.reserve(m_conns.size());
    for (const auto& [id, c] : m_conns) list.push_back(c->info);
    return list;
}

Group GroupManager::groupById(const std::string& id) const {
    std::lock_guard<std::mutex> lk(m_mutex);
    auto it = m_conns.find(id);
    return it != m_conns.end() ? it->second->info : Group{};
}

// ── Listeners ─────────────────────────────────────────────────────────────────

GroupManager::Token GroupManager::addListener(GroupEvent ev) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    const Token t = m_nextToken++;
    m_listeners.emplace_back(t, std::move(ev));
    return t;
}

void GroupManager::removeListener(Token t) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    m_listeners.erase(
        std::remove_if(m_listeners.begin(), m_listeners.end(),
                       [t](const auto& p) { return p.first == t; }),
        m_listeners.end());
}
