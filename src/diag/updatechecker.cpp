#include "naleystogramm-core/diag/updatechecker.h"
#include "naleystogramm-core/storage/sessionmanager.h"
#include <nlohmann/json.hpp>
#include <ctime>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <thread>
#include <string>
#include <string_view>
#include <initializer_list>
#include <algorithm>
#ifdef HAVE_CURL
#  include <curl/curl.h>
#endif

// ── /etc/os-release reader ────────────────────────────────────────────────────

static std::pair<std::string, std::string> detectOsRelease() {
    std::string id, idLike;
    std::ifstream f("/etc/os-release");
    if (!f.is_open()) return {};
    std::string line;
    while (std::getline(f, line)) {
        auto parseField = [&](const char* key) -> std::string {
            const std::string_view prefix{key};
            if (line.rfind(prefix, 0) != 0 || line.size() <= prefix.size() + 1) return {};
            if (line[prefix.size()] != '=') return {};
            std::string v = line.substr(prefix.size() + 1);
            if (!v.empty() && v.front() == '"') v = v.substr(1);
            if (!v.empty() && v.back()  == '"') v.pop_back();
            std::transform(v.begin(), v.end(), v.begin(), ::tolower);
            return v;
        };
        if (const auto v = parseField("ID");      !v.empty()) id     = v;
        if (const auto v = parseField("ID_LIKE"); !v.empty()) idLike = v;
    }
    return {id, idLike};
}

static bool inFamily(const std::string& id, const std::string& idLike,
                     std::initializer_list<std::string_view> list) {
    auto match = [&](std::string_view token) {
        for (auto s : list) if (token == s) return true;
        return false;
    };
    if (match(id)) return true;
    std::istringstream ss(idLike);
    std::string token;
    while (std::getline(ss, token, ' '))
        if (!token.empty() && match(token)) return true;
    return false;
}

// ── Выбор лучшего ассета ──────────────────────────────────────────────────────

static std::pair<std::string, std::string> pickAsset(const nlohmann::json& assets) {
    const auto [id, idLike] = detectOsRelease();

    std::string appUrl, appName, debUrl, debName, rpmUrl, rpmName, pkgUrl, pkgName;

    auto endsWith = [](const std::string& s, const std::string& suffix) {
        return s.size() >= suffix.size() &&
               s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
    };

    for (const auto& a : assets) {
        const auto name = a.value("name", std::string{});
        const auto url  = a.value("browser_download_url", std::string{});
        if      (endsWith(name, ".AppImage"))   { appUrl = url; appName = name; }
        else if (endsWith(name, ".deb"))         { debUrl = url; debName = name; }
        else if (endsWith(name, ".rpm"))         { rpmUrl = url; rpmName = name; }
        else if (endsWith(name, ".pkg.tar.zst")) { pkgUrl = url; pkgName = name; }
    }

    if (inFamily(id, idLike, {
            "arch","artix","manjaro","endeavouros","garuda","cachyos","blackarch",
            "archlabs","archcraft","arcolinux","arcolinuxb","archman","archstrike",
            "bluestar","crystal","ctlos","obarun","rebornos","anarchy","axyl",
            "steamos","holo","parabola","hyperbola","kaos","alci","blendos",
            "xerolinux","athena","instantos","mabox","biglinux","linhes",
            "archbang","alfheim","librewish","peux","pojde","prism","archex",
            "archlinux32","chakra","archphile","archi3","holographos","snal",
            "tarch","archsway","antergos","apricity","archarm","alarm",
            "sirula","parchlinux","subliminal","fenix","m-os","mesk",
            "easy-arch","bridge","chimeraos","holoiso","archlinuxarm"
        }) && !pkgUrl.empty())
        return {pkgUrl, pkgName};

    if (inFamily(id, idLike, {
            "debian","ubuntu","kubuntu","lubuntu","xubuntu","ubuntu-mate","ubuntu-budgie",
            "ubuntukylin","ubuntu-studio","edubuntu","linuxmint","lmde",
            "kali","parrot","blackbox","backbox","tails","elementary","zorin",
            "pop","popos","pop_os","deepin","uos","kylin","neokylin",
            "mx","mxlinux","antix","devuan","pureos","trisquel",
            "raspbian","raspios","raspberry","armbian","dietpi","mobian",
            "sparky","siduction","neptune","bunsenlabs","bodhi","knoppix",
            "nitrux","regolith","q4os","peppermint","lite","linuxlite",
            "neon","kdeneon","endless","astra","astra-linux","whonix",
            "openmediavault","proxmox","pve","grml","kanotix","pinguyos","lxle",
            "voyager","emmabuntus","drauger","linuxfx","makulu","bento",
            "subgraph","hefftor","tuxedo","volumio","turnkey",
            "skolelinux","debian-edu","vinux","nimbleux","storm","libranet",
            "xandros","linex","fluxbuntu","nobara-ubuntu","bazzite-ubuntu",
            "chromeos-flex","cloudready","rpd","pios","pios-lite","risiOS-debian"
        }) && !debUrl.empty())
        return {debUrl, debName};

    if (inFamily(id, idLike, {
            "fedora","rhel","centos","centos-stream",
            "rocky","almalinux","oracle","oraclelinux","scientific","sl",
            "springdale","eurolinux","clearos","cloudlinux",
            "opensuse","opensuse-leap","opensuse-tumbleweed","opensuse-microos",
            "opensuse-kubic","microos","suse","sle","sled","sles","geckolinux",
            "mageia","openmandriva","rosa","pclinuxos","turbolinux","vine",
            "alt","altlinux","alt-server","alt-workstation","alt-education",
            "alt-kworkstation","simply-linux",
            "amzn","amazon","amazonlinux","nobara","ultramarine",
            "bazzite","aurora","bluefin","onyx","sericea","vauxite","lazos",
            "silverblue","kinoite","fedora-silverblue","fedora-kinoite",
            "coreos","fcos","rhcos","fedora-coreos","flatcar","cos",
            "asahi","asahi-linux","qubes","circle","navynix","berry","risios",
            "opencloudos","anolis","openeuler","alinux","tencentos","miraclelinux",
            "pidora","photon","mariner","azurelinux","navy","rosa-fresh"
        }) && !rpmUrl.empty())
        return {rpmUrl, rpmName};

    return {appUrl, appName};
}

// ── Semver ────────────────────────────────────────────────────────────────────
// Схема версий: major.minor.patch[.hotfix]
//   patch=0          — beta/alpha
//   patch=1+         — стабильный релиз
//   hotfix (4-й)     — внеплановая сборка поверх сломанного patch; выше
//                      предыдущего patch, но ниже следующего (x.x.x.y < x.x.x+1)

static std::tuple<int,int,int,int> parseSemver(const std::string& v) {
    std::string s = v;
    if (!s.empty() && (s[0] == 'v' || s[0] == 'V')) s = s.substr(1);
    const auto dash = s.find('-');
    if (dash != std::string::npos) s = s.substr(0, dash);
    int maj = 0, min = 0, pat = 0, hot = 0;
    std::sscanf(s.c_str(), "%d.%d.%d.%d", &maj, &min, &pat, &hot);
    return {maj, min, pat, hot};
}

// ── Timestamp helpers ─────────────────────────────────────────────────────────

static std::string currentIsoTimestamp() {
    const std::time_t t = std::time(nullptr);
    struct tm tm_info {};
#ifdef _WIN32
    localtime_s(&tm_info, &t);
#else
    localtime_r(&t, &tm_info);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_info);
    return std::string(buf);
}

// Parse ISO "YYYY-MM-DDTHH:MM:SS" → time_t (-1 on failure)
static std::time_t parseIsoTimestamp(const std::string& iso) {
    if (iso.empty()) return -1;
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    if (std::sscanf(iso.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &s) < 6) return -1;
    struct tm tm_info {};
    tm_info.tm_year  = y - 1900;
    tm_info.tm_mon   = mo - 1;
    tm_info.tm_mday  = d;
    tm_info.tm_hour  = h;
    tm_info.tm_min   = mi;
    tm_info.tm_sec   = s;
    tm_info.tm_isdst = -1;
    return std::mktime(&tm_info);
}

// ── libcurl write callback ────────────────────────────────────────────────────

#ifdef HAVE_CURL
static size_t curlWrite(void* ptr, size_t size, size_t nmemb, std::string* out) {
    const size_t chunk = size * nmemb;
    // Защита от OOM: безлимитное тело ответа не должно исчерпать память.
    static constexpr size_t kMaxResponse = 8 * 1024 * 1024;
    if (out->size() + chunk > kMaxResponse) return 0;
    out->append(static_cast<char*>(ptr), chunk);
    return chunk;
}
#endif

// ── UpdateChecker ─────────────────────────────────────────────────────────────

UpdateChecker::UpdateChecker() = default;

UpdateChecker::~UpdateChecker() {
    m_alive = false;
}

std::string UpdateChecker::lastChecked() const {
    return SessionManager::instance().lastUpdateCheck();
}

UpdateInfo UpdateChecker::cachedResult() const {
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_cached;
}

void UpdateChecker::checkInBackground() {
    if (!SessionManager::instance().autoCheckUpdates()) return;
    const std::string iso = SessionManager::instance().lastUpdateCheck();
    const std::time_t last = parseIsoTimestamp(iso);
    if (last != -1 && (std::time(nullptr) - last) < 6 * 3600) return;
    doCheck();
}

void UpdateChecker::checkNow() {
    doCheck();
}

// ── Listener management ───────────────────────────────────────────────────────

UpdateChecker::Token UpdateChecker::subscribeUpdateAvailable(
    std::function<void(const UpdateInfo&)> fn) {
    std::lock_guard<std::mutex> lk(m_mutex);
    Token t = m_nextToken++;
    m_onAvailable.emplace_back(t, std::move(fn));
    return t;
}

UpdateChecker::Token UpdateChecker::subscribeNoUpdate(
    std::function<void(const std::string&)> fn) {
    std::lock_guard<std::mutex> lk(m_mutex);
    Token t = m_nextToken++;
    m_onNoUpdate.emplace_back(t, std::move(fn));
    return t;
}

UpdateChecker::Token UpdateChecker::subscribeCheckFailed(
    std::function<void(const std::string&)> fn) {
    std::lock_guard<std::mutex> lk(m_mutex);
    Token t = m_nextToken++;
    m_onFailed.emplace_back(t, std::move(fn));
    return t;
}

UpdateChecker::Token UpdateChecker::subscribeCheckStarted(std::function<void()> fn) {
    std::lock_guard<std::mutex> lk(m_mutex);
    Token t = m_nextToken++;
    m_onStarted.emplace_back(t, std::move(fn));
    return t;
}

void UpdateChecker::unsubscribe(Token t) {
    std::lock_guard<std::mutex> lk(m_mutex);
    auto rm = [t](auto& v) {
        v.erase(std::remove_if(v.begin(), v.end(),
                               [t](const auto& p){ return p.first == t; }), v.end());
    };
    rm(m_onAvailable); rm(m_onNoUpdate); rm(m_onFailed); rm(m_onStarted);
}

void UpdateChecker::notifyAvailable(const UpdateInfo& info) {
    std::vector<std::pair<Token, std::function<void(const UpdateInfo&)>>> snap;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_cached = info;
        snap = m_onAvailable;
    }
    for (auto& [t, fn] : snap) fn(info);
}

void UpdateChecker::notifyNoUpdate(const std::string& ver) {
    std::vector<std::pair<Token, std::function<void(const std::string&)>>> snap;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        snap = m_onNoUpdate;
    }
    for (auto& [t, fn] : snap) fn(ver);
}

void UpdateChecker::notifyFailed(const std::string& err) {
    std::vector<std::pair<Token, std::function<void(const std::string&)>>> snap;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        snap = m_onFailed;
    }
    for (auto& [t, fn] : snap) fn(err);
}

void UpdateChecker::notifyStarted() {
    std::vector<std::pair<Token, std::function<void()>>> snap;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        snap = m_onStarted;
    }
    for (auto& [t, fn] : snap) fn();
}

// ── doCheck ───────────────────────────────────────────────────────────────────

void UpdateChecker::doCheck() {
    notifyStarted();

#ifndef HAVE_CURL
    notifyFailed("libcurl не найден при сборке");
    return;
#else
    std::thread([this]() {
        const std::string url = std::string("https://api.github.com/repos/")
                                + kGitHubOwner + "/" + kGitHubRepo + "/releases/latest";

        std::string body;
        CURLcode rc = CURLE_FAILED_INIT;

        CURL* curl = curl_easy_init();
        if (curl) {
            const std::string ua = std::string("naleystogramm/") + kCurrentVersion;
            struct curl_slist* hdrs = nullptr;
            hdrs = curl_slist_append(hdrs, ("User-Agent: " + ua).c_str());
            hdrs = curl_slist_append(hdrs, "Accept: application/vnd.github+json");

            curl_easy_setopt(curl, CURLOPT_URL,           url.c_str());
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    hdrs);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curlWrite);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &body);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT,       8L);
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

            rc = curl_easy_perform(curl);
            curl_slist_free_all(hdrs);
            curl_easy_cleanup(curl);
        }

        if (!m_alive) return;

        if (rc != CURLE_OK) {
            notifyFailed(std::string(curl_easy_strerror(rc)));
            return;
        }

        // Сохраняем время проверки (лёгкая гонка с SessionManager — приемлема)
        SessionManager::instance().setLastUpdateCheck(currentIsoTimestamp());

        const auto doc = nlohmann::json::parse(body, nullptr, false);
        if (doc.is_discarded() || !doc.is_object()) {
            notifyFailed("Неверный ответ от GitHub API");
            return;
        }

        const std::string tagName = doc.value("tag_name", std::string{});
        const std::string htmlUrl = doc.value("html_url",  std::string{});
        std::string       body_s  = doc.value("body",      std::string{});

        if (tagName.empty()) {
            notifyFailed("Релизы не найдены");
            return;
        }

        // Обрезаем notes до ~280 UTF-8 байт
        if (body_s.size() > 280) {
            body_s.resize(280);
            body_s += "…";  // '…'
        }

        const auto [dlUrl, dlName] = pickAsset(doc.value("assets", nlohmann::json::array()));

        const bool newer = isNewerVersion(tagName, kCurrentVersion);
        UpdateInfo info{
            .version     = tagName,
            .url         = htmlUrl,
            .notes       = body_s,
            .downloadUrl = dlUrl,
            .assetName   = dlName,
            .available   = newer,
        };

        if (!m_alive) return;

        if (newer) notifyAvailable(info);
        else       notifyNoUpdate(std::string(kCurrentVersion));

    }).detach();
#endif
}

bool UpdateChecker::isNewerVersion(const std::string& remote, const std::string& local) {
    const auto [rMaj, rMin, rPat, rHot] = parseSemver(remote);
    const auto [lMaj, lMin, lPat, lHot] = parseSemver(local);
    if (rMaj != lMaj) return rMaj > lMaj;
    if (rMin != lMin) return rMin > lMin;
    if (rPat != lPat) return rPat > lPat;
    return rHot > lHot;
}
