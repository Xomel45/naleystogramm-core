#include "naleystogramm-core/identity/device_pairing.h"
#include <chrono>
#include <cstdio>
#include <openssl/rand.h>

std::string DevicePairing::s_code;
int64_t     DevicePairing::s_expiry{0};

// ── LinkedDevice ──────────────────────────────────────────────────────────────

nlohmann::json LinkedDevice::toJson() const {
    return {
        {"uuid",      uuid},
        {"name",      name},
        {"isPrimary", isPrimary},
        {"linkedAt",  linkedAt},
    };
}

LinkedDevice LinkedDevice::fromJson(const nlohmann::json& obj) {
    LinkedDevice d;
    d.uuid      = obj.value("uuid",      std::string{});
    d.name      = obj.value("name",      std::string{});
    d.isPrimary = obj.value("isPrimary", false);
    d.linkedAt  = obj.value("linkedAt",  int64_t{0});
    return d;
}

// ── DevicePairing ─────────────────────────────────────────────────────────────

static int64_t nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

std::string DevicePairing::generateCode() {
    // Rejection sampling: draw 4 random bytes, reduce mod 1 000 000.
    // Bias < 295 / 4 294 967 296 ≈ 7e-8 — negligible for a 6-digit OTP.
    uint32_t val = 0;
    do {
        RAND_bytes(reinterpret_cast<unsigned char*>(&val), 4);
    } while (val >= 4000000000u);  // reject top ~6.7% to stay bias-free
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%06u", val % 1000000u);
    s_code   = buf;
    s_expiry = nowMs() + static_cast<int64_t>(kCodeTtlSecs) * 1000LL;
    return s_code;
}

std::string DevicePairing::currentCode() {
    if (s_code.empty()) return {};
    if (nowMs() > s_expiry) { clearCode(); return {}; }
    return s_code;
}

int64_t DevicePairing::codeExpiry() {
    return s_expiry;
}

bool DevicePairing::validateAndConsume(const std::string& code) {
    if (s_code.empty()) return false;
    if (nowMs() > s_expiry) { clearCode(); return false; }

    // Константное по времени сравнение — не даём измерять совпадение по префиксу.
    if (code.size() != s_code.size()) return false;
    unsigned diff = 0;
    for (size_t i = 0; i < s_code.size(); ++i)
        diff |= static_cast<unsigned>(code[i] ^ s_code[i]);
    if (diff != 0) return false;

    clearCode();
    return true;
}

void DevicePairing::clearCode() {
    s_code.clear();
    s_expiry = 0;
}

nlohmann::json DevicePairing::makePairRequest(
    const std::string& ownUuid, const std::string& ownName, const std::string& code)
{
    return {{"type", "DEVICE_PAIR_REQUEST"}, {"uuid", ownUuid}, {"name", ownName}, {"code", code}};
}

nlohmann::json DevicePairing::makePairAccept(
    const std::string& ownUuid, const std::string& ownName)
{
    return {{"type", "DEVICE_PAIR_ACCEPT"}, {"uuid", ownUuid}, {"name", ownName}};
}

nlohmann::json DevicePairing::makePairReject(const std::string& reason) {
    return {{"type", "DEVICE_PAIR_REJECT"}, {"reason", reason}};
}
