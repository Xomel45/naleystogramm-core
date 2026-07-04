#pragma once
#include <string>
#include <cstdint>
#include <nlohmann/json.hpp>

// ── LinkedDevice ──────────────────────────────────────────────────────────────
struct LinkedDevice {
    std::string uuid;
    std::string name;
    bool        isPrimary{false};
    int64_t     linkedAt{0};  // Unix timestamp ms

    [[nodiscard]] nlohmann::json toJson() const;
    static LinkedDevice fromJson(const nlohmann::json& obj);
};

// ── DevicePairing ─────────────────────────────────────────────────────────────
class DevicePairing {
public:
    static constexpr int kCodeLength  = 6;
    static constexpr int kCodeTtlSecs = 60;

    [[nodiscard]] static std::string generateCode();
    [[nodiscard]] static std::string currentCode();
    [[nodiscard]] static int64_t     codeExpiry();  // Unix timestamp ms (0 = no code)
    [[nodiscard]] static bool        validateAndConsume(const std::string& code);
    static void clearCode();

    [[nodiscard]] static nlohmann::json makePairRequest(
        const std::string& ownUuid, const std::string& ownName, const std::string& code);
    [[nodiscard]] static nlohmann::json makePairAccept(
        const std::string& ownUuid, const std::string& ownName);
    [[nodiscard]] static nlohmann::json makePairReject(const std::string& reason);

private:
    static std::string s_code;
    static int64_t     s_expiry;  // Unix ms (0 = no active code)
};
