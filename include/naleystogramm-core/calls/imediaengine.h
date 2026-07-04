#pragma once
#include "naleystogramm-crypto/bytes.h"
#include <cstdint>
#include <functional>
#include <string>

// ── IMediaEngine ─────────────────────────────────────────────────────────────
// Граница CallManager↔MediaEngine, полностью на std/Bytes — без единого Qt-типа.
// Desktop подставляет QtMediaEngineAdapter (src/media/), оборачивающий
// Qt-реализацию MediaEngine; будущий Android JNI-мост (v0.9.0) подставит
// свою реализацию поверх нативного аудио-стека.
class IMediaEngine {
public:
    virtual ~IMediaEngine() = default;

    // peerIp/peerUdpPort — куда отправлять пакеты; mediaKey — 32 байта
    // AES-256-GCM ключа (из E2EManager::snapshotMediaKey). true при успехе.
    virtual bool startCall(const std::string& peerIp, uint16_t peerUdpPort,
                            const Bytes& mediaKey) = 0;
    virtual void endCall() = 0;

    [[nodiscard]] virtual bool     isInCall() const = 0;
    [[nodiscard]] virtual uint16_t localUdpPort() const = 0;

    // Включить UDP-ретрансляцию (режим ClientServer) — вызывается до startCall().
    virtual void enableUdpRelay(const std::string& relayIp, uint16_t relayUdpPort,
                                 const std::string& myUuid,
                                 const std::string& peerUuid) = 0;

    virtual void setErrorCallback(std::function<void(const std::string&)> cb) = 0;
};
