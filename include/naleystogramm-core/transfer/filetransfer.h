#pragma once
#include "naleystogramm-crypto/bytes.h"
#include "naleystogramm-crypto/openssl_raii.h"
#include "naleystogramm-core/types.h"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

class NetworkManager;
class E2EManager;

// ── Состояние передачи ───────────────────────────────────────────────────────
enum class TransferState {
    Pending,       // Ожидание подтверждения
    Active,        // Идёт передача
    Paused,        // Приостановлено
    Completed,     // Завершено успешно
    Failed,        // Ошибка
    Cancelled      // Отменено пользователем
};

// ── Информация для возобновления передачи ────────────────────────────────────
// Сериализуется в JSON и сохраняется на диск при разрыве соединения
struct TransferResumeInfo {
    std::string id;                  // ID передачи
    std::string peerUuid;            // UUID пира
    std::string fileName;            // Имя файла
    std::string tempFilePath;        // Путь к временному файлу
    int64_t     totalSize{0};        // Полный размер файла
    int64_t     lastConfirmedChunk{0}; // Последний подтверждённый чанк
    Bytes       key;                 // Ключ шифрования (32 байта для AES-256)
    Bytes       nonce;               // Базовый nonce (12 байт для GCM)
    bool        outgoing{false};     // true = отправка, false = получение
};

// ── Исходящая передача (стриминг) ────────────────────────────────────────────
struct OutgoingTransfer {
    std::string  id;               // Уникальный ID передачи
    std::string  peerUuid;         // UUID получателя
    std::string  filePath;         // Путь к исходному файлу
    std::string  fileName;         // Имя файла для получателя
    int64_t      fileSize{0};      // Размер файла в байтах
    Bytes        fileHash;         // SHA-256 хеш всего файла
    Bytes        key;              // Ключ AES-256-GCM (32 байта)
    Bytes        nonce;            // Базовый nonce (12 байт)
    int64_t      bytesSent{0};     // Отправлено байт
    int64_t      chunksSent{0};    // Отправлено чанков
    std::unique_ptr<std::ifstream> file; // Открытый файл для стриминга
    std::chrono::steady_clock::time_point startTime; // Для вычисления скорости
    TransferState state{TransferState::Pending};   // Текущее состояние
    int64_t      lastSpeedCalcBytes{0}; // Байты при последнем расчёте скорости
    int64_t      lastSpeedCalcTime{0};  // Время последнего расчёта (мс)
    double       currentSpeed{0.0};     // Текущая скорость (байт/сек)
    int          durationMs{0};         // Длительность голосового (0 = обычный файл)
};

// ── Входящая передача (стриминг) ─────────────────────────────────────────────
struct IncomingTransfer {
    std::string  id;               // Уникальный ID передачи
    std::string  peerUuid;         // UUID отправителя
    std::string  fileName;         // Имя файла
    std::string  tempFilePath;     // Путь к временному файлу
    std::string  finalFilePath;    // Путь к финальному файлу
    int64_t      fileSize{0};      // Ожидаемый размер файла
    Bytes        expectedHash;     // Ожидаемый SHA-256 хеш
    Bytes        key;              // Ключ AES-256-GCM (32 байта)
    Bytes        nonce;            // Базовый nonce (12 байт)
    int64_t      bytesReceived{0}; // Получено байт
    int64_t      chunksReceived{0}; // Получено чанков
    std::unique_ptr<std::ofstream> file; // Открытый временный файл
    EvpMdCtxPtr  hasher;           // SHA-256 хешер для проверки целостности
    std::chrono::steady_clock::time_point startTime; // Для вычисления скорости
    TransferState state{TransferState::Pending};   // Текущее состояние
    int64_t      lastSpeedCalcBytes{0}; // Байты при последнем расчёте скорости
    int64_t      lastSpeedCalcTime{0};  // Время последнего расчёта (мс)
    double       currentSpeed{0.0};     // Текущая скорость (байт/сек)
    int          durationMs{0};         // Длительность голосового (0 = обычный файл)
};

// ── FileTransferEvent (callbacks вместо Qt-сигналов) ─────────────────────────
// Вызываются на потоке io_context (NetworkManager::ioContext()) или
// непосредственно из вызвавшего потока — подписчик из UI должен
// перепоставить на Qt-поток через QMetaObject::invokeMethod(..., Qt::QueuedConnection).
struct FileTransferEvent {
    // Входящее предложение файла. durationMs > 0 = голосовое сообщение
    // → принимать автоматически без диалога.
    std::function<void(const std::string& from, const std::string& name,
                        int64_t size, const std::string& offerId, int durationMs)> onFileOffer;
    std::function<void(const TransferProgress&)> onTransferStarted;
    std::function<void(const TransferProgress&)> onTransferProgress;
    std::function<void(const std::string& id, const std::string& filePath, bool outgoing)> onTransferCompleted;
    std::function<void(const std::string& id, const std::string& error)> onTransferFailed;
    std::function<void(const std::string& id)> onTransferCancelled;
    // Файл получен (для совместимости со старым кодом)
    std::function<void(const std::string& from, const std::string& path, const std::string& name)> onFileReceived;
};

// ── FileTransfer ─────────────────────────────────────────────────────────────
// Потоковая передача файлов с AES-256-GCM шифрованием и проверкой хеша.
//
// Протокол:
//   FILE_OFFER    → получатель показывает диалог принятия
//   FILE_ACCEPT   → отправитель начинает стриминг FILE_CHUNK
//   FILE_REJECT   → отправитель удаляет передачу
//   FILE_CHUNK    → зашифрованный чанк с auth tag + nonce
//   FILE_COMPLETE → передача завершена, проверка хеша
//   FILE_CANCEL   → отмена передачи (в любую сторону)
//   FILE_PAUSE    → приостановка передачи
//   FILE_RESUME_REQUEST → запрос на возобновление (от получателя)
//   FILE_RESUME_ACK     → подтверждение возобновления (от отправителя)
//
class FileTransfer {
public:
    FileTransfer(NetworkManager* network, E2EManager* e2e, std::filesystem::path dataDir);
    ~FileTransfer();

    // Отправка файла пиру (стриминг).
    // durationMs > 0 = голосовое сообщение: поле duration_ms добавляется в FILE_OFFER,
    // получатель принимает автоматически без диалога.
    void sendFile(const std::string& peerUuid, const std::string& filePath, int durationMs = 0);

    // Обработка входящих сообщений протокола
    void handleMessage(const std::string& from, const nlohmann::json& msg);

    // Получить текущий прогресс передачи
    [[nodiscard]] TransferProgress getProgress(const std::string& transferId) const;

    // Проверить наличие незавершённых передач для пира
    [[nodiscard]] bool hasPendingTransfers(const std::string& peerUuid) const;

    // Принять предложение файла
    void acceptOffer(const std::string& from, const std::string& offerId);

    // Отклонить предложение файла
    void rejectOffer(const std::string& from, const std::string& offerId);

    // Отменить активную передачу
    void cancelTransfer(const std::string& transferId);

    // Приостановить передачу
    void pauseTransfer(const std::string& transferId);

    // Возобновить передачу
    void resumeTransfer(const std::string& transferId);

    // ── Listener API ─────────────────────────────────────────────────────────
    using Token = uint32_t;
    Token addListener   (FileTransferEvent ev);
    void  removeListener(Token t);

private:
    // ── Методы стриминга отправки ────────────────────────────────────────────

    // Вычислить SHA-256 хеш файла (запускается в отдельном потоке)
    static Bytes computeFileHashStatic(const std::string& filePath);

    // Отправить FILE_OFFER после вычисления хеша. Вызывается с захваченным m_mutex.
    void sendFileOffer(const std::string& offerId);

    // Начать стриминг (вызывается после FILE_ACCEPT). Вызывается с захваченным m_mutex.
    void startStreaming(const std::string& offerId);

    // Отправить следующий чанк (продолжение через asio::post). Вызывается с захваченным m_mutex.
    void sendNextChunk(const std::string& offerId);

    // Зашифровать чанк с AES-256-GCM
    Bytes encryptChunk(const Bytes& plaintext, const Bytes& key, const Bytes& nonce,
                        int64_t chunkSeq, Bytes& authTagOut);

    // ── Методы стриминга получения ───────────────────────────────────────────

    // Обработать входящий чанк. Вызывается с захваченным m_mutex.
    void handleFileChunk(const std::string& from, const nlohmann::json& msg);

    // Расшифровать чанк с AES-256-GCM
    Bytes decryptChunk(const Bytes& ciphertext, const Bytes& authTag, const Bytes& key,
                        const Bytes& nonce, int64_t chunkSeq);

    // Завершить приём файла (проверка хеша, переименование). Вызывается с захваченным m_mutex.
    void finishReceiving(const std::string& offerId);

    // ── Методы паузы/возобновления ───────────────────────────────────────────

    // Сохранить состояние передачи на диск
    void saveTransferState(const TransferResumeInfo& info);

    // Загрузить состояние передачи с диска
    bool loadTransferState(const std::string& transferId, TransferResumeInfo& info);

    // Удалить сохранённое состояние
    void removeTransferState(const std::string& transferId);

    // Обработать запрос на возобновление. Вызывается с захваченным m_mutex.
    void handleResumeRequest(const std::string& from, const nlohmann::json& msg);

    // ── Утилиты ──────────────────────────────────────────────────────────────

    // Валидация идентификатора передачи (защита от path traversal через id)
    static bool isValidTransferId(const std::string& id);

    // Санитизация имени файла (защита от path traversal)
    std::string sanitizeFileName(const std::string& name);

    // Безопасный путь для сохранения
    std::string safeDownloadPath(const std::string& fileName);

    // Путь к временному файлу
    std::string tempFilePath(const std::string& transferId);

    // Путь к директории состояния передач
    std::filesystem::path transferStateDir();

    // Обновить и отправить прогресс
    void emitProgress(OutgoingTransfer& t);
    void emitProgress(IncomingTransfer& t);

    // Вычислить текущую скорость передачи
    double calculateSpeed(int64_t currentBytes, int64_t& lastBytes, int64_t& lastTimeMs,
                           std::chrono::steady_clock::time_point startTime);

    // Helper: уведомить всех подписчиков (не должен держать m_listenerMutex)
    template<typename Fn>
    void fire(Fn&& invoke) const {
        std::vector<std::pair<Token, FileTransferEvent>> snap;
        {
            std::lock_guard<std::mutex> lk(m_listenerMutex);
            snap = m_listeners;
        }
        for (auto& [tok, ev] : snap)
            invoke(ev);
    }

    // ── Данные ───────────────────────────────────────────────────────────────

    NetworkManager* m_net{nullptr};
    E2EManager*     m_e2e{nullptr};
    std::filesystem::path m_dataDir;

    // Защищает m_outgoing/m_incoming: публичные методы вызываются с Qt-потока,
    // продолжения streaming/хеширования — через asio::post на io-потоке.
    // Recursive — внутренние методы вызывают друг друга с уже захваченным мьютексом.
    mutable std::recursive_mutex m_mutex;
    std::unordered_map<std::string, OutgoingTransfer> m_outgoing;  // Исходящие передачи
    std::unordered_map<std::string, IncomingTransfer> m_incoming;  // Входящие передачи

    // Флаг уничтожения объекта — проверяется в колбэках из фонового потока
    // хеширования и продолжениях asio::post после возможного удаления FileTransfer.
    std::shared_ptr<std::atomic<bool>> m_destroyed;

    mutable std::mutex m_listenerMutex;
    std::vector<std::pair<Token, FileTransferEvent>> m_listeners;
    Token m_nextToken{0};

    // Константы
    static constexpr int64_t kChunkSize          = 65536;      // 64 KB чанк
    static constexpr int     kGcmTagSize         = 16;         // 16 байт для GCM auth tag
    static constexpr int     kGcmNonceSize       = 12;         // 12 байт для GCM nonce
    static constexpr int     kAesKeySize         = 32;         // 32 байта для AES-256
    static constexpr int64_t kSpeedCalcInterval  = 500;        // Интервал расчёта скорости (мс)
};
