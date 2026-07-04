#include "naleystogramm-core/transfer/filetransfer.h"
#include "naleystogramm-core/diag/logger.h"
#include "naleystogramm-core/net/network.h"
#include "naleystogramm-crypto/e2e.h"
#include "naleystogramm-crypto/keyprotector.h"

#include <algorithm>
#include <asio.hpp>
#include <cstdio>
#include <cstdlib>
#include <openssl/rand.h>
#include <random>
#include <sstream>
#include <thread>

// ── UUID v4 (как в callmanager.cpp/network.cpp — независимая копия) ──────────
static std::string generateUuid() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;
    uint64_t hi = dist(gen);
    uint64_t lo = dist(gen);
    hi = (hi & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;  // version 4
    lo = (lo & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;  // variant 10xx
    char buf[37];
    std::snprintf(buf, sizeof(buf),
        "%08x-%04x-%04x-%04x-%012llx",
        static_cast<uint32_t>(hi >> 32),
        static_cast<uint16_t>(hi >> 16),
        static_cast<uint16_t>(hi),
        static_cast<uint16_t>(lo >> 48),
        static_cast<unsigned long long>(lo & 0x0000FFFFFFFFFFFFULL));
    return std::string(buf);
}

// ── Каталог загрузок (заменяет QStandardPaths::DownloadLocation) ─────────────
static std::filesystem::path downloadsDir() {
#ifdef _WIN32
    const char* userProfile = std::getenv("USERPROFILE");
    return std::filesystem::path(userProfile ? userProfile : "C:\\") / "Downloads";
#else
    const char* home = std::getenv("HOME");
    const std::string homeStr = home ? home : "";

    // Парсим ~/.config/user-dirs.dirs: XDG_DOWNLOAD_DIR="$HOME/Загрузки"
    const std::filesystem::path configFile =
        std::filesystem::path(homeStr) / ".config" / "user-dirs.dirs";
    std::ifstream f(configFile);
    if (f.is_open()) {
        std::string line;
        while (std::getline(f, line)) {
            const auto pos = line.find("XDG_DOWNLOAD_DIR=");
            if (pos == std::string::npos) continue;

            const auto start = line.find('"', pos);
            const auto end = (start == std::string::npos) ? std::string::npos
                                                            : line.find('"', start + 1);
            if (start == std::string::npos || end == std::string::npos) continue;

            std::string value = line.substr(start + 1, end - start - 1);
            constexpr std::string_view kHomePlaceholder = "$HOME";
            const auto hp = value.find(kHomePlaceholder);
            if (hp != std::string::npos)
                value.replace(hp, kHomePlaceholder.size(), homeStr);

            if (!value.empty()) return std::filesystem::path(value);
        }
    }
    return std::filesystem::path(homeStr) / "Downloads";
#endif
}

// ── Конструктор/деструктор ───────────────────────────────────────────────────

FileTransfer::FileTransfer(NetworkManager* network, E2EManager* e2e, std::filesystem::path dataDir)
    : m_net(network)
    , m_e2e(e2e)
    , m_dataDir(std::move(dataDir))
    , m_destroyed(std::make_shared<std::atomic<bool>>(false))
{
    LOG_INFO(FileTransfer, "FileTransfer initialized");
}

FileTransfer::~FileTransfer() {
    *m_destroyed = true;

    std::lock_guard<std::recursive_mutex> lk(m_mutex);
    for (auto& [id, t] : m_outgoing) {
        if (t.file) t.file->close();
    }
    for (auto& [id, t] : m_incoming) {
        if (t.file) t.file->close();
    }
}

// ── Отправка файла ───────────────────────────────────────────────────────────

void FileTransfer::sendFile(const std::string& peerUuid, const std::string& filePath, int durationMs) {
    std::error_code ec;
    if (!std::filesystem::exists(filePath, ec)) {
        LOG_ERROR(FileTransfer, "File Not Found");
        return;
    }

    const std::string offerId = generateUuid();

    LOG_INFO(FileTransfer, "Preparing File Offer");

    OutgoingTransfer t;
    t.id         = offerId;
    t.peerUuid   = peerUuid;
    t.filePath   = filePath;
    t.fileName   = std::filesystem::path(filePath).filename().string();
    t.fileSize   = static_cast<int64_t>(std::filesystem::file_size(filePath, ec));
    t.bytesSent  = 0;
    t.chunksSent = 0;
    t.state      = TransferState::Pending;
    t.lastSpeedCalcBytes = 0;
    t.lastSpeedCalcTime  = 0;
    t.currentSpeed       = 0.0;
    t.durationMs         = durationMs;

    // Генерируем ключ AES-256 (32 байта) и nonce (12 байт для GCM)
    t.key.resize(kAesKeySize);
    t.nonce.resize(kGcmNonceSize);
    RAND_bytes(t.key.data(), kAesKeySize);
    RAND_bytes(t.nonce.data(), kGcmNonceSize);

    {
        std::lock_guard<std::recursive_mutex> lk(m_mutex);
        m_outgoing[offerId] = std::move(t);
    }

    // Вычисляем SHA-256 в фоновом потоке — не блокируем вызывающий поток на 150–600мс
    auto destroyed = m_destroyed;
    std::thread([this, filePath, offerId, destroyed]() {
        Bytes hash = computeFileHashStatic(filePath);
        asio::post(m_net->ioContext(), [this, offerId, hash = std::move(hash), destroyed]() {
            if (*destroyed) return;
            std::lock_guard<std::recursive_mutex> lk(m_mutex);

            auto it = m_outgoing.find(offerId);
            if (it == m_outgoing.end()) return;  // передача отменена пока считался хеш

            if (hash.empty()) {
                LOG_ERROR(FileTransfer, "File Hash Error");
                const std::string err = "Ошибка вычисления хеша файла";
                fire([&](FileTransferEvent& ev) { if (ev.onTransferFailed) ev.onTransferFailed(offerId, err); });
                m_outgoing.erase(it);
                return;
            }

            it->second.fileHash = hash;
            sendFileOffer(offerId);
        });
    }).detach();
}

// ── Вычисление хеша файла (запускается в отдельном потоке) ───────────────────

Bytes FileTransfer::computeFileHashStatic(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        LOG_ERROR(FileTransfer, "Cannot Open File For Hashing");
        return {};
    }

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
        LOG_ERROR(FileTransfer, "Cannot Init Hash Context");
        return {};
    }

    // Читаем файл чанками для экономии памяти
    constexpr std::streamsize hashChunkSize = 1024 * 1024;  // 1 MB
    std::vector<char> buf(static_cast<size_t>(hashChunkSize));
    while (file) {
        file.read(buf.data(), hashChunkSize);
        const std::streamsize n = file.gcount();
        if (n > 0)
            EVP_DigestUpdate(ctx.get(), buf.data(), static_cast<size_t>(n));
    }

    Bytes result(EVP_MAX_MD_SIZE);
    unsigned int outLen = 0;
    EVP_DigestFinal_ex(ctx.get(), result.data(), &outLen);
    result.resize(outLen);
    return result;
}

// ── Формирование и отправка FILE_OFFER ───────────────────────────────────────
// Вызывается из колбэка асинхронного вычисления хеша. m_mutex уже захвачен.

void FileTransfer::sendFileOffer(const std::string& offerId) {
    auto it = m_outgoing.find(offerId);
    if (it == m_outgoing.end()) return;
    auto& t = it->second;

    // Формируем FILE_OFFER сообщение
    nlohmann::json offer;
    offer["type"] = "FILE_OFFER";
    offer["id"]   = offerId;
    offer["name"] = t.fileName;
    offer["size"] = t.fileSize;
    offer["hash"] = bytesToHex(t.fileHash);
    // Поле duration_ms > 0 сигнализирует получателю что это голосовое сообщение
    if (t.durationMs > 0)
        offer["duration_ms"] = t.durationMs;

    // Шифруем ключ + nonce через E2E сессию.
    // Без активной сессии отправка НЕВОЗМОЖНА: ключ файла не должен идти по сети в открытом виде.
    // Передача завершается с ошибкой — пользователь должен дождаться установки E2E-сессии.
    if (!m_e2e || !m_e2e->hasSession(t.peerUuid)) {
        LOG_ERROR(FileTransfer, "Offer Failed (No Active Session)");
        const std::string err = "Нет E2E-сессии — ключ файла нельзя передать безопасно";
        fire([&](FileTransferEvent& ev) { if (ev.onTransferFailed) ev.onTransferFailed(offerId, err); });
        m_outgoing.erase(it);
        return;
    }

    const Bytes keyMaterial = t.key + t.nonce;  // 32 + 12 = 44 байта
    offer["enc_key_env"] = m_e2e->encrypt(t.peerUuid, keyMaterial);
    LOG_DEBUG(FileTransfer, "Ключ файла зашифрован через E2E-сессию");

    m_net->sendFrame(t.peerUuid, offer);
    LOG_INFO(FileTransfer, "File Offer Sent");
}

// ── Стриминг отправки ────────────────────────────────────────────────────────
// Вызывается из handleMessage (FILE_ACCEPT). m_mutex уже захвачен.

void FileTransfer::startStreaming(const std::string& offerId) {
    auto it = m_outgoing.find(offerId);
    if (it == m_outgoing.end()) {
        LOG_WARNING(FileTransfer, "Unknown Offer");
        return;
    }
    auto& t = it->second;

    // Открываем файл для стриминга
    t.file = std::make_unique<std::ifstream>(t.filePath, std::ios::binary);
    if (!t.file->is_open()) {
        LOG_ERROR(FileTransfer, "File Open Failed");
        const std::string err = "Cannot open file";
        fire([&](FileTransferEvent& ev) { if (ev.onTransferFailed) ev.onTransferFailed(offerId, err); });
        m_outgoing.erase(it);
        return;
    }

    t.state = TransferState::Active;
    t.startTime = std::chrono::steady_clock::now();
    t.lastSpeedCalcTime  = 0;
    t.lastSpeedCalcBytes = 0;

    LOG_INFO(FileTransfer, "Streaming Started");

    // Эмитим начало передачи
    TransferProgress progress;
    progress.id               = offerId;
    progress.fileName         = t.fileName;
    progress.bytesTransferred = 0;
    progress.totalBytes       = t.fileSize;
    progress.speedBytesPerSec = 0;
    progress.etaSeconds       = 0;
    progress.percent          = 0;
    progress.outgoing         = true;
    fire([&](FileTransferEvent& ev) { if (ev.onTransferStarted) ev.onTransferStarted(progress); });

    // Отправляем первый чанк
    sendNextChunk(offerId);
}

void FileTransfer::sendNextChunk(const std::string& offerId) {
    auto it = m_outgoing.find(offerId);
    if (it == m_outgoing.end()) return;
    auto& t = it->second;

    // Проверяем состояние (пауза/отмена)
    if (t.state == TransferState::Paused || t.state == TransferState::Cancelled) {
        return;
    }

    if (!t.file || t.bytesSent >= t.fileSize) {
        // Все данные отправлены — отправляем FILE_COMPLETE
        LOG_INFO(FileTransfer, "Streaming Completed");

        nlohmann::json complete;
        complete["type"]    = "FILE_COMPLETE";
        complete["id"]      = offerId;
        complete["hash"]    = bytesToHex(t.fileHash);
        complete["success"] = true;
        m_net->sendFrame(t.peerUuid, complete);

        t.state = TransferState::Completed;
        const std::string filePath = t.filePath;
        fire([&](FileTransferEvent& ev) { if (ev.onTransferCompleted) ev.onTransferCompleted(offerId, filePath, true); });

        // Очищаем ресурсы
        if (t.file) t.file->close();
        removeTransferState(offerId);
        m_outgoing.erase(it);
        return;
    }

    // Читаем следующий чанк
    std::vector<char> buf(static_cast<size_t>(kChunkSize));
    t.file->read(buf.data(), kChunkSize);
    const std::streamsize n = t.file->gcount();
    if (n <= 0) {
        LOG_WARNING(FileTransfer, "Empty Chunk");
        return;
    }
    const Bytes plainChunk(buf.begin(), buf.begin() + n);

    // Шифруем чанк с AES-256-GCM
    Bytes authTag;
    const Bytes encryptedChunk = encryptChunk(plainChunk, t.key, t.nonce, t.chunksSent, authTag);

    if (encryptedChunk.empty()) {
        LOG_ERROR(FileTransfer, "Chunk Encryption Failed");
        const std::string err = "Encryption failed";
        fire([&](FileTransferEvent& ev) { if (ev.onTransferFailed) ev.onTransferFailed(offerId, err); });
        // Закрываем и освобождаем файл, иначе дескриптор зависнет до конца сессии
        if (t.file) { t.file->close(); t.file.reset(); }
        m_outgoing.erase(it);
        return;
    }

    // Обновляем статистику
    t.bytesSent += static_cast<int64_t>(plainChunk.size());
    const bool isLast = t.bytesSent >= t.fileSize;

    // Формируем сообщение FILE_CHUNK
    nlohmann::json chunk;
    chunk["type"] = "FILE_CHUNK";
    chunk["id"]   = offerId;
    chunk["seq"]  = t.chunksSent;
    chunk["data"] = bytesToBase64(encryptedChunk);
    chunk["tag"]  = bytesToBase64(authTag);
    chunk["last"] = isLast;

    m_net->sendFrame(t.peerUuid, chunk);

    t.chunksSent++;

    // Эмитим прогресс
    emitProgress(t);

    // Планируем отправку следующего чанка асинхронно (не блокируем вызывающий поток)
    auto destroyed = m_destroyed;
    asio::post(m_net->ioContext(), [this, offerId, destroyed]() {
        if (*destroyed) return;
        std::lock_guard<std::recursive_mutex> lk(m_mutex);
        sendNextChunk(offerId);
    });
}

// ── AES-256-GCM шифрование ───────────────────────────────────────────────────

Bytes FileTransfer::encryptChunk(const Bytes& plaintext, const Bytes& key, const Bytes& baseNonce,
                                  int64_t chunkSeq, Bytes& authTagOut) {
    // Формируем уникальный nonce для этого чанка: baseNonce XOR chunkSeq
    Bytes nonce = baseNonce;
    for (int i = 0; i < 8 && i < static_cast<int>(nonce.size()); ++i) {
        nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>((chunkSeq >> (i * 8)) & 0xFF);
    }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        LOG_ERROR(FileTransfer, "Failed to create EVP_CIPHER_CTX");
        return {};
    }

    // Инициализируем AES-256-GCM
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return {};

    // Устанавливаем длину nonce (12 байт для GCM)
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kGcmNonceSize, nullptr) != 1)
        return {};

    // Устанавливаем ключ и nonce
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        return {};

    // Шифруем данные
    Bytes ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;
    int totalLen = 0;

    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &outLen,
                           plaintext.data(), static_cast<int>(plaintext.size())) != 1)
        return {};
    totalLen = outLen;

    // Финализируем
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + totalLen, &outLen) != 1)
        return {};
    totalLen += outLen;
    ciphertext.resize(static_cast<size_t>(totalLen));

    // Получаем auth tag (16 байт)
    authTagOut.resize(kGcmTagSize);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kGcmTagSize, authTagOut.data()) != 1)
        return {};

    return ciphertext;
}

// ── AES-256-GCM расшифровка ──────────────────────────────────────────────────

Bytes FileTransfer::decryptChunk(const Bytes& ciphertext, const Bytes& authTag, const Bytes& key,
                                  const Bytes& baseNonce, int64_t chunkSeq) {
    // Формируем тот же nonce что при шифровании
    Bytes nonce = baseNonce;
    for (int i = 0; i < 8 && i < static_cast<int>(nonce.size()); ++i) {
        nonce[nonce.size() - 1 - i] ^= static_cast<uint8_t>((chunkSeq >> (i * 8)) & 0xFF);
    }

    EvpCipherCtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        LOG_ERROR(FileTransfer, "Failed to create EVP_CIPHER_CTX for decryption");
        return {};
    }

    // Инициализируем AES-256-GCM
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        return {};

    // Устанавливаем длину nonce
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kGcmNonceSize, nullptr) != 1)
        return {};

    // Устанавливаем ключ и nonce
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        return {};

    // Расшифровываем данные
    Bytes plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
    int outLen = 0;
    int totalLen = 0;

    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &outLen,
                           ciphertext.data(), static_cast<int>(ciphertext.size())) != 1)
        return {};
    totalLen = outLen;

    // Устанавливаем auth tag для проверки
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, kGcmTagSize,
                             const_cast<uint8_t*>(authTag.data())) != 1)
        return {};

    // Финализируем и проверяем auth tag
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + totalLen, &outLen) != 1) {
        LOG_ERROR(FileTransfer, "GCM auth tag verification failed — data tampered!");
        return {};  // Auth tag не совпал — данные повреждены/подменены
    }
    totalLen += outLen;
    plaintext.resize(static_cast<size_t>(totalLen));

    return plaintext;
}

// ── Обработка входящих сообщений ─────────────────────────────────────────────

void FileTransfer::handleMessage(const std::string& from, const nlohmann::json& msg) {
    const std::string type = msg.value("type", std::string());
    const std::string id   = msg.value("id", std::string());

    // Защита от path traversal: id приходит от пира и попадает в пути ФС
    // (tempFilePath, saveTransferState). Отвергаем любой некорректный id.
    if (!isValidTransferId(id)) {
        LOG_WARNING(FileTransfer, "Rejected frame with invalid transfer id");
        return;
    }

    std::lock_guard<std::recursive_mutex> lk(m_mutex);

    if (type == "FILE_OFFER") {
        // Получили предложение файла
        IncomingTransfer t;
        t.id            = id;
        t.peerUuid      = from;
        t.fileName      = sanitizeFileName(msg.value("name", std::string()));
        t.fileSize      = msg.value("size", static_cast<int64_t>(0));

        // Отрицательный размер — некорректный оффер (и ломает проверку объёма
        // при приёме чанков, где сравниваем bytesReceived с fileSize).
        if (t.fileSize < 0) {
            LOG_WARNING(FileTransfer, "Rejected file offer with negative size");
            return;
        }
        t.expectedHash  = bytesFromHex(msg.value("hash", std::string()));
        t.bytesReceived = 0;
        t.chunksReceived = 0;
        t.state         = TransferState::Pending;
        t.lastSpeedCalcBytes = 0;
        t.lastSpeedCalcTime  = 0;
        t.currentSpeed       = 0.0;
        // Читаем длительность голосового сообщения (0 если не голосовое)
        t.durationMs         = msg.value("duration_ms", 0);

        // Расшифровываем ключ
        if (msg.contains("enc_key_env") && m_e2e && m_e2e->hasSession(from)) {
            const auto keyMaterial = m_e2e->decrypt(from, msg["enc_key_env"]);
            if (keyMaterial.has_value() &&
                keyMaterial->size() >= static_cast<size_t>(kAesKeySize + kGcmNonceSize)) {
                t.key   = bytesLeft(*keyMaterial, static_cast<size_t>(kAesKeySize));
                t.nonce = bytesMid(*keyMaterial, static_cast<size_t>(kAesKeySize),
                                    static_cast<size_t>(kGcmNonceSize));
                LOG_DEBUG(FileTransfer, "File key decrypted via E2E session");
            } else {
                LOG_ERROR(FileTransfer, "Failed to decrypt file key via E2E");
                return;
            }
        } else {
            // Fallback: открытый ключ
            t.key   = bytesFromHex(msg.value("enc_key", std::string()));
            t.nonce = bytesFromHex(msg.value("enc_nonce", std::string()));
            LOG_WARNING(FileTransfer, "Received file key unencrypted");
        }

        // Определяем пути
        t.tempFilePath  = tempFilePath(id);
        t.finalFilePath = safeDownloadPath(t.fileName);

        const std::string fileName = t.fileName;
        const int64_t     fileSize = t.fileSize;
        const int         durMs    = t.durationMs;

        m_incoming[id] = std::move(t);

        LOG_INFO(FileTransfer, "File Offer Received");

        fire([&](FileTransferEvent& ev) {
            if (ev.onFileOffer) ev.onFileOffer(from, fileName, fileSize, id, durMs);
        });

    } else if (type == "FILE_ACCEPT") {
        // Получатель принял — начинаем стриминг
        LOG_INFO(FileTransfer, "File Accept Received");
        startStreaming(id);

    } else if (type == "FILE_REJECT") {
        // Получатель отклонил
        LOG_INFO(FileTransfer, "File Reject Received");
        auto it = m_outgoing.find(id);
        if (it != m_outgoing.end()) {
            if (it->second.file) it->second.file->close();
            m_outgoing.erase(it);
        }

    } else if (type == "FILE_CHUNK") {
        handleFileChunk(from, msg);

    } else if (type == "FILE_COMPLETE") {
        // Отправитель сообщает о завершении (дублирующая проверка)
        LOG_DEBUG(FileTransfer, "File Complete Received");

    } else if (type == "FILE_CANCEL") {
        // Отмена передачи
        LOG_INFO(FileTransfer, "File Cancel Received");
        if (auto it = m_outgoing.find(id); it != m_outgoing.end()) {
            it->second.state = TransferState::Cancelled;
            if (it->second.file) it->second.file->close();
            fire([&](FileTransferEvent& ev) { if (ev.onTransferCancelled) ev.onTransferCancelled(id); });
            m_outgoing.erase(it);
        }
        if (auto it = m_incoming.find(id); it != m_incoming.end()) {
            it->second.state = TransferState::Cancelled;
            if (it->second.file) {
                it->second.file->close();
                std::error_code ec;
                std::filesystem::remove(it->second.tempFilePath, ec);
            }
            fire([&](FileTransferEvent& ev) { if (ev.onTransferCancelled) ev.onTransferCancelled(id); });
            m_incoming.erase(it);
        }
        removeTransferState(id);

    } else if (type == "FILE_PAUSE") {
        // Приостановка передачи
        LOG_INFO(FileTransfer, "File Pause Received");
        if (auto it = m_outgoing.find(id); it != m_outgoing.end()) {
            it->second.state = TransferState::Paused;
        }

    } else if (type == "FILE_RESUME_REQUEST") {
        handleResumeRequest(from, msg);

    } else if (type == "FILE_RESUME_ACK") {
        // Отправитель подтвердил возобновление
        const int64_t resumeFrom = msg.value("resume_from", static_cast<int64_t>(0));
        LOG_INFO(FileTransfer, "File Resume ACK Received");
        if (auto it = m_incoming.find(id); it != m_incoming.end()) {
            it->second.state = TransferState::Active;
            it->second.chunksReceived = resumeFrom;
        }
    }
}

// ── Обработка входящего чанка ────────────────────────────────────────────────
// Вызывается из handleMessage. m_mutex уже захвачен.

void FileTransfer::handleFileChunk(const std::string& /*from*/, const nlohmann::json& msg) {
    const std::string id  = msg.value("id", std::string());
    const int64_t     seq = msg.value("seq", static_cast<int64_t>(0));

    auto it = m_incoming.find(id);
    if (it == m_incoming.end()) {
        LOG_WARNING(FileTransfer, "Unknown Transfer");
        return;
    }
    auto& t = it->second;

    // Проверяем состояние
    if (t.state == TransferState::Paused || t.state == TransferState::Cancelled) {
        return;
    }

    // Проверяем последовательность
    if (seq != t.chunksReceived) {
        LOG_WARNING(FileTransfer, "Chunk Sequence Mismatch");
        // Можно запросить повтор или отменить передачу
        return;
    }

    // Открываем файл при первом чанке
    if (!t.file) {
        t.file = std::make_unique<std::ofstream>(t.tempFilePath, std::ios::binary | std::ios::trunc);
        if (!t.file->is_open()) {
            LOG_ERROR(FileTransfer, "Temp File Creation Failed");
            const std::string err = "Cannot create temp file";
            fire([&](FileTransferEvent& ev) { if (ev.onTransferFailed) ev.onTransferFailed(id, err); });
            t.file.reset();
            m_incoming.erase(it);
            return;
        }

        t.hasher.reset(EVP_MD_CTX_new());
        EVP_DigestInit_ex(t.hasher.get(), EVP_sha256(), nullptr);
        t.startTime = std::chrono::steady_clock::now();
        t.state = TransferState::Active;

        // Эмитим начало передачи
        TransferProgress progress;
        progress.id               = id;
        progress.fileName         = t.fileName;
        progress.bytesTransferred = 0;
        progress.totalBytes       = t.fileSize;
        progress.speedBytesPerSec = 0;
        progress.etaSeconds       = 0;
        progress.percent          = 0;
        progress.outgoing         = false;
        fire([&](FileTransferEvent& ev) { if (ev.onTransferStarted) ev.onTransferStarted(progress); });
    }

    // Расшифровываем чанк
    const Bytes ciphertext = bytesFromBase64(msg.value("data", std::string()));
    const Bytes authTag    = bytesFromBase64(msg.value("tag", std::string()));

    const Bytes plaintext = decryptChunk(ciphertext, authTag, t.key, t.nonce, seq);

    if (plaintext.empty()) {
        LOG_ERROR(FileTransfer, "Chunk Decryption Failed");
        const std::string err = "Decryption failed — data corrupted";
        fire([&](FileTransferEvent& ev) { if (ev.onTransferFailed) ev.onTransferFailed(id, err); });

        // Очищаем ресурсы
        t.file->close();
        std::error_code ec;
        std::filesystem::remove(t.tempFilePath, ec);
        m_incoming.erase(it);
        return;
    }

    // Защита от переполнения диска: завершение управляется флагом "last" от
    // отправителя, поэтому без сверки с заявленным размером пир может слать
    // чанки бесконечно и переполнить диск жертвы. Обрываем, если суммарный
    // объём превысил объявленный fileSize.
    if (t.bytesReceived + static_cast<int64_t>(plaintext.size()) > t.fileSize) {
        LOG_ERROR(FileTransfer, "Received data exceeds announced file size — aborting");
        const std::string err = "Transfer exceeded announced size";
        fire([&](FileTransferEvent& ev) { if (ev.onTransferFailed) ev.onTransferFailed(id, err); });
        t.file->close();
        std::error_code ec;
        std::filesystem::remove(t.tempFilePath, ec);
        m_incoming.erase(it);
        return;
    }

    // Записываем в файл
    t.file->write(reinterpret_cast<const char*>(plaintext.data()), static_cast<std::streamsize>(plaintext.size()));

    // Обновляем хеш
    EVP_DigestUpdate(t.hasher.get(), plaintext.data(), plaintext.size());

    // Обновляем статистику
    t.bytesReceived += static_cast<int64_t>(plaintext.size());
    t.chunksReceived++;

    // Эмитим прогресс
    emitProgress(t);

    // Проверяем завершение
    if (msg.value("last", false)) {
        finishReceiving(id);
    }
}

// ── Завершение приёма файла ──────────────────────────────────────────────────
// Вызывается из handleFileChunk. m_mutex уже захвачен.

void FileTransfer::finishReceiving(const std::string& offerId) {
    auto it = m_incoming.find(offerId);
    if (it == m_incoming.end()) return;
    auto& t = it->second;

    // Закрываем файл
    t.file->close();

    // Проверяем хеш
    Bytes computedHash(EVP_MAX_MD_SIZE);
    unsigned int outLen = 0;
    EVP_DigestFinal_ex(t.hasher.get(), computedHash.data(), &outLen);
    computedHash.resize(outLen);

    if (computedHash != t.expectedHash) {
        LOG_ERROR(FileTransfer, "Hash Mismatch");

        const std::string err = "File hash mismatch — corrupted";
        fire([&](FileTransferEvent& ev) { if (ev.onTransferFailed) ev.onTransferFailed(offerId, err); });

        std::error_code ec;
        std::filesystem::remove(t.tempFilePath, ec);
        m_incoming.erase(it);
        return;
    }

    LOG_INFO(FileTransfer, "Hash Verified");

    // Перемещаем из временного файла в финальный
    // Если файл уже существует — добавляем суффикс
    std::filesystem::path finalPath = t.finalFilePath;
    {
        const std::filesystem::path orig(t.finalFilePath);
        int counter = 1;
        std::error_code existsEc;
        while (std::filesystem::exists(finalPath, existsEc)) {
            finalPath = orig.parent_path() /
                (orig.stem().string() + " (" + std::to_string(counter++) + ")" + orig.extension().string());
        }
    }

    bool moved = false;
    std::error_code renameEc;
    std::filesystem::rename(t.tempFilePath, finalPath, renameEc);
    if (!renameEc) {
        moved = true;
    } else if (renameEc.value() == static_cast<int>(std::errc::cross_device_link)) {
        // QFile::rename имел встроенный copy-fallback при разных ФС — повторяем его
        std::error_code copyEc;
        std::filesystem::copy_file(t.tempFilePath, finalPath, copyEc);
        if (!copyEc) {
            std::error_code removeEc;
            std::filesystem::remove(t.tempFilePath, removeEc);
            moved = true;
        }
    }

    if (!moved) {
        LOG_ERROR(FileTransfer, "File Save Failed");

        const std::string err = "Cannot save file";
        fire([&](FileTransferEvent& ev) { if (ev.onTransferFailed) ev.onTransferFailed(offerId, err); });

        std::error_code ec;
        std::filesystem::remove(t.tempFilePath, ec);
        m_incoming.erase(it);
        return;
    }

    LOG_INFO(FileTransfer, "File Received");

    t.state = TransferState::Completed;
    const std::string finalPathStr = finalPath.string();
    const std::string fileName     = t.fileName;
    const std::string peerUuid     = t.peerUuid;
    fire([&](FileTransferEvent& ev) { if (ev.onTransferCompleted) ev.onTransferCompleted(offerId, finalPathStr, false); });
    fire([&](FileTransferEvent& ev) { if (ev.onFileReceived) ev.onFileReceived(peerUuid, finalPathStr, fileName); });

    // Очищаем ресурсы
    removeTransferState(offerId);
    m_incoming.erase(it);
}

// ── Принятие/отклонение предложения ──────────────────────────────────────────

void FileTransfer::acceptOffer(const std::string& from, const std::string& offerId) {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);
    if (m_incoming.find(offerId) == m_incoming.end()) {
        LOG_WARNING(FileTransfer, "Accept: Unknown Offer");
        return;
    }

    LOG_INFO(FileTransfer, "Accepting File Offer");

    nlohmann::json msg;
    msg["type"] = "FILE_ACCEPT";
    msg["id"]   = offerId;
    m_net->sendFrame(from, msg);
}

void FileTransfer::rejectOffer(const std::string& from, const std::string& offerId) {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);
    LOG_INFO(FileTransfer, "Rejecting File Offer");

    nlohmann::json msg;
    msg["type"] = "FILE_REJECT";
    msg["id"]   = offerId;
    m_net->sendFrame(from, msg);

    m_incoming.erase(offerId);
}

// ── Отмена передачи ──────────────────────────────────────────────────────────

void FileTransfer::cancelTransfer(const std::string& transferId) {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);
    LOG_INFO(FileTransfer, "Cancelling Transfer");

    nlohmann::json msg;
    msg["type"]   = "FILE_CANCEL";
    msg["id"]     = transferId;
    msg["reason"] = "user cancelled";

    if (auto it = m_outgoing.find(transferId); it != m_outgoing.end()) {
        auto& t = it->second;
        t.state = TransferState::Cancelled;
        m_net->sendFrame(t.peerUuid, msg);

        if (t.file) t.file->close();
        fire([&](FileTransferEvent& ev) { if (ev.onTransferCancelled) ev.onTransferCancelled(transferId); });
        m_outgoing.erase(it);
    }

    if (auto it = m_incoming.find(transferId); it != m_incoming.end()) {
        auto& t = it->second;
        t.state = TransferState::Cancelled;
        m_net->sendFrame(t.peerUuid, msg);

        if (t.file) {
            t.file->close();
            std::error_code ec;
            std::filesystem::remove(t.tempFilePath, ec);
        }
        fire([&](FileTransferEvent& ev) { if (ev.onTransferCancelled) ev.onTransferCancelled(transferId); });
        m_incoming.erase(it);
    }

    removeTransferState(transferId);
}

// ── Пауза/возобновление ──────────────────────────────────────────────────────

void FileTransfer::pauseTransfer(const std::string& transferId) {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);
    LOG_INFO(FileTransfer, "Pausing Transfer");

    if (auto it = m_outgoing.find(transferId); it != m_outgoing.end()) {
        auto& t = it->second;
        t.state = TransferState::Paused;

        // Сохраняем состояние на диск
        TransferResumeInfo info;
        info.id                 = transferId;
        info.peerUuid           = t.peerUuid;
        info.fileName           = t.fileName;
        info.tempFilePath       = t.filePath;
        info.totalSize          = t.fileSize;
        info.lastConfirmedChunk = t.chunksSent;
        info.key                = t.key;
        info.nonce              = t.nonce;
        info.outgoing           = true;
        saveTransferState(info);

        nlohmann::json msg;
        msg["type"] = "FILE_PAUSE";
        msg["id"]   = transferId;
        m_net->sendFrame(t.peerUuid, msg);
    }

    if (auto it = m_incoming.find(transferId); it != m_incoming.end()) {
        auto& t = it->second;
        t.state = TransferState::Paused;

        // Сохраняем состояние на диск
        TransferResumeInfo info;
        info.id                 = transferId;
        info.peerUuid           = t.peerUuid;
        info.fileName           = t.fileName;
        info.tempFilePath       = t.tempFilePath;
        info.totalSize          = t.fileSize;
        info.lastConfirmedChunk = t.chunksReceived;
        info.key                = t.key;
        info.nonce              = t.nonce;
        info.outgoing           = false;
        saveTransferState(info);

        nlohmann::json msg;
        msg["type"] = "FILE_PAUSE";
        msg["id"]   = transferId;
        m_net->sendFrame(t.peerUuid, msg);
    }
}

void FileTransfer::resumeTransfer(const std::string& transferId) {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);
    LOG_INFO(FileTransfer, "Resuming Transfer");

    if (auto it = m_incoming.find(transferId); it != m_incoming.end()) {
        // Отправляем запрос на возобновление отправителю
        nlohmann::json msg;
        msg["type"]       = "FILE_RESUME_REQUEST";
        msg["id"]         = transferId;
        msg["last_chunk"] = it->second.chunksReceived;
        m_net->sendFrame(it->second.peerUuid, msg);
    }
}

void FileTransfer::handleResumeRequest(const std::string& from, const nlohmann::json& msg) {
    const std::string id        = msg.value("id", std::string());
    const int64_t     lastChunk = msg.value("last_chunk", static_cast<int64_t>(0));

    LOG_INFO(FileTransfer, "Resume Request Received");

    auto it = m_outgoing.find(id);
    if (it == m_outgoing.end()) {
        // Попробуем загрузить сохранённое состояние
        TransferResumeInfo info;
        if (!loadTransferState(id, info)) {
            LOG_WARNING(FileTransfer, "Resume Failed: No Saved State");
            return;
        }

        // Восстанавливаем передачу
        OutgoingTransfer t;
        t.id         = id;
        t.peerUuid   = info.peerUuid;
        t.filePath   = info.tempFilePath;
        t.fileName   = info.fileName;
        t.fileSize   = info.totalSize;
        t.key        = info.key;
        t.nonce      = info.nonce;
        t.bytesSent  = lastChunk * kChunkSize;
        t.chunksSent = lastChunk + 1;  // Начинаем со следующего чанка
        t.state      = TransferState::Active;

        t.file = std::make_unique<std::ifstream>(t.filePath, std::ios::binary);
        if (!t.file->is_open()) {
            LOG_ERROR(FileTransfer, "File Reopen Failed");
            return;
        }

        // Перематываем к нужной позиции
        t.file->seekg(t.chunksSent * kChunkSize);
        t.startTime = std::chrono::steady_clock::now();

        m_outgoing[id] = std::move(t);
    } else {
        auto& t = it->second;
        t.state = TransferState::Active;
        t.chunksSent = lastChunk + 1;
        if (t.file) {
            t.file->seekg(t.chunksSent * kChunkSize);
        }
    }

    // Подтверждаем возобновление
    nlohmann::json ack;
    ack["type"]        = "FILE_RESUME_ACK";
    ack["id"]          = id;
    ack["resume_from"] = lastChunk + 1;
    m_net->sendFrame(from, ack);

    // Продолжаем отправку
    sendNextChunk(id);
}

// ── Сохранение/загрузка состояния передачи ───────────────────────────────────

std::filesystem::path FileTransfer::transferStateDir() {
    const std::filesystem::path dir = m_dataDir / "transfers";
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return dir;
}

void FileTransfer::saveTransferState(const TransferResumeInfo& info) {
    nlohmann::json obj;
    obj["id"]                 = info.id;
    obj["peerUuid"]           = info.peerUuid;
    obj["fileName"]           = info.fileName;
    obj["tempFilePath"]       = info.tempFilePath;
    obj["totalSize"]          = info.totalSize;
    obj["lastConfirmedChunk"] = info.lastConfirmedChunk;
    obj["key"]                = bytesToHex(info.key);
    obj["nonce"]              = bytesToHex(info.nonce);
    obj["outgoing"]           = info.outgoing;

    const std::string jsonStr = obj.dump();

    // M-3: шифруем состояние передачи перед записью — AES-ключ файла не должен
    // лежать на диске открытым текстом. Формат файла: зашифрованный блоб (KeyProtector)
    // или fallback plaintext, если KeyProtector не инициализирован.
    const std::filesystem::path path = transferStateDir() / (info.id + ".json");
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        LOG_ERROR(FileTransfer, "Transfer State Save Failed");
        return;
    }

    if (KeyProtector::instance().isReady()) {
        const Bytes encrypted = KeyProtector::instance().encrypt(sv2bytes(jsonStr));
        if (!encrypted.empty()) {
            file.write(reinterpret_cast<const char*>(encrypted.data()),
                       static_cast<std::streamsize>(encrypted.size()));
            LOG_DEBUG(FileTransfer, "Transfer State Saved (Encrypted)");
        } else {
            // Шифрование провалилось — не сохраняем ключевой материал открытым текстом
            LOG_ERROR(FileTransfer, "Transfer State Encryption Failed");
        }
    } else {
        // KeyProtector не готов — plaintext (деградация, логируем предупреждение)
        LOG_WARNING(FileTransfer, "Transfer State Saved Unencrypted");
        file.write(jsonStr.data(), static_cast<std::streamsize>(jsonStr.size()));
    }
}

bool FileTransfer::loadTransferState(const std::string& transferId, TransferResumeInfo& info) {
    const std::filesystem::path path = transferStateDir() / (transferId + ".json");
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    const std::string raw = ss.str();
    file.close();

    // M-3: определяем формат блоба (зашифрованный или legacy plaintext).
    // Plaintext JSON начинается с '{' (0x7B); зашифрованный блоб — случайный nonce.
    std::string jsonStr;
    const bool looksLikeJson = !raw.empty() && raw[0] == '{';
    if (!looksLikeJson && KeyProtector::instance().isReady()) {
        const Bytes decrypted = KeyProtector::instance().decrypt(sv2bytes(raw));
        if (decrypted.empty()) {
            LOG_ERROR(FileTransfer, "Transfer State Decryption Failed");
            return false;
        }
        jsonStr.assign(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
    } else {
        jsonStr = raw;  // legacy plaintext или KeyProtector не готов
    }

    nlohmann::json obj;
    try {
        obj = nlohmann::json::parse(jsonStr);
    } catch (const std::exception&) {
        LOG_ERROR(FileTransfer, "Transfer State Parse Failed");
        return false;
    }

    info.id                 = obj.value("id", std::string());
    info.peerUuid           = obj.value("peerUuid", std::string());
    info.fileName           = obj.value("fileName", std::string());
    info.tempFilePath       = obj.value("tempFilePath", std::string());
    info.totalSize          = obj.value("totalSize", static_cast<int64_t>(0));
    info.lastConfirmedChunk = obj.value("lastConfirmedChunk", static_cast<int64_t>(0));
    info.key                = bytesFromHex(obj.value("key", std::string()));
    info.nonce              = bytesFromHex(obj.value("nonce", std::string()));
    info.outgoing           = obj.value("outgoing", false);

    LOG_DEBUG(FileTransfer, "Transfer State Loaded");
    return true;
}

void FileTransfer::removeTransferState(const std::string& transferId) {
    const std::filesystem::path path = transferStateDir() / (transferId + ".json");
    std::error_code ec;
    if (std::filesystem::exists(path, ec)) {
        std::filesystem::remove(path, ec);
        LOG_DEBUG(FileTransfer, "Transfer State Removed");
    }
}

// ── Утилиты ──────────────────────────────────────────────────────────────────

bool FileTransfer::isValidTransferId(const std::string& id) {
    // id используется в путях файловой системы (tempFilePath, saveTransferState),
    // поэтому допускаем только UUID-подобный набор символов: hex + дефисы.
    // Это исключает разделители путей, "..", NUL и прочие traversal-последовательности.
    if (id.empty() || id.size() > 64) return false;
    for (const char c : id) {
        const bool ok = (c >= '0' && c <= '9') ||
                        (c >= 'a' && c <= 'f') ||
                        (c >= 'A' && c <= 'F') ||
                        c == '-';
        if (!ok) return false;
    }
    return true;
}

std::string FileTransfer::sanitizeFileName(const std::string& name) {
    // Берём только последний компонент пути — убираем любые директории
    std::string safe = std::filesystem::path(name).filename().string();

    // Дополнительно удаляем разделители путей и нулевые байты
    safe.erase(std::remove_if(safe.begin(), safe.end(), [](char c) {
        return c == '/' || c == '\\' || c == '\0';
    }), safe.end());

    // Запрещаем имена вида "..": полностью убираем любое вхождение ".."
    std::size_t pos;
    while ((pos = safe.find("..")) != std::string::npos) {
        safe.erase(pos, 2);
    }

    // Ограничиваем длину
    if (safe.length() > 200)
        safe = safe.substr(0, 200);

    // Пустое или только точки — дефолтное имя
    {
        std::string stripped = safe;
        stripped.erase(std::remove(stripped.begin(), stripped.end(), '.'), stripped.end());
        if (safe.empty() || stripped.empty())
            safe = "unnamed_file";
    }

    return safe;
}

std::string FileTransfer::safeDownloadPath(const std::string& fileName) {
    const std::filesystem::path baseDir = downloadsDir() / "naleystogramm";
    std::error_code ec;
    std::filesystem::create_directories(baseDir, ec);

    const std::string safe = sanitizeFileName(fileName);
    const std::filesystem::path baseNormal = baseDir.lexically_normal();
    const std::filesystem::path candidate  = (baseDir / safe).lexically_normal();

    // Жёсткая проверка: финальный путь ОБЯЗАН начинаться с baseDir.
    // Это исключает любые path-traversal обходы через symlinks и canonicalization.
    const std::string candidateStr = candidate.string();
    const std::string basePrefix   = baseNormal.string() + "/";
    if (candidateStr.compare(0, basePrefix.size(), basePrefix) != 0) {
        LOG_WARNING(FileTransfer, "Path Traversal Blocked");
        return (baseDir / "unnamed_file").string();
    }
    return candidateStr;
}

std::string FileTransfer::tempFilePath(const std::string& transferId) {
    return (transferStateDir() / (transferId + ".tmp")).string();
}

// ── Прогресс и скорость ──────────────────────────────────────────────────────

double FileTransfer::calculateSpeed(int64_t currentBytes, int64_t& lastBytes, int64_t& lastTimeMs,
                                     std::chrono::steady_clock::time_point startTime) {
    const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - startTime).count();
    const int64_t timeDelta = now - lastTimeMs;

    if (timeDelta < kSpeedCalcInterval) {
        return -1.0;  // Слишком рано для пересчёта
    }

    const int64_t bytesDelta = currentBytes - lastBytes;
    const double speed = (bytesDelta * 1000.0) / static_cast<double>(timeDelta);

    lastBytes = currentBytes;
    lastTimeMs = now;

    return speed;
}

void FileTransfer::emitProgress(OutgoingTransfer& t) {
    const double newSpeed = calculateSpeed(
        t.bytesSent, t.lastSpeedCalcBytes, t.lastSpeedCalcTime, t.startTime);

    if (newSpeed >= 0) {
        t.currentSpeed = newSpeed;
    }

    TransferProgress progress;
    progress.id               = t.id;
    progress.fileName         = t.fileName;
    progress.bytesTransferred = t.bytesSent;
    progress.totalBytes       = t.fileSize;
    progress.speedBytesPerSec = t.currentSpeed;
    progress.percent          = t.fileSize > 0
        ? static_cast<int>(100 * t.bytesSent / t.fileSize) : 0;
    progress.etaSeconds       = t.currentSpeed > 0
        ? static_cast<int>(static_cast<double>(t.fileSize - t.bytesSent) / t.currentSpeed) : 0;
    progress.outgoing         = true;

    fire([&](FileTransferEvent& ev) { if (ev.onTransferProgress) ev.onTransferProgress(progress); });
}

void FileTransfer::emitProgress(IncomingTransfer& t) {
    const double newSpeed = calculateSpeed(
        t.bytesReceived, t.lastSpeedCalcBytes, t.lastSpeedCalcTime, t.startTime);

    if (newSpeed >= 0) {
        t.currentSpeed = newSpeed;
    }

    TransferProgress progress;
    progress.id               = t.id;
    progress.fileName         = t.fileName;
    progress.bytesTransferred = t.bytesReceived;
    progress.totalBytes       = t.fileSize;
    progress.speedBytesPerSec = t.currentSpeed;
    progress.percent          = t.fileSize > 0
        ? static_cast<int>(100 * t.bytesReceived / t.fileSize) : 0;
    progress.etaSeconds       = t.currentSpeed > 0
        ? static_cast<int>(static_cast<double>(t.fileSize - t.bytesReceived) / t.currentSpeed) : 0;
    progress.outgoing         = false;

    fire([&](FileTransferEvent& ev) { if (ev.onTransferProgress) ev.onTransferProgress(progress); });
}

// ── Получение прогресса ──────────────────────────────────────────────────────

TransferProgress FileTransfer::getProgress(const std::string& transferId) const {
    TransferProgress progress = {};
    progress.id = transferId;

    std::lock_guard<std::recursive_mutex> lk(m_mutex);

    if (auto it = m_outgoing.find(transferId); it != m_outgoing.end()) {
        const auto& t = it->second;
        progress.fileName         = t.fileName;
        progress.bytesTransferred = t.bytesSent;
        progress.totalBytes       = t.fileSize;
        progress.speedBytesPerSec = t.currentSpeed;
        progress.percent          = t.fileSize > 0
            ? static_cast<int>(100 * t.bytesSent / t.fileSize) : 0;
        progress.etaSeconds       = t.currentSpeed > 0
            ? static_cast<int>(static_cast<double>(t.fileSize - t.bytesSent) / t.currentSpeed) : 0;
        progress.outgoing         = true;
    } else if (auto it2 = m_incoming.find(transferId); it2 != m_incoming.end()) {
        const auto& t = it2->second;
        progress.fileName         = t.fileName;
        progress.bytesTransferred = t.bytesReceived;
        progress.totalBytes       = t.fileSize;
        progress.speedBytesPerSec = t.currentSpeed;
        progress.percent          = t.fileSize > 0
            ? static_cast<int>(100 * t.bytesReceived / t.fileSize) : 0;
        progress.etaSeconds       = t.currentSpeed > 0
            ? static_cast<int>(static_cast<double>(t.fileSize - t.bytesReceived) / t.currentSpeed) : 0;
        progress.outgoing         = false;
    }

    return progress;
}

bool FileTransfer::hasPendingTransfers(const std::string& peerUuid) const {
    std::lock_guard<std::recursive_mutex> lk(m_mutex);

    for (const auto& [id, t] : m_outgoing) {
        if (t.peerUuid == peerUuid &&
            (t.state == TransferState::Active || t.state == TransferState::Pending)) {
            return true;
        }
    }
    for (const auto& [id, t] : m_incoming) {
        if (t.peerUuid == peerUuid &&
            (t.state == TransferState::Active || t.state == TransferState::Pending)) {
            return true;
        }
    }
    return false;
}

// ── Listener API ──────────────────────────────────────────────────────────────

FileTransfer::Token FileTransfer::addListener(FileTransferEvent ev) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    Token t = m_nextToken++;
    m_listeners.emplace_back(t, std::move(ev));
    return t;
}

void FileTransfer::removeListener(Token t) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    m_listeners.erase(
        std::remove_if(m_listeners.begin(), m_listeners.end(),
                       [t](const auto& p) { return p.first == t; }),
        m_listeners.end());
}
