#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

// ── AudioRecorder ──────────────────────────────────────────────────────────
// Запись голосовых сообщений через микрофон в WAV-файл.
// Формат: PCM 16-bit, 16000 Гц, моно.
// Бэкенд захвата: ALSA (HAVE_ALSA, Linux) / WinMM (_WIN32).
// Без бэкенда — no-op (onRecorded("", 0) сразу после startRecording).
//
// Использование:
//   AudioRecorder rec;
//   rec.addListener({...});
//   rec.startRecording();       // начать запись
//   rec.stopRecording();        // остановить → onRecorded(path, durationMs)

class AudioRecorder {
public:
    struct AudioRecorderEvent {
        // Запись завершена: filePath — временный WAV-файл (нужно скопировать/
        // отправить, потом удалить); пуст при ошибке или отсутствии бэкенда.
        std::function<void(const std::string& filePath, int durationMs)> onRecorded;
        // Уровень звука (0.0–1.0) — обновляется ~каждые 50 мс для визуализации.
        std::function<void(float level)> onLevelChanged;
    };

    AudioRecorder() = default;
    ~AudioRecorder();

    AudioRecorder(const AudioRecorder&) = delete;
    AudioRecorder& operator=(const AudioRecorder&) = delete;

    void startRecording();
    void stopRecording();
    [[nodiscard]] bool isRecording() const { return m_recording; }

    using Token = uint32_t;
    Token addListener(AudioRecorderEvent ev);
    void  removeListener(Token t);

private:
    template<typename Fn>
    void fire(Fn&& invoke) const {
        std::vector<std::pair<Token, AudioRecorderEvent>> snap;
        { std::lock_guard<std::mutex> lk(m_listenerMutex); snap = m_listeners; }
        for (auto& [tok, ev] : snap) invoke(ev);
    }

    std::atomic<bool> m_recording{false};
    std::atomic<bool> m_stopRequested{false};
    std::thread m_captureThread;

    mutable std::mutex m_listenerMutex;
    std::vector<std::pair<Token, AudioRecorderEvent>> m_listeners;
    Token m_nextToken{0};
};
