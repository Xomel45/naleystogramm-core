#include "naleystogramm-core/calls/audiorecorder.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>

#if defined(HAVE_ALSA)
#include <alsa/asoundlib.h>
#include <cerrno>
#elif defined(_WIN32)
#include <windows.h>
#include <mmsystem.h>
#endif

namespace {

constexpr unsigned int kSampleRate      = 16000;
constexpr unsigned int kChannels        = 1;
constexpr unsigned int kBitsPerSample   = 16;
constexpr int          kWavHeaderSize   = 44;
constexpr int          kPeriodMs        = 50;
constexpr unsigned int kFramesPerPeriod = kSampleRate * kPeriodMs / 1000;

// WAV-заголовок — 44 байта стандартного PCM RIFF.
// Записывается дважды: сначала с нулевым размером (placeholder),
// потом перезаписывается с реальным размером после остановки записи.
void writeWavHeader(std::ofstream& f, uint32_t dataSize) {
    const uint16_t blockAlign = static_cast<uint16_t>(kChannels * (kBitsPerSample / 8));
    const uint32_t byteRate   = kSampleRate * blockAlign;
    const uint32_t riffSize   = 36 + dataSize;

    uint8_t hdr[kWavHeaderSize];
    std::memset(hdr, 0, sizeof(hdr));

    hdr[0] = 'R'; hdr[1] = 'I'; hdr[2] = 'F'; hdr[3] = 'F';
    hdr[4]  = static_cast<uint8_t>(riffSize);
    hdr[5]  = static_cast<uint8_t>(riffSize >> 8);
    hdr[6]  = static_cast<uint8_t>(riffSize >> 16);
    hdr[7]  = static_cast<uint8_t>(riffSize >> 24);
    hdr[8] = 'W'; hdr[9] = 'A'; hdr[10] = 'V'; hdr[11] = 'E';

    hdr[12] = 'f'; hdr[13] = 'm'; hdr[14] = 't'; hdr[15] = ' ';
    hdr[16] = 16; hdr[17] = 0; hdr[18] = 0; hdr[19] = 0;  // chunk size = 16 (PCM)
    hdr[20] = 1;  hdr[21] = 0;                            // AudioFormat = 1 (PCM)
    hdr[22] = static_cast<uint8_t>(kChannels);
    hdr[23] = static_cast<uint8_t>(kChannels >> 8);
    hdr[24] = static_cast<uint8_t>(kSampleRate);
    hdr[25] = static_cast<uint8_t>(kSampleRate >> 8);
    hdr[26] = static_cast<uint8_t>(kSampleRate >> 16);
    hdr[27] = static_cast<uint8_t>(kSampleRate >> 24);
    hdr[28] = static_cast<uint8_t>(byteRate);
    hdr[29] = static_cast<uint8_t>(byteRate >> 8);
    hdr[30] = static_cast<uint8_t>(byteRate >> 16);
    hdr[31] = static_cast<uint8_t>(byteRate >> 24);
    hdr[32] = static_cast<uint8_t>(blockAlign);
    hdr[33] = static_cast<uint8_t>(blockAlign >> 8);
    hdr[34] = static_cast<uint8_t>(kBitsPerSample);
    hdr[35] = static_cast<uint8_t>(kBitsPerSample >> 8);

    hdr[36] = 'd'; hdr[37] = 'a'; hdr[38] = 't'; hdr[39] = 'a';
    hdr[40] = static_cast<uint8_t>(dataSize);
    hdr[41] = static_cast<uint8_t>(dataSize >> 8);
    hdr[42] = static_cast<uint8_t>(dataSize >> 16);
    hdr[43] = static_cast<uint8_t>(dataSize >> 24);

    f.write(reinterpret_cast<const char*>(hdr), kWavHeaderSize);
}

std::filesystem::path tempWavPath() {
    std::ostringstream oss;
    oss << "naleys_voice_" << std::hex
        << static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count())
        << ".wav";
    return std::filesystem::temp_directory_path() / oss.str();
}

// Уровень 0.0-1.0 по PCM16-сэмплам: средний |sample|/32768, с усилением x3 (как в оригинале).
float levelFromSamples(const int16_t* samples, int count) {
    if (count <= 0) return 0.0f;
    int64_t sum = 0;
    for (int i = 0; i < count; ++i) sum += std::abs(static_cast<int>(samples[i]));
    const float level = static_cast<float>(sum) / count / 32768.0f;
    return std::min(level * 3.0f, 1.0f);
}

#if defined(HAVE_ALSA)

bool captureLoop(std::ofstream& f, std::atomic<bool>& stop,
                 const std::function<void(float)>& onLevel, uint64_t& dataSize) {
    snd_pcm_t* handle = nullptr;
    int err = snd_pcm_open(&handle, "default", SND_PCM_STREAM_CAPTURE, 0);
    if (err < 0) {
        fprintf(stderr, "[AudioRecorder] snd_pcm_open: %s\n", snd_strerror(err));
        return false;
    }

    unsigned int rate = kSampleRate;
    err = snd_pcm_set_params(handle, SND_PCM_FORMAT_S16_LE, SND_PCM_ACCESS_RW_INTERLEAVED,
                              kChannels, rate, 1, kPeriodMs * 1000);
    if (err < 0) {
        fprintf(stderr, "[AudioRecorder] snd_pcm_set_params: %s\n", snd_strerror(err));
        snd_pcm_close(handle);
        return false;
    }

    std::vector<int16_t> buf(kFramesPerPeriod * kChannels);

    while (!stop.load()) {
        snd_pcm_sframes_t n = snd_pcm_readi(handle, buf.data(), kFramesPerPeriod);
        if (n == -EPIPE) {
            snd_pcm_prepare(handle);
            continue;
        }
        if (n < 0) {
            n = snd_pcm_recover(handle, static_cast<int>(n), 1);
            if (n < 0) break;
            continue;
        }
        if (n == 0) continue;

        const auto bytes = static_cast<size_t>(n) * kChannels * sizeof(int16_t);
        f.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(bytes));
        dataSize += bytes;

        onLevel(levelFromSamples(buf.data(), static_cast<int>(n) * static_cast<int>(kChannels)));
    }

    snd_pcm_close(handle);
    return true;
}

#elif defined(_WIN32)

bool captureLoop(std::ofstream& f, std::atomic<bool>& stop,
                 const std::function<void(float)>& onLevel, uint64_t& dataSize) {
    WAVEFORMATEX wfx{};
    wfx.wFormatTag      = WAVE_FORMAT_PCM;
    wfx.nChannels       = static_cast<WORD>(kChannels);
    wfx.nSamplesPerSec  = kSampleRate;
    wfx.wBitsPerSample  = static_cast<WORD>(kBitsPerSample);
    wfx.nBlockAlign     = static_cast<WORD>(wfx.nChannels * wfx.wBitsPerSample / 8);
    wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;

    HANDLE hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!hEvent) {
        fprintf(stderr, "[AudioRecorder] CreateEventW failed\n");
        return false;
    }

    HWAVEIN hwi = nullptr;
    if (waveInOpen(&hwi, WAVE_MAPPER, &wfx, reinterpret_cast<DWORD_PTR>(hEvent), 0,
                   CALLBACK_EVENT) != MMSYSERR_NOERROR) {
        fprintf(stderr, "[AudioRecorder] waveInOpen failed\n");
        CloseHandle(hEvent);
        return false;
    }

    constexpr int kNumBufs = 4;
    const DWORD bufBytes = kFramesPerPeriod * wfx.nBlockAlign;
    std::vector<std::vector<char>> bufs(kNumBufs, std::vector<char>(bufBytes));
    std::vector<WAVEHDR> hdrs(kNumBufs);

    for (int i = 0; i < kNumBufs; ++i) {
        WAVEHDR& h = hdrs[i];
        std::memset(&h, 0, sizeof(h));
        h.lpData = bufs[i].data();
        h.dwBufferLength = bufBytes;
        waveInPrepareHeader(hwi, &h, sizeof(h));
        waveInAddBuffer(hwi, &h, sizeof(h));
    }

    waveInStart(hwi);

    while (!stop.load()) {
        WaitForSingleObject(hEvent, 100);
        for (int i = 0; i < kNumBufs; ++i) {
            WAVEHDR& h = hdrs[i];
            if (h.dwFlags & WHDR_DONE) {
                const auto bytes = static_cast<size_t>(h.dwBytesRecorded);
                if (bytes > 0) {
                    f.write(h.lpData, static_cast<std::streamsize>(bytes));
                    dataSize += bytes;

                    const auto* samples = reinterpret_cast<const int16_t*>(h.lpData);
                    onLevel(levelFromSamples(samples, static_cast<int>(bytes / sizeof(int16_t))));
                }
                h.dwFlags &= ~WHDR_DONE;
                if (!stop.load()) waveInAddBuffer(hwi, &h, sizeof(h));
            }
        }
    }

    waveInStop(hwi);
    waveInReset(hwi);
    for (int i = 0; i < kNumBufs; ++i) waveInUnprepareHeader(hwi, &hdrs[i], sizeof(WAVEHDR));
    waveInClose(hwi);
    CloseHandle(hEvent);
    return true;
}

#else

bool captureLoop(std::ofstream&, std::atomic<bool>&,
                 const std::function<void(float)>&, uint64_t&) {
    fprintf(stderr, "[AudioRecorder] Бэкенд захвата звука недоступен\n");
    return false;
}

#endif

} // namespace

AudioRecorder::~AudioRecorder() {
    if (m_recording) stopRecording();
    if (m_captureThread.joinable()) m_captureThread.join();
}

void AudioRecorder::startRecording() {
    if (m_recording) return;
    if (m_captureThread.joinable()) m_captureThread.join();

    const std::filesystem::path path = tempWavPath();
    m_stopRequested = false;
    m_recording = true;

    m_captureThread = std::thread([this, path]() {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) {
            fprintf(stderr, "[AudioRecorder] Не удалось создать временный файл: %s\n",
                    path.string().c_str());
            m_recording = false;
            fire([](AudioRecorderEvent& ev) { if (ev.onRecorded) ev.onRecorded("", 0); });
            return;
        }

        writeWavHeader(f, 0);

        const auto t0 = std::chrono::steady_clock::now();
        uint64_t dataSize = 0;
        const bool ok = captureLoop(f, m_stopRequested,
            [this](float level) {
                fire([level](AudioRecorderEvent& ev) {
                    if (ev.onLevelChanged) ev.onLevelChanged(level);
                });
            }, dataSize);

        const auto durationMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();

        f.seekp(0);
        writeWavHeader(f, static_cast<uint32_t>(dataSize));
        f.close();

        m_recording = false;
        fire([](AudioRecorderEvent& ev) { if (ev.onLevelChanged) ev.onLevelChanged(0.0f); });

        if (!ok || dataSize == 0) {
            std::error_code ec;
            std::filesystem::remove(path, ec);
            fire([](AudioRecorderEvent& ev) { if (ev.onRecorded) ev.onRecorded("", 0); });
        } else {
            const std::string filePath = path.string();
            const int duration = static_cast<int>(durationMs);
            fire([&filePath, duration](AudioRecorderEvent& ev) {
                if (ev.onRecorded) ev.onRecorded(filePath, duration);
            });
        }
    });
}

void AudioRecorder::stopRecording() {
    if (!m_recording) return;
    m_stopRequested = true;
    if (m_captureThread.joinable()) m_captureThread.join();
}

AudioRecorder::Token AudioRecorder::addListener(AudioRecorderEvent ev) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    const Token t = m_nextToken++;
    m_listeners.emplace_back(t, std::move(ev));
    return t;
}

void AudioRecorder::removeListener(Token t) {
    std::lock_guard<std::mutex> lk(m_listenerMutex);
    m_listeners.erase(
        std::remove_if(m_listeners.begin(), m_listeners.end(),
                       [t](const auto& p) { return p.first == t; }),
        m_listeners.end());
}
