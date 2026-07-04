<div align="center">

# Naleystogramm Core

**Платформо-независимое ядро Naleystogramm (identity, сеть, storage, звонки, remote shell) — общее для desktop и Android**

</div>

---

## О проекте

Вынесено из `naleystogramm/src/core/` в отдельную библиотеку, чтобы desktop
(C++/Qt6) и Android (через будущий NDK JNI-мост, v0.9.0) использовали **один**
код бизнес-логики вместо параллельных реализаций.

Код не менялся по логике при переносе — только пути `#include` (namespaced
под `naleystogramm-core/...`) и граница `CallManager↔MediaEngine`: раньше
`callmanager.cpp` подключал Qt-типы напрямую через `qt_bridge.h` (единственное
разрешённое исключение из правила "core без Qt"), теперь эта граница —
абстрактный интерфейс `IMediaEngine` (`calls/imediaengine.h`, только
std/`Bytes`). Платформенная реализация (Qt на desktop, нативный аудио-стек на
Android) подставляется потребителем библиотеки, а не живёт внутри неё.

## Состав

- **App** (`app.h/.cpp`) — точка сборки всех менеджеров
- **identity/** — `Identity`, `DevicePairing` (OTP-сопряжение устройств)
- **net/** — `NetworkManager` (P2P TCP + JSON-фреймы), `UpnpMapper`,
  `GroupManager` (опционально, `HAVE_GROUPS`), `DiscoveryClient` (опционально,
  `HAVE_DISCOVERY`)
- **storage/** — `StorageManager` (sqlite3/SQLCipher), `SessionManager`
- **transfer/** — `FileTransfer`
- **calls/** — `CallManager` + `IMediaEngine` (абстракция), `AudioRecorder`
  (ALSA/WinMM)
- **shell/** — `RemoteShellManager`, `ShellProcess` (кросс-платформенный
  аналог `QProcess`)
- **diag/** — `SystemInfo`, `UpdateChecker`, `DemoMode`, `Logger`,
  `VersionUtils`

## Зависимости

- C++23
- OpenSSL (`libssl`/`libcrypto`) — обязательна
- [asio](https://think-async.com/Asio/) (standalone, header-only) — обязательна
- [nlohmann/json](https://github.com/nlohmann/json) — обязательна
- [naleystogramm-crypto](https://github.com/Xomel45/naleystogramm-crypto) — E2E (X3DH + Double Ratchet), подключается через FetchContent
- sqlite3 или SQLCipher (опционально, `HAVE_SQLCIPHER`) — Storage
- ALSA (опционально, `HAVE_ALSA`, Linux) — запись голосовых в `AudioRecorder`
- libcurl (опционально, `HAVE_CURL`/`HAVE_GROUPS`/`HAVE_DISCOVERY`) — `UpdateChecker`/`GroupManager`/`DiscoveryClient`
- **Никакого Qt** — единственная граница к платформенному UI/медиа —
  абстрактный `IMediaEngine`

## Версия приложения

`APP_VERSION`/`APP_CODENAME` (используются `UpdateChecker`/`SessionManager`)
задаются потребителем через cache-переменные **до**
`FetchContent_MakeAvailable(naleystogramm-core)`:

```cmake
set(NALEYSTOGRAMM_CORE_APP_VERSION  "0.8.2"       CACHE STRING "" FORCE)
set(NALEYSTOGRAMM_CORE_APP_CODENAME "Оплошность"  CACHE STRING "" FORCE)
```

## Проверка чистоты от Qt

```bash
cmake --build . --target core-purity
```
