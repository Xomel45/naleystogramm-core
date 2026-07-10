cmake_minimum_required(VERSION 3.22)
project(naleystogramm-core LANGUAGES CXX)

# C нужен для вендоренного sqlite3.c (third_party/sqlite3/) — фолбэк, когда
# нет системного sqlite3/SQLCipher (Android NDK и т.п.)
enable_language(C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Библиотека без Qt — граница CallManager↔MediaEngine выражена абстрактным
# IMediaEngine (include/naleystogramm-core/calls/imediaengine.h). Собирается
# как отдельный проект или как add_subdirectory()/FetchContent из desktop
# (naleystogramm) и будущего Android NDK-таргета (v0.9.0).

# ── APP_VERSION/APP_CODENAME ─────────────────────────────────────────────────
# Потребитель (desktop/mobile) задаёт эти cache-переменные ДО
# FetchContent_MakeAvailable(naleystogramm-core), чтобы попасть в реальную
# версию приложения. Значения по умолчанию — только для standalone-сборки
# этого репозитория (ctest и т.п.).
set(NALEYSTOGRAMM_CORE_APP_VERSION  "0.0.0-standalone" CACHE STRING "Значение макроса APP_VERSION")
set(NALEYSTOGRAMM_CORE_APP_CODENAME "standalone"        CACHE STRING "Значение макроса APP_CODENAME")

if(WIN32)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
find_package(OpenSSL REQUIRED)
find_package(PkgConfig QUIET)

# pkg-config шеллится в ХОСТОВЫЙ pkg-config и не уважает CMAKE_FIND_ROOT_PATH/
# sysroot при кросс-компиляции — под Android NDK он находит host-пакеты
# (например Arch-сборку sqlcipher), которые физически не совместимы с
# ABI цели. Поэтому здесь эти detection'ы пропускаются полностью при
# кросс-компиляции (ANDROID выставляется NDK-тулчейном); Android получает
# core без SQLCipher/ALSA, пока под них не появятся отдельные Android-сборки.
if(PkgConfig_FOUND AND NOT WIN32 AND NOT ANDROID AND NOT CMAKE_CROSSCOMPILING)
    pkg_check_modules(SQLCIPHER QUIET sqlcipher)
    pkg_check_modules(ALSA     QUIET alsa)
endif()

# ── Standalone Asio + nlohmann/json (header-only) ────────────────────────────
include(FetchContent)

find_path(ASIO_SYSTEM_INCLUDE asio.hpp
    PATHS /usr/include /usr/local/include
    NO_DEFAULT_PATH)
if(ASIO_SYSTEM_INCLUDE)
    message(STATUS "naleystogramm-core: asio системный (${ASIO_SYSTEM_INCLUDE})")
    set(ASIO_INCLUDE_DIR ${ASIO_SYSTEM_INCLUDE})
else()
    FetchContent_Declare(asio
        GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
        GIT_TAG        asio-1-30-2
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(asio)
    set(ASIO_INCLUDE_DIR ${asio_SOURCE_DIR}/asio/include)
    message(STATUS "naleystogramm-core: asio FetchContent (${ASIO_INCLUDE_DIR})")
endif()

find_package(nlohmann_json QUIET CONFIG)
if(nlohmann_json_FOUND)
    message(STATUS "naleystogramm-core: nlohmann/json системный (${nlohmann_json_VERSION})")
else()
    FetchContent_Declare(nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
    message(STATUS "naleystogramm-core: nlohmann/json FetchContent v3.11.3")
endif()

# ── naleystogramm-crypto (E2E: X3DH + Double Ratchet) ────────────────────────
FetchContent_Declare(naleystogramm-crypto
    GIT_REPOSITORY https://github.com/Xomel45/naleystogramm-crypto.git
    GIT_TAG        8d182fe42a55d63aab9d374eb7a59fdc1baedfd3
    GIT_SHALLOW    FALSE
)
FetchContent_MakeAvailable(naleystogramm-crypto)

# ══════════════════════════════════════════════════════════════════════════════
# ПРАВИЛО: этот репозиторий НЕ включает Qt напрямую — без исключений.
#   🔍 Проверить нарушения:  cmake --build . --target core-purity
#   🔒 STRICT_NO_QT_IN_CORE=ON (по умолчанию) — запрет на уровне компилятора.
# ══════════════════════════════════════════════════════════════════════════════
option(STRICT_NO_QT_IN_CORE "Запретить Qt в naleystogramm-core на уровне компилятора" ON)

set(CORE_SOURCES
    include/naleystogramm-core/types.h
    include/naleystogramm-core/app.h
    src/app.cpp

    include/naleystogramm-core/identity/identity.h
    src/identity/identity.cpp
    include/naleystogramm-core/identity/device_pairing.h
    src/identity/device_pairing.cpp

    include/naleystogramm-core/net/network.h
    src/net/network.cpp
    include/naleystogramm-core/net/upnp.h
    src/net/upnp.cpp

    include/naleystogramm-core/storage/storage.h
    src/storage/storage.cpp
    include/naleystogramm-core/storage/sessionmanager.h
    src/storage/sessionmanager.cpp

    include/naleystogramm-core/transfer/filetransfer.h
    src/transfer/filetransfer.cpp

    include/naleystogramm-core/calls/imediaengine.h
    include/naleystogramm-core/calls/callmanager.h
    src/calls/callmanager.cpp
    include/naleystogramm-core/calls/audiorecorder.h
    src/calls/audiorecorder.cpp

    include/naleystogramm-core/shell/remoteshellmanager.h
    src/shell/remoteshellmanager.cpp
    include/naleystogramm-core/shell/shellprocess.h
    src/shell/shellprocess.cpp

    include/naleystogramm-core/diag/systeminfo.h
    src/diag/systeminfo.cpp
    include/naleystogramm-core/diag/updatechecker.h
    src/diag/updatechecker.cpp
    include/naleystogramm-core/diag/demomode.h
    src/diag/demomode.cpp
    include/naleystogramm-core/diag/logger.h
    src/diag/logger.cpp
    include/naleystogramm-core/diag/versionutils.h
)

add_library(naleystogramm-core STATIC ${CORE_SOURCES})

target_include_directories(naleystogramm-core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    ${ASIO_INCLUDE_DIR}
)

target_compile_definitions(naleystogramm-core PUBLIC
    APP_VERSION="${NALEYSTOGRAMM_CORE_APP_VERSION}"
    APP_CODENAME="${NALEYSTOGRAMM_CORE_APP_CODENAME}"
    ASIO_STANDALONE
    ASIO_NO_DEPRECATED
)

target_link_libraries(naleystogramm-core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    naleystogramm-crypto
    nlohmann_json::nlohmann_json
)

# ── Qt-запрет ─────────────────────────────────────────────────────────────────
if(STRICT_NO_QT_IN_CORE)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        foreach(_src ${CORE_SOURCES})
            if(_src MATCHES "\\.cpp$")
                set_source_files_properties(${_src} PROPERTIES
                    COMPILE_OPTIONS "-include${CMAKE_CURRENT_SOURCE_DIR}/include/naleystogramm-core/no_qt.h")
            endif()
        endforeach()
        message(STATUS "STRICT_NO_QT_IN_CORE: ON — Qt запрещён в naleystogramm-core")
    else()
        message(STATUS "STRICT_NO_QT_IN_CORE: пропущено — требует GCC/Clang")
    endif()
else()
    message(STATUS "STRICT_NO_QT_IN_CORE: OFF — используй 'core-purity' для проверки")
endif()

add_custom_target(core-purity
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan
        "=== Проверка Qt-зависимостей в naleystogramm-core ==="
    COMMAND bash -c
        "violations=\$(grep -rn --include='*.h' --include='*.cpp' \
            -e '#include <Q' -e '#include \"Q' \
            ${CMAKE_CURRENT_SOURCE_DIR}/include/ ${CMAKE_CURRENT_SOURCE_DIR}/src/ \
          | grep -v 'no_qt\\.h'); \
         if [ -n \"\$violations\" ]; then \
           echo ''; echo 'НАРУШЕНИЯ — Qt в naleystogramm-core:'; \
           echo \"\$violations\"; exit 1; \
         else \
           echo 'Чисто — Qt не найден'; \
         fi"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Проверка отсутствия Qt в naleystogramm-core"
    VERBATIM
)

# ── sqlite3 (Storage) — только если не найден SQLCipher (взаимоисключающие) ──
if(NOT SQLCIPHER_FOUND)
    if(NOT ANDROID AND NOT CMAKE_CROSSCOMPILING)
        pkg_check_modules(SQLITE3 QUIET sqlite3)
    endif()
    if(SQLITE3_FOUND)
        target_link_libraries(naleystogramm-core PUBLIC ${SQLITE3_LINK_LIBRARIES})
        target_include_directories(naleystogramm-core PUBLIC ${SQLITE3_INCLUDE_DIRS})
    else()
        # Нет системного sqlite3 (Android NDK sysroot его не поставляет, либо
        # host без sqlite3-dev) — компилируем вендоренный amalgamation
        # (third_party/sqlite3/, sqlite3.org, версия синхронизирована с
        # системной на момент выноса — 3.53.3).
        message(STATUS "sqlite3:         системный не найден — используется вендоренный amalgamation")
        add_library(sqlite3-vendored STATIC third_party/sqlite3/sqlite3.c)
        target_include_directories(sqlite3-vendored PUBLIC third_party/sqlite3)
        target_compile_definitions(sqlite3-vendored PRIVATE
            SQLITE_THREADSAFE=1
            SQLITE_OMIT_LOAD_EXTENSION=1
        )
        if(NOT WIN32)
            find_package(Threads REQUIRED)
            target_link_libraries(sqlite3-vendored PUBLIC Threads::Threads ${CMAKE_DL_LIBS})
        endif()
        target_link_libraries(naleystogramm-core PUBLIC sqlite3-vendored)
    endif()
else()
    message(STATUS "SQLCipher:       найден (${SQLCIPHER_VERSION}) — шифрование БД включено")
    target_compile_definitions(naleystogramm-core PUBLIC HAVE_SQLCIPHER)
    target_include_directories(naleystogramm-core PUBLIC ${SQLCIPHER_INCLUDE_DIRS})
    target_link_libraries(naleystogramm-core PUBLIC ${SQLCIPHER_LINK_LIBRARIES})
endif()

# ── ALSA (AudioRecorder, Linux) ───────────────────────────────────────────────
if(ALSA_FOUND)
    target_compile_definitions(naleystogramm-core PUBLIC HAVE_ALSA)
    target_include_directories(naleystogramm-core PUBLIC ${ALSA_INCLUDE_DIRS})
    target_link_libraries(naleystogramm-core PUBLIC ${ALSA_LIBRARIES})
    message(STATUS "ALSA:            найден (${ALSA_VERSION}) — запись голосовых включена")
else()
    message(STATUS "ALSA:            не найден — запись голосовых отключена (Linux)")
endif()

# ── libcurl (UpdateChecker/GroupManager/DiscoveryClient) ─────────────────────
find_package(CURL QUIET)
if(CURL_FOUND)
    message(STATUS "libcurl:         найден — UpdateChecker/GroupManager/DiscoveryClient включены")
    target_compile_definitions(naleystogramm-core PRIVATE HAVE_CURL)
    target_link_libraries(naleystogramm-core PRIVATE CURL::libcurl)

    target_sources(naleystogramm-core PRIVATE
        include/naleystogramm-core/net/groupmanager.h
        src/net/groupmanager.cpp
    )
    target_compile_definitions(naleystogramm-core PUBLIC HAVE_GROUPS)

    target_sources(naleystogramm-core PRIVATE
        include/naleystogramm-core/net/discoveryclient.h
        src/net/discoveryclient.cpp
    )
    target_compile_definitions(naleystogramm-core PUBLIC HAVE_DISCOVERY)
else()
    message(STATUS "libcurl:         не найден — UpdateChecker/GroupManager/DiscoveryClient отключены")
endif()

target_compile_options(naleystogramm-core PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)
