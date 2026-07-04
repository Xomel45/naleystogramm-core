#pragma once
#include <memory>

class StorageManager;
class E2EManager;
class NetworkManager;
class FileTransfer;
class CallManager;
class RemoteShellManager;

// Слой владения core-сервисами.
// Создаётся в main() до MainWindow; передаётся по ссылке в конструктор MainWindow.
// Управляет порядком инициализации: KeyProtector → Storage → E2E → Network → остальные.
// NetworkManager::init() (запуск сервера) вызывается из MainWindow после подключения сигналов.
class App {
public:
    App();
    ~App();

    [[nodiscard]] StorageManager&     storage();
    [[nodiscard]] E2EManager&         e2e();
    [[nodiscard]] NetworkManager&     network();
    [[nodiscard]] FileTransfer&       fileTransfer();
    [[nodiscard]] CallManager&        callManager();
    [[nodiscard]] RemoteShellManager& shellManager();

private:
    StorageManager*                m_storage     {nullptr};
    std::unique_ptr<E2EManager>    m_e2e;
    NetworkManager*                m_network     {nullptr};
    std::unique_ptr<FileTransfer>  m_fileTransfer;
    std::unique_ptr<CallManager>   m_callManager;
    std::unique_ptr<RemoteShellManager> m_shellManager;
};
