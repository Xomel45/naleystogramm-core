#pragma once
// ══════════════════════════════════════════════════════════════════════════════
//  no_qt.h — hard-запрет Qt в naleystogramm-core.
//
//  Подключается через -include при STRICT_NO_QT_IN_CORE=ON.
//  Любая попытка #include <QObject> / <QString> / ... вызовет ошибку:
//  «use of poisoned identifier».
//
//  Включать Qt-типы в naleystogramm-core запрещено, без исключений. Граница
//  CallManager↔MediaEngine — через абстрактный IMediaEngine
//  (include/naleystogramm-core/calls/imediaengine.h); Qt↔std конвертация —
//  на стороне потребителя (desktop: src/media/qtmediaengineadapter.cpp через
//  src/crypto/qt_bridge.h — эти файлы вне этого репозитория).
// ══════════════════════════════════════════════════════════════════════════════

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC poison QString
#pragma GCC poison QByteArray
#pragma GCC poison QUuid
#pragma GCC poison QObject
#pragma GCC poison QTimer
#pragma GCC poison QFile
#pragma GCC poison QDir
#pragma GCC poison QJsonObject
#pragma GCC poison QJsonDocument
#pragma GCC poison QJsonArray
#pragma GCC poison QJsonValue
#pragma GCC poison QNetworkAccessManager
#pragma GCC poison QNetworkRequest
#pragma GCC poison QNetworkReply
#pragma GCC poison QProcess
#pragma GCC poison QFuture
#pragma GCC poison QFutureWatcher
#pragma GCC poison QWebSocket
#pragma GCC poison QCryptographicHash
#pragma GCC poison QElapsedTimer
#pragma GCC poison QMutex
#pragma GCC poison QThread
#pragma GCC poison QList
#pragma GCC poison QVector
#pragma GCC poison QMap
#pragma GCC poison QHash
#pragma GCC poison QSet
#pragma GCC poison QVariant
#pragma GCC poison QUrl
#pragma GCC poison QHostAddress
#pragma GCC poison QTcpSocket
#pragma GCC poison QTcpServer
#pragma GCC poison QUdpSocket
#pragma GCC poison QSqlDatabase
#pragma GCC poison QSqlQuery
#pragma GCC poison QSqlError
#pragma GCC poison QStandardPaths
#pragma GCC poison QSettings
#pragma GCC poison QApplication
#pragma GCC poison QCoreApplication
#pragma GCC poison QWidget
#else
#  error "STRICT_NO_QT_IN_CORE requires GCC or Clang"
#endif
