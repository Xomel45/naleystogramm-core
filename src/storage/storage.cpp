#include "naleystogramm-core/storage/storage.h"
#ifdef HAVE_SQLCIPHER
#  include <sqlcipher/sqlite3.h>
#else
#  include <sqlite3.h>
#endif
#include "naleystogramm-crypto/keyprotector.h"
#include "naleystogramm-crypto/bytes.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <chrono>
#include <filesystem>

static constexpr const char* kStorageAppVersion = "0.8.0";

// ── Временны́е хелперы ────────────────────────────────────────────────────────

static int64_t nowEpochMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ISO-строка → epoch ms; 0 при неудаче
static int64_t isoToEpochMs(const std::string& iso) {
    if (iso.empty()) return 0;
    struct tm t = {};
    if (std::sscanf(iso.c_str(), "%d-%d-%dT%d:%d:%d",
            &t.tm_year, &t.tm_mon, &t.tm_mday,
            &t.tm_hour, &t.tm_min, &t.tm_sec) < 6) return 0;
    t.tm_year -= 1900;
    t.tm_mon  -= 1;
    t.tm_isdst = -1;
    const std::time_t epoch = std::mktime(&t);
    return epoch >= 0 ? static_cast<int64_t>(epoch) * 1000LL : 0LL;
}

// epoch ms → ISO-строка (локальное время без зоны — совместимо со старой БД)
static std::string epochMsToIso(int64_t ms) {
    if (ms <= 0) ms = nowEpochMs();
    const std::time_t secs = static_cast<std::time_t>(ms / 1000);
    struct tm t = {};
#ifdef _WIN32
    localtime_s(&t, &secs);
#else
    localtime_r(&secs, &t);
#endif
    char buf[24];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &t);
    return buf;
}

// ── Путь к базе ──────────────────────────────────────────────────────────────

static std::string dbPath() {
#ifdef _WIN32
    const char* local = std::getenv("LOCALAPPDATA");
    std::string base  = std::string(local ? local : "C:\\ProgramData") + "\\naleystogramm";
#else
    const char* xdg   = std::getenv("XDG_DATA_HOME");
    const char* home  = std::getenv("HOME");
    std::string base  = std::string((xdg && *xdg) ? xdg
                                    : (std::string(home ? home : "/tmp") + "/.local/share"))
                        + "/naleystogramm";
#endif
    std::error_code ec;
    std::filesystem::create_directories(base, ec);
    return base +
#ifdef _WIN32
        "\\data.db";
#else
        "/data.db";
#endif
}

// ── RAII для sqlite3_stmt ────────────────────────────────────────────────────

struct Stmt {
    sqlite3_stmt* s{nullptr};
    ~Stmt() { sqlite3_finalize(s); }
    sqlite3_stmt** ptr() { return &s; }
    sqlite3_stmt*  get() const { return s; }
};

// ── Вспомогательные функции ──────────────────────────────────────────────────

static std::string colText(sqlite3_stmt* s, int i) {
    const unsigned char* t = sqlite3_column_text(s, i);
    return t ? std::string(reinterpret_cast<const char*>(t)) : std::string{};
}

static Bytes colBlob(sqlite3_stmt* s, int i) {
    const void* d = sqlite3_column_blob(s, i);
    const int   n = sqlite3_column_bytes(s, i);
    if (!d || n <= 0) return {};
    const auto* p = static_cast<const uint8_t*>(d);
    return Bytes(p, p + n);
}

static void bindText(sqlite3_stmt* s, int i, const std::string& v) {
    sqlite3_bind_text(s, i, v.c_str(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
}

static void bindBlob(sqlite3_stmt* s, int i, const Bytes& v) {
    if (v.empty()) sqlite3_bind_null(s, i);
    else sqlite3_bind_blob(s, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
}

static void execSql(sqlite3* db, const char* sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::fprintf(stderr, "[Storage] SQL: %s\n", err ? err : "(no message)");
        sqlite3_free(err);
    }
}

// ── Row mappers ──────────────────────────────────────────────────────────────

// contacts columns: uuid,name,ip,port,identity_key,avatar_hash,avatar_path,
//   is_blocked,is_muted,last_seen,systeminfo_json,birthday,version_created
static constexpr const char* kSelectContacts =
    "SELECT uuid,name,ip,port,identity_key,avatar_hash,avatar_path,"
    "is_blocked,is_muted,last_seen,systeminfo_json,birthday,version_created"
    " FROM contacts";

static Contact rowToContact(sqlite3_stmt* s) {
    Contact c;
    c.uuid           = colText(s, 0);
    c.name           = colText(s, 1);
    c.ip             = colText(s, 2);
    c.port           = static_cast<uint16_t>(sqlite3_column_int(s, 3));
    c.identityKey    = colBlob(s, 4);
    c.avatarHash     = colText(s, 5);
    c.avatarPath     = colText(s, 6);
    c.isBlocked      = sqlite3_column_int(s, 7) != 0;
    c.isMuted        = sqlite3_column_int(s, 8) != 0;
    const int64_t ls = sqlite3_column_int64(s, 9);
    c.lastSeen       = ls > 0 ? ls * 1000LL : 0LL;  // DB stores Unix seconds → epoch ms
    c.systemInfoJson = colText(s, 10);
    c.birthday       = colText(s, 11);
    const std::string vc = colText(s, 12);
    c.versionCreated = vc.empty() ? "0.1.0" : vc;
    return c;
}

// messages columns: id,peer_uuid,outgoing,text,file_name,file_size,ciphertext,
//   timestamp,delivered,is_voice,voice_duration_ms,version_created
static constexpr const char* kSelectMessages =
    "SELECT id,peer_uuid,outgoing,text,file_name,file_size,ciphertext,"
    "timestamp,delivered,is_voice,voice_duration_ms,version_created"
    " FROM messages";

static Message rowToMessage(sqlite3_stmt* s) {
    Message m;
    m.id              = sqlite3_column_int64(s, 0);
    m.peerUuid        = colText(s, 1);
    m.outgoing        = sqlite3_column_int(s, 2) != 0;
    m.text            = colText(s, 3);
    m.fileName        = colText(s, 4);
    m.fileSize        = sqlite3_column_int64(s, 5);
    m.ciphertext      = colBlob(s, 6);
    m.timestamp       = isoToEpochMs(colText(s, 7));
    m.delivered       = sqlite3_column_int(s, 8) != 0;
    m.isVoice         = sqlite3_column_int(s, 9) != 0;
    m.voiceDurationMs = sqlite3_column_int(s, 10);
    const std::string mvc = colText(s, 11);
    m.versionCreated  = mvc.empty() ? "0.1.0" : mvc;
    return m;
}

// groups columns: id,name,type,server_url,username,token_enc,group_key_enc,
//   local_priv_key_enc,local_pub_key,is_admin,joined_at
static constexpr const char* kSelectGroups =
    "SELECT id,name,type,server_url,username,token_enc,group_key_enc,"
    "local_priv_key_enc,local_pub_key,is_admin,joined_at"
    " FROM groups";

static Group rowToGroup(sqlite3_stmt* s) {
    Group g;
    g.id        = colText(s, 0);
    g.name      = colText(s, 1);
    g.type      = colText(s, 2) == "channel" ? GroupType::Channel : GroupType::Group;
    g.serverUrl = colText(s, 3);
    g.username  = colText(s, 4);
    g.isAdmin   = sqlite3_column_int(s, 9) != 0;
    g.joinedAt  = isoToEpochMs(colText(s, 10));

    const auto& kp = KeyProtector::instance();
    if (kp.isReady()) {
        const Bytes encTok = colBlob(s, 5);
        if (!encTok.empty()) {
            const Bytes plain = kp.decrypt(encTok);
            g.token = std::string(plain.begin(), plain.end());
        }
        const Bytes encKey = colBlob(s, 6);
        if (!encKey.empty()) g.groupKey   = kp.decrypt(encKey);

        const Bytes encPriv = colBlob(s, 7);
        if (!encPriv.empty()) g.localPrivKey = kp.decrypt(encPriv);
    }
    g.localPubKey = colBlob(s, 8);
    return g;
}

// ── StorageManager ───────────────────────────────────────────────────────────

StorageManager::StorageManager() = default;

StorageManager::~StorageManager() {
    sqlite3_close(m_db);
    m_db = nullptr;
}

bool StorageManager::open() {
    const std::string path = dbPath();
    const int rc = sqlite3_open(path.c_str(), &m_db);
    if (rc != SQLITE_OK) {
        std::fprintf(stderr, "[Storage] Cannot open DB (%s): %s\n",
                     path.c_str(), sqlite3_errmsg(m_db));
        sqlite3_close(m_db);
        m_db = nullptr;
        return false;
    }

#ifdef HAVE_SQLCIPHER
    {
        const Bytes dbKey = KeyProtector::instance().deriveKey(
            sv2bytes("naleystogramm-db-key-v1"));
        if (dbKey.empty()) {
            std::fprintf(stderr, "[Storage] KeyProtector не готов — SQLCipher ключ не получен!\n");
        } else {
            const std::string hexKey = bytesToHex(dbKey);
            const std::string pragma = "PRAGMA key = \"x'" + hexKey + "'\"";
            char* err = nullptr;
            if (sqlite3_exec(m_db, pragma.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
                std::fprintf(stderr, "[Storage] SQLCipher PRAGMA key failed: %s\n",
                             err ? err : "");
                sqlite3_free(err);
            }
        }
    }
#endif

    migrate();
    return true;
}

// ── Проверка существования колонки ───────────────────────────────────────────

bool StorageManager::hasColumn(const char* table, const char* col) const {
    const std::string sql = std::string("PRAGMA table_info(") + table + ")";
    Stmt st;
    if (sqlite3_prepare_v2(m_db, sql.c_str(), -1, st.ptr(), nullptr) != SQLITE_OK)
        return false;
    while (sqlite3_step(st.get()) == SQLITE_ROW) {
        const unsigned char* nm = sqlite3_column_text(st.get(), 1);
        if (nm && std::strcmp(reinterpret_cast<const char*>(nm), col) == 0)
            return true;
    }
    return false;
}

// ── Миграция схемы ───────────────────────────────────────────────────────────

void StorageManager::migrate() {
    execSql(m_db, "PRAGMA journal_mode=WAL");
    execSql(m_db, "PRAGMA foreign_keys=ON");
    execSql(m_db, "PRAGMA secure_delete=ON");

    execSql(m_db, R"(
        CREATE TABLE IF NOT EXISTS contacts (
            uuid         TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            ip           TEXT,
            port         INTEGER DEFAULT 0,
            identity_key BLOB
        )
    )");

    execSql(m_db, R"(
        CREATE TABLE IF NOT EXISTS messages (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_uuid  TEXT NOT NULL,
            outgoing   INTEGER NOT NULL DEFAULT 0,
            text       TEXT NOT NULL DEFAULT '',
            file_name  TEXT,
            file_size  INTEGER DEFAULT 0,
            ciphertext BLOB,
            timestamp  TEXT NOT NULL,
            delivered  INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(peer_uuid) REFERENCES contacts(uuid)
        )
    )");

    execSql(m_db, "CREATE INDEX IF NOT EXISTS idx_msg_peer ON messages(peer_uuid, timestamp DESC)");
    execSql(m_db, "CREATE INDEX IF NOT EXISTS idx_msg_id   ON messages(peer_uuid, id DESC)");

    execSql(m_db, R"(
        CREATE TABLE IF NOT EXISTS blocked_list (
            uuid       TEXT PRIMARY KEY,
            blocked_at TEXT NOT NULL DEFAULT ''
        )
    )");

    auto addCol = [this](const char* table, const char* col, const char* def) {
        if (!hasColumn(table, col)) {
            const std::string sql = std::string("ALTER TABLE ") + table +
                                    " ADD COLUMN " + col + " " + def;
            execSql(m_db, sql.c_str());
        }
    };

    addCol("contacts", "avatar_hash",    "TEXT DEFAULT ''");
    addCol("contacts", "avatar_path",    "TEXT DEFAULT ''");
    addCol("contacts", "is_blocked",     "INTEGER NOT NULL DEFAULT 0");
    addCol("contacts", "systeminfo_json","TEXT NOT NULL DEFAULT '{}'");
    addCol("contacts", "version_created","TEXT NOT NULL DEFAULT '0.1.0'");
    addCol("contacts", "is_muted",       "INTEGER NOT NULL DEFAULT 0");
    addCol("contacts", "last_seen",      "INTEGER NOT NULL DEFAULT 0");
    addCol("contacts", "birthday",       "TEXT NOT NULL DEFAULT ''");

    addCol("messages", "is_voice",          "INTEGER NOT NULL DEFAULT 0");
    addCol("messages", "voice_duration_ms", "INTEGER NOT NULL DEFAULT 0");
    addCol("messages", "version_created",   "TEXT NOT NULL DEFAULT '0.1.0'");

    execSql(m_db, R"(
        CREATE TABLE IF NOT EXISTS groups (
            id                 TEXT PRIMARY KEY,
            name               TEXT NOT NULL DEFAULT '',
            type               TEXT NOT NULL DEFAULT 'group',
            server_url         TEXT NOT NULL DEFAULT '',
            username           TEXT NOT NULL DEFAULT '',
            token_enc          BLOB,
            group_key_enc      BLOB,
            local_priv_key_enc BLOB,
            local_pub_key      BLOB,
            is_admin           INTEGER NOT NULL DEFAULT 0,
            joined_at          TEXT NOT NULL DEFAULT ''
        )
    )");

    execSql(m_db, R"(
        CREATE TABLE IF NOT EXISTS group_messages (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id  TEXT NOT NULL,
            sender    TEXT NOT NULL DEFAULT '',
            text      TEXT NOT NULL DEFAULT '',
            ts        INTEGER NOT NULL DEFAULT 0,
            outgoing  INTEGER NOT NULL DEFAULT 0
        )
    )");

    execSql(m_db, "CREATE INDEX IF NOT EXISTS idx_grp_msg_group ON group_messages(group_id, ts DESC)");

    execSql(m_db, R"(
        CREATE TABLE IF NOT EXISTS discovery_account (
            id            INTEGER PRIMARY KEY CHECK (id=1),
            host          TEXT NOT NULL DEFAULT '',
            port          INTEGER NOT NULL DEFAULT 0,
            username      TEXT NOT NULL DEFAULT '',
            token_enc     BLOB,
            registered_at TEXT NOT NULL DEFAULT ''
        )
    )");
}

// ── Contacts ──────────────────────────────────────────────────────────────────

bool StorageManager::addContact(const Contact& c) {
    {
        Stmt ck;
        sqlite3_prepare_v2(m_db, "SELECT COUNT(*) FROM contacts WHERE uuid=?", -1, ck.ptr(), nullptr);
        bindText(ck.get(), 1, c.uuid);
        const bool exists = sqlite3_step(ck.get()) == SQLITE_ROW &&
                            sqlite3_column_int(ck.get(), 0) > 0;

        Stmt q;
        if (exists) {
            sqlite3_prepare_v2(m_db,
                "UPDATE contacts SET name=?,ip=?,port=?,version_created=? WHERE uuid=?",
                -1, q.ptr(), nullptr);
            bindText(q.get(), 1, c.name);
            bindText(q.get(), 2, c.ip);
            sqlite3_bind_int(q.get(), 3, c.port);
            sqlite3_bind_text(q.get(), 4, kStorageAppVersion, -1, SQLITE_STATIC);
            bindText(q.get(), 5, c.uuid);
        } else {
            sqlite3_prepare_v2(m_db, R"(
                INSERT INTO contacts
                    (uuid,name,ip,port,identity_key,avatar_hash,avatar_path,
                     is_blocked,systeminfo_json,version_created)
                VALUES (?,?,?,?,?,?,?,0,?,?)
            )", -1, q.ptr(), nullptr);
            bindText(q.get(), 1, c.uuid);
            bindText(q.get(), 2, c.name);
            bindText(q.get(), 3, c.ip);
            sqlite3_bind_int(q.get(), 4, c.port);
            bindBlob(q.get(), 5, c.identityKey);
            bindText(q.get(), 6, c.avatarHash);
            bindText(q.get(), 7, c.avatarPath);
            bindText(q.get(), 8, c.systemInfoJson.empty() ? "{}" : c.systemInfoJson);
            sqlite3_bind_text(q.get(), 9, kStorageAppVersion, -1, SQLITE_STATIC);
        }
        if (sqlite3_step(q.get()) != SQLITE_DONE) {
            std::fprintf(stderr, "[Storage] addContact: %s\n", sqlite3_errmsg(m_db));
            return false;
        }
    }
    return true;
}

bool StorageManager::updateContactAddress(const std::string& uuid, const std::string& ip, uint16_t port) {
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE contacts SET ip=?,port=? WHERE uuid=?", -1, q.ptr(), nullptr);
    bindText(q.get(), 1, ip);
    sqlite3_bind_int(q.get(), 2, port);
    bindText(q.get(), 3, uuid);
    return sqlite3_step(q.get()) == SQLITE_DONE;
}

bool StorageManager::updateContactKey(const std::string& uuid, const std::vector<uint8_t>& key) {
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE contacts SET identity_key=? WHERE uuid=?", -1, q.ptr(), nullptr);
    bindBlob(q.get(), 1, key);
    bindText(q.get(), 2, uuid);
    return sqlite3_step(q.get()) == SQLITE_DONE;
}

bool StorageManager::updateContactName(const std::string& uuid, const std::string& name) {
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE contacts SET name=? WHERE uuid=?", -1, q.ptr(), nullptr);
    bindText(q.get(), 1, name);
    bindText(q.get(), 2, uuid);
    if (sqlite3_step(q.get()) != SQLITE_DONE) {
        std::fprintf(stderr, "[Storage] updateContactName: %s\n", sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

bool StorageManager::updateAvatar(const std::string& uuid, const std::string& hash, const std::string& path) {
    Stmt q;
    sqlite3_prepare_v2(m_db,
        "UPDATE contacts SET avatar_hash=?,avatar_path=? WHERE uuid=?",
        -1, q.ptr(), nullptr);
    bindText(q.get(), 1, hash);
    bindText(q.get(), 2, path);
    bindText(q.get(), 3, uuid);
    if (sqlite3_step(q.get()) != SQLITE_DONE) {
        std::fprintf(stderr, "[Storage] updateAvatar: %s\n", sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

bool StorageManager::updateContactSystemInfo(const std::string& uuid, const std::string& infoJson) {
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE contacts SET systeminfo_json=? WHERE uuid=?", -1, q.ptr(), nullptr);
    bindText(q.get(), 1, infoJson);
    bindText(q.get(), 2, uuid);
    if (sqlite3_step(q.get()) != SQLITE_DONE) {
        std::fprintf(stderr, "[Storage] updateContactSystemInfo: %s\n", sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

bool StorageManager::updateContactBirthday(const std::string& uuid, const std::string& birthday) {
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE contacts SET birthday=? WHERE uuid=?", -1, q.ptr(), nullptr);
    bindText(q.get(), 1, birthday);
    bindText(q.get(), 2, uuid);
    if (sqlite3_step(q.get()) != SQLITE_DONE) {
        std::fprintf(stderr, "[Storage] updateContactBirthday: %s\n", sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

bool StorageManager::blockContact(const std::string& uuid, bool blocked) {
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE contacts SET is_blocked=? WHERE uuid=?", -1, q.ptr(), nullptr);
    sqlite3_bind_int(q.get(), 1, blocked ? 1 : 0);
    bindText(q.get(), 2, uuid);
    if (sqlite3_step(q.get()) != SQLITE_DONE) {
        std::fprintf(stderr, "[Storage] blockContact: %s\n", sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

bool StorageManager::setContactMuted(const std::string& uuid, bool muted) {
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE contacts SET is_muted=? WHERE uuid=?", -1, q.ptr(), nullptr);
    sqlite3_bind_int(q.get(), 1, muted ? 1 : 0);
    bindText(q.get(), 2, uuid);
    if (sqlite3_step(q.get()) != SQLITE_DONE) {
        std::fprintf(stderr, "[Storage] setContactMuted: %s\n", sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

bool StorageManager::updateLastSeen(const std::string& uuid) {
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE contacts SET last_seen=? WHERE uuid=?", -1, q.ptr(), nullptr);
    sqlite3_bind_int64(q.get(), 1, nowEpochMs() / 1000);  // DB stores Unix seconds
    bindText(q.get(), 2, uuid);
    if (sqlite3_step(q.get()) != SQLITE_DONE) {
        std::fprintf(stderr, "[Storage] updateLastSeen: %s\n", sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

Contact StorageManager::getContact(const std::string& uuid) const {
    const std::string sql = std::string(kSelectContacts) + " WHERE uuid=?";
    Stmt q;
    sqlite3_prepare_v2(m_db, sql.c_str(), -1, q.ptr(), nullptr);
    bindText(q.get(), 1, uuid);
    if (sqlite3_step(q.get()) == SQLITE_ROW) return rowToContact(q.get());
    return {};
}

std::vector<Contact> StorageManager::allContacts() const {
    const std::string sql = std::string(kSelectContacts) + " ORDER BY name ASC";
    Stmt q;
    sqlite3_prepare_v2(m_db, sql.c_str(), -1, q.ptr(), nullptr);
    std::vector<Contact> list;
    while (sqlite3_step(q.get()) == SQLITE_ROW)
        list.push_back(rowToContact(q.get()));
    return list;
}

bool StorageManager::deleteContact(const std::string& uuid) {
    // If contact is blocked — preserve UUID in blocked_list before deletion
    {
        Stmt ck;
        sqlite3_prepare_v2(m_db, "SELECT is_blocked FROM contacts WHERE uuid=?",
                           -1, ck.ptr(), nullptr);
        bindText(ck.get(), 1, uuid);
        if (sqlite3_step(ck.get()) == SQLITE_ROW && sqlite3_column_int(ck.get(), 0) != 0) {
            Stmt bl;
            sqlite3_prepare_v2(m_db,
                "INSERT OR REPLACE INTO blocked_list (uuid,blocked_at) VALUES (?,?)",
                -1, bl.ptr(), nullptr);
            bindText(bl.get(), 1, uuid);
            bindText(bl.get(), 2, epochMsToIso(nowEpochMs()));
            sqlite3_step(bl.get());
        }
    }

    {
        Stmt dm;
        sqlite3_prepare_v2(m_db, "DELETE FROM messages WHERE peer_uuid=?", -1, dm.ptr(), nullptr);
        bindText(dm.get(), 1, uuid);
        sqlite3_step(dm.get());
    }

    Stmt dc;
    sqlite3_prepare_v2(m_db, "DELETE FROM contacts WHERE uuid=?", -1, dc.ptr(), nullptr);
    bindText(dc.get(), 1, uuid);
    const bool ok = sqlite3_step(dc.get()) == SQLITE_DONE;
    if (!ok) std::fprintf(stderr, "[Storage] deleteContact: %s\n", sqlite3_errmsg(m_db));
    return ok;
}

bool StorageManager::isUuidBlocked(const std::string& uuid) const {
    Stmt q;
    sqlite3_prepare_v2(m_db, "SELECT COUNT(*) FROM blocked_list WHERE uuid=?", -1, q.ptr(), nullptr);
    bindText(q.get(), 1, uuid);
    return sqlite3_step(q.get()) == SQLITE_ROW && sqlite3_column_int(q.get(), 0) > 0;
}

bool StorageManager::clearMessages(const std::string& uuid) {
    Stmt q;
    sqlite3_prepare_v2(m_db, "DELETE FROM messages WHERE peer_uuid=?", -1, q.ptr(), nullptr);
    bindText(q.get(), 1, uuid);
    if (sqlite3_step(q.get()) != SQLITE_DONE) {
        std::fprintf(stderr, "[Storage] clearMessages: %s\n", sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

// ── Messages ──────────────────────────────────────────────────────────────────

int64_t StorageManager::saveMessage(const Message& msg) {
    Stmt q;
    sqlite3_prepare_v2(m_db, R"(
        INSERT INTO messages
            (peer_uuid,outgoing,text,file_name,file_size,ciphertext,
             timestamp,delivered,is_voice,voice_duration_ms,version_created)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    )", -1, q.ptr(), nullptr);

    bindText(q.get(),  1, msg.peerUuid);
    sqlite3_bind_int(q.get(),  2, msg.outgoing ? 1 : 0);
    bindText(q.get(),  3, msg.text);
    if (msg.fileName.empty()) sqlite3_bind_null(q.get(), 4);
    else                      bindText(q.get(), 4, msg.fileName);
    sqlite3_bind_int64(q.get(), 5, msg.fileSize);
    bindBlob(q.get(),  6, msg.ciphertext);
    bindText(q.get(),  7, epochMsToIso(msg.timestamp));
    sqlite3_bind_int(q.get(),  8, msg.delivered ? 1 : 0);
    sqlite3_bind_int(q.get(),  9, msg.isVoice ? 1 : 0);
    sqlite3_bind_int(q.get(), 10, msg.voiceDurationMs);
    sqlite3_bind_text(q.get(),11, kStorageAppVersion, -1, SQLITE_STATIC);

    if (sqlite3_step(q.get()) != SQLITE_DONE) {
        std::fprintf(stderr, "[Storage] saveMessage: %s\n", sqlite3_errmsg(m_db));
        return -1;
    }
    return static_cast<int64_t>(sqlite3_last_insert_rowid(m_db));
}

std::vector<Message> StorageManager::getMessages(const std::string& peerUuid,
                                                   int limit, int offset) const {
    const char* rawSql = R"(
        SELECT id,peer_uuid,outgoing,text,file_name,file_size,ciphertext,
               timestamp,delivered,is_voice,voice_duration_ms,version_created
        FROM (
            SELECT id,peer_uuid,outgoing,text,file_name,file_size,ciphertext,
                   timestamp,delivered,is_voice,voice_duration_ms,version_created
            FROM messages WHERE peer_uuid=?
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        ) ORDER BY id ASC
    )";
    Stmt q;
    sqlite3_prepare_v2(m_db, rawSql, -1, q.ptr(), nullptr);
    bindText(q.get(), 1, peerUuid);
    sqlite3_bind_int(q.get(), 2, limit);
    sqlite3_bind_int(q.get(), 3, offset);

    std::vector<Message> list;
    while (sqlite3_step(q.get()) == SQLITE_ROW)
        list.push_back(rowToMessage(q.get()));
    return list;
}

bool StorageManager::markDelivered(int64_t msgId) {
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE messages SET delivered=1 WHERE id=?", -1, q.ptr(), nullptr);
    sqlite3_bind_int64(q.get(), 1, msgId);
    return sqlite3_step(q.get()) == SQLITE_DONE;
}

std::string StorageManager::lastMessageText(const std::string& peerUuid) const {
    Stmt q;
    sqlite3_prepare_v2(m_db,
        "SELECT text,file_name FROM messages WHERE peer_uuid=? ORDER BY timestamp DESC LIMIT 1",
        -1, q.ptr(), nullptr);
    bindText(q.get(), 1, peerUuid);
    if (sqlite3_step(q.get()) != SQLITE_ROW) return {};
    const std::string fname = colText(q.get(), 1);
    return fname.empty() ? colText(q.get(), 0) : "[Файл: " + fname + "]";
}

int64_t StorageManager::lastMessageTime(const std::string& peerUuid) const {
    Stmt q;
    sqlite3_prepare_v2(m_db,
        "SELECT timestamp FROM messages WHERE peer_uuid=? ORDER BY timestamp DESC LIMIT 1",
        -1, q.ptr(), nullptr);
    bindText(q.get(), 1, peerUuid);
    if (sqlite3_step(q.get()) != SQLITE_ROW) return 0;
    return isoToEpochMs(colText(q.get(), 0));
}

// ── Groups ────────────────────────────────────────────────────────────────────

bool StorageManager::saveGroup(const Group& g) {
    const auto& kp = KeyProtector::instance();
    Bytes tokenEnc, keyEnc, privEnc;
    if (kp.isReady()) {
        if (!g.token.empty()) {
            const Bytes plain(g.token.begin(), g.token.end());
            tokenEnc = kp.encrypt(plain);
        }
        if (!g.groupKey.empty())   keyEnc  = kp.encrypt(g.groupKey);
        if (!g.localPrivKey.empty()) privEnc = kp.encrypt(g.localPrivKey);
    }

    Stmt q;
    sqlite3_prepare_v2(m_db, R"(
        INSERT OR REPLACE INTO groups
            (id,name,type,server_url,username,token_enc,group_key_enc,
             local_priv_key_enc,local_pub_key,is_admin,joined_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    )", -1, q.ptr(), nullptr);

    bindText(q.get(),  1, g.id);
    bindText(q.get(),  2, g.name);
    sqlite3_bind_text(q.get(), 3,
                      g.type == GroupType::Channel ? "channel" : "group",
                      -1, SQLITE_STATIC);
    bindText(q.get(),  4, g.serverUrl);
    bindText(q.get(),  5, g.username);
    bindBlob(q.get(),  6, tokenEnc);
    bindBlob(q.get(),  7, keyEnc);
    bindBlob(q.get(),  8, privEnc);
    bindBlob(q.get(),  9, g.localPubKey);
    sqlite3_bind_int(q.get(), 10, g.isAdmin ? 1 : 0);
    bindText(q.get(), 11, epochMsToIso(g.joinedAt > 0 ? g.joinedAt : nowEpochMs()));

    if (sqlite3_step(q.get()) != SQLITE_DONE) {
        std::fprintf(stderr, "[Storage] saveGroup: %s\n", sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

bool StorageManager::updateGroupToken(const std::string& groupId, const std::string& token) {
    const auto& kp = KeyProtector::instance();
    Bytes enc;
    if (kp.isReady() && !token.empty()) {
        const Bytes plain(token.begin(), token.end());
        enc = kp.encrypt(plain);
    }
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE groups SET token_enc=? WHERE id=?", -1, q.ptr(), nullptr);
    bindBlob(q.get(), 1, enc);
    bindText(q.get(), 2, groupId);
    return sqlite3_step(q.get()) == SQLITE_DONE;
}

bool StorageManager::updateGroupKey(const std::string& groupId, const std::vector<uint8_t>& key) {
    const auto& kp = KeyProtector::instance();
    const Bytes enc = kp.isReady() ? kp.encrypt(key) : key;
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE groups SET group_key_enc=? WHERE id=?", -1, q.ptr(), nullptr);
    bindBlob(q.get(), 1, enc);
    bindText(q.get(), 2, groupId);
    return sqlite3_step(q.get()) == SQLITE_DONE;
}

bool StorageManager::updateGroupName(const std::string& groupId, const std::string& name) {
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE groups SET name=? WHERE id=?", -1, q.ptr(), nullptr);
    bindText(q.get(), 1, name);
    bindText(q.get(), 2, groupId);
    return sqlite3_step(q.get()) == SQLITE_DONE;
}

bool StorageManager::setGroupAdmin(const std::string& groupId, bool isAdmin) {
    Stmt q;
    sqlite3_prepare_v2(m_db, "UPDATE groups SET is_admin=? WHERE id=?", -1, q.ptr(), nullptr);
    sqlite3_bind_int(q.get(), 1, isAdmin ? 1 : 0);
    bindText(q.get(), 2, groupId);
    return sqlite3_step(q.get()) == SQLITE_DONE;
}

Group StorageManager::getGroup(const std::string& groupId) const {
    const std::string sql = std::string(kSelectGroups) + " WHERE id=?";
    Stmt q;
    sqlite3_prepare_v2(m_db, sql.c_str(), -1, q.ptr(), nullptr);
    bindText(q.get(), 1, groupId);
    if (sqlite3_step(q.get()) == SQLITE_ROW) return rowToGroup(q.get());
    return {};
}

std::vector<Group> StorageManager::allGroups() const {
    const std::string sql = std::string(kSelectGroups) + " ORDER BY name ASC";
    Stmt q;
    sqlite3_prepare_v2(m_db, sql.c_str(), -1, q.ptr(), nullptr);
    std::vector<Group> list;
    while (sqlite3_step(q.get()) == SQLITE_ROW)
        list.push_back(rowToGroup(q.get()));
    return list;
}

bool StorageManager::deleteGroup(const std::string& groupId) {
    {
        Stmt q;
        sqlite3_prepare_v2(m_db, "DELETE FROM group_messages WHERE group_id=?", -1, q.ptr(), nullptr);
        bindText(q.get(), 1, groupId);
        sqlite3_step(q.get());
    }
    Stmt q;
    sqlite3_prepare_v2(m_db, "DELETE FROM groups WHERE id=?", -1, q.ptr(), nullptr);
    bindText(q.get(), 1, groupId);
    return sqlite3_step(q.get()) == SQLITE_DONE;
}

// ── Group Messages ────────────────────────────────────────────────────────────

int64_t StorageManager::saveGroupMessage(const GroupMessage& msg) {
    Stmt q;
    sqlite3_prepare_v2(m_db,
        "INSERT INTO group_messages (group_id,sender,text,ts,outgoing) VALUES (?,?,?,?,?)",
        -1, q.ptr(), nullptr);
    bindText(q.get(), 1, msg.groupId);
    bindText(q.get(), 2, msg.sender);
    bindText(q.get(), 3, msg.text);
    sqlite3_bind_int64(q.get(), 4, msg.ts);
    sqlite3_bind_int(q.get(), 5, msg.outgoing ? 1 : 0);
    if (sqlite3_step(q.get()) != SQLITE_DONE) {
        std::fprintf(stderr, "[Storage] saveGroupMessage: %s\n", sqlite3_errmsg(m_db));
        return -1;
    }
    return static_cast<int64_t>(sqlite3_last_insert_rowid(m_db));
}

std::vector<GroupMessage> StorageManager::getGroupMessages(const std::string& groupId,
                                                            int limit, int offset) const {
    Stmt q;
    sqlite3_prepare_v2(m_db, R"(
        SELECT id,group_id,sender,text,ts,outgoing
        FROM (
            SELECT id,group_id,sender,text,ts,outgoing
            FROM group_messages WHERE group_id=?
            ORDER BY ts DESC
            LIMIT ? OFFSET ?
        ) ORDER BY ts ASC
    )", -1, q.ptr(), nullptr);
    bindText(q.get(), 1, groupId);
    sqlite3_bind_int(q.get(), 2, limit);
    sqlite3_bind_int(q.get(), 3, offset);

    std::vector<GroupMessage> list;
    while (sqlite3_step(q.get()) == SQLITE_ROW) {
        GroupMessage m;
        m.id       = sqlite3_column_int64(q.get(), 0);
        m.groupId  = colText(q.get(), 1);
        m.sender   = colText(q.get(), 2);
        m.text     = colText(q.get(), 3);
        m.ts       = sqlite3_column_int64(q.get(), 4);
        m.outgoing = sqlite3_column_int(q.get(), 5) != 0;
        list.push_back(m);
    }
    return list;
}

std::string StorageManager::lastGroupMessageText(const std::string& groupId) const {
    Stmt q;
    sqlite3_prepare_v2(m_db,
        "SELECT text,sender FROM group_messages WHERE group_id=? ORDER BY ts DESC LIMIT 1",
        -1, q.ptr(), nullptr);
    bindText(q.get(), 1, groupId);
    if (sqlite3_step(q.get()) != SQLITE_ROW) return {};
    const std::string sender = colText(q.get(), 1);
    const std::string text   = colText(q.get(), 0);
    return sender.empty() ? text : sender + ": " + text;
}

// ── Discovery account ─────────────────────────────────────────────────────────

bool StorageManager::saveDiscoveryAccount(const DiscoveryAccount& a) {
    const auto& kp = KeyProtector::instance();
    Bytes tokenEnc;
    if (kp.isReady() && !a.token.empty()) {
        const Bytes plain(a.token.begin(), a.token.end());
        tokenEnc = kp.encrypt(plain);
    }

    Stmt q;
    sqlite3_prepare_v2(m_db, R"(
        INSERT INTO discovery_account (id,host,port,username,token_enc,registered_at)
        VALUES (1,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            host=excluded.host, port=excluded.port, username=excluded.username,
            token_enc=excluded.token_enc, registered_at=excluded.registered_at
    )", -1, q.ptr(), nullptr);

    bindText(q.get(), 1, a.host);
    sqlite3_bind_int(q.get(), 2, a.port);
    bindText(q.get(), 3, a.username);
    bindBlob(q.get(), 4, tokenEnc);
    bindText(q.get(), 5, epochMsToIso(a.registeredAt > 0 ? a.registeredAt : nowEpochMs()));

    if (sqlite3_step(q.get()) != SQLITE_DONE) {
        std::fprintf(stderr, "[Storage] saveDiscoveryAccount: %s\n", sqlite3_errmsg(m_db));
        return false;
    }
    return true;
}

DiscoveryAccount StorageManager::getDiscoveryAccount() const {
    Stmt q;
    sqlite3_prepare_v2(m_db,
        "SELECT host,port,username,token_enc,registered_at FROM discovery_account WHERE id=1",
        -1, q.ptr(), nullptr);
    if (sqlite3_step(q.get()) != SQLITE_ROW) return {};

    DiscoveryAccount a;
    a.host         = colText(q.get(), 0);
    a.port         = static_cast<uint16_t>(sqlite3_column_int(q.get(), 1));
    a.username     = colText(q.get(), 2);
    a.registeredAt = isoToEpochMs(colText(q.get(), 4));

    const auto& kp = KeyProtector::instance();
    if (kp.isReady()) {
        const Bytes encTok = colBlob(q.get(), 3);
        if (!encTok.empty()) {
            const Bytes plain = kp.decrypt(encTok);
            a.token = std::string(plain.begin(), plain.end());
        }
    }
    return a;
}

bool StorageManager::clearDiscoveryAccount() {
    Stmt q;
    sqlite3_prepare_v2(m_db, "DELETE FROM discovery_account WHERE id=1", -1, q.ptr(), nullptr);
    return sqlite3_step(q.get()) == SQLITE_DONE;
}
