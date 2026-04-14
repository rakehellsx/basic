/*
 * DbStorage.cpp
 * SQLite3 数据库存储封装层实现
 */
#include "DbStorage.h"
#include "../../third_party/sqlite3/sqlite3.h"
#include <windows.h>
#include <time.h>
#include <sstream>

/* -----------------------------------------------------------------------
 * 内部工具：获取当前 UTC 时间字符串
 * --------------------------------------------------------------------- */
static std::string NowUtcString()
{
    time_t t = time(NULL);
    struct tm tmVal;
    gmtime_s(&tmVal, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmVal);
    return buf;
}

/* -----------------------------------------------------------------------
 * 构造 / 析构
 * --------------------------------------------------------------------- */
DbStorage::DbStorage() : m_db(NULL) {}

DbStorage::~DbStorage()
{
    Close();
}

/* -----------------------------------------------------------------------
 * Open：打开或创建数据库文件
 * --------------------------------------------------------------------- */
bool DbStorage::Open(const std::string& dbPath)
{
    if (m_db) Close();

    int rc = sqlite3_open(dbPath.c_str(),
                          reinterpret_cast<sqlite3**>(&m_db));
    if (rc != SQLITE_OK)
    {
        m_lastError = sqlite3_errmsg(
            reinterpret_cast<sqlite3*>(m_db));
        sqlite3_close(reinterpret_cast<sqlite3*>(m_db));
        m_db = NULL;
        return false;
    }

    /* 开启 WAL 模式，提升并发写入性能 */
    sqlite3_exec(reinterpret_cast<sqlite3*>(m_db),
                 "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);

    return CreateTable();
}

/* -----------------------------------------------------------------------
 * Close
 * --------------------------------------------------------------------- */
void DbStorage::Close()
{
    if (m_db)
    {
        sqlite3_close(reinterpret_cast<sqlite3*>(m_db));
        m_db = NULL;
    }
}

bool DbStorage::IsOpen() const
{
    return m_db != NULL;
}

std::string DbStorage::LastError() const
{
    return m_lastError;
}

/* -----------------------------------------------------------------------
 * CreateTable：自动建表（若不存在）
 *
 * 表结构：detection_results
 *   id           INTEGER  PRIMARY KEY AUTOINCREMENT
 *   module_name  TEXT     NOT NULL   -- 模块名称
 *   params_json  TEXT               -- 调用参数
 *   result_json  TEXT               -- 检测结果（完整 JSON）
 *   created_at   TEXT               -- 记录时间（UTC）
 * --------------------------------------------------------------------- */
bool DbStorage::CreateTable()
{
    const char* sql =
        "CREATE TABLE IF NOT EXISTS detection_results ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  module_name TEXT    NOT NULL,"
        "  params_json TEXT,"
        "  result_json TEXT,"
        "  created_at  TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_module_name "
        "  ON detection_results(module_name);"
        "CREATE INDEX IF NOT EXISTS idx_created_at "
        "  ON detection_results(created_at);";

    char* errMsg = NULL;
    int rc = sqlite3_exec(reinterpret_cast<sqlite3*>(m_db),
                          sql, NULL, NULL, &errMsg);
    if (rc != SQLITE_OK)
    {
        m_lastError = errMsg ? errMsg : "CreateTable failed";
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

/* -----------------------------------------------------------------------
 * SaveResult：插入一条检测记录
 * --------------------------------------------------------------------- */
long long DbStorage::SaveResult(const std::string& moduleName,
                                const std::string& paramsJson,
                                const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }

    const char* sql =
        "INSERT INTO detection_results "
        "(module_name, params_json, result_json, created_at) "
        "VALUES (?, ?, ?, ?);";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(
        reinterpret_cast<sqlite3*>(m_db), sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK)
    {
        m_lastError = sqlite3_errmsg(reinterpret_cast<sqlite3*>(m_db));
        return -1;
    }

    std::string now = NowUtcString();
    sqlite3_bind_text(stmt, 1, moduleName.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, paramsJson.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, resultJson.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, now.c_str(),         -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE)
    {
        m_lastError = sqlite3_errmsg(reinterpret_cast<sqlite3*>(m_db));
        return -1;
    }

    return (long long)sqlite3_last_insert_rowid(
        reinterpret_cast<sqlite3*>(m_db));
}

/* -----------------------------------------------------------------------
 * QueryByModule：按模块名查询最近 N 条记录
 * --------------------------------------------------------------------- */
std::vector<DetectionRecord> DbStorage::QueryByModule(
    const std::string& moduleName, int limit)
{
    std::vector<DetectionRecord> records;
    if (!m_db) return records;

    std::string sql;
    if (moduleName.empty())
    {
        sql = "SELECT id, module_name, params_json, result_json, created_at "
              "FROM detection_results "
              "ORDER BY id DESC LIMIT ?;";
    }
    else
    {
        sql = "SELECT id, module_name, params_json, result_json, created_at "
              "FROM detection_results "
              "WHERE module_name = ? "
              "ORDER BY id DESC LIMIT ?;";
    }

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(
        reinterpret_cast<sqlite3*>(m_db), sql.c_str(), -1, &stmt, NULL);
    if (rc != SQLITE_OK) return records;

    if (moduleName.empty())
    {
        sqlite3_bind_int(stmt, 1, limit);
    }
    else
    {
        sqlite3_bind_text(stmt, 1, moduleName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, limit);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        DetectionRecord rec;
        rec.id          = sqlite3_column_int64(stmt, 0);

        const char* mn  = (const char*)sqlite3_column_text(stmt, 1);
        const char* pj  = (const char*)sqlite3_column_text(stmt, 2);
        const char* rj  = (const char*)sqlite3_column_text(stmt, 3);
        const char* ca  = (const char*)sqlite3_column_text(stmt, 4);

        rec.module_name = mn ? mn : "";
        rec.params_json = pj ? pj : "";
        rec.result_json = rj ? rj : "";
        rec.created_at  = ca ? ca : "";

        records.push_back(rec);
    }

    sqlite3_finalize(stmt);
    return records;
}
