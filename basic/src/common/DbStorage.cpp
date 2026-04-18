/*
 * DbStorage.cpp  —  SQLite3 字段级存储封装层实现
 *
 * 所有字段单独作为列存储，不使用 JSON 字段。
 * 列表型模块采用 snapshot_id 关联同一次采集的多条子记录。
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "DbStorage.h"
#include "../../third_party/sqlite3/sqlite3.h"
#include "../../third_party/cJSON/cJSON.h"
#include <windows.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>

/* -----------------------------------------------------------------------
 * 内部工具
 * --------------------------------------------------------------------- */
static std::string NowUtc()
{
    time_t t = time(NULL);
    struct tm tm0;
    gmtime_s(&tm0, &t);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm0);
    return buf;
}

/* 安全取 cJSON 字符串值，NULL 时返回空串 */
static std::string JStr(cJSON* obj, const char* key)
{
    if (!obj) return "";
    cJSON* item = cJSON_GetObjectItem(obj, key);
    if (!item || !cJSON_IsString(item) || !item->valuestring) return "";
    return item->valuestring;
}

/* 安全取 cJSON 数字值 */
static double JNum(cJSON* obj, const char* key, double def = 0.0)
{
    if (!obj) return def;
    cJSON* item = cJSON_GetObjectItem(obj, key);
    if (!item || !cJSON_IsNumber(item)) return def;
    return item->valuedouble;
}

/* 安全取 cJSON bool 值 */
static int JBool(cJSON* obj, const char* key, int def = 0)
{
    if (!obj) return def;
    cJSON* item = cJSON_GetObjectItem(obj, key);
    if (!item) return def;
    if (cJSON_IsTrue(item))  return 1;
    if (cJSON_IsFalse(item)) return 0;
    if (cJSON_IsNumber(item)) return item->valueint ? 1 : 0;
    return def;
}

/* -----------------------------------------------------------------------
 * 构造 / 析构
 * --------------------------------------------------------------------- */
DbStorage::DbStorage() : m_db(NULL) {}
DbStorage::~DbStorage() { Close(); }

/* -----------------------------------------------------------------------
 * Open
 * --------------------------------------------------------------------- */
bool DbStorage::Open(const std::string& dbPath)
{
    if (m_db) Close();
    int rc = sqlite3_open(dbPath.c_str(),
                          reinterpret_cast<sqlite3**>(&m_db));
    if (rc != SQLITE_OK)
    {
        m_lastError = sqlite3_errmsg(reinterpret_cast<sqlite3*>(m_db));
        sqlite3_close(reinterpret_cast<sqlite3*>(m_db));
        m_db = NULL;
        return false;
    }
    sqlite3_exec(reinterpret_cast<sqlite3*>(m_db),
                 "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    return CreateAllTables();
}

void DbStorage::Close()
{
    if (m_db) { sqlite3_close(reinterpret_cast<sqlite3*>(m_db)); m_db = NULL; }
}
bool DbStorage::IsOpen() const { return m_db != NULL; }
std::string DbStorage::LastError() const { return m_lastError; }

long long DbStorage::LastInsertRowId()
{
    return (long long)sqlite3_last_insert_rowid(
        reinterpret_cast<sqlite3*>(m_db));
}

bool DbStorage::ExecSql(const char* sql)
{
    char* err = NULL;
    int rc = sqlite3_exec(reinterpret_cast<sqlite3*>(m_db),
                          sql, NULL, NULL, &err);
    if (rc != SQLITE_OK)
    {
        m_lastError = err ? err : "ExecSql failed";
        sqlite3_free(err);
        return false;
    }
    return true;
}

/* -----------------------------------------------------------------------
 * CreateAllTables  —  建立所有模块专属表
 * --------------------------------------------------------------------- */
bool DbStorage::CreateAllTables()
{
    /* ---- 模块01 系统信息 ---- */
    if (!ExecSql(
        /* 快照表：每次采集一行 */
        "CREATE TABLE IF NOT EXISTS sys_info ("
        "  id                      INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  product_name            TEXT,"   /* Windows 产品名 */
        "  display_version         TEXT,"   /* 显示版本 */
        "  current_build           TEXT,"   /* 内部版本号 */
        "  ubr                     TEXT,"   /* 更新版本号 */
        "  edition_id              TEXT,"   /* 版本标识 */
        "  registered_owner        TEXT,"   /* 注册所有者 */
        "  registered_organization TEXT,"   /* 注册组织 */
        "  install_date            TEXT,"   /* 安装日期 */
        "  computer_name           TEXT,"   /* 计算机名 */
        "  system_directory        TEXT,"   /* 系统目录 */
        "  windows_directory       TEXT,"   /* Windows 目录 */
        "  processor_architecture  TEXT,"   /* 处理器架构 */
        "  number_of_processors    INTEGER,"/* 处理器数量 */
        "  total_physical_mb       INTEGER,"/* 物理内存 MB */
        "  available_physical_mb   INTEGER,"/* 可用内存 MB */
        "  memory_load_percent     INTEGER,"/* 内存使用率 */
        "  created_at              TEXT"
        ");"
        /* 账户子表 */
        "CREATE TABLE IF NOT EXISTS sys_accounts ("
        "  id                      INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id             INTEGER NOT NULL,"  /* 关联 sys_info.id */
        "  username                TEXT,"
        "  full_name               TEXT,"
        "  comment                 TEXT,"
        "  priv                    TEXT,"
        "  disabled                INTEGER,"
        "  password_never_expires  INTEGER,"
        "  lockout                 INTEGER,"
        "  last_logon              TEXT,"
        "  created_at              TEXT,"
        "  FOREIGN KEY(snapshot_id) REFERENCES sys_info(id)"
        ");"
    )) return false;

    /* ---- 模块02 网络信息 ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS network_adapters ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"  /* 同一次采集批次 */
        "  adapter_name    TEXT,"   /* 网卡名称 */
        "  description     TEXT,"   /* 描述 */
        "  mac_address     TEXT,"   /* MAC 地址 */
        "  ip_address      TEXT,"   /* IPv4 地址（逗号分隔多个） */
        "  subnet_mask     TEXT,"   /* 子网掩码 */
        "  gateway         TEXT,"   /* 默认网关 */
        "  dns_servers     TEXT,"   /* DNS 服务器（逗号分隔） */
        "  dhcp_enabled    INTEGER,"/* 是否启用 DHCP */
        "  dhcp_server     TEXT,"   /* DHCP 服务器 */
        "  adapter_type    TEXT,"   /* 网卡类型 */
        "  status          TEXT,"   /* 状态（up/down） */
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS network_snapshots ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at  TEXT"
        ");"
    )) return false;

    /* ---- 模块03 硬盘信息 ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS disk_physical ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  device_id       TEXT,"   /* 设备标识，如 PhysicalDrive0 */
        "  vendor          TEXT,"   /* 厂商 */
        "  model           TEXT,"   /* 型号 */
        "  serial_number   TEXT,"   /* 序列号 */
        "  total_bytes     INTEGER,"/* 总容量（字节） */
        "  power_on_count  INTEGER,"/* 启动次数 */
        "  power_on_hours  INTEGER,"/* 累计使用时间（小时） */
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS disk_volumes ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  drive_letter    TEXT,"   /* 盘符，如 C:，隐藏分区可能为空 */
        "  volume_name     TEXT,"   /* 卷标 */
        "  volume_guid     TEXT,"   /* 卷GUID路径 */
        "  file_system     TEXT,"   /* 文件系统类型 */
        "  drive_type      TEXT,"   /* 驱动器类型 */
        "  total_bytes     INTEGER,"/* 总大小（字节） */
        "  free_bytes      INTEGER,"/* 可用大小（字节） */
        "  used_bytes      INTEGER,"/* 已用大小（字节） */
        "  serial_number   TEXT,"   /* 卷序列号 */
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS disk_snapshots ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at  TEXT"
        ");"
    )) return false;

    /* ---- 模块04 自启动信息 ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS autorun_items ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  source          TEXT,"   /* 来源（注册表路径/启动目录等） */
        "  name            TEXT,"   /* 项名称 */
        "  command         TEXT,"   /* 命令行 */
        "  publisher       TEXT,"   /* 发行商 */
        "  file_path       TEXT,"   /* 可执行文件路径 */
        "  is_signed       INTEGER,"/* 是否有签名 */
        "  sign_valid      INTEGER,"/* 签名是否有效 */
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS autorun_context_menu ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  menu_item       TEXT,"
        "  reg_path        TEXT,"
        "  command         TEXT,"
        "  risk_level      TEXT,"
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS autorun_debugger ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  target_program  TEXT,"
        "  debugger_path   TEXT,"
        "  risk_level      TEXT,"
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS autorun_snapshots ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at  TEXT"
        ");"
    )) return false;

    /* ---- 模块05 进程信息 ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS process_list ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  pid             INTEGER,"/* 进程 ID */
        "  ppid            INTEGER,"/* 父进程 ID */
        "  process_name    TEXT,"   /* 进程名 */
        "  exe_path        TEXT,"   /* 可执行文件路径 */
        "  command_line    TEXT,"   /* 命令行 */
        "  user_name       TEXT,"   /* 所属用户 */
        "  session_id      INTEGER,"/* 会话 ID */
        "  priority        INTEGER,"/* 优先级 */
        "  thread_count    INTEGER,"/* 线程数 */
        "  handle_count    INTEGER,"/* 句柄数 */
        "  memory_kb       INTEGER,"/* 内存占用 KB */
        "  cpu_time_ms     INTEGER,"/* CPU 时间（毫秒） */
        "  start_time      TEXT,"   /* 启动时间 */
        "  is_signed       INTEGER,"/* 是否有签名 */
        "  sign_valid      INTEGER,"/* 签名是否有效 */
        "  publisher       TEXT,"   /* 发行商 */
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS process_snapshots ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at  TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_proc_pid "
        "  ON process_list(pid);"
        "CREATE INDEX IF NOT EXISTS idx_proc_snap "
        "  ON process_list(snapshot_id);"
    )) return false;

    /* ---- 模块06 计划任务 ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS scheduled_tasks ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  task_name       TEXT,"   /* 任务名称 */
        "  task_path       TEXT,"   /* 任务路径 */
        "  status          TEXT,"   /* 状态（Ready/Running/Disabled 等） */
        "  last_run_time   TEXT,"   /* 上次运行时间 */
        "  next_run_time   TEXT,"   /* 下次运行时间 */
        "  run_as_user     TEXT,"   /* 运行账户 */
        "  action_type     TEXT,"   /* 操作类型（Exec/ComHandler 等） */
        "  action_path     TEXT,"   /* 可执行文件路径 */
        "  action_args     TEXT,"   /* 参数 */
        "  trigger_type    TEXT,"   /* 触发器类型 */
        "  trigger_start   TEXT,"   /* 触发器起始时间 */
        "  enabled         INTEGER,"/* 是否启用 */
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS task_snapshots ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at  TEXT"
        ");"
    )) return false;

    /* ---- 模块07 端口信息 ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS port_connections ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  protocol        TEXT,"   /* TCP / UDP */
        "  local_address   TEXT,"   /* 本地地址 */
        "  local_port      INTEGER,"/* 本地端口 */
        "  remote_address  TEXT,"   /* 远端地址 */
        "  remote_port     INTEGER,"/* 远端端口 */
        "  state           TEXT,"   /* 连接状态（LISTEN/ESTABLISHED 等） */
        "  pid             INTEGER,"/* 进程 ID */
        "  process_name    TEXT,"   /* 进程名 */
        "  process_path    TEXT,"   /* 进程路径（新增） */
        "  exe_path        TEXT,"   /* 可执行文件路径（旧版兼容） */
        "  publisher       TEXT,"   /* 发行商 */
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS port_snapshots ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at  TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_port_snap "
        "  ON port_connections(snapshot_id);"
        "CREATE INDEX IF NOT EXISTS idx_port_local "
        "  ON port_connections(local_port);"
    )) return false;

    /* ---- 模块08 共享资源 ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS shared_resources ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  share_name      TEXT,"   /* 共享名 */
        "  share_path      TEXT,"   /* 本地路径 */
        "  share_type      TEXT,"   /* 类型（Disk/Printer/IPC 等） */
        "  remark          TEXT,"   /* 备注 */
        "  max_uses        INTEGER,"/* 最大连接数 */
        "  current_uses    INTEGER,"/* 当前连接数 */
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS share_snapshots ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at  TEXT"
        ");"
    )) return false;

    /* ---- 新增：服务信息 ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS service_list ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  service_name    TEXT,"
        "  display_name    TEXT,"
        "  description     TEXT,"
        "  executable_path TEXT,"
        "  start_type      TEXT,"
        "  service_type    TEXT,"
        "  state           TEXT,"
        "  account_name    TEXT,"
        "  publisher       TEXT,"
        "  is_signed       INTEGER,"
        "  sign_valid      INTEGER,"
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS service_snapshots ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at  TEXT"
        ");"
    )) return false;

    /* ---- 模块09 驱动信息 ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS driver_list ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  driver_name     TEXT,"   /* 驱动名称 */
        "  display_name    TEXT,"   /* 显示名称 */
        "  driver_path     TEXT,"   /* 驱动文件路径 */
        "  start_type      TEXT,"   /* 启动类型（Boot/System/Auto/Manual/Disabled） */
        "  service_type    TEXT,"   /* 服务类型 */
        "  state           TEXT,"   /* 当前状态（Running/Stopped 等） */
        "  description     TEXT,"   /* 描述 */
        "  publisher       TEXT,"   /* 发行商 */
        "  is_signed       INTEGER,"/* 是否有签名 */
        "  sign_valid      INTEGER,"/* 签名是否有效 */
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS driver_snapshots ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at  TEXT"
        ");"
    )) return false;

    /* ---- 模块10 浏览器插件 ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS browser_plugins ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  browser         TEXT,"   /* 浏览器（Chrome/Firefox/Edge 等） */
        "  plugin_id       TEXT,"   /* 插件 ID */
        "  plugin_name     TEXT,"   /* 插件名称 */
        "  version         TEXT,"   /* 版本 */
        "  description     TEXT,"   /* 描述 */
        "  install_path    TEXT,"   /* 安装路径 */
        "  enabled         INTEGER,"/* 是否启用 */
        "  is_signed       INTEGER,"/* 是否有签名 */
        "  sign_valid      INTEGER,"/* 签名是否有效 */
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS plugin_snapshots ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at  TEXT"
        ");"
    )) return false;

    /* ---- 模块11 内核模块（内存映像） ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS kernel_modules ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id     INTEGER NOT NULL,"
        "  load_order      INTEGER,"/* 加载序号 */
        "  module_name     TEXT,"   /* 模块文件名 */
        "  full_path       TEXT,"   /* 完整路径 */
        "  base_address    TEXT,"   /* 基址（十六进制） */
        "  image_size      INTEGER,"/* 映像大小（字节） */
        "  load_count      INTEGER,"/* 引用计数 */
        "  flags_hex       TEXT,"   /* 标志（十六进制） */
        "  flags_desc      TEXT,"   /* 标志描述 */
        "  trust_status    TEXT,"   /* 签名状态 */
        "  modify_time     TEXT,"   /* 文件修改时间 */
        "  created_at      TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS kernel_snapshots ("
        "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  created_at  TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_km_snap "
        "  ON kernel_modules(snapshot_id);"
    )) return false;

    /* ---- 模块12 数字证书 ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS cert_info ("
        "  id                  INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  file_path           TEXT,"   /* 被检测文件路径 */
        "  file_sha1           TEXT,"   /* 文件 SHA1 */
        "  file_sha256         TEXT,"   /* 文件 SHA256 */
        "  has_signature       INTEGER,"/* 是否有签名 */
        "  signature_valid     INTEGER,"/* 签名是否有效 */
        "  file_tampered       INTEGER,"/* 文件是否被篡改 */
        "  tamper_detail       TEXT,"   /* 篡改详情 */
        "  verify_result       TEXT,"   /* 验证结果描述 */
        "  subject             TEXT,"   /* 证书使用者 */
        "  issuer              TEXT,"   /* 颁发者 */
        "  serial_number       TEXT,"   /* 序列号 */
        "  not_before          TEXT,"   /* 有效期起始 */
        "  not_after           TEXT,"   /* 有效期截止 */
        "  not_expired         INTEGER,"/* 是否在有效期内 */
        "  signature_algorithm TEXT,"   /* 签名算法 */
        "  thumbprint_sha1     TEXT,"   /* SHA1 指纹 */
        "  thumbprint_sha256   TEXT,"   /* SHA256 指纹 */
        "  is_ca               INTEGER,"/* 是否为 CA 证书 */
        "  timestamp           TEXT,"   /* 时间戳 */
        "  created_at          TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_cert_path "
        "  ON cert_info(file_path);"
    )) return false;

    /* ---- 模块14 文件关联 ---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS file_assoc_items ("
        "  id                  INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  snapshot_id         INTEGER NOT NULL,"
        "  ext                 TEXT,"   /* 扩展名，如 .txt */
        "  is_known            INTEGER,"/* 是否已知扩展名 */
        "  prog_id             TEXT,"   /* ProgID */
        "  prog_id_desc        TEXT,"   /* ProgID 描述 */
        "  open_command        TEXT,"   /* 默认打开命令 */
        "  icon_path           TEXT,"   /* 图标路径 */
        "  user_choice_prog_id TEXT,"   /* UserChoice ProgID */
        "  exe_signed          INTEGER,"/* 关联程序是否有签名 */
        "  is_tampered         INTEGER,"/* 是否被篡改 */
        "  tamper_reason       TEXT,"   /* 篡改原因 */
        "  created_at          TEXT"
        ");"
        "CREATE TABLE IF NOT EXISTS assoc_snapshots ("
        "  id              INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  total_scanned   INTEGER,"
        "  total_tampered  INTEGER,"
        "  total_unknown   INTEGER,"
        "  created_at      TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_assoc_snap "
        "  ON file_assoc_items(snapshot_id);"
        "CREATE INDEX IF NOT EXISTS idx_assoc_ext "
        "  ON file_assoc_items(ext);"
    )) return false;

    /* ---- 通用检测记录表（供 QueryModuleAndSave / QueryHistory 使用）---- */
    if (!ExecSql(
        "CREATE TABLE IF NOT EXISTS detection_records ("
        "  id           INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  module_name  TEXT NOT NULL,"
        "  params_json  TEXT,"
        "  result_json  TEXT,"
        "  created_at   TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_det_module "
        "  ON detection_records(module_name);"
    )) return false;

    return true;
}

/* =======================================================================
 * 各模块 Save* 实现
 * 统一流程：
 *   1. 解析 resultJson（cJSON）
 *   2. 插入快照/批次行（获取 snapshot_id）
 *   3. 遍历子数组，逐行插入子记录
 * ======================================================================= */

/* -----------------------------------------------------------------------
 * 内部辅助：sqlite3_prepare + bind + step 封装
 * --------------------------------------------------------------------- */
static long long InsertRow(sqlite3* db, const char* sql,
    void(*bindFn)(sqlite3_stmt*, void*), void* ctx)
{
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;
    if (bindFn) bindFn(stmt, ctx);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return -1;
    return (long long)sqlite3_last_insert_rowid(db);
}

/* -----------------------------------------------------------------------
 * 模块01 系统信息
 * --------------------------------------------------------------------- */
long long DbStorage::SaveSysInfo(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    cJSON* osInfo = cJSON_GetObjectItem(root, "os_info");
    cJSON* memInfo = cJSON_GetObjectItem(root, "memory_info");

    std::string now = NowUtc();

    /* 插入快照行 */
    const char* sqlSnap =
        "INSERT INTO sys_info ("
        "product_name, display_version, current_build, ubr, edition_id,"
        "registered_owner, registered_organization, install_date,"
        "computer_name, system_directory, windows_directory,"
        "processor_architecture, number_of_processors,"
        "total_physical_mb, available_physical_mb, memory_load_percent,"
        "created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sqlSnap, -1, &stmt, NULL) != SQLITE_OK)
    {
        m_lastError = sqlite3_errmsg(db);
        cJSON_Delete(root);
        return -1;
    }

    /* total_physical / available_physical are byte-count strings from LargeIntToString.
     * Convert to MB (divide by 1048576) before storing in *_mb INTEGER columns. */
    long long totalBytes = 0, availBytes = 0;
    {
        std::string s = JStr(memInfo, "total_physical");
        if (!s.empty()) totalBytes = _atoi64(s.c_str());
    }
    {
        std::string s = JStr(memInfo, "available_physical");
        if (!s.empty()) availBytes = _atoi64(s.c_str());
    }
    long long totalMbInt = totalBytes / (1024LL * 1024LL);
    long long availMbInt = availBytes / (1024LL * 1024LL);
    int memLoad = (int)JNum(memInfo, "memory_load_percent");

    sqlite3_bind_text (stmt,  1, JStr(osInfo, "product_name").c_str(),             -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt,  2, JStr(osInfo, "display_version").c_str(),          -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt,  3, JStr(osInfo, "current_build").c_str(),            -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt,  4, JStr(osInfo, "ubr").c_str(),                      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt,  5, JStr(osInfo, "edition_id").c_str(),               -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt,  6, JStr(osInfo, "registered_owner").c_str(),         -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt,  7, JStr(osInfo, "registered_organization").c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt,  8, JStr(osInfo, "install_date").c_str(),             -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt,  9, JStr(root,   "computer_name").c_str(),            -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 10, JStr(root,   "system_directory").c_str(),         -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 11, JStr(root,   "windows_directory").c_str(),        -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 12, JStr(root,   "processor_architecture").c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_int  (stmt, 13, (int)JNum(root, "number_of_processors"));
    sqlite3_bind_int64(stmt, 14, totalMbInt);
    sqlite3_bind_int64(stmt, 15, availMbInt);
    sqlite3_bind_int  (stmt, 16, memLoad);
    sqlite3_bind_text (stmt, 17, now.c_str(),      -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
    {
        m_lastError = sqlite3_errmsg(db);
        cJSON_Delete(root);
        return -1;
    }
    long long snapId = LastInsertRowId();

    /* 插入账户子记录 */
    cJSON* accounts = cJSON_GetObjectItem(root, "accounts");
    if (accounts && cJSON_IsArray(accounts))
    {
        const char* sqlAcc =
            "INSERT INTO sys_accounts ("
            "snapshot_id, username, full_name, comment, priv,"
            "disabled, password_never_expires, lockout, last_logon, created_at)"
            "VALUES (?,?,?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(accounts);
        for (int i = 0; i < n; i++)
        {
            cJSON* acc = cJSON_GetArrayItem(accounts, i);
            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlAcc, -1, &s2, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s2, 1, snapId);
            sqlite3_bind_text (s2, 2, JStr(acc, "username").c_str(),               -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 3, JStr(acc, "full_name").c_str(),              -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 4, JStr(acc, "comment").c_str(),                -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 5, JStr(acc, "priv").c_str(),                   -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2, 6, JBool(acc, "disabled"));
            sqlite3_bind_int  (s2, 7, JBool(acc, "password_never_expires"));
            sqlite3_bind_int  (s2, 8, JBool(acc, "lockout"));
            sqlite3_bind_text (s2, 9, JStr(acc, "last_logon").c_str(),             -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,10, now.c_str(),                                 -1, SQLITE_TRANSIENT);
            sqlite3_step(s2);
            sqlite3_finalize(s2);
        }
    }

    cJSON_Delete(root);
    return snapId;
}

/* -----------------------------------------------------------------------
 * 模块02 网络信息
 * --------------------------------------------------------------------- */
long long DbStorage::SaveNetworkInfo(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    /* 插入批次行 */
    const char* sqlSnap = "INSERT INTO network_snapshots (created_at) VALUES (?);";
    sqlite3_stmt* s0 = NULL;
    sqlite3_prepare_v2(db, sqlSnap, -1, &s0, NULL);
    sqlite3_bind_text(s0, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s0); sqlite3_finalize(s0);
    long long snapId = LastInsertRowId();

    /* 插入网卡子记录 */
    cJSON* adapters = cJSON_GetObjectItem(root, "adapters");
    if (!adapters) adapters = cJSON_GetObjectItem(root, "network_adapters");
    if (adapters && cJSON_IsArray(adapters))
    {
        const char* sqlAdp =
            "INSERT INTO network_adapters ("
            "snapshot_id, adapter_name, description, mac_address,"
            "ip_address, subnet_mask, gateway, dns_servers,"
            "dhcp_enabled, dhcp_server, adapter_type, status, created_at)"
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(adapters);
        for (int i = 0; i < n; i++)
        {
            cJSON* adp = cJSON_GetArrayItem(adapters, i);
            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlAdp, -1, &s2, NULL) != SQLITE_OK) continue;
            /* NetworkInfo.cpp stores IPs in nested unicast_addresses array;
             * extract first IPv4 address and compute subnet mask from prefix length */
            std::string ipAddr, subnetMask, gateway, dnsServers;

            cJSON* unicast = cJSON_GetObjectItem(adp, "unicast_addresses");
            if (unicast && cJSON_IsArray(unicast))
            {
                int uCount = cJSON_GetArraySize(unicast);
                for (int u = 0; u < uCount; u++)
                {
                    cJSON* ua = cJSON_GetArrayItem(unicast, u);
                    std::string fam = JStr(ua, "family");
                    if (fam == "IPv4" && ipAddr.empty())
                    {
                        ipAddr = JStr(ua, "address");
                        /* Convert prefix length to dotted subnet mask */
                        int prefix = (int)JNum(ua, "prefix_length");
                        if (prefix >= 0 && prefix <= 32)
                        {
                            unsigned int mask = prefix == 0 ? 0 : (~0u << (32 - prefix));
                            char maskBuf[20];
                            _snprintf_s(maskBuf, sizeof(maskBuf), _TRUNCATE,
                                "%u.%u.%u.%u",
                                (mask >> 24) & 0xFF, (mask >> 16) & 0xFF,
                                (mask >>  8) & 0xFF,  mask        & 0xFF);
                            subnetMask = maskBuf;
                        }
                        break;
                    }
                }
            }
            /* Fall back to flat field if present */
            if (ipAddr.empty())    ipAddr     = JStr(adp, "ip_address");
            if (subnetMask.empty()) subnetMask = JStr(adp, "subnet_mask");

            /* Gateway: first entry from gateways array, or flat field */
            cJSON* gwArr = cJSON_GetObjectItem(adp, "gateways");
            if (gwArr && cJSON_IsArray(gwArr) && cJSON_GetArraySize(gwArr) > 0)
            {
                cJSON* gw0 = cJSON_GetArrayItem(gwArr, 0);
                if (cJSON_IsString(gw0)) gateway = gw0->valuestring;
            }
            if (gateway.empty()) gateway = JStr(adp, "gateway");

            /* DNS servers: join array entries with comma, or flat field */
            cJSON* dnsArr = cJSON_GetObjectItem(adp, "dns_servers");
            if (dnsArr && cJSON_IsArray(dnsArr))
            {
                int dc = cJSON_GetArraySize(dnsArr);
                for (int d = 0; d < dc; d++)
                {
                    cJSON* dns = cJSON_GetArrayItem(dnsArr, d);
                    if (cJSON_IsString(dns))
                    {
                        if (!dnsServers.empty()) dnsServers += ",";
                        dnsServers += dns->valuestring;
                    }
                }
            }
            if (dnsServers.empty()) dnsServers = JStr(adp, "dns_servers");

            /* adapter_type: NetworkInfo.cpp uses "type"; fall back */
            std::string adpType = JStr(adp, "adapter_type");
            if (adpType.empty()) adpType = JStr(adp, "type");

            /* status: NetworkInfo.cpp uses "oper_status"; fall back */
            std::string adpStatus = JStr(adp, "status");
            if (adpStatus.empty()) adpStatus = JStr(adp, "oper_status");

            sqlite3_bind_int64(s2,  1, snapId);
            sqlite3_bind_text (s2,  2, JStr(adp, "adapter_name").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  3, JStr(adp, "description").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  4, JStr(adp, "mac_address").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  5, ipAddr.c_str(),                     -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  6, subnetMask.c_str(),                 -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  7, gateway.c_str(),                    -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  8, dnsServers.c_str(),                 -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2,  9, JBool(adp, "dhcp_enabled"));
            sqlite3_bind_text (s2, 10, JStr(adp, "dhcp_server").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 11, adpType.c_str(),                    -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 12, adpStatus.c_str(),                  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 13, now.c_str(),                        -1, SQLITE_TRANSIENT);
            sqlite3_step(s2); sqlite3_finalize(s2);
        }
    }

    cJSON_Delete(root);
    return snapId;
}

/* -----------------------------------------------------------------------
 * 模块03 硬盘信息
 * --------------------------------------------------------------------- */
long long DbStorage::SaveDiskInfo(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    const char* sqlSnap = "INSERT INTO disk_snapshots (created_at) VALUES (?);";
    sqlite3_stmt* s0 = NULL;
    sqlite3_prepare_v2(db, sqlSnap, -1, &s0, NULL);
    sqlite3_bind_text(s0, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s0); sqlite3_finalize(s0);
    long long snapId = LastInsertRowId();

    /* 1. Save Physical Disks */
    cJSON* physicals = cJSON_GetObjectItem(root, "physical_disks");
    if (physicals && cJSON_IsArray(physicals))
    {
        const char* sqlPhys =
            "INSERT INTO disk_physical ("
            "snapshot_id, device_id, vendor, model, serial_number,"
            "total_bytes, power_on_count, power_on_hours, created_at)"
            "VALUES (?,?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(physicals);
        for (int i = 0; i < n; i++)
        {
            cJSON* disk = cJSON_GetArrayItem(physicals, i);
            sqlite3_stmt* s1 = NULL;
            if (sqlite3_prepare_v2(db, sqlPhys, -1, &s1, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s1, 1, snapId);
            sqlite3_bind_text (s1, 2, JStr(disk, "device_id").c_str(),     -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s1, 3, JStr(disk, "vendor").c_str(),        -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s1, 4, JStr(disk, "model").c_str(),         -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s1, 5, JStr(disk, "serial_number").c_str(), -1, SQLITE_TRANSIENT);
            
            long long totalB = _atoi64(JStr(disk, "total_bytes").c_str());
            if (totalB == 0) totalB = (long long)JNum(disk, "total_bytes");
            sqlite3_bind_int64(s1, 6, totalB);
            
            sqlite3_bind_int64(s1, 7, (long long)JNum(disk, "power_cycle_count"));
            sqlite3_bind_int64(s1, 8, (long long)JNum(disk, "power_on_hours"));
            sqlite3_bind_text (s1, 9, now.c_str(),                         -1, SQLITE_TRANSIENT);
            
            sqlite3_step(s1); sqlite3_finalize(s1);
        }
    }

    /* 2. Save Logical Volumes (including hidden partitions) */
    cJSON* volumes = cJSON_GetObjectItem(root, "logical_volumes");
    if (!volumes) volumes = cJSON_GetObjectItem(root, "logical_drives");
    if (volumes && cJSON_IsArray(volumes))
    {
        const char* sqlVol =
            "INSERT INTO disk_volumes ("
            "snapshot_id, drive_letter, volume_name, volume_guid, file_system, drive_type,"
            "total_bytes, free_bytes, used_bytes, serial_number, created_at)"
            "VALUES (?,?,?,?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(volumes);
        for (int i = 0; i < n; i++)
        {
            cJSON* vol = cJSON_GetArrayItem(volumes, i);
            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlVol, -1, &s2, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s2, 1, snapId);
            sqlite3_bind_text (s2, 2, JStr(vol, "drive_letter").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 3, JStr(vol, "volume_name").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 4, JStr(vol, "volume_guid").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 5, JStr(vol, "file_system").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 6, JStr(vol, "drive_type").c_str(),    -1, SQLITE_TRANSIENT);
            
            long long totalB = _atoi64(JStr(vol, "total_bytes").c_str());
            long long freeB  = _atoi64(JStr(vol, "free_bytes").c_str());
            if (totalB == 0) totalB = (long long)JNum(vol, "total_bytes");
            if (freeB  == 0) freeB  = (long long)JNum(vol, "free_bytes");
            long long usedB  = totalB - freeB;
            
            sqlite3_bind_int64(s2, 7, totalB);
            sqlite3_bind_int64(s2, 8, freeB);
            sqlite3_bind_int64(s2, 9, usedB);
            
            std::string sn = JStr(vol, "serial_number");
            if (sn.empty()) sn = JStr(vol, "volume_serial");
            sqlite3_bind_text (s2, 10, sn.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 11, now.c_str(), -1, SQLITE_TRANSIENT);
            
            sqlite3_step(s2); sqlite3_finalize(s2);
        }
    }

    cJSON_Delete(root);
    return snapId;
}

/* -----------------------------------------------------------------------
 * 模块04 自启动信息
 * --------------------------------------------------------------------- */
long long DbStorage::SaveAutorunInfo(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    const char* sqlSnap = "INSERT INTO autorun_snapshots (created_at) VALUES (?);";
    sqlite3_stmt* s0 = NULL;
    sqlite3_prepare_v2(db, sqlSnap, -1, &s0, NULL);
    sqlite3_bind_text(s0, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s0); sqlite3_finalize(s0);
    long long snapId = LastInsertRowId();

    cJSON* items = cJSON_GetObjectItem(root, "autorun_entries");
    if (!items) items = cJSON_GetObjectItem(root, "autorun_items");
    if (!items) items = cJSON_GetObjectItem(root, "items");
    if (items && cJSON_IsArray(items))
    {
        const char* sqlItem =
            "INSERT INTO autorun_items ("
            "snapshot_id, source, name, command, publisher,"
            "file_path, is_signed, sign_valid, created_at)"
            "VALUES (?,?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(items);
        for (int i = 0; i < n; i++)
        {
            cJSON* item = cJSON_GetArrayItem(items, i);
            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlItem, -1, &s2, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s2, 1, snapId);
            sqlite3_bind_text (s2, 2, JStr(item, "source").c_str(),    -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 3, JStr(item, "name").c_str(),      -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 4, JStr(item, "command").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 5, JStr(item, "publisher").c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 6, JStr(item, "file_path").c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2, 7, JBool(item, "is_signed"));
            sqlite3_bind_int  (s2, 8, JBool(item, "sign_valid"));
            sqlite3_bind_text (s2, 9, now.c_str(),                     -1, SQLITE_TRANSIENT);
            sqlite3_step(s2); sqlite3_finalize(s2);
        }
    }

    cJSON* contextMenus = cJSON_GetObjectItem(root, "context_menus");
    if (contextMenus && cJSON_IsArray(contextMenus))
    {
        const char* sqlCtx =
            "INSERT INTO autorun_context_menu ("
            "snapshot_id, menu_item, reg_path, command, risk_level, created_at)"
            "VALUES (?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(contextMenus);
        for (int i = 0; i < n; i++)
        {
            cJSON* item = cJSON_GetArrayItem(contextMenus, i);
            sqlite3_stmt* s3 = NULL;
            if (sqlite3_prepare_v2(db, sqlCtx, -1, &s3, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s3, 1, snapId);
            sqlite3_bind_text (s3, 2, JStr(item, "menu_item").c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s3, 3, JStr(item, "reg_path").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s3, 4, JStr(item, "command").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s3, 5, JStr(item, "risk_level").c_str(),-1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s3, 6, now.c_str(),                     -1, SQLITE_TRANSIENT);
            sqlite3_step(s3); sqlite3_finalize(s3);
        }
    }

    cJSON* debuggers = cJSON_GetObjectItem(root, "debuggers");
    if (debuggers && cJSON_IsArray(debuggers))
    {
        const char* sqlDbg =
            "INSERT INTO autorun_debugger ("
            "snapshot_id, target_program, debugger_path, risk_level, created_at)"
            "VALUES (?,?,?,?,?);";

        int n = cJSON_GetArraySize(debuggers);
        for (int i = 0; i < n; i++)
        {
            cJSON* item = cJSON_GetArrayItem(debuggers, i);
            sqlite3_stmt* s4 = NULL;
            if (sqlite3_prepare_v2(db, sqlDbg, -1, &s4, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s4, 1, snapId);
            sqlite3_bind_text (s4, 2, JStr(item, "target_program").c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s4, 3, JStr(item, "debugger_path").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s4, 4, JStr(item, "risk_level").c_str(),     -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s4, 5, now.c_str(),                          -1, SQLITE_TRANSIENT);
            sqlite3_step(s4); sqlite3_finalize(s4);
        }
    }

    cJSON_Delete(root);
    return snapId;
}

/* -----------------------------------------------------------------------
 * 模块05 进程信息
 * --------------------------------------------------------------------- */
long long DbStorage::SaveProcessInfo(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    const char* sqlSnap = "INSERT INTO process_snapshots (created_at) VALUES (?);";
    sqlite3_stmt* s0 = NULL;
    sqlite3_prepare_v2(db, sqlSnap, -1, &s0, NULL);
    sqlite3_bind_text(s0, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s0); sqlite3_finalize(s0);
    long long snapId = LastInsertRowId();

    cJSON* procs = cJSON_GetObjectItem(root, "processes");
    if (!procs) procs = cJSON_GetObjectItem(root, "process_list");
    if (procs && cJSON_IsArray(procs))
    {
        const char* sqlProc =
            "INSERT INTO process_list ("
            "snapshot_id, pid, ppid, process_name, exe_path, command_line,"
            "user_name, session_id, priority, thread_count, handle_count,"
            "memory_kb, cpu_time_ms, start_time, is_signed, sign_valid, publisher, created_at)"
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(procs);
        for (int i = 0; i < n; i++)
        {
            cJSON* p = cJSON_GetArrayItem(procs, i);
            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlProc, -1, &s2, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s2,  1, snapId);
            sqlite3_bind_int  (s2,  2, (int)JNum(p, "pid"));
            sqlite3_bind_int  (s2,  3, (int)JNum(p, "ppid"));
            sqlite3_bind_text (s2,  4, JStr(p, "process_name").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  5, JStr(p, "exe_path").c_str(),      -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  6, JStr(p, "command_line").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  7, JStr(p, "user_name").c_str(),     -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2,  8, (int)JNum(p, "session_id"));
            sqlite3_bind_int  (s2,  9, (int)JNum(p, "priority"));
            sqlite3_bind_int  (s2, 10, (int)JNum(p, "thread_count"));
            sqlite3_bind_int  (s2, 11, (int)JNum(p, "handle_count"));
            sqlite3_bind_int64(s2, 12, (long long)JNum(p, "memory_kb"));
            sqlite3_bind_int64(s2, 13, (long long)JNum(p, "cpu_time_ms"));
            sqlite3_bind_text (s2, 14, JStr(p, "start_time").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2, 15, JBool(p, "is_signed"));
            sqlite3_bind_int  (s2, 16, JBool(p, "sign_valid"));
            sqlite3_bind_text (s2, 17, JStr(p, "publisher").c_str(),    -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 18, now.c_str(),                     -1, SQLITE_TRANSIENT);
            sqlite3_step(s2); sqlite3_finalize(s2);
        }
    }

    cJSON_Delete(root);
    return snapId;
}

/* -----------------------------------------------------------------------
 * 模块06 计划任务
 * --------------------------------------------------------------------- */
long long DbStorage::SaveScheduledTasks(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    const char* sqlSnap = "INSERT INTO task_snapshots (created_at) VALUES (?);";
    sqlite3_stmt* s0 = NULL;
    sqlite3_prepare_v2(db, sqlSnap, -1, &s0, NULL);
    sqlite3_bind_text(s0, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s0); sqlite3_finalize(s0);
    long long snapId = LastInsertRowId();

    cJSON* tasks = cJSON_GetObjectItem(root, "tasks");
    if (!tasks) tasks = cJSON_GetObjectItem(root, "scheduled_tasks");
    if (tasks && cJSON_IsArray(tasks))
    {
        const char* sqlTask =
            "INSERT INTO scheduled_tasks ("
            "snapshot_id, task_name, task_path, status, last_run_time, next_run_time,"
            "run_as_user, action_type, action_path, action_args,"
            "trigger_type, trigger_start, enabled, created_at)"
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(tasks);
        for (int i = 0; i < n; i++)
        {
            cJSON* t = cJSON_GetArrayItem(tasks, i);
            /* 取 actions[0] 和 triggers[0] 的第一项 */
            cJSON* actions  = cJSON_GetObjectItem(t, "actions");
            cJSON* triggers = cJSON_GetObjectItem(t, "triggers");
            cJSON* act0  = (actions  && cJSON_IsArray(actions)  && cJSON_GetArraySize(actions)  > 0) ? cJSON_GetArrayItem(actions,  0) : NULL;
            cJSON* trig0 = (triggers && cJSON_IsArray(triggers) && cJSON_GetArraySize(triggers) > 0) ? cJSON_GetArrayItem(triggers, 0) : NULL;

            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlTask, -1, &s2, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s2,  1, snapId);
            sqlite3_bind_text (s2,  2, JStr(t, "task_name").c_str(),       -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  3, JStr(t, "task_path").c_str(),       -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  4, JStr(t, "status").c_str(),          -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  5, JStr(t, "last_run_time").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  6, JStr(t, "next_run_time").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  7, JStr(t, "run_as_user").c_str(),     -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  8, JStr(act0,  "type").c_str(),        -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  9, JStr(act0,  "path").c_str(),        -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 10, JStr(act0,  "arguments").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 11, JStr(trig0, "type").c_str(),        -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 12, JStr(trig0, "start_boundary").c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2, 13, JBool(t, "enabled"));
            sqlite3_bind_text (s2, 14, now.c_str(),                        -1, SQLITE_TRANSIENT);
            sqlite3_step(s2); sqlite3_finalize(s2);
        }
    }

    cJSON_Delete(root);
    return snapId;
}

/* -----------------------------------------------------------------------
 * 模块07 端口信息
 * --------------------------------------------------------------------- */
long long DbStorage::SavePortInfo(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    const char* sqlSnap = "INSERT INTO port_snapshots (created_at) VALUES (?);";
    sqlite3_stmt* s0 = NULL;
    sqlite3_prepare_v2(db, sqlSnap, -1, &s0, NULL);
    sqlite3_bind_text(s0, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s0); sqlite3_finalize(s0);
    long long snapId = LastInsertRowId();

    const char* sqlConn =
        "INSERT INTO port_connections ("
        "snapshot_id, protocol, local_address, local_port,"
        "remote_address, remote_port, state, pid, process_name,"
        "process_path, exe_path, publisher, created_at)"
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);";

    /* PortInfo.cpp outputs a single "ports" array with a "protocol" field per entry.
     * Also support split tcp_connections/udp_connections for future compatibility. */
    auto SavePortArray = [&](cJSON* arr, const char* defaultProto)
    {
        if (!arr || !cJSON_IsArray(arr)) return;
        int n = cJSON_GetArraySize(arr);
        for (int i = 0; i < n; i++)
        {
            cJSON* c = cJSON_GetArrayItem(arr, i);
            /* Determine protocol: from item field first, then caller-supplied default */
            std::string proto = JStr(c, "protocol");
            if (proto.empty()) proto = defaultProto ? defaultProto : "TCP";
            /* local_ip / remote_ip are used by PortInfo.cpp;
               local_address / remote_address kept for compatibility */
            std::string localAddr = JStr(c, "local_ip");
            if (localAddr.empty()) localAddr = JStr(c, "local_address");
            std::string remoteAddr = JStr(c, "remote_ip");
            if (remoteAddr.empty()) remoteAddr = JStr(c, "remote_address");
            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlConn, -1, &s2, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s2,  1, snapId);
            sqlite3_bind_text (s2,  2, proto.c_str(),       -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  3, localAddr.c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2,  4, (int)JNum(c, "local_port"));
            sqlite3_bind_text (s2,  5, remoteAddr.c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2,  6, (int)JNum(c, "remote_port"));
            std::string procPath = JStr(c, "process_path");
            if (procPath.empty()) procPath = JStr(c, "image_path");
            if (procPath.empty()) procPath = JStr(c, "exe_path");

            sqlite3_bind_text (s2,  7, JStr(c, "state").c_str(),          -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2,  8, (int)JNum(c, "pid"));
            sqlite3_bind_text (s2,  9, JStr(c, "process_name").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 10, procPath.c_str(),                  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 11, procPath.c_str(),                  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 12, JStr(c, "publisher").c_str(),      -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 13, now.c_str(),                       -1, SQLITE_TRANSIENT);
            sqlite3_step(s2); sqlite3_finalize(s2);
        }
    };
    /* Single unified array (PortInfo.cpp style) */
    cJSON* portsArr = cJSON_GetObjectItem(root, "ports");
    if (portsArr) { SavePortArray(portsArr, NULL); }
    else
    {
        /* Split arrays (alternative style) */
        SavePortArray(cJSON_GetObjectItem(root, "tcp_connections"), "TCP");
        SavePortArray(cJSON_GetObjectItem(root, "udp_connections"), "UDP");
        SavePortArray(cJSON_GetObjectItem(root, "tcp"), "TCP");
        SavePortArray(cJSON_GetObjectItem(root, "udp"), "UDP");
    }

    cJSON_Delete(root);
    return snapId;
}

/* -----------------------------------------------------------------------
 * 模块08 共享资源
 * --------------------------------------------------------------------- */
long long DbStorage::SaveSharedResources(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    const char* sqlSnap = "INSERT INTO share_snapshots (created_at) VALUES (?);";
    sqlite3_stmt* s0 = NULL;
    sqlite3_prepare_v2(db, sqlSnap, -1, &s0, NULL);
    sqlite3_bind_text(s0, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s0); sqlite3_finalize(s0);
    long long snapId = LastInsertRowId();

    cJSON* shares = cJSON_GetObjectItem(root, "shares");
    if (!shares) shares = cJSON_GetObjectItem(root, "shared_resources");
    if (shares && cJSON_IsArray(shares))
    {
        const char* sqlShare =
            "INSERT INTO shared_resources ("
            "snapshot_id, share_name, share_path, share_type,"
            "remark, max_uses, current_uses, created_at)"
            "VALUES (?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(shares);
        for (int i = 0; i < n; i++)
        {
            cJSON* sh = cJSON_GetArrayItem(shares, i);
            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlShare, -1, &s2, NULL) != SQLITE_OK) continue;
            /* SharedResources.cpp uses "path" and "type"; fall back to share_path/share_type */
            std::string sharePath = JStr(sh, "share_path");
            if (sharePath.empty()) sharePath = JStr(sh, "path");
            std::string shareType = JStr(sh, "share_type");
            if (shareType.empty()) shareType = JStr(sh, "type");

            sqlite3_bind_int64(s2, 1, snapId);
            sqlite3_bind_text (s2, 2, JStr(sh, "share_name").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 3, sharePath.c_str(),               -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 4, shareType.c_str(),               -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 5, JStr(sh, "remark").c_str(),      -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2, 6, (int)JNum(sh, "max_uses"));
            sqlite3_bind_int  (s2, 7, (int)JNum(sh, "current_uses"));
            sqlite3_bind_text (s2, 8, now.c_str(),                     -1, SQLITE_TRANSIENT);
            sqlite3_step(s2); sqlite3_finalize(s2);
        }
    }

    cJSON_Delete(root);
    return snapId;
}

/* -----------------------------------------------------------------------
 * 模块09 驱动信息
 * --------------------------------------------------------------------- */
long long DbStorage::SaveDriverInfo(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    const char* sqlSnap = "INSERT INTO driver_snapshots (created_at) VALUES (?);";
    sqlite3_stmt* s0 = NULL;
    sqlite3_prepare_v2(db, sqlSnap, -1, &s0, NULL);
    sqlite3_bind_text(s0, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s0); sqlite3_finalize(s0);
    long long snapId = LastInsertRowId();

    cJSON* drivers = cJSON_GetObjectItem(root, "drivers");
    if (!drivers) drivers = cJSON_GetObjectItem(root, "driver_list");
    if (drivers && cJSON_IsArray(drivers))
    {
        const char* sqlDrv =
            "INSERT INTO driver_list ("
            "snapshot_id, driver_name, display_name, driver_path,"
            "start_type, service_type, state, description,"
            "publisher, is_signed, sign_valid, created_at)"
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(drivers);
        for (int i = 0; i < n; i++)
        {
            cJSON* d = cJSON_GetArrayItem(drivers, i);
            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlDrv, -1, &s2, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s2,  1, snapId);
            sqlite3_bind_text (s2,  2, JStr(d, "driver_name").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  3, JStr(d, "display_name").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  4, JStr(d, "driver_path").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  5, JStr(d, "start_type").c_str(),    -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  6, JStr(d, "service_type").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  7, JStr(d, "state").c_str(),         -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  8, JStr(d, "description").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  9, JStr(d, "publisher").c_str(),     -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2, 10, JBool(d, "is_signed"));
            sqlite3_bind_int  (s2, 11, JBool(d, "sign_valid"));
            sqlite3_bind_text (s2, 12, now.c_str(),                      -1, SQLITE_TRANSIENT);
            sqlite3_step(s2); sqlite3_finalize(s2);
        }
    }

    cJSON_Delete(root);
    return snapId;
}

/* -----------------------------------------------------------------------
 * 新增：服务信息
 * --------------------------------------------------------------------- */
long long DbStorage::SaveServiceInfo(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    const char* sqlSnap = "INSERT INTO service_snapshots (created_at) VALUES (?);";
    sqlite3_stmt* s0 = NULL;
    sqlite3_prepare_v2(db, sqlSnap, -1, &s0, NULL);
    sqlite3_bind_text(s0, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s0); sqlite3_finalize(s0);
    long long snapId = LastInsertRowId();

    cJSON* services = cJSON_GetObjectItem(root, "services");
    if (!services) services = cJSON_GetObjectItem(root, "service_list");
    if (services && cJSON_IsArray(services))
    {
        const char* sqlSvc =
            "INSERT INTO service_list ("
            "snapshot_id, service_name, display_name, description,"
            "executable_path, start_type, service_type, state,"
            "account_name, publisher, is_signed, sign_valid, created_at)"
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(services);
        for (int i = 0; i < n; i++)
        {
            cJSON* s = cJSON_GetArrayItem(services, i);
            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlSvc, -1, &s2, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s2,  1, snapId);
            sqlite3_bind_text (s2,  2, JStr(s, "service_name").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  3, JStr(s, "display_name").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  4, JStr(s, "description").c_str(),    -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  5, JStr(s, "executable_path").c_str(),-1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  6, JStr(s, "start_type").c_str(),     -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  7, JStr(s, "service_type").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  8, JStr(s, "state").c_str(),          -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  9, JStr(s, "account_name").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 10, JStr(s, "publisher").c_str(),      -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2, 11, JBool(s, "is_signed"));
            sqlite3_bind_int  (s2, 12, JBool(s, "sign_valid"));
            sqlite3_bind_text (s2, 13, now.c_str(),                       -1, SQLITE_TRANSIENT);
            sqlite3_step(s2); sqlite3_finalize(s2);
        }
    }

    cJSON_Delete(root);
    return snapId;
}

/* -----------------------------------------------------------------------
 * 模块10 浏览器插件
 * --------------------------------------------------------------------- */
long long DbStorage::SaveBrowserPlugins(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    const char* sqlSnap = "INSERT INTO plugin_snapshots (created_at) VALUES (?);";
    sqlite3_stmt* s0 = NULL;
    sqlite3_prepare_v2(db, sqlSnap, -1, &s0, NULL);
    sqlite3_bind_text(s0, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s0); sqlite3_finalize(s0);
    long long snapId = LastInsertRowId();

    cJSON* plugins = cJSON_GetObjectItem(root, "plugins");
    if (!plugins) plugins = cJSON_GetObjectItem(root, "browser_plugins");
    if (plugins && cJSON_IsArray(plugins))
    {
        const char* sqlPlg =
            "INSERT INTO browser_plugins ("
            "snapshot_id, browser, plugin_id, plugin_name, version,"
            "description, install_path, enabled, is_signed, sign_valid, created_at)"
            "VALUES (?,?,?,?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(plugins);
        for (int i = 0; i < n; i++)
        {
            cJSON* p = cJSON_GetArrayItem(plugins, i);
            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlPlg, -1, &s2, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s2,  1, snapId);
            sqlite3_bind_text (s2,  2, JStr(p, "browser").c_str(),      -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  3, JStr(p, "plugin_id").c_str(),    -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  4, JStr(p, "plugin_name").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  5, JStr(p, "version").c_str(),      -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  6, JStr(p, "description").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  7, JStr(p, "install_path").c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2,  8, JBool(p, "enabled"));
            sqlite3_bind_int  (s2,  9, JBool(p, "is_signed"));
            sqlite3_bind_int  (s2, 10, JBool(p, "sign_valid"));
            sqlite3_bind_text (s2, 11, now.c_str(),                     -1, SQLITE_TRANSIENT);
            sqlite3_step(s2); sqlite3_finalize(s2);
        }
    }

    cJSON_Delete(root);
    return snapId;
}

/* -----------------------------------------------------------------------
 * 模块11 内存映像（内核模块）
 * --------------------------------------------------------------------- */
long long DbStorage::SaveMemoryImageInfo(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    const char* sqlSnap = "INSERT INTO kernel_snapshots (created_at) VALUES (?);";
    sqlite3_stmt* s0 = NULL;
    sqlite3_prepare_v2(db, sqlSnap, -1, &s0, NULL);
    sqlite3_bind_text(s0, 1, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s0); sqlite3_finalize(s0);
    long long snapId = LastInsertRowId();

    cJSON* modules = cJSON_GetObjectItem(root, "kernel_modules");
    if (!modules) modules = cJSON_GetObjectItem(root, "modules");
    if (modules && cJSON_IsArray(modules))
    {
        const char* sqlKm =
            "INSERT INTO kernel_modules ("
            "snapshot_id, load_order, module_name, full_path,"
            "base_address, image_size, load_count, flags_hex, flags_desc,"
            "trust_status, modify_time, created_at)"
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(modules);
        for (int i = 0; i < n; i++)
        {
            cJSON* km = cJSON_GetArrayItem(modules, i);
            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlKm, -1, &s2, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s2,  1, snapId);
            sqlite3_bind_int  (s2,  2, (int)JNum(km, "index"));
            sqlite3_bind_text (s2,  3, JStr(km, "module_name").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  4, JStr(km, "path").c_str(),         -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  5, JStr(km, "base_address").c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(s2,  6, (long long)JNum(km, "image_size"));
            sqlite3_bind_int  (s2,  7, (int)JNum(km, "load_count"));
            sqlite3_bind_text (s2,  8, JStr(km, "flags_hex").c_str(),   -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  9, JStr(km, "flags_desc").c_str(),  -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 10, JStr(km, "trust_status").c_str(),-1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 11, JStr(km, "modify_time").c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 12, now.c_str(),                     -1, SQLITE_TRANSIENT);
            sqlite3_step(s2); sqlite3_finalize(s2);
        }
    }

    cJSON_Delete(root);
    return snapId;
}

/* -----------------------------------------------------------------------
 * 模块12 数字证书
 * --------------------------------------------------------------------- */
long long DbStorage::SaveCertInfo(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    /* GetCertInfo puts cert fields inside signature_details.signer_certificate.
     * Fall back chain: cert_info subobj -> signature_details.signer_certificate -> root */
    cJSON* cert = cJSON_GetObjectItem(root, "cert_info");
    if (!cert)
    {
        cJSON* sigDetails = cJSON_GetObjectItem(root, "signature_details");
        if (sigDetails)
            cert = cJSON_GetObjectItem(sigDetails, "signer_certificate");
    }
    if (!cert) cert = root;

    /* 取文件哈希 */
    cJSON* fileHash = cJSON_GetObjectItem(root, "file_hash");

    const char* sql =
        "INSERT INTO cert_info ("
        "file_path, file_sha1, file_sha256,"
        "has_signature, signature_valid, file_tampered, tamper_detail,"
        "verify_result, subject, issuer, serial_number,"
        "not_before, not_after, not_expired, signature_algorithm,"
        "thumbprint_sha1, thumbprint_sha256, is_ca, timestamp, created_at)"
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        m_lastError = sqlite3_errmsg(db);
        cJSON_Delete(root);
        return -1;
    }

    sqlite3_bind_text (stmt,  1, JStr(root, "file_path").c_str(),          -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt,  2, JStr(fileHash, "sha1").c_str(),           -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt,  3, JStr(fileHash, "sha256").c_str(),         -1, SQLITE_TRANSIENT);
    sqlite3_bind_int  (stmt,  4, JBool(root, "has_signature"));
    sqlite3_bind_int  (stmt,  5, JBool(root, "signature_valid"));
    sqlite3_bind_int  (stmt,  6, JBool(root, "file_tampered"));
    sqlite3_bind_text (stmt,  7, JStr(root, "tamper_detail").c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt,  8, JStr(root, "verify_result").c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt,  9, JStr(cert, "subject").c_str(),            -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 10, JStr(cert, "issuer").c_str(),             -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 11, JStr(cert, "serial_number").c_str(),      -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 12, JStr(cert, "not_before").c_str(),         -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 13, JStr(cert, "not_after").c_str(),          -1, SQLITE_TRANSIENT);
    sqlite3_bind_int  (stmt, 14, JBool(cert, "not_expired"));
    sqlite3_bind_text (stmt, 15, JStr(cert, "signature_algorithm").c_str(),-1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 16, JStr(cert, "thumbprint_sha1").c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 17, JStr(cert, "thumbprint_sha256").c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_int  (stmt, 18, JBool(cert, "is_ca"));
    sqlite3_bind_text (stmt, 19, JStr(root, "timestamp").c_str(),          -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 20, now.c_str(),                              -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
    {
        m_lastError = sqlite3_errmsg(db);
        cJSON_Delete(root);
        return -1;
    }

    long long rowId = LastInsertRowId();
    cJSON_Delete(root);
    return rowId;
}

/* -----------------------------------------------------------------------
 * 模块14 文件关联
 * --------------------------------------------------------------------- */
long long DbStorage::SaveFileAssocInfo(const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    cJSON* root = cJSON_Parse(resultJson.c_str());
    if (!root) { m_lastError = "JSON parse error"; return -1; }

    std::string now = NowUtc();

    /* 插入快照汇总行 */
    const char* sqlSnap =
        "INSERT INTO assoc_snapshots "
        "(total_scanned, total_tampered, total_unknown, created_at) "
        "VALUES (?,?,?,?);";
    sqlite3_stmt* s0 = NULL;
    sqlite3_prepare_v2(db, sqlSnap, -1, &s0, NULL);
    sqlite3_bind_int (s0, 1, (int)JNum(root, "total_scanned"));
    sqlite3_bind_int (s0, 2, (int)JNum(root, "total_tampered"));
    sqlite3_bind_int (s0, 3, (int)JNum(root, "total_unknown"));
    sqlite3_bind_text(s0, 4, now.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(s0); sqlite3_finalize(s0);
    long long snapId = LastInsertRowId();

    /* 插入每条关联项 */
    cJSON* items = cJSON_GetObjectItem(root, "items");
    if (items && cJSON_IsArray(items))
    {
        const char* sqlItem =
            "INSERT INTO file_assoc_items ("
            "snapshot_id, ext, is_known, prog_id, prog_id_desc,"
            "open_command, icon_path, user_choice_prog_id,"
            "exe_signed, is_tampered, tamper_reason, created_at)"
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?);";

        int n = cJSON_GetArraySize(items);
        for (int i = 0; i < n; i++)
        {
            cJSON* e = cJSON_GetArrayItem(items, i);
            sqlite3_stmt* s2 = NULL;
            if (sqlite3_prepare_v2(db, sqlItem, -1, &s2, NULL) != SQLITE_OK) continue;
            sqlite3_bind_int64(s2,  1, snapId);
            sqlite3_bind_text (s2,  2, JStr(e, "ext").c_str(),                 -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2,  3, JBool(e, "is_known"));
            sqlite3_bind_text (s2,  4, JStr(e, "prog_id").c_str(),             -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  5, JStr(e, "prog_id_desc").c_str(),        -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  6, JStr(e, "open_command").c_str(),        -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  7, JStr(e, "icon_path").c_str(),           -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2,  8, JStr(e, "user_choice_prog_id").c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int  (s2,  9, JBool(e, "exe_signed"));
            sqlite3_bind_int  (s2, 10, JBool(e, "is_tampered"));
            sqlite3_bind_text (s2, 11, JStr(e, "tamper_reason").c_str(),       -1, SQLITE_TRANSIENT);
            sqlite3_bind_text (s2, 12, now.c_str(),                            -1, SQLITE_TRANSIENT);
            sqlite3_step(s2); sqlite3_finalize(s2);
        }
    }

    cJSON_Delete(root);
    return snapId;
}

/* =======================================================================
 * 通用接口：SaveResult / QueryByModule
 * ======================================================================= */

long long DbStorage::SaveResult(const std::string& moduleName,
                                const std::string& paramsJson,
                                const std::string& resultJson)
{
    if (!m_db) { m_lastError = "Database not open"; return -1; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);
    std::string now = NowUtc();
    const char* sql =
        "INSERT INTO detection_records "
        "(module_name, params_json, result_json, created_at) "
        "VALUES (?,?,?,?);";
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
        m_lastError = sqlite3_errmsg(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, moduleName.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, paramsJson.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, resultJson.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, now.c_str(),          -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE)
    {
        m_lastError = sqlite3_errmsg(db);
        return -1;
    }
    return LastInsertRowId();
}

std::vector<DetectionRecord> DbStorage::QueryByModule(
    const std::string& moduleName, int limit)
{
    std::vector<DetectionRecord> result;
    if (!m_db) { m_lastError = "Database not open"; return result; }
    sqlite3* db = reinterpret_cast<sqlite3*>(m_db);

    std::string sql;
    sqlite3_stmt* stmt = NULL;
    if (moduleName.empty())
    {
        sql = "SELECT id, module_name, params_json, result_json, created_at "
              "FROM detection_records ORDER BY id DESC LIMIT ?;";
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
        {
            m_lastError = sqlite3_errmsg(db);
            return result;
        }
        sqlite3_bind_int(stmt, 1, limit);
    }
    else
    {
        sql = "SELECT id, module_name, params_json, result_json, created_at "
              "FROM detection_records WHERE module_name=? ORDER BY id DESC LIMIT ?;";
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) != SQLITE_OK)
        {
            m_lastError = sqlite3_errmsg(db);
            return result;
        }
        sqlite3_bind_text(stmt, 1, moduleName.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (stmt, 2, limit);
    }

    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        DetectionRecord rec;
        rec.id          = (long long)sqlite3_column_int64(stmt, 0);
        const char* mn  = (const char*)sqlite3_column_text(stmt, 1);
        const char* pj  = (const char*)sqlite3_column_text(stmt, 2);
        const char* rj  = (const char*)sqlite3_column_text(stmt, 3);
        const char* ca  = (const char*)sqlite3_column_text(stmt, 4);
        rec.module_name = mn ? mn : "";
        rec.params_json = pj ? pj : "";
        rec.result_json = rj ? rj : "";
        rec.created_at  = ca ? ca : "";
        result.push_back(rec);
    }
    sqlite3_finalize(stmt);
    return result;
}
