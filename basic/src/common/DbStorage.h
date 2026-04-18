#pragma once
/*
 * DbStorage.h  —  SQLite3 字段级存储封装层
 *
 * 设计原则：
 *   每个模块对应一张（或两张）专属表，所有字段单独作为列存储，
 *   不使用 JSON 字段。列表型模块（进程/端口/驱动等）采用
 *   snapshot_id 关联同一次采集的多条子记录。
 *
 * 专属表清单：
 *   sys_info              模块01 系统信息（单行快照）
 *   sys_accounts          模块01 账户列表（多行，关联 sys_info.id）
 *   network_adapters      模块02 网卡列表
 *   disk_volumes          模块03 磁盘/分区列表
 *   autorun_items         模块04 自启动项列表
 *   process_list          模块05 进程列表
 *   scheduled_tasks       模块06 计划任务列表
 *   port_connections      模块07 端口连接列表
 *   shared_resources      模块08 共享资源列表
 *   driver_list           模块09 驱动列表
 *   browser_plugins       模块10 浏览器插件列表
 *   kernel_modules        模块11 内核模块列表
 *   cert_info             模块12 数字证书（单行，按文件路径）
 *   file_assoc_items      模块14 文件关联项列表
 */
#ifndef DB_STORAGE_H
#define DB_STORAGE_H

#include <string>
#include <vector>

/* -----------------------------------------------------------------------
 * 通用检测记录结构体（供 QueryModule.cpp 使用）
 * --------------------------------------------------------------------- */
struct DetectionRecord
{
    long long   id;
    std::string module_name;
    std::string params_json;
    std::string result_json;
    std::string created_at;
};

/* -----------------------------------------------------------------------
 * DbStorage 类
 * --------------------------------------------------------------------- */
class DbStorage
{
public:
    DbStorage();
    ~DbStorage();

    bool Open(const std::string& dbPath);
    void Close();
    bool IsOpen() const;
    std::string LastError() const;

    /* ------------------------------------------------------------------ */
    /* 模块01 系统信息                                                      */
    /* 返回 snapshot_id（sys_info.id），失败返回 -1                         */
    /* ------------------------------------------------------------------ */
    long long SaveSysInfo(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 模块02 网络信息                                                      */
    /* ------------------------------------------------------------------ */
    long long SaveNetworkInfo(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 模块03 硬盘信息                                                      */
    /* ------------------------------------------------------------------ */
    long long SaveDiskInfo(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 模块04 自启动信息                                                    */
    /* ------------------------------------------------------------------ */
    long long SaveAutorunInfo(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 模块05 进程信息                                                      */
    /* ------------------------------------------------------------------ */
    long long SaveProcessInfo(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 模块06 计划任务                                                      */
    /* ------------------------------------------------------------------ */
    long long SaveScheduledTasks(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 模块07 端口信息                                                      */
    /* ------------------------------------------------------------------ */
    long long SavePortInfo(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 模块08 共享资源                                                      */
    /* ------------------------------------------------------------------ */
    long long SaveSharedResources(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 模块09 驱动信息                                                      */
    /* ------------------------------------------------------------------ */
    long long SaveDriverInfo(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 模块10 浏览器插件                                                    */
    /* ------------------------------------------------------------------ */
    long long SaveBrowserPlugins(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 新增：服务信息                                                       */
    /* ------------------------------------------------------------------ */
    long long SaveServiceInfo(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 模块11 内存映像（内核模块）                                           */
    /* ------------------------------------------------------------------ */
    long long SaveMemoryImageInfo(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 模块12 数字证书                                                      */
    /* ------------------------------------------------------------------ */
    long long SaveCertInfo(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 模夆14 文件关联                                                      */
    /* ------------------------------------------------------------------ */
    long long SaveFileAssocInfo(const std::string& resultJson);

    /* ------------------------------------------------------------------ */
    /* 通用接口：将任意模块结果存入 detection_records 表                    */
    /* 返回插入的行 ID，失败返回 -1                                      */
    /* ------------------------------------------------------------------ */
    long long SaveResult(const std::string& moduleName,
                         const std::string& paramsJson,
                         const std::string& resultJson);

    /* 按模块名查询历史记录，为空则查全部 */
    std::vector<DetectionRecord> QueryByModule(const std::string& moduleName,
                                               int limit = 100);

private:
    void*       m_db;
    std::string m_lastError;

    bool CreateAllTables();
    bool ExecSql(const char* sql);
    long long LastInsertRowId();
};

#endif /* DB_STORAGE_H */
