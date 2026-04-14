#pragma once
/*
 * DbStorage.h
 * SQLite3 数据库存储封装层
 *
 * 功能：
 *   - 打开/创建 SQLite3 数据库文件
 *   - 自动建表（detection_results）
 *   - 将模块检测结果（JSON 字符串）写入数据库
 *   - 支持按模块名、时间范围查询历史记录
 */
#ifndef DB_STORAGE_H
#define DB_STORAGE_H

#include <string>
#include <vector>

/* 单条检测记录 */
struct DetectionRecord
{
    long long   id;           // 自增主键
    std::string module_name;  // 模块名称，如 "system_info"
    std::string params_json;  // 调用时传入的参数 JSON
    std::string result_json;  // 模块返回的结果 JSON
    std::string created_at;   // 记录时间（UTC，格式：YYYY-MM-DD HH:MM:SS）
};

/* -----------------------------------------------------------------------
 * DbStorage 类：封装 SQLite3 的生命周期与 CRUD 操作
 * --------------------------------------------------------------------- */
class DbStorage
{
public:
    DbStorage();
    ~DbStorage();

    /**
     * 打开（或创建）数据库文件
     * @param dbPath  数据库文件路径（UTF-8），如 "C:\\basic_detect.db"
     * @return true 表示成功
     */
    bool Open(const std::string& dbPath);

    /** 关闭数据库连接 */
    void Close();

    /** 是否已成功打开 */
    bool IsOpen() const;

    /**
     * 将一条检测结果写入数据库
     * @param moduleName  模块名称
     * @param paramsJson  调用参数 JSON
     * @param resultJson  检测结果 JSON
     * @return 插入成功返回新行的 rowid，失败返回 -1
     */
    long long SaveResult(const std::string& moduleName,
                         const std::string& paramsJson,
                         const std::string& resultJson);

    /**
     * 按模块名查询最近 N 条记录
     * @param moduleName  模块名称（空字符串表示查询所有模块）
     * @param limit       最多返回条数（默认 100）
     */
    std::vector<DetectionRecord> QueryByModule(
        const std::string& moduleName, int limit = 100);

    /** 返回最后一次操作的错误信息 */
    std::string LastError() const;

private:
    void*       m_db;       // sqlite3* 句柄（void* 避免头文件依赖 sqlite3.h）
    std::string m_lastError;

    bool CreateTable();
};

#endif /* DB_STORAGE_H */
