/*
 * QueryModule.cpp
 * 统一模块查询与持久化接口
 *
 * 导出接口：
 *   QueryModuleAndSave(paramsJson)
 *     - 按 module_name 调用对应检测模块
 *     - 将结果写入 SQLite3 数据库
 *     - 返回包含检测结果 + 存储状态的 JSON 字符串
 *
 *   QueryHistory(paramsJson)
 *     - 从数据库查询历史检测记录
 *     - 支持按模块名过滤、限制返回条数
 */
#include <windows.h>
#include <string>
#include "../common/Utils.h"
#include "../common/DbStorage.h"

/* -----------------------------------------------------------------------
 * 前向声明：各模块导出函数
 * --------------------------------------------------------------------- */
extern "C" {
    char* GetSysInfo(const char* paramsJson);
    char* GetNetworkInfo(const char* paramsJson);
    char* GetDiskInfo(const char* paramsJson);
    char* GetAutorunInfo(const char* paramsJson);
    char* GetProcessInfo(const char* paramsJson);
    char* GetScheduledTasks(const char* paramsJson);
    char* GetPortInfo(const char* paramsJson);
    char* GetSharedResources(const char* paramsJson);
    char* GetDriverInfo(const char* paramsJson);
    char* GetBrowserPlugins(const char* paramsJson);
    char* GetMemoryImageInfo(const char* paramsJson);
    char* GetCertInfo(const char* paramsJson);
    char* BatchGetCertInfo(const char* paramsJson);
    char* GetFileAssocInfo(const char* paramsJson);
    char* CheckFileAssoc(const char* paramsJson);
    char* DetectFileFormat(const char* paramsJson);
    char* ScanDirectoryFormat(const char* paramsJson);
    const char* GetFileStaticInfo(const char* paramsJson);
    const char* SaveFileStaticInfo(const char* paramsJson);
}

/* -----------------------------------------------------------------------
 * 模块名 → 函数指针映射表
 * --------------------------------------------------------------------- */
typedef char* (*ModuleFunc)(const char*);

struct ModuleEntry
{
    const char* name;
    ModuleFunc  func;
};

static const ModuleEntry g_moduleTable[] =
{
    { "system_info",      GetSysInfo         },
    { "network_info",     GetNetworkInfo     },
    { "disk_info",        GetDiskInfo        },
    { "autorun_info",     GetAutorunInfo     },
    { "process_info",     GetProcessInfo     },
    { "scheduled_tasks",  GetScheduledTasks  },
    { "port_info",        GetPortInfo        },
    { "shared_resources", GetSharedResources },
    { "driver_info",      GetDriverInfo      },
    { "browser_plugins",  GetBrowserPlugins  },
    { "memory_image",     GetMemoryImageInfo },
    { "cert_info",        GetCertInfo        },
    { "batch_cert_info",  BatchGetCertInfo   },
    { "file_assoc_info",  GetFileAssocInfo   },
    { "check_file_assoc",     CheckFileAssoc       },
    { "detect_file_format",   DetectFileFormat     },
    { "scan_directory_format",ScanDirectoryFormat  },
    { "file_static_info",     (ModuleFunc)GetFileStaticInfo  },
    { "save_file_static_info",(ModuleFunc)SaveFileStaticInfo },
    { NULL,                   NULL                 }
};

/* -----------------------------------------------------------------------
 * 查找模块函数
 * --------------------------------------------------------------------- */
static ModuleFunc FindModule(const std::string& name)
{
    for (int i = 0; g_moduleTable[i].name; i++)
    {
        if (name == g_moduleTable[i].name)
            return g_moduleTable[i].func;
    }
    return NULL;
}

/* -----------------------------------------------------------------------
 * QueryModuleAndSave
 *
 * paramsJson 格式：
 * {
 *   "module_name" : "system_info",          // 必填，目标模块名称
 *   "module_params": {},                    // 可选，传递给目标模块的参数
 *   "db_path"     : "C:\\basic_detect.db",  // 可选，数据库路径（默认同目录）
 *   "save_to_db"  : true                    // 可选，是否存库（默认 true）
 * }
 *
 * 返回 JSON 格式：
 * {
 *   "module"       : "query_module_and_save",
 *   "module_name"  : "system_info",
 *   "db_path"      : "C:\\basic_detect.db",
 *   "record_id"    : 1,              // 插入的数据库行 ID（-1 表示未存库或失败）
 *   "save_status"  : "success",      // "success" / "skipped" / "error: ..."
 *   "result"       : { ... },        // 模块检测结果（JSON 对象）
 *   "status"       : "success"
 * }
 * --------------------------------------------------------------------- */
extern "C" __declspec(dllexport)
char* QueryModuleAndSave(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "query_module_and_save");

    /* 解析参数 */
    std::string moduleName  = GetStringParam(paramsJson, "module_name",  "");
    std::string moduleParams= GetStringParam(paramsJson, "module_params", "{}");
    std::string dbPath      = GetStringParam(paramsJson, "db_path",
                                "C:\\basic_detect.db");
    bool saveToDb = GetBoolParam(paramsJson, "save_to_db", true);

    cJSON_AddStringToObject(root, "module_name", moduleName.c_str());
    cJSON_AddStringToObject(root, "db_path",     dbPath.c_str());

    /* 校验模块名 */
    if (moduleName.empty())
    {
        cJSON_AddNumberToObject(root, "record_id", -1);
        cJSON_AddStringToObject(root, "save_status", "skipped");
        cJSON_AddStringToObject(root, "status", "error");
        cJSON_AddStringToObject(root, "error_message",
            "module_name is required");
        return SerializeJson(root);
    }

    ModuleFunc fn = FindModule(moduleName);
    if (!fn)
    {
        /* 构建可用模块列表 */
        std::string available;
        for (int i = 0; g_moduleTable[i].name; i++)
        {
            if (!available.empty()) available += ", ";
            available += g_moduleTable[i].name;
        }
        cJSON_AddNumberToObject(root, "record_id", -1);
        cJSON_AddStringToObject(root, "save_status", "skipped");
        cJSON_AddStringToObject(root, "status", "error");
        cJSON_AddStringToObject(root, "error_message",
            ("unknown module_name. available: " + available).c_str());
        return SerializeJson(root);
    }

    /* 调用目标模块 */
    char* resultRaw = fn(moduleParams.c_str());
    std::string resultStr = resultRaw ? resultRaw : "{}";

    /* 将结果 JSON 字符串解析后嵌入输出 */
    cJSON* resultObj = cJSON_Parse(resultStr.c_str());
    if (resultObj)
        cJSON_AddItemToObject(root, "result", resultObj);
    else
        cJSON_AddStringToObject(root, "result_raw", resultStr.c_str());

    /* 释放模块返回的内存 */
    if (resultRaw)
    {
        free(resultRaw);
    }

    /* 存入 SQLite3 数据库 */
    long long recordId = -1;
    std::string saveStatus;

    if (saveToDb)
    {
        DbStorage db;
        if (!db.Open(dbPath))
        {
            saveStatus = "error: " + db.LastError();
        }
        else
        {
            recordId = db.SaveResult(moduleName, moduleParams, resultStr);
            if (recordId < 0)
                saveStatus = "error: " + db.LastError();
            else
                saveStatus = "success";
        }
    }
    else
    {
        saveStatus = "skipped";
    }

    cJSON_AddNumberToObject(root, "record_id",   (double)recordId);
    cJSON_AddStringToObject(root, "save_status", saveStatus.c_str());
    cJSON_AddStringToObject(root, "status",      "success");

    return SerializeJson(root);
}

/* -----------------------------------------------------------------------
 * QueryHistory
 *
 * paramsJson 格式：
 * {
 *   "module_name" : "system_info",          // 可选，为空则查全部
 *   "db_path"     : "C:\\basic_detect.db",  // 可选
 *   "limit"       : 50                      // 可选，默认 100
 * }
 *
 * 返回 JSON 格式：
 * {
 *   "module"      : "query_history",
 *   "module_name" : "system_info",
 *   "db_path"     : "C:\\basic_detect.db",
 *   "total"       : 3,
 *   "records"     : [
 *     {
 *       "id"          : 3,
 *       "module_name" : "system_info",
 *       "params_json" : "{}",
 *       "result_json" : "{ ... }",
 *       "created_at"  : "2025-04-13 10:00:00"
 *     },
 *     ...
 *   ],
 *   "status" : "success"
 * }
 * --------------------------------------------------------------------- */
extern "C" __declspec(dllexport)
char* QueryHistory(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "query_history");

    std::string moduleName = GetStringParam(paramsJson, "module_name", "");
    std::string dbPath     = GetStringParam(paramsJson, "db_path",
                               "C:\\basic_detect.db");
    int limit = GetIntParam(paramsJson, "limit", 100);

    cJSON_AddStringToObject(root, "module_name", moduleName.c_str());
    cJSON_AddStringToObject(root, "db_path",     dbPath.c_str());

    DbStorage db;
    if (!db.Open(dbPath))
    {
        cJSON_AddNumberToObject(root, "total", 0);
        cJSON_AddItemToObject(root, "records", cJSON_CreateArray());
        cJSON_AddStringToObject(root, "status", "error");
        cJSON_AddStringToObject(root, "error_message",
            db.LastError().c_str());
        return SerializeJson(root);
    }

    std::vector<DetectionRecord> records =
        db.QueryByModule(moduleName, limit);

    cJSON_AddNumberToObject(root, "total", (double)records.size());

    cJSON* arr = cJSON_CreateArray();
    for (size_t ri = 0; ri < records.size(); ri++)
    {
        const DetectionRecord& rec = records[ri];
        cJSON* item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "id",          (double)rec.id);
        cJSON_AddStringToObject(item, "module_name", rec.module_name.c_str());
        cJSON_AddStringToObject(item, "params_json", rec.params_json.c_str());

        /* 尝试将 result_json 解析为对象嵌入，失败则作为字符串 */
        cJSON* resultObj = cJSON_Parse(rec.result_json.c_str());
        if (resultObj)
            cJSON_AddItemToObject(item, "result", resultObj);
        else
            cJSON_AddStringToObject(item, "result_json",
                rec.result_json.c_str());

        cJSON_AddStringToObject(item, "created_at",  rec.created_at.c_str());
        cJSON_AddItemToArray(arr, item);
    }
    cJSON_AddItemToObject(root, "records", arr);
    cJSON_AddStringToObject(root, "status", "success");

    return SerializeJson(root);
}
