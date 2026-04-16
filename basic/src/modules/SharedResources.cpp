/*
 * 模块：共享资源
 * 指标：共享名称、种类、当前用户、映像路径
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <lm.h>
#include <string>
#include "../common/Utils.h"
#include "../common/DbStorage.h"

#pragma comment(lib, "netapi32.lib")

static std::string GetShareTypeStr(DWORD type)
{
    DWORD baseType = type & ~STYPE_SPECIAL & ~STYPE_TEMPORARY;
    std::string result;
    switch (baseType)
    {
    case STYPE_DISKTREE: result = "DiskTree"; break;
    case STYPE_PRINTQ:   result = "PrintQueue"; break;
    case STYPE_DEVICE:   result = "Device"; break;
    case STYPE_IPC:      result = "IPC"; break;
    default:             result = "Unknown"; break;
    }
    if (type & STYPE_SPECIAL)   result += "|Special";
    if (type & STYPE_TEMPORARY) result += "|Temporary";
    return result;
}

extern "C" __declspec(dllexport)
char* GetSharedResources(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "shared_resources");

    cJSON* sharesArr = cJSON_CreateArray();

    // 枚举共享（SHARE_INFO_502 包含权限和连接数）
    NET_API_STATUS status;
    SHARE_INFO_502* pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0;
    DWORD_PTR resumeHandle = 0;

    do {
        status = NetShareEnum(NULL, 502, (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH,
            &entriesRead, &totalEntries, &resumeHandle);

        if (status == NERR_Success || status == ERROR_MORE_DATA)
        {
            for (DWORD i = 0; i < entriesRead; i++)
            {
                SHARE_INFO_502& s = pBuf[i];
                cJSON* share = cJSON_CreateObject();

                cJSON_AddStringToObject(share, "share_name",
                    WideToUtf8(s.shi502_netname).c_str());
                cJSON_AddStringToObject(share, "type",
                    GetShareTypeStr(s.shi502_type).c_str());
                cJSON_AddStringToObject(share, "remark",
                    WideToUtf8(s.shi502_remark).c_str());
                cJSON_AddStringToObject(share, "path",
                    WideToUtf8(s.shi502_path).c_str());
                cJSON_AddNumberToObject(share, "current_uses",
                    (double)s.shi502_current_uses);
                cJSON_AddNumberToObject(share, "max_uses",
                    s.shi502_max_uses == SHI_USES_UNLIMITED ?
                    -1.0 : (double)s.shi502_max_uses);
                cJSON_AddStringToObject(share, "password",
                    WideToUtf8(s.shi502_passwd).c_str());

                // 获取当前连接用户（NetSessionEnum）
                SESSION_INFO_10* pSessions = NULL;
                DWORD sesRead = 0, sesTot = 0;
                DWORD_PTR sesResume = 0;
                cJSON* usersArr = cJSON_CreateArray();

                NET_API_STATUS sesStatus = NetSessionEnum(
                    NULL, NULL, NULL, 10,
                    (LPBYTE*)&pSessions, MAX_PREFERRED_LENGTH,
                    &sesRead, &sesTot, &sesResume);

                if ((sesStatus == NERR_Success || sesStatus == ERROR_MORE_DATA) && pSessions)
                {
                    for (DWORD j = 0; j < sesRead; j++)
                    {
                        cJSON* user = cJSON_CreateObject();
                        cJSON_AddStringToObject(user, "username",
                            WideToUtf8(pSessions[j].sesi10_username).c_str());
                        cJSON_AddStringToObject(user, "client_name",
                            WideToUtf8(pSessions[j].sesi10_cname).c_str());
                        cJSON_AddNumberToObject(user, "active_time",
                            (double)pSessions[j].sesi10_time);
                        cJSON_AddNumberToObject(user, "idle_time",
                            (double)pSessions[j].sesi10_idle_time);
                        cJSON_AddItemToArray(usersArr, user);
                    }
                    NetApiBufferFree(pSessions);
                }
                cJSON_AddItemToObject(share, "current_users", usersArr);

                cJSON_AddItemToArray(sharesArr, share);
            }
            NetApiBufferFree(pBuf);
            pBuf = NULL;
        }
    } while (status == ERROR_MORE_DATA);

    cJSON_AddItemToObject(root, "shares", sharesArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}

/*
 * SaveSharedResources — 采集共享资源并字段级存入 SQLite3
 * 参数 JSON: { "db_path": "C:\\basic.db" }
 * 返回 JSON: { "snapshot_id": N, "rows_inserted": N, "status": "success" }
 */
extern "C" __declspec(dllexport)
char* SaveSharedResources(const char* paramsJson)
{
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "module", "saveSharedResources");

    std::string dbPath = "basic_detect.db";
    if (paramsJson && paramsJson[0])
    {
        cJSON* p = cJSON_Parse(paramsJson);
        if (p)
        {
            cJSON* dp = cJSON_GetObjectItem(p, "db_path");
            if (dp && cJSON_IsString(dp) && dp->valuestring)
                dbPath = dp->valuestring;
            cJSON_Delete(p);
        }
    }

    char* jsonStr = GetSharedResources(paramsJson);
    if (!jsonStr)
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", "GetSharedResources failed");
        return SerializeJson(result);
    }

    DbStorage db;
    if (!db.Open(dbPath))
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", db.LastError().c_str());
        FreeJsonString(jsonStr);
        return SerializeJson(result);
    }

    long long snapId = db.SaveSharedResources(jsonStr);
    FreeJsonString(jsonStr);

    if (snapId < 0)
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", db.LastError().c_str());
    }
    else
    {
        cJSON_AddNumberToObject(result, "snapshot_id", (double)snapId);
        cJSON_AddStringToObject(result, "status", "success");
    }
    return SerializeJson(result);
}

