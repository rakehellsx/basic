/*
 * 模块：进程信息
 * 指标：进程、模块、线程、文件句柄、发行商、修改时间、映像路径、授信状态
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include "../common/Utils.h"
#include "../common/DbStorage.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "version.lib")

/* 获取文件修改时间 */
static std::string GetFileModifyTime(const wchar_t* filePath)
{
    WIN32_FILE_ATTRIBUTE_DATA fad = {0};
    if (!GetFileAttributesExW(filePath, GetFileExInfoStandard, &fad))
        return "";
    return FileTimeToString(fad.ftLastWriteTime);
}

/* 枚举进程的模块列表 */
static cJSON* EnumProcModules(DWORD pid)
{
    cJSON* arr = cJSON_CreateArray();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (hSnap == INVALID_HANDLE_VALUE) return arr;

    MODULEENTRY32W me = {0};
    me.dwSize = sizeof(me);
    if (Module32FirstW(hSnap, &me))
    {
        do {
            cJSON* mod = cJSON_CreateObject();
            cJSON_AddStringToObject(mod, "module_name", WideToUtf8(me.szModule).c_str());
            cJSON_AddStringToObject(mod, "exe_path",    WideToUtf8(me.szExePath).c_str());
            cJSON_AddStringToObject(mod, "publisher",
                GetFilePublisherW(me.szExePath).c_str());
            cJSON_AddStringToObject(mod, "modify_time",
                GetFileModifyTime(me.szExePath).c_str());
            cJSON_AddStringToObject(mod, "trust_status",
                VerifyAuthenticode(me.szExePath).c_str());

            /* 基址字符串（避免 lambda） */
            char addrBuf[32];
            _snprintf_s(addrBuf, sizeof(addrBuf), _TRUNCATE,
                "0x%p", (void*)me.modBaseAddr);
            cJSON_AddStringToObject(mod, "base_address", addrBuf);
            cJSON_AddNumberToObject(mod, "base_size", (double)me.modBaseSize);
            cJSON_AddItemToArray(arr, mod);
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    return arr;
}

/* 枚举进程的线程列表 */
static cJSON* EnumProcThreads(DWORD pid)
{
    cJSON* arr = cJSON_CreateArray();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return arr;

    THREADENTRY32 te = {0};
    te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te))
    {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            cJSON* thd = cJSON_CreateObject();
            cJSON_AddNumberToObject(thd, "thread_id",     (double)te.th32ThreadID);
            cJSON_AddNumberToObject(thd, "base_priority", (double)te.tpBasePri);
            cJSON_AddNumberToObject(thd, "delta_priority",(double)te.tpDeltaPri);
            cJSON_AddItemToArray(arr, thd);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return arr;
}

/* 获取进程句柄数（使用 Windows API，避免递归） */
static DWORD QueryHandleCount(HANDLE hProcess)
{
    DWORD count = 0;
    ::GetProcessHandleCount(hProcess, &count);
    return count;
}

extern "C" __declspec(dllexport)
char* GetProcessInfo(const char* paramsJson)
{
    bool inclModules = GetBoolParam(paramsJson, "include_modules", true);
    bool inclThreads = GetBoolParam(paramsJson, "include_threads", true);

    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "process_info");

    cJSON* procArr = cJSON_CreateArray();

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return BuildErrorJson("process_info", "CreateToolhelp32Snapshot failed");

    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(hSnap, &pe))
    {
        do {
            cJSON* proc = cJSON_CreateObject();
            cJSON_AddNumberToObject(proc, "pid",          (double)pe.th32ProcessID);
            cJSON_AddNumberToObject(proc, "ppid",         (double)pe.th32ParentProcessID);
            cJSON_AddStringToObject(proc, "name",         WideToUtf8(pe.szExeFile).c_str());
            cJSON_AddNumberToObject(proc, "thread_count", (double)pe.cntThreads);

            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, pe.th32ProcessID);

            if (hProc)
            {
                wchar_t imagePath[MAX_PATH] = {0};
                DWORD pathLen = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, imagePath, &pathLen))
                {
                    cJSON_AddStringToObject(proc, "image_path",
                        WideToUtf8(imagePath).c_str());
                    cJSON_AddStringToObject(proc, "publisher",
                        GetFilePublisherW(imagePath).c_str());
                    cJSON_AddStringToObject(proc, "modify_time",
                        GetFileModifyTime(imagePath).c_str());
                    cJSON_AddStringToObject(proc, "trust_status",
                        VerifyAuthenticode(imagePath).c_str());
                }

                cJSON_AddNumberToObject(proc, "handle_count",
                    (double)QueryHandleCount(hProc));

                PROCESS_MEMORY_COUNTERS_EX pmc = {0};
                pmc.cb = sizeof(pmc);
                if (GetProcessMemoryInfo(hProc,
                    (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc)))
                {
                    cJSON_AddStringToObject(proc, "working_set",
                        LargeIntToString(pmc.WorkingSetSize).c_str());
                    cJSON_AddStringToObject(proc, "private_usage",
                        LargeIntToString(pmc.PrivateUsage).c_str());
                }

                CloseHandle(hProc);
            }

            if (inclModules)
                cJSON_AddItemToObject(proc, "modules",
                    EnumProcModules(pe.th32ProcessID));

            if (inclThreads)
                cJSON_AddItemToObject(proc, "threads",
                    EnumProcThreads(pe.th32ProcessID));

            cJSON_AddItemToArray(procArr, proc);
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    cJSON_AddItemToObject(root, "processes", procArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}

/*
 * SaveProcessInfo — 采集进程信息并字段级存入 SQLite3
 * 参数 JSON: { "db_path": "C:\\basic.db" }
 * 返回 JSON: { "snapshot_id": N, "rows_inserted": N, "status": "success" }
 */
extern "C" __declspec(dllexport)
char* SaveProcessInfo(const char* paramsJson)
{
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "module", "saveProcessInfo");

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

    char* jsonStr = GetProcessInfo(paramsJson);
    if (!jsonStr)
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", "GetProcessInfo failed");
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

    long long snapId = db.SaveProcessInfo(jsonStr);
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

