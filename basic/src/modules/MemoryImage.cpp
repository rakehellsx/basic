/*
 * 模块：内存映像（系统）
 * 指标：内存运行状态、内核模块基址、映像大小、标志(Flags)、序号(Index)、路径、授信状态
 * 可选：保存当前内存映像到文件（MiniDump）
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <winternl.h>
#include <string>
#include <vector>
#include "../common/Utils.h"
#include "../common/DbStorage.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "version.lib")

/* -----------------------------------------------------------------------
 * NtQuerySystemInformation 相关结构定义
 * --------------------------------------------------------------------- */
#define BASIC_SystemModuleInformation 11

typedef struct _BASIC_SYSTEM_MODULE_ENTRY
{
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} BASIC_SYSTEM_MODULE_ENTRY, *PBASIC_SYSTEM_MODULE_ENTRY;

typedef struct _BASIC_SYSTEM_MODULE_INFORMATION
{
    ULONG                    Count;
    BASIC_SYSTEM_MODULE_ENTRY Module[1];
} BASIC_SYSTEM_MODULE_INFORMATION, *PBASIC_SYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(WINAPI* PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

/* -----------------------------------------------------------------------
 * 标志位解析
 * --------------------------------------------------------------------- */
static std::string ParseModuleFlags(ULONG flags)
{
    struct FlagEntry { ULONG bit; const char* name; };
    static const FlagEntry flagTable[] = {
        { 0x00000001, "LDRP_STATIC_LINK"            },
        { 0x00000002, "LDRP_IMAGE_DLL"              },
        { 0x00000004, "LDRP_LOAD_IN_PROGRESS"       },
        { 0x00000008, "LDRP_UNLOAD_IN_PROGRESS"     },
        { 0x00000010, "LDRP_ENTRY_PROCESSED"        },
        { 0x00000020, "LDRP_ENTRY_INSERTED"         },
        { 0x00000040, "LDRP_CURRENT_LOAD"           },
        { 0x00000080, "LDRP_FAILED_BUILTIN_LOAD"    },
        { 0x00000100, "LDRP_DONT_CALL_FOR_THREADS"  },
        { 0x00000200, "LDRP_PROCESS_ATTACH_CALLED"  },
        { 0x00000400, "LDRP_DEBUG_SYMBOLS_LOADED"   },
        { 0x00000800, "LDRP_IMAGE_NOT_AT_BASE"      },
        { 0x00001000, "LDRP_WX86_IGNORE_MACHINETYPE"},
        { 0x00002000, "LDRP_COR_IMAGE"              },
        { 0x00004000, "LDRP_COR_OWNS_UNMAP"         },
        { 0x00008000, "LDRP_SYSTEM_MAPPED"          },
        { 0x00010000, "LDRP_IMAGE_VERIFYING"        },
        { 0x00020000, "LDRP_DRIVER_DEPENDENT_DLL"   },
        { 0x00040000, "LDRP_ENTRY_NATIVE"           },
        { 0x00080000, "LDRP_REDIRECTED"             },
        { 0x00100000, "LDRP_NON_PAGED_DEBUG_INFO"   },
        { 0x00200000, "LDRP_MM_LOADED"              },
        { 0x00400000, "LDRP_COMPAT_DATABASE_PROCESSED" },
        { 0,          NULL }
    };
    std::string result;
    for (int i = 0; flagTable[i].name; i++)
    {
        if (flags & flagTable[i].bit)
        {
            if (!result.empty()) result += "|";
            result += flagTable[i].name;
        }
    }
    if (result.empty())
    {
        char buf[16];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%08X", flags);
        result = buf;
    }
    return result;
}

/* -----------------------------------------------------------------------
 * 保存进程内存映像到文件（MiniDump）
 * --------------------------------------------------------------------- */
static bool SaveMemoryDump(DWORD pid, const wchar_t* outputPath)
{
    typedef BOOL(WINAPI* PFN_MINIDUMPWRITEDUMP)(
        HANDLE, DWORD, HANDLE, DWORD,
        PVOID, PVOID, PVOID);

    HMODULE hDbgHelp = LoadLibraryW(L"dbghelp.dll");
    if (!hDbgHelp) return false;

    PFN_MINIDUMPWRITEDUMP pMiniDumpWriteDump =
        (PFN_MINIDUMPWRITEDUMP)GetProcAddress(hDbgHelp, "MiniDumpWriteDump");
    if (!pMiniDumpWriteDump) { FreeLibrary(hDbgHelp); return false; }

    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) { FreeLibrary(hDbgHelp); return false; }

    HANDLE hFile = CreateFileW(outputPath, GENERIC_WRITE, 0, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hProc);
        FreeLibrary(hDbgHelp);
        return false;
    }

    /* MiniDumpWithFullMemory(2) | MiniDumpWithHandleData(4) = 6 */
    BOOL ok = pMiniDumpWriteDump(hProc, pid, hFile, (DWORD)6,
        NULL, NULL, NULL);

    CloseHandle(hFile);
    CloseHandle(hProc);
    FreeLibrary(hDbgHelp);
    return ok != FALSE;
}

/* -----------------------------------------------------------------------
 * 主接口：GetMemoryImageInfo
 * --------------------------------------------------------------------- */
extern "C" __declspec(dllexport)
char* GetMemoryImageInfo(const char* paramsJson)
{
    bool saveDump = GetBoolParam(paramsJson, "save_dump", false);
    int  dumpPid  = GetIntParam(paramsJson, "dump_pid", 0);
    std::string dumpPath = GetStringParam(paramsJson, "dump_path", "C:\\memdump.dmp");

    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "memory_image");

    /* ===== 1. 系统内存状态 ===== */
    MEMORYSTATUSEX ms = {0};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
    {
        cJSON* memStatus = cJSON_CreateObject();
        cJSON_AddNumberToObject(memStatus, "memory_load_percent",  (double)ms.dwMemoryLoad);
        cJSON_AddStringToObject(memStatus, "total_physical",       LargeIntToString(ms.ullTotalPhys).c_str());
        cJSON_AddStringToObject(memStatus, "available_physical",   LargeIntToString(ms.ullAvailPhys).c_str());
        cJSON_AddStringToObject(memStatus, "total_page_file",      LargeIntToString(ms.ullTotalPageFile).c_str());
        cJSON_AddStringToObject(memStatus, "available_page_file",  LargeIntToString(ms.ullAvailPageFile).c_str());
        cJSON_AddStringToObject(memStatus, "total_virtual",        LargeIntToString(ms.ullTotalVirtual).c_str());
        cJSON_AddStringToObject(memStatus, "available_virtual",    LargeIntToString(ms.ullAvailVirtual).c_str());
        cJSON_AddItemToObject(root, "memory_status", memStatus);
    }

    /* ===== 2. 内核模块列表（含 Flags 和 Index）===== */
    cJSON* kernelModules = cJSON_CreateArray();

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NtQuerySystemInformation pNtQSI = hNtdll
        ? (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation")
        : NULL;

    bool usedNtQSI = false;
    if (pNtQSI)
    {
        ULONG bufLen = 0;
        pNtQSI(BASIC_SystemModuleInformation, NULL, 0, &bufLen);
        bufLen += 4096;

        /* 使用 malloc 替代 vector::data() */
        BYTE* buf = (BYTE*)malloc(bufLen);
        if (buf)
        {
            memset(buf, 0, bufLen);
            NTSTATUS ntStatus = pNtQSI(BASIC_SystemModuleInformation,
                buf, bufLen, &bufLen);

            if (ntStatus == 0)
            {
                PBASIC_SYSTEM_MODULE_INFORMATION pInfo =
                    (PBASIC_SYSTEM_MODULE_INFORMATION)buf;

                for (ULONG i = 0; i < pInfo->Count; i++)
                {
                    BASIC_SYSTEM_MODULE_ENTRY* entry = &pInfo->Module[i];
                    cJSON* km = cJSON_CreateObject();

                    cJSON_AddNumberToObject(km, "index", (double)entry->LoadOrderIndex);

                    char addrBuf[32];
                    _snprintf_s(addrBuf, sizeof(addrBuf), _TRUNCATE,
                        "0x%p", entry->ImageBase);
                    cJSON_AddStringToObject(km, "base_address", addrBuf);

                    cJSON_AddNumberToObject(km, "image_size", (double)entry->ImageSize);

                    char flagHex[16];
                    _snprintf_s(flagHex, sizeof(flagHex), _TRUNCATE,
                        "0x%08X", entry->Flags);
                    cJSON_AddStringToObject(km, "flags_hex",  flagHex);
                    cJSON_AddStringToObject(km, "flags_desc",
                        ParseModuleFlags(entry->Flags).c_str());

                    cJSON_AddNumberToObject(km, "load_count", (double)entry->LoadCount);

                    const char* rawPath = (const char*)entry->FullPathName;
                    std::string ansiPath(rawPath);
                    std::string dosPath = ansiPath;

                    if (ansiPath.find("\\SystemRoot\\") == 0)
                    {
                        wchar_t winDir[MAX_PATH] = {0};
                        GetWindowsDirectoryW(winDir, MAX_PATH);
                        dosPath = WideToUtf8(winDir) + ansiPath.substr(11);
                    }
                    else if (ansiPath.find("\\??\\") == 0)
                    {
                        dosPath = ansiPath.substr(4);
                    }

                    cJSON_AddStringToObject(km, "path", dosPath.c_str());

                    const char* baseName = rawPath + entry->OffsetToFileName;
                    cJSON_AddStringToObject(km, "module_name", baseName);

                    if (!dosPath.empty())
                    {
                        std::wstring wPath = Utf8ToWstr(dosPath);
                        cJSON_AddStringToObject(km, "trust_status",
                            VerifyAuthenticode(wPath).c_str());

                        WIN32_FILE_ATTRIBUTE_DATA fad = {0};
                        if (GetFileAttributesExW(wPath.c_str(),
                            GetFileExInfoStandard, &fad))
                            cJSON_AddStringToObject(km, "modify_time",
                                FileTimeToString(fad.ftLastWriteTime).c_str());
                    }

                    cJSON_AddItemToArray(kernelModules, km);
                }
                usedNtQSI = true;
            }
            free(buf);
        }
    }

    /* 备用方案：EnumDeviceDrivers */
    if (!usedNtQSI)
    {
        LPVOID drivers[1024] = {0};
        DWORD cbNeeded = 0;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
        {
            DWORD count = cbNeeded / sizeof(LPVOID);
            for (DWORD i = 0; i < count; i++)
            {
                cJSON* km = cJSON_CreateObject();
                cJSON_AddNumberToObject(km, "index", (double)i);

                char addrBuf[32];
                _snprintf_s(addrBuf, sizeof(addrBuf), _TRUNCATE, "0x%p", drivers[i]);
                cJSON_AddStringToObject(km, "base_address", addrBuf);
                cJSON_AddStringToObject(km, "flags_hex",  "N/A");
                cJSON_AddStringToObject(km, "flags_desc",
                    "unavailable(EnumDeviceDrivers fallback)");

                wchar_t drvPath[MAX_PATH] = {0};
                if (GetDeviceDriverFileNameW(drivers[i], drvPath, MAX_PATH))
                {
                    std::wstring rawPath = drvPath;
                    std::wstring winPath;
                    if (rawPath.find(L"\\SystemRoot\\") == 0)
                    {
                        wchar_t winDir[MAX_PATH] = {0};
                        GetWindowsDirectoryW(winDir, MAX_PATH);
                        winPath = std::wstring(winDir) + rawPath.substr(11);
                    }
                    else if (rawPath.find(L"\\??\\") == 0)
                        winPath = rawPath.substr(4);
                    else
                        winPath = rawPath;

                    cJSON_AddStringToObject(km, "path",
                        WideToUtf8(winPath.c_str()).c_str());

                    wchar_t baseName[MAX_PATH] = {0};
                    GetDeviceDriverBaseNameW(drivers[i], baseName, MAX_PATH);
                    cJSON_AddStringToObject(km, "module_name",
                        WideToUtf8(baseName).c_str());

                    if (!winPath.empty())
                        cJSON_AddStringToObject(km, "trust_status",
                            VerifyAuthenticode(winPath).c_str());

                    WIN32_FILE_ATTRIBUTE_DATA fad = {0};
                    if (GetFileAttributesExW(winPath.c_str(),
                        GetFileExInfoStandard, &fad))
                        cJSON_AddStringToObject(km, "modify_time",
                            FileTimeToString(fad.ftLastWriteTime).c_str());
                }

                cJSON_AddItemToArray(kernelModules, km);
            }
        }
    }

    cJSON_AddItemToObject(root, "kernel_modules", kernelModules);

    /* ===== 3. 系统性能信息 ===== */
    PERFORMANCE_INFORMATION perfInfo = {0};
    perfInfo.cb = sizeof(perfInfo);
    if (GetPerformanceInfo(&perfInfo, sizeof(perfInfo)))
    {
        cJSON* perf = cJSON_CreateObject();
        cJSON_AddNumberToObject(perf, "commit_total",        (double)perfInfo.CommitTotal);
        cJSON_AddNumberToObject(perf, "commit_limit",        (double)perfInfo.CommitLimit);
        cJSON_AddNumberToObject(perf, "commit_peak",         (double)perfInfo.CommitPeak);
        cJSON_AddNumberToObject(perf, "physical_total",      (double)perfInfo.PhysicalTotal);
        cJSON_AddNumberToObject(perf, "physical_available",  (double)perfInfo.PhysicalAvailable);
        cJSON_AddNumberToObject(perf, "system_cache",        (double)perfInfo.SystemCache);
        cJSON_AddNumberToObject(perf, "kernel_total",        (double)perfInfo.KernelTotal);
        cJSON_AddNumberToObject(perf, "kernel_paged",        (double)perfInfo.KernelPaged);
        cJSON_AddNumberToObject(perf, "kernel_nonpaged",     (double)perfInfo.KernelNonpaged);
        cJSON_AddNumberToObject(perf, "page_size",           (double)perfInfo.PageSize);
        cJSON_AddNumberToObject(perf, "process_count",       (double)perfInfo.ProcessCount);
        cJSON_AddNumberToObject(perf, "thread_count",        (double)perfInfo.ThreadCount);
        cJSON_AddNumberToObject(perf, "handle_count",        (double)perfInfo.HandleCount);
        cJSON_AddItemToObject(root, "performance_info", perf);
    }

    /* ===== 4. 可选：保存内存映像 ===== */
    if (saveDump && dumpPid > 0)
    {
        std::wstring wDumpPath = Utf8ToWstr(dumpPath);
        bool dumpOk = SaveMemoryDump((DWORD)dumpPid, wDumpPath.c_str());
        cJSON* dumpInfo = cJSON_CreateObject();
        cJSON_AddNumberToObject(dumpInfo, "target_pid",  (double)dumpPid);
        cJSON_AddStringToObject(dumpInfo, "output_path", dumpPath.c_str());
        cJSON_AddStringToObject(dumpInfo, "result",      dumpOk ? "success" : "failed");
        cJSON_AddItemToObject(root, "dump_result", dumpInfo);
    }

    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}

/*
 * SaveMemoryImageInfo — 采集内存映像并字段级存入 SQLite3
 * 参数 JSON: { "db_path": "C:\\basic.db" }
 * 返回 JSON: { "snapshot_id": N, "rows_inserted": N, "status": "success" }
 */
extern "C" __declspec(dllexport)
char* SaveMemoryImageInfo(const char* paramsJson)
{
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "module", "saveMemoryImageInfo");

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

    char* jsonStr = GetMemoryImageInfo(paramsJson);
    if (!jsonStr)
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", "GetMemoryImageInfo failed");
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

    long long snapId = db.SaveMemoryImageInfo(jsonStr);
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

