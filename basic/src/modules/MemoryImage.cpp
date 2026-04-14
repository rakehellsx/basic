/*
 * 模块：内存映像（系统）
 * 指标：内存运行状态、内核模块基址、映像大小、标志(Flags)、序号(Index)、路径、授信状态
 * 可选：保存当前内存映像到文件（MiniDump）
 *
 * 实现说明：
 *   - 内核模块的 Flags 和 Index 通过 NtQuerySystemInformation(SystemModuleInformation)
 *     获取，该接口返回 SYSTEM_MODULE_ENTRY 结构，包含完整的 Flags、LoadOrderIndex 等字段。
 *   - EnumDeviceDrivers 仅用于备用路径，不提供 Flags 信息。
 */
#include <windows.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <winternl.h>
#include <string>
#include <vector>
#include "../../third_party/cJSON/cJSON.h"
#include "../common/Utils.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "ntdll.lib")

/* -----------------------------------------------------------------------
 * NtQuerySystemInformation 相关结构定义
 * （Windows SDK 未完全公开，需手动定义）
 * --------------------------------------------------------------------- */
#define SystemModuleInformation 11

typedef struct _SYSTEM_MODULE_ENTRY
{
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;       // 模块加载基址
    ULONG   ImageSize;       // 映像大小
    ULONG   Flags;           // 模块标志位（LDRP_xxx）
    USHORT  LoadOrderIndex;  // 加载顺序序号
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName; // 文件名在 FullPathName 中的偏移
    UCHAR   FullPathName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG               Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

/* NtQuerySystemInformation 函数指针 */
typedef NTSTATUS(WINAPI* PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

/* -----------------------------------------------------------------------
 * 标志位解析：将 Flags 转为可读字符串列表
 * --------------------------------------------------------------------- */
static std::string ParseModuleFlags(ULONG flags)
{
    std::string result;
    struct { ULONG bit; const char* name; } flagTable[] = {
        { 0x00000001, "LDRP_STATIC_LINK"           },
        { 0x00000002, "LDRP_IMAGE_DLL"             },
        { 0x00000004, "LDRP_LOAD_IN_PROGRESS"      },
        { 0x00000008, "LDRP_UNLOAD_IN_PROGRESS"    },
        { 0x00000010, "LDRP_ENTRY_PROCESSED"       },
        { 0x00000020, "LDRP_ENTRY_INSERTED"        },
        { 0x00000040, "LDRP_CURRENT_LOAD"          },
        { 0x00000080, "LDRP_FAILED_BUILTIN_LOAD"   },
        { 0x00000100, "LDRP_DONT_CALL_FOR_THREADS" },
        { 0x00000200, "LDRP_PROCESS_ATTACH_CALLED" },
        { 0x00000400, "LDRP_DEBUG_SYMBOLS_LOADED"  },
        { 0x00000800, "LDRP_IMAGE_NOT_AT_BASE"     },
        { 0x00001000, "LDRP_WX86_IGNORE_MACHINETYPE"},
        { 0x00002000, "LDRP_COR_IMAGE"             },
        { 0x00004000, "LDRP_COR_OWNS_UNMAP"        },
        { 0x00008000, "LDRP_SYSTEM_MAPPED"         },
        { 0x00010000, "LDRP_IMAGE_VERIFYING"       },
        { 0x00020000, "LDRP_DRIVER_DEPENDENT_DLL"  },
        { 0x00040000, "LDRP_ENTRY_NATIVE"          },
        { 0x00080000, "LDRP_REDIRECTED"            },
        { 0x00100000, "LDRP_NON_PAGED_DEBUG_INFO"  },
        { 0x00200000, "LDRP_MM_LOADED"             },
        { 0x00400000, "LDRP_COMPAT_DATABASE_PROCESSED" },
        { 0,          NULL }
    };
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
 * 授信状态验证
 * --------------------------------------------------------------------- */
static std::string VerifyTrust(const wchar_t* path)
{
    if (!path || !path[0]) return "Unknown";
    WINTRUST_FILE_INFO fi = {0};
    fi.cbStruct    = sizeof(fi);
    fi.pcwszFilePath = path;
    GUID pg = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA td = {0};
    td.cbStruct          = sizeof(td);
    td.dwUIChoice        = WTD_UI_NONE;
    td.fdwRevocationChecks = WTD_REVOKE_NONE;
    td.dwUnionChoice     = WTD_CHOICE_FILE;
    td.pFile             = &fi;
    td.dwStateAction     = WTD_STATEACTION_VERIFY;
    td.dwProvFlags       = WTD_SAFER_FLAG;
    LONG r = WinVerifyTrust(NULL, &pg, &td);
    td.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &pg, &td);
    switch (r)
    {
    case ERROR_SUCCESS:               return "Trusted";
    case TRUST_E_NOSIGNATURE:         return "Unsigned";
    case TRUST_E_EXPLICIT_DISTRUST:   return "Distrust";
    case TRUST_E_SUBJECT_NOT_TRUSTED: return "NotTrusted";
    default:
        char buf[32];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Unknown(0x%08X)", (unsigned)r);
        return buf;
    }
}

/* -----------------------------------------------------------------------
 * 保存进程内存映像到文件（MiniDump）
 * --------------------------------------------------------------------- */
static bool SaveMemoryDump(DWORD pid, const wchar_t* outputPath)
{
    typedef BOOL(WINAPI* PFN_MINIDUMPWRITEDUMP)(
        HANDLE, DWORD, HANDLE, MINIDUMP_TYPE,
        PMINIDUMP_EXCEPTION_INFORMATION,
        PMINIDUMP_USER_STREAM_INFORMATION,
        PMINIDUMP_CALLBACK_INFORMATION);

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

    BOOL ok = pMiniDumpWriteDump(hProc, pid, hFile,
        (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithHandleData),
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
    bool saveDump   = GetBoolParam(paramsJson, "save_dump", false);
    int  dumpPid    = GetIntParam(paramsJson, "dump_pid", 0);
    std::string dumpPath = GetStringParam(paramsJson, "dump_path", "C:\\memdump.dmp");

    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "memory_image");

    /* ===== 1. 系统内存状态 ===== */
    MEMORYSTATUSEX ms = {0};
    ms.dwLength = sizeof(ms);
    if (GlobalMemoryStatusEx(&ms))
    {
        cJSON* memStatus = cJSON_CreateObject();
        cJSON_AddNumberToObject(memStatus, "memory_load_percent",
            (double)ms.dwMemoryLoad);
        cJSON_AddStringToObject(memStatus, "total_physical",
            LargeIntToString(ms.ullTotalPhys).c_str());
        cJSON_AddStringToObject(memStatus, "available_physical",
            LargeIntToString(ms.ullAvailPhys).c_str());
        cJSON_AddStringToObject(memStatus, "total_page_file",
            LargeIntToString(ms.ullTotalPageFile).c_str());
        cJSON_AddStringToObject(memStatus, "available_page_file",
            LargeIntToString(ms.ullAvailPageFile).c_str());
        cJSON_AddStringToObject(memStatus, "total_virtual",
            LargeIntToString(ms.ullTotalVirtual).c_str());
        cJSON_AddStringToObject(memStatus, "available_virtual",
            LargeIntToString(ms.ullAvailVirtual).c_str());
        cJSON_AddItemToObject(root, "memory_status", memStatus);
    }

    /* ===== 2. 内核模块列表（含 Flags 和 Index）===== */
    cJSON* kernelModules = cJSON_CreateArray();

    /* 优先使用 NtQuerySystemInformation 获取完整信息（含 Flags / Index） */
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    PFN_NtQuerySystemInformation pNtQSI = hNtdll
        ? (PFN_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation")
        : NULL;

    bool usedNtQSI = false;
    if (pNtQSI)
    {
        ULONG bufLen = 0;
        /* 第一次调用获取所需缓冲区大小 */
        pNtQSI(SystemModuleInformation, NULL, 0, &bufLen);
        bufLen += 4096; /* 留余量 */

        std::vector<BYTE> buf(bufLen, 0);
        NTSTATUS status = pNtQSI(SystemModuleInformation,
            buf.data(), bufLen, &bufLen);

        if (status == 0 /* STATUS_SUCCESS */)
        {
            PSYSTEM_MODULE_INFORMATION pInfo =
                reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(buf.data());

            for (ULONG i = 0; i < pInfo->Count; i++)
            {
                SYSTEM_MODULE_ENTRY& entry = pInfo->Module[i];
                cJSON* km = cJSON_CreateObject();

                /* 序号（LoadOrderIndex） */
                cJSON_AddNumberToObject(km, "index",
                    (double)entry.LoadOrderIndex);

                /* 基址 */
                char addrBuf[32];
                _snprintf_s(addrBuf, sizeof(addrBuf), _TRUNCATE,
                    "0x%p", entry.ImageBase);
                cJSON_AddStringToObject(km, "base_address", addrBuf);

                /* 映像大小 */
                cJSON_AddNumberToObject(km, "image_size",
                    (double)entry.ImageSize);

                /* 标志（原始值 + 可读解析） */
                char flagHex[16];
                _snprintf_s(flagHex, sizeof(flagHex), _TRUNCATE,
                    "0x%08X", entry.Flags);
                cJSON_AddStringToObject(km, "flags_hex", flagHex);
                cJSON_AddStringToObject(km, "flags_desc",
                    ParseModuleFlags(entry.Flags).c_str());

                /* 加载计数 */
                cJSON_AddNumberToObject(km, "load_count",
                    (double)entry.LoadCount);

                /* 路径（FullPathName 为 ANSI，转 UTF-8） */
                const char* rawPath =
                    reinterpret_cast<const char*>(entry.FullPathName);
                std::string ansiPath(rawPath);

                /* 将 \SystemRoot\ 替换为实际 Windows 目录 */
                std::string dosPath = ansiPath;
                if (ansiPath.find("\\SystemRoot\\") == 0)
                {
                    wchar_t winDir[MAX_PATH] = {0};
                    GetWindowsDirectoryW(winDir, MAX_PATH);
                    std::string winDirA = WideToUtf8(winDir);
                    dosPath = winDirA + ansiPath.substr(11);
                }
                else if (ansiPath.find("\\??\\") == 0)
                    dosPath = ansiPath.substr(4);

                cJSON_AddStringToObject(km, "path", dosPath.c_str());

                /* 模块名（FullPathName + OffsetToFileName） */
                const char* baseName = rawPath + entry.OffsetToFileName;
                cJSON_AddStringToObject(km, "module_name", baseName);

                /* 授信状态 */
                if (!dosPath.empty())
                {
                    int wlen = MultiByteToWideChar(
                        CP_UTF8, 0, dosPath.c_str(), -1, NULL, 0);
                    std::wstring wPath(wlen - 1, L'\0');
                    MultiByteToWideChar(
                        CP_UTF8, 0, dosPath.c_str(), -1, &wPath[0], wlen);
                    cJSON_AddStringToObject(km, "trust_status",
                        VerifyTrust(wPath.c_str()).c_str());

                    /* 修改时间 */
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
    }

    /* 备用方案：EnumDeviceDrivers（不提供 Flags，仅提供基址和路径） */
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
                _snprintf_s(addrBuf, sizeof(addrBuf), _TRUNCATE,
                    "0x%p", drivers[i]);
                cJSON_AddStringToObject(km, "base_address", addrBuf);

                /* Flags 不可用时标注 */
                cJSON_AddStringToObject(km, "flags_hex", "N/A");
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
                            VerifyTrust(winPath.c_str()).c_str());

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
        cJSON_AddNumberToObject(perf, "commit_total",    (double)perfInfo.CommitTotal);
        cJSON_AddNumberToObject(perf, "commit_limit",    (double)perfInfo.CommitLimit);
        cJSON_AddNumberToObject(perf, "commit_peak",     (double)perfInfo.CommitPeak);
        cJSON_AddNumberToObject(perf, "physical_total",  (double)perfInfo.PhysicalTotal);
        cJSON_AddNumberToObject(perf, "physical_available", (double)perfInfo.PhysicalAvailable);
        cJSON_AddNumberToObject(perf, "system_cache",    (double)perfInfo.SystemCache);
        cJSON_AddNumberToObject(perf, "kernel_total",    (double)perfInfo.KernelTotal);
        cJSON_AddNumberToObject(perf, "kernel_paged",    (double)perfInfo.KernelPaged);
        cJSON_AddNumberToObject(perf, "kernel_nonpaged", (double)perfInfo.KernelNonpaged);
        cJSON_AddNumberToObject(perf, "page_size",       (double)perfInfo.PageSize);
        cJSON_AddNumberToObject(perf, "process_count",   (double)perfInfo.ProcessCount);
        cJSON_AddNumberToObject(perf, "thread_count",    (double)perfInfo.ThreadCount);
        cJSON_AddNumberToObject(perf, "handle_count",    (double)perfInfo.HandleCount);
        cJSON_AddItemToObject(root, "performance_info", perf);
    }

    /* ===== 4. 可选：保存内存映像 ===== */
    if (saveDump && dumpPid > 0)
    {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, dumpPath.c_str(), -1, NULL, 0);
        std::wstring wDumpPath(wlen - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, dumpPath.c_str(), -1, &wDumpPath[0], wlen);

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
