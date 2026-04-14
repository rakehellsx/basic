/*
 * 模块：内存映像（系统）
 * 指标：内存运行状态、内核模块基址、映像大小、标志、序号、路径、授信状态
 * 可选：保存当前内存映像到文件
 */
#include <windows.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#include <vector>
#include "../../third_party/cJSON/cJSON.h"
#include "../common/Utils.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "version.lib")

static std::string VerifyTrust(const wchar_t* path)
{
    if (!path || !path[0]) return "Unknown";
    WINTRUST_FILE_INFO fi = {0};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path;
    GUID pg = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA td = {0};
    td.cbStruct = sizeof(td);
    td.dwUIChoice = WTD_UI_NONE;
    td.fdwRevocationChecks = WTD_REVOKE_NONE;
    td.dwUnionChoice = WTD_CHOICE_FILE;
    td.pFile = &fi;
    td.dwStateAction = WTD_STATEACTION_VERIFY;
    td.dwProvFlags = WTD_SAFER_FLAG;
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

// 保存进程内存映像到文件（MiniDump）
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
    if (!pMiniDumpWriteDump)
    {
        FreeLibrary(hDbgHelp);
        return false;
    }

    HANDLE hProc = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc)
    {
        FreeLibrary(hDbgHelp);
        return false;
    }

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

extern "C" __declspec(dllexport)
char* GetMemoryImageInfo(const char* paramsJson)
{
    // 参数：save_dump(bool), dump_pid(int), dump_path(string)
    bool saveDump = GetBoolParam(paramsJson, "save_dump", false);
    int dumpPid   = GetIntParam(paramsJson, "dump_pid", 0);
    std::string dumpPath = GetStringParam(paramsJson, "dump_path", "C:\\memdump.dmp");

    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "memory_image");

    // ===== 1. 系统内存状态 =====
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

    // ===== 2. 内核模块（驱动）列表 =====
    // 使用 EnumDeviceDrivers 获取内核模块基址
    LPVOID drivers[1024] = {0};
    DWORD cbNeeded = 0;
    cJSON* kernelModules = cJSON_CreateArray();

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
    {
        DWORD count = cbNeeded / sizeof(LPVOID);
        for (DWORD i = 0; i < count; i++)
        {
            cJSON* km = cJSON_CreateObject();

            // 基址
            char addrBuf[32];
            _snprintf_s(addrBuf, sizeof(addrBuf), _TRUNCATE,
                "0x%p", drivers[i]);
            cJSON_AddStringToObject(km, "base_address", addrBuf);
            cJSON_AddNumberToObject(km, "index", (double)i);

            // 模块路径
            wchar_t drvPath[MAX_PATH] = {0};
            if (GetDeviceDriverFileNameW(drivers[i], drvPath, MAX_PATH))
            {
                // 将 \Device\HarddiskVolume 路径转为 DOS 路径
                wchar_t dosPath[MAX_PATH] = {0};
                // 尝试通过GetSystemDirectory前缀替换
                wchar_t sysRoot[MAX_PATH] = {0};
                GetSystemDirectoryW(sysRoot, MAX_PATH);

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

                // 映像大小（通过GetDeviceDriverBaseName获取文件名）
                wchar_t baseName[MAX_PATH] = {0};
                GetDeviceDriverBaseNameW(drivers[i], baseName, MAX_PATH);
                cJSON_AddStringToObject(km, "module_name",
                    WideToUtf8(baseName).c_str());

                // 授信状态
                if (!winPath.empty())
                    cJSON_AddStringToObject(km, "trust_status",
                        VerifyTrust(winPath.c_str()).c_str());

                // 修改时间
                WIN32_FILE_ATTRIBUTE_DATA fad = {0};
                if (GetFileAttributesExW(winPath.c_str(),
                    GetFileExInfoStandard, &fad))
                    cJSON_AddStringToObject(km, "modify_time",
                        FileTimeToString(fad.ftLastWriteTime).c_str());
            }

            cJSON_AddItemToArray(kernelModules, km);
        }
    }
    cJSON_AddItemToObject(root, "kernel_modules", kernelModules);

    // ===== 3. 系统页面文件信息 =====
    PERFORMANCE_INFORMATION perfInfo = {0};
    perfInfo.cb = sizeof(perfInfo);
    if (GetPerformanceInfo(&perfInfo, sizeof(perfInfo)))
    {
        cJSON* perf = cJSON_CreateObject();
        cJSON_AddNumberToObject(perf, "commit_total",
            (double)perfInfo.CommitTotal);
        cJSON_AddNumberToObject(perf, "commit_limit",
            (double)perfInfo.CommitLimit);
        cJSON_AddNumberToObject(perf, "commit_peak",
            (double)perfInfo.CommitPeak);
        cJSON_AddNumberToObject(perf, "physical_total",
            (double)perfInfo.PhysicalTotal);
        cJSON_AddNumberToObject(perf, "physical_available",
            (double)perfInfo.PhysicalAvailable);
        cJSON_AddNumberToObject(perf, "system_cache",
            (double)perfInfo.SystemCache);
        cJSON_AddNumberToObject(perf, "kernel_total",
            (double)perfInfo.KernelTotal);
        cJSON_AddNumberToObject(perf, "kernel_paged",
            (double)perfInfo.KernelPaged);
        cJSON_AddNumberToObject(perf, "kernel_nonpaged",
            (double)perfInfo.KernelNonpaged);
        cJSON_AddNumberToObject(perf, "page_size",
            (double)perfInfo.PageSize);
        cJSON_AddNumberToObject(perf, "process_count",
            (double)perfInfo.ProcessCount);
        cJSON_AddNumberToObject(perf, "thread_count",
            (double)perfInfo.ThreadCount);
        cJSON_AddNumberToObject(perf, "handle_count",
            (double)perfInfo.HandleCount);
        cJSON_AddItemToObject(root, "performance_info", perf);
    }

    // ===== 4. 可选：保存内存映像 =====
    if (saveDump && dumpPid > 0)
    {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, dumpPath.c_str(), -1, NULL, 0);
        std::wstring wDumpPath(wlen - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, dumpPath.c_str(), -1, &wDumpPath[0], wlen);

        bool dumpOk = SaveMemoryDump((DWORD)dumpPid, wDumpPath.c_str());
        cJSON* dumpInfo = cJSON_CreateObject();
        cJSON_AddNumberToObject(dumpInfo, "target_pid", (double)dumpPid);
        cJSON_AddStringToObject(dumpInfo, "output_path", dumpPath.c_str());
        cJSON_AddStringToObject(dumpInfo, "result", dumpOk ? "success" : "failed");
        cJSON_AddItemToObject(root, "dump_result", dumpInfo);
    }

    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}
