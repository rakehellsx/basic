/*
 * 模块：进程信息
 * 指标：进程、模块、线程、文件句柄、发行商、修改时间、映像路径、授信状态
 */
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include "../../third_party/cJSON/cJSON.h"
#include "../common/Utils.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "version.lib")

// 验证文件数字签名（Authenticode）
static std::string VerifyFileTrust(const wchar_t* filePath)
{
    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData = {0};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_SAFER_FLAG;

    LONG result = WinVerifyTrust(NULL, &policyGUID, &trustData);

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);

    switch (result)
    {
    case ERROR_SUCCESS:         return "Trusted";
    case TRUST_E_NOSIGNATURE:   return "Unsigned";
    case TRUST_E_EXPLICIT_DISTRUST: return "Distrust";
    case TRUST_E_SUBJECT_NOT_TRUSTED: return "NotTrusted";
    case CRYPT_E_SECURITY_SETTINGS: return "SecuritySettings";
    default:
        char buf[32];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Unknown(0x%08X)", (unsigned)result);
        return buf;
    }
}

// 从版本信息获取发行商（CompanyName）
static std::string GetFilePublisher(const wchar_t* filePath)
{
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(filePath, &dummy);
    if (size == 0) return "";

    std::vector<BYTE> buf(size);
    if (!GetFileVersionInfoW(filePath, 0, size, buf.data())) return "";

    struct LANGCODEPAGE { WORD language; WORD codePage; };
    LANGCODEPAGE* lpTranslate = NULL;
    UINT cbTranslate = 0;
    if (!VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation",
        (LPVOID*)&lpTranslate, &cbTranslate))
        return "";

    if (cbTranslate < sizeof(LANGCODEPAGE)) return "";

    wchar_t subBlock[64];
    _snwprintf_s(subBlock, 64, _TRUNCATE,
        L"\\StringFileInfo\\%04x%04x\\CompanyName",
        lpTranslate[0].language, lpTranslate[0].codePage);

    wchar_t* company = NULL;
    UINT compLen = 0;
    if (VerQueryValueW(buf.data(), subBlock, (LPVOID*)&company, &compLen) && company)
        return WideToUtf8(company);
    return "";
}

// 获取文件修改时间
static std::string GetFileModifyTime(const wchar_t* filePath)
{
    WIN32_FILE_ATTRIBUTE_DATA fad = {0};
    if (!GetFileAttributesExW(filePath, GetFileExInfoStandard, &fad))
        return "";
    return FileTimeToString(fad.ftLastWriteTime);
}

// 枚举进程的模块列表
static cJSON* GetProcessModules(DWORD pid)
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
                GetFilePublisher(me.szExePath).c_str());
            cJSON_AddStringToObject(mod, "modify_time",
                GetFileModifyTime(me.szExePath).c_str());
            cJSON_AddStringToObject(mod, "trust_status",
                VerifyFileTrust(me.szExePath).c_str());
            cJSON_AddStringToObject(mod, "base_address",
                [&]() -> std::string {
                    char buf[32];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%p", me.modBaseAddr);
                    return buf;
                }().c_str());
            cJSON_AddNumberToObject(mod, "base_size", (double)me.modBaseSize);
            cJSON_AddItemToArray(arr, mod);
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    return arr;
}

// 枚举进程的线程列表
static cJSON* GetProcessThreads(DWORD pid)
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
            cJSON_AddNumberToObject(thd, "thread_id", (double)te.th32ThreadID);
            cJSON_AddNumberToObject(thd, "base_priority", (double)te.tpBasePri);
            cJSON_AddNumberToObject(thd, "delta_priority", (double)te.tpDeltaPri);
            cJSON_AddItemToArray(arr, thd);
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return arr;
}

// 枚举进程打开的文件句柄（通过NtQuerySystemInformation，简化版）
static int GetProcessHandleCount(HANDLE hProcess)
{
    DWORD count = 0;
    GetProcessHandleCount(hProcess, &count);
    return (int)count;
}

extern "C" __declspec(dllexport)
char* GetProcessInfo(const char* paramsJson)
{
    // 参数：include_modules(bool), include_threads(bool)
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
            cJSON_AddNumberToObject(proc, "pid",        (double)pe.th32ProcessID);
            cJSON_AddNumberToObject(proc, "ppid",       (double)pe.th32ParentProcessID);
            cJSON_AddStringToObject(proc, "name",       WideToUtf8(pe.szExeFile).c_str());
            cJSON_AddNumberToObject(proc, "thread_count", (double)pe.cntThreads);

            // 打开进程获取详细信息
            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, pe.th32ProcessID);

            if (hProc)
            {
                // 映像路径
                wchar_t imagePath[MAX_PATH] = {0};
                DWORD pathLen = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, imagePath, &pathLen))
                {
                    cJSON_AddStringToObject(proc, "image_path",
                        WideToUtf8(imagePath).c_str());
                    cJSON_AddStringToObject(proc, "publisher",
                        GetFilePublisher(imagePath).c_str());
                    cJSON_AddStringToObject(proc, "modify_time",
                        GetFileModifyTime(imagePath).c_str());
                    cJSON_AddStringToObject(proc, "trust_status",
                        VerifyFileTrust(imagePath).c_str());
                }

                // 文件句柄数
                cJSON_AddNumberToObject(proc, "handle_count",
                    (double)GetProcessHandleCount(hProc));

                // 内存信息
                PROCESS_MEMORY_COUNTERS_EX pmc = {0};
                pmc.cb = sizeof(pmc);
                if (GetProcessMemoryInfo(hProc, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc)))
                {
                    cJSON_AddStringToObject(proc, "working_set",
                        LargeIntToString(pmc.WorkingSetSize).c_str());
                    cJSON_AddStringToObject(proc, "private_usage",
                        LargeIntToString(pmc.PrivateUsage).c_str());
                }

                CloseHandle(hProc);
            }

            // 模块列表
            if (inclModules)
                cJSON_AddItemToObject(proc, "modules",
                    GetProcessModules(pe.th32ProcessID));

            // 线程列表
            if (inclThreads)
                cJSON_AddItemToObject(proc, "threads",
                    GetProcessThreads(pe.th32ProcessID));

            cJSON_AddItemToArray(procArr, proc);
        } while (Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    cJSON_AddItemToObject(root, "processes", procArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}
