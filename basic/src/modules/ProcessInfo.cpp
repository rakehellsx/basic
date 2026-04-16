/*
 * Module: Process Information
 * Metrics: process list, modules, threads, command line, user name,
 *          CPU time, start time, memory, handle count, publisher, sign status
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
#include <sddl.h>
#include <time.h>
#include <string>
#include <vector>
#include "../common/Utils.h"
#include "../common/DbStorage.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "advapi32.lib")

/* -----------------------------------------------------------------------
 * Helper: get file last-write time as string
 * --------------------------------------------------------------------- */
static std::string GetFileModifyTime(const wchar_t* filePath)
{
    WIN32_FILE_ATTRIBUTE_DATA fad = {0};
    if (!GetFileAttributesExW(filePath, GetFileExInfoStandard, &fad))
        return "";
    return FileTimeToString(fad.ftLastWriteTime);
}

/* -----------------------------------------------------------------------
 * Helper: get process command line via PEB (works on Vista+)
 * Returns UTF-8 string; empty on failure or access denied.
 * --------------------------------------------------------------------- */
static std::string GetProcessCommandLine(HANDLE hProcess)
{
    /* Use NtQueryInformationProcess to get PEB address */
    typedef LONG (WINAPI *pfnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static pfnNtQIP NtQIP = (pfnNtQIP)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQIP) return "";

    /* PROCESS_BASIC_INFORMATION layout */
    struct PBI {
        PVOID Reserved1;
        PVOID PebBaseAddress;
        PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId;
        PVOID Reserved3;
    } pbi = {0};

    ULONG retLen = 0;
    if (NtQIP(hProcess, 0 /*ProcessBasicInformation*/,
              &pbi, sizeof(pbi), &retLen) != 0)
        return "";

    /* Read PEB.ProcessParameters offset (0x20 on x64, 0x10 on x86) */
#ifdef _WIN64
    const SIZE_T offParams = 0x20;
    const SIZE_T offCmdLine = 0x70; /* RTL_USER_PROCESS_PARAMETERS.CommandLine */
#else
    const SIZE_T offParams = 0x10;
    const SIZE_T offCmdLine = 0x40;
#endif

    PVOID pebBase = pbi.PebBaseAddress;
    PVOID paramsPtr = NULL;
    SIZE_T read = 0;
    if (!ReadProcessMemory(hProcess,
            (LPBYTE)pebBase + offParams, &paramsPtr, sizeof(paramsPtr), &read))
        return "";

    /* Read UNICODE_STRING (Length + MaximumLength + Buffer) */
    USHORT len = 0;
    PVOID  buf = NULL;
    if (!ReadProcessMemory(hProcess,
            (LPBYTE)paramsPtr + offCmdLine, &len, sizeof(len), &read))
        return "";
    if (!ReadProcessMemory(hProcess,
            (LPBYTE)paramsPtr + offCmdLine + sizeof(ULONG_PTR), &buf, sizeof(buf), &read))
        return "";

    if (!buf || len == 0 || len > 32767) return "";

    std::vector<wchar_t> wbuf(len / sizeof(wchar_t) + 1, L'\0');
    if (!ReadProcessMemory(hProcess, buf, wbuf.data(), len, &read))
        return "";

    return WideToUtf8(wbuf.data());
}

/* -----------------------------------------------------------------------
 * Helper: get the user name that owns the process token
 * --------------------------------------------------------------------- */
static std::string GetProcessUserName(HANDLE hProcess)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
        return "";

    DWORD needed = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &needed);
    if (needed == 0) { CloseHandle(hToken); return ""; }

    std::vector<BYTE> buf(needed);
    if (!GetTokenInformation(hToken, TokenUser, buf.data(), needed, &needed))
    {
        CloseHandle(hToken); return "";
    }
    CloseHandle(hToken);

    TOKEN_USER* ptu = reinterpret_cast<TOKEN_USER*>(buf.data());
    wchar_t name[256] = {0}, domain[256] = {0};
    DWORD nameLen = 256, domainLen = 256;
    SID_NAME_USE use;
    if (!LookupAccountSidW(NULL, ptu->User.Sid,
            name, &nameLen, domain, &domainLen, &use))
        return "";

    /* Return "DOMAIN\User" or just "User" */
    std::wstring result;
    if (domainLen > 0 && domain[0] != L'\0')
        result = std::wstring(domain) + L"\\" + std::wstring(name);
    else
        result = std::wstring(name);
    return WideToUtf8(result.c_str());
}

/* -----------------------------------------------------------------------
 * Helper: get process CPU time in milliseconds (kernel + user)
 * --------------------------------------------------------------------- */
static long long GetProcessCpuTimeMs(HANDLE hProcess)
{
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (!GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser))
        return 0;
    ULARGE_INTEGER k, u;
    k.LowPart  = ftKernel.dwLowDateTime;  k.HighPart = ftKernel.dwHighDateTime;
    u.LowPart  = ftUser.dwLowDateTime;    u.HighPart = ftUser.dwHighDateTime;
    /* 100-nanosecond intervals -> milliseconds */
    return (long long)((k.QuadPart + u.QuadPart) / 10000ULL);
}

/* -----------------------------------------------------------------------
 * Helper: get process start time as UTC string
 * --------------------------------------------------------------------- */
static std::string GetProcessStartTime(HANDLE hProcess)
{
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (!GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser))
        return "";
    return FileTimeToString(ftCreate);
}

/* -----------------------------------------------------------------------
 * Helper: convert trust_status string to is_signed / sign_valid booleans
 * VerifyAuthenticode returns strings like "Signed", "Unsigned", "Invalid", etc.
 * --------------------------------------------------------------------- */
static void ParseTrustStatus(const std::string& status, int& isSigned, int& signValid)
{
    isSigned  = 0;
    signValid = 0;
    if (status.empty() || status == "Unsigned") return;
    isSigned = 1;
    if (status == "Signed") signValid = 1;
}

/* -----------------------------------------------------------------------
 * Helper: enumerate modules of a process
 * --------------------------------------------------------------------- */
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

/* -----------------------------------------------------------------------
 * Helper: enumerate threads of a process
 * --------------------------------------------------------------------- */
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

/* -----------------------------------------------------------------------
 * Helper: get process handle count
 * --------------------------------------------------------------------- */
static DWORD QueryHandleCount(HANDLE hProcess)
{
    DWORD count = 0;
    ::GetProcessHandleCount(hProcess, &count);
    return count;
}

/* -----------------------------------------------------------------------
 * Export: GetProcessInfo
 * Returns JSON with "processes" array. Each entry uses field names that
 * match DbStorage.SaveProcessInfo expectations:
 *   pid, ppid, process_name, exe_path, command_line, user_name,
 *   session_id, priority, thread_count, handle_count,
 *   memory_kb, cpu_time_ms, start_time,
 *   is_signed, sign_valid, publisher
 * --------------------------------------------------------------------- */
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

            /* Basic fields from snapshot (always available) */
            cJSON_AddNumberToObject(proc, "pid",          (double)pe.th32ProcessID);
            cJSON_AddNumberToObject(proc, "ppid",         (double)pe.th32ParentProcessID);
            cJSON_AddStringToObject(proc, "process_name", WideToUtf8(pe.szExeFile).c_str());
            cJSON_AddNumberToObject(proc, "thread_count", (double)pe.cntThreads);

            /* Fields requiring an open process handle */
            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, pe.th32ProcessID);

            if (hProc)
            {
                /* exe_path (replaces image_path) */
                wchar_t imagePath[MAX_PATH] = {0};
                DWORD pathLen = MAX_PATH;
                if (QueryFullProcessImageNameW(hProc, 0, imagePath, &pathLen))
                {
                    cJSON_AddStringToObject(proc, "exe_path",
                        WideToUtf8(imagePath).c_str());

                    /* Sign / publisher info */
                    std::string trustStatus = VerifyAuthenticode(imagePath);
                    int isSigned = 0, signValid = 0;
                    ParseTrustStatus(trustStatus, isSigned, signValid);
                    cJSON_AddNumberToObject(proc, "is_signed",  (double)isSigned);
                    cJSON_AddNumberToObject(proc, "sign_valid", (double)signValid);
                    cJSON_AddStringToObject(proc, "publisher",
                        GetFilePublisherW(imagePath).c_str());
                    /* Keep extra fields for raw JSON consumers */
                    cJSON_AddStringToObject(proc, "modify_time",
                        GetFileModifyTime(imagePath).c_str());
                    cJSON_AddStringToObject(proc, "trust_status", trustStatus.c_str());
                }

                /* command_line */
                cJSON_AddStringToObject(proc, "command_line",
                    GetProcessCommandLine(hProc).c_str());

                /* user_name */
                cJSON_AddStringToObject(proc, "user_name",
                    GetProcessUserName(hProc).c_str());

                /* session_id */
                DWORD sessionId = 0;
                ProcessIdToSessionId(pe.th32ProcessID, &sessionId);
                cJSON_AddNumberToObject(proc, "session_id", (double)sessionId);

                /* priority class -> numeric priority */
                DWORD pc = GetPriorityClass(hProc);
                int prio = 8; /* NORMAL_PRIORITY_CLASS default */
                switch (pc)
                {
                case IDLE_PRIORITY_CLASS:          prio = 4;  break;
                case BELOW_NORMAL_PRIORITY_CLASS:  prio = 6;  break;
                case NORMAL_PRIORITY_CLASS:        prio = 8;  break;
                case ABOVE_NORMAL_PRIORITY_CLASS:  prio = 10; break;
                case HIGH_PRIORITY_CLASS:          prio = 13; break;
                case REALTIME_PRIORITY_CLASS:      prio = 24; break;
                }
                cJSON_AddNumberToObject(proc, "priority", (double)prio);

                /* handle_count */
                cJSON_AddNumberToObject(proc, "handle_count",
                    (double)QueryHandleCount(hProc));

                /* memory_kb (working set in KB) */
                PROCESS_MEMORY_COUNTERS_EX pmc = {0};
                pmc.cb = sizeof(pmc);
                if (GetProcessMemoryInfo(hProc,
                    (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc)))
                {
                    long long wskb = (long long)(pmc.WorkingSetSize / 1024);
                    cJSON_AddNumberToObject(proc, "memory_kb",     (double)wskb);
                    /* Keep raw byte strings for other consumers */
                    cJSON_AddStringToObject(proc, "working_set",
                        LargeIntToString(pmc.WorkingSetSize).c_str());
                    cJSON_AddStringToObject(proc, "private_usage",
                        LargeIntToString(pmc.PrivateUsage).c_str());
                }

                /* cpu_time_ms */
                cJSON_AddNumberToObject(proc, "cpu_time_ms",
                    (double)GetProcessCpuTimeMs(hProc));

                /* start_time */
                cJSON_AddStringToObject(proc, "start_time",
                    GetProcessStartTime(hProc).c_str());

                CloseHandle(hProc);
            }
            else
            {
                /* Process not accessible: fill required fields with defaults */
                cJSON_AddStringToObject(proc, "exe_path",     "");
                cJSON_AddStringToObject(proc, "command_line", "");
                cJSON_AddStringToObject(proc, "user_name",    "");
                cJSON_AddNumberToObject(proc, "session_id",   0);
                cJSON_AddNumberToObject(proc, "priority",     0);
                cJSON_AddNumberToObject(proc, "handle_count", 0);
                cJSON_AddNumberToObject(proc, "memory_kb",    0);
                cJSON_AddNumberToObject(proc, "cpu_time_ms",  0);
                cJSON_AddStringToObject(proc, "start_time",   "");
                cJSON_AddNumberToObject(proc, "is_signed",    0);
                cJSON_AddNumberToObject(proc, "sign_valid",   0);
                cJSON_AddStringToObject(proc, "publisher",    "");
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
 * SaveProcessInfo - collect process info and store field-by-field into SQLite3
 * Params JSON: { "db_path": "C:\\basic.db" }
 * Return JSON: { "snapshot_id": N, "status": "success" }
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
