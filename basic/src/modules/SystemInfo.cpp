/*
 * 模块：系统信息
 * 指标：系统版本、安装时间、计算机名称、账户
 */
#include <windows.h>
#include <lm.h>
#include <sddl.h>
#include <string>
#include "../../third_party/cJSON/cJSON.h"
#include "../common/Utils.h"

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")

// 从注册表读取Windows安装时间
static std::string GetWindowsInstallDate()
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return "unknown";

    DWORD installDate = 0;
    DWORD size = sizeof(DWORD);
    DWORD type = REG_DWORD;
    if (RegQueryValueExW(hKey, L"InstallDate", NULL, &type,
        (LPBYTE)&installDate, &size) == ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        // installDate 是 Unix 时间戳
        time_t t = (time_t)installDate;
        struct tm tmInfo;
        gmtime_s(&tmInfo, &t);
        char buf[32];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmInfo);
        return std::string(buf) + " (UTC)";
    }
    RegCloseKey(hKey);
    return "unknown";
}

// 读取注册表字符串值
static std::string GetRegString(HKEY hKey, const wchar_t* valueName)
{
    wchar_t buf[512] = {0};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    if (RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)buf, &size) == ERROR_SUCCESS)
        return WideToUtf8(buf);
    return "";
}

// 枚举本地账户
static cJSON* EnumLocalAccounts()
{
    cJSON* arr = cJSON_CreateArray();
    NET_API_STATUS status;
    USER_INFO_3* pBuf = NULL;
    DWORD entriesRead = 0, totalEntries = 0;
    DWORD_PTR resumeHandle = 0;

    do {
        status = NetUserEnum(NULL, 3, FILTER_NORMAL_ACCOUNT,
            (LPBYTE*)&pBuf, MAX_PREFERRED_LENGTH,
            &entriesRead, &totalEntries, &resumeHandle);
        if (status == NERR_Success || status == ERROR_MORE_DATA)
        {
            for (DWORD i = 0; i < entriesRead; i++)
            {
                cJSON* user = cJSON_CreateObject();
                cJSON_AddStringToObject(user, "username",
                    WideToUtf8(pBuf[i].usri3_name).c_str());
                cJSON_AddStringToObject(user, "full_name",
                    WideToUtf8(pBuf[i].usri3_full_name).c_str());
                cJSON_AddStringToObject(user, "comment",
                    WideToUtf8(pBuf[i].usri3_comment).c_str());

                // 账户标志解析
                DWORD flags = pBuf[i].usri3_flags;
                cJSON_AddBoolToObject(user, "disabled",
                    (flags & UF_ACCOUNTDISABLE) ? 1 : 0);
                cJSON_AddBoolToObject(user, "password_never_expires",
                    (flags & UF_DONT_EXPIRE_PASSWD) ? 1 : 0);
                cJSON_AddBoolToObject(user, "lockout",
                    (flags & UF_LOCKOUT) ? 1 : 0);

                // 最后登录时间
                if (pBuf[i].usri3_last_logon != 0)
                {
                    time_t t = (time_t)pBuf[i].usri3_last_logon;
                    struct tm tmInfo;
                    gmtime_s(&tmInfo, &t);
                    char buf[32];
                    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmInfo);
                    cJSON_AddStringToObject(user, "last_logon",
                        (std::string(buf) + " (UTC)").c_str());
                }
                else
                    cJSON_AddStringToObject(user, "last_logon", "never");

                // 账户类型
                cJSON_AddStringToObject(user, "priv",
                    pBuf[i].usri3_priv == USER_PRIV_ADMIN ? "admin" :
                    pBuf[i].usri3_priv == USER_PRIV_GUEST ? "guest" : "user");

                cJSON_AddItemToArray(arr, user);
            }
            NetApiBufferFree(pBuf);
            pBuf = NULL;
        }
    } while (status == ERROR_MORE_DATA);

    return arr;
}

extern "C" __declspec(dllexport)
char* GetSystemInfo(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "system_info");

    // 1. 操作系统版本
    HKEY hKey = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        cJSON* osInfo = cJSON_CreateObject();
        cJSON_AddStringToObject(osInfo, "product_name",
            GetRegString(hKey, L"ProductName").c_str());
        cJSON_AddStringToObject(osInfo, "display_version",
            GetRegString(hKey, L"DisplayVersion").c_str());
        cJSON_AddStringToObject(osInfo, "current_build",
            GetRegString(hKey, L"CurrentBuild").c_str());
        cJSON_AddStringToObject(osInfo, "ubr",
            GetRegString(hKey, L"UBR").c_str());
        cJSON_AddStringToObject(osInfo, "edition_id",
            GetRegString(hKey, L"EditionID").c_str());
        cJSON_AddStringToObject(osInfo, "registered_owner",
            GetRegString(hKey, L"RegisteredOwner").c_str());
        cJSON_AddStringToObject(osInfo, "registered_organization",
            GetRegString(hKey, L"RegisteredOrganization").c_str());
        cJSON_AddStringToObject(osInfo, "install_date",
            GetWindowsInstallDate().c_str());
        RegCloseKey(hKey);
        cJSON_AddItemToObject(root, "os_info", osInfo);
    }

    // 2. 计算机名称
    wchar_t compName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD compNameLen = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(compName, &compNameLen))
        cJSON_AddStringToObject(root, "computer_name", WideToUtf8(compName).c_str());
    else
        cJSON_AddStringToObject(root, "computer_name", "unknown");

    // 3. 系统目录
    wchar_t sysDir[MAX_PATH] = {0};
    GetSystemDirectoryW(sysDir, MAX_PATH);
    cJSON_AddStringToObject(root, "system_directory", WideToUtf8(sysDir).c_str());

    wchar_t winDir[MAX_PATH] = {0};
    GetWindowsDirectoryW(winDir, MAX_PATH);
    cJSON_AddStringToObject(root, "windows_directory", WideToUtf8(winDir).c_str());

    // 4. 系统架构
    SYSTEM_INFO si = {0};
    GetNativeSystemInfo(&si);
    const char* arch = "unknown";
    switch (si.wProcessorArchitecture)
    {
    case PROCESSOR_ARCHITECTURE_AMD64: arch = "x64"; break;
    case PROCESSOR_ARCHITECTURE_INTEL: arch = "x86"; break;
    case PROCESSOR_ARCHITECTURE_ARM64: arch = "ARM64"; break;
    case PROCESSOR_ARCHITECTURE_ARM:   arch = "ARM"; break;
    }
    cJSON_AddStringToObject(root, "processor_architecture", arch);
    cJSON_AddNumberToObject(root, "number_of_processors", si.dwNumberOfProcessors);

    // 5. 内存信息
    MEMORYSTATUSEX memStat = {0};
    memStat.dwLength = sizeof(memStat);
    if (GlobalMemoryStatusEx(&memStat))
    {
        cJSON* memInfo = cJSON_CreateObject();
        cJSON_AddStringToObject(memInfo, "total_physical",
            LargeIntToString(memStat.ullTotalPhys).c_str());
        cJSON_AddStringToObject(memInfo, "available_physical",
            LargeIntToString(memStat.ullAvailPhys).c_str());
        cJSON_AddNumberToObject(memInfo, "memory_load_percent",
            (double)memStat.dwMemoryLoad);
        cJSON_AddItemToObject(root, "memory_info", memInfo);
    }

    // 6. 本地账户列表
    cJSON_AddItemToObject(root, "accounts", EnumLocalAccounts());

    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}
