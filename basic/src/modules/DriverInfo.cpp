/*
 * Module: Driver Information
 * Fields: driver_name, display_name, driver_path, start_type, service_type,
 *         state, description, publisher, is_signed, sign_valid
 * Uses SetupAPI to enumerate present devices, then reads SCM data for each
 * associated service to obtain start_type, service_type, and current state.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#include <vector>
#include "../common/Utils.h"
#include "../common/DbStorage.h"

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "advapi32.lib")

/* Convert SERVICE_START_TYPE constant to string */
static std::string StartTypeStr(DWORD t)
{
    switch (t)
    {
    case SERVICE_BOOT_START:   return "Boot";
    case SERVICE_SYSTEM_START: return "System";
    case SERVICE_AUTO_START:   return "Auto";
    case SERVICE_DEMAND_START: return "Manual";
    case SERVICE_DISABLED:     return "Disabled";
    default:                   return "Unknown";
    }
}

/* Convert SERVICE_TYPE constant to string */
static std::string ServiceTypeStr(DWORD t)
{
    DWORD base = t & ~SERVICE_INTERACTIVE_PROCESS;
    std::string s;
    switch (base)
    {
    case SERVICE_KERNEL_DRIVER:       s = "KernelDriver";    break;
    case SERVICE_FILE_SYSTEM_DRIVER:  s = "FileSystemDriver";break;
    case SERVICE_WIN32_OWN_PROCESS:   s = "Win32OwnProcess"; break;
    case SERVICE_WIN32_SHARE_PROCESS: s = "Win32ShareProcess";break;
    default:                          s = "Unknown";          break;
    }
    if (t & SERVICE_INTERACTIVE_PROCESS) s += "|Interactive";
    return s;
}

/* Convert SERVICE_CURRENT_STATE to string */
static std::string StateStr(DWORD s)
{
    switch (s)
    {
    case SERVICE_STOPPED:          return "Stopped";
    case SERVICE_START_PENDING:    return "StartPending";
    case SERVICE_STOP_PENDING:     return "StopPending";
    case SERVICE_RUNNING:          return "Running";
    case SERVICE_CONTINUE_PENDING: return "ContinuePending";
    case SERVICE_PAUSE_PENDING:    return "PausePending";
    case SERVICE_PAUSED:           return "Paused";
    default:                       return "Unknown";
    }
}

/* Query SCM for a service: fills start_type, service_type, state, display_name */
struct ScmInfo { std::string startType, serviceType, state, displayName; };
static ScmInfo QueryScm(SC_HANDLE hScm, const wchar_t* serviceName)
{
    ScmInfo info;
    if (!hScm || !serviceName || !serviceName[0]) return info;
    SC_HANDLE hSvc = OpenServiceW(hScm, serviceName,
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS);
    if (!hSvc) return info;

    /* Display name */
    wchar_t dispBuf[512] = {0};
    DWORD dispLen = sizeof(dispBuf);
    GetServiceDisplayNameW(hScm, serviceName, dispBuf, &dispLen);
    info.displayName = WideToUtf8(dispBuf);

    /* Config (start type, service type) */
    DWORD needed = 0;
    QueryServiceConfigW(hSvc, NULL, 0, &needed);
    if (needed > 0)
    {
        std::vector<BYTE> buf(needed);
        QUERY_SERVICE_CONFIGW* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(buf.data());
        if (QueryServiceConfigW(hSvc, cfg, needed, &needed))
        {
            info.startType   = StartTypeStr(cfg->dwStartType);
            info.serviceType = ServiceTypeStr(cfg->dwServiceType);
        }
    }

    /* Current state */
    SERVICE_STATUS_PROCESS ssp = {0};
    DWORD needed2 = 0;
    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
        (LPBYTE)&ssp, sizeof(ssp), &needed2))
        info.state = StateStr(ssp.dwCurrentState);

    CloseServiceHandle(hSvc);
    return info;
}

extern "C" __declspec(dllexport)
char* GetDriverInfo(const char* /*paramsJson*/)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "driver_info");

    cJSON* driversArr = cJSON_CreateArray();

    /* Open SCM once for all service queries */
    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(NULL, NULL, NULL,
        DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE)
    {
        if (hScm) CloseServiceHandle(hScm);
        return BuildErrorJson("driver_info", "SetupDiGetClassDevs failed");
    }

    SP_DEVINFO_DATA devData = {0};
    devData.cbSize = sizeof(devData);

    for (DWORD idx = 0;
        SetupDiEnumDeviceInfo(hDevInfo, idx, &devData); idx++)
    {
        cJSON* drv = cJSON_CreateObject();

        /* device_description -> used as description */
        wchar_t devDesc[512]  = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_DEVICEDESC, NULL, (PBYTE)devDesc, sizeof(devDesc), NULL);

        wchar_t className[256] = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_CLASS, NULL, (PBYTE)className, sizeof(className), NULL);

        wchar_t mfg[256] = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_MFG, NULL, (PBYTE)mfg, sizeof(mfg), NULL);

        /* Service name -> used as driver_name */
        wchar_t service[256] = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_SERVICE, NULL, (PBYTE)service, sizeof(service), NULL);

        /* Resolve driver image path from registry */
        std::wstring imagePath;
        if (service[0])
        {
            std::wstring svcKey = std::wstring(
                L"SYSTEM\\CurrentControlSet\\Services\\") + service;
            HKEY hSvc = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, svcKey.c_str(),
                0, KEY_READ, &hSvc) == ERROR_SUCCESS)
            {
                wchar_t imgBuf[1024] = {0};
                DWORD imgSize = sizeof(imgBuf);
                DWORD imgType = 0;
                if (RegQueryValueExW(hSvc, L"ImagePath", NULL, &imgType,
                    (LPBYTE)imgBuf, &imgSize) == ERROR_SUCCESS)
                {
                    wchar_t expanded[1024] = {0};
                    ExpandEnvironmentStringsW(imgBuf, expanded, 1024);
                    imagePath = expanded;
                }
                RegCloseKey(hSvc);
            }
        }

        /* Query SCM for start_type, service_type, state, display_name */
        ScmInfo scm = QueryScm(hScm, service);

        /* driver_name: service name (SCM key) */
        cJSON_AddStringToObject(drv, "driver_name",   WideToUtf8(service).c_str());
        /* display_name: from SCM or driver description */
        std::string dispName = scm.displayName.empty()
            ? WideToUtf8(devDesc) : scm.displayName;
        cJSON_AddStringToObject(drv, "display_name",  dispName.c_str());
        /* driver_path: expanded image path */
        cJSON_AddStringToObject(drv, "driver_path",   WideToUtf8(imagePath.c_str()).c_str());
        /* start_type / service_type / state from SCM */
        cJSON_AddStringToObject(drv, "start_type",    scm.startType.c_str());
        cJSON_AddStringToObject(drv, "service_type",  scm.serviceType.c_str());
        cJSON_AddStringToObject(drv, "state",         scm.state.c_str());
        /* description: device description */
        cJSON_AddStringToObject(drv, "description",   WideToUtf8(devDesc).c_str());

        /* publisher, is_signed, sign_valid from image file */
        if (!imagePath.empty())
        {
            std::string trustStatus = VerifyAuthenticode(imagePath);
            cJSON_AddStringToObject(drv, "publisher",
                GetFilePublisherW(imagePath).c_str());
            cJSON_AddBoolToObject(drv, "is_signed",
                (trustStatus != "Unsigned") ? 1 : 0);
            cJSON_AddBoolToObject(drv, "sign_valid",
                (trustStatus == "Signed") ? 1 : 0);
        }
        else
        {
            cJSON_AddStringToObject(drv, "publisher",  "");
            cJSON_AddBoolToObject(drv, "is_signed",   0);
            cJSON_AddBoolToObject(drv, "sign_valid",  0);
        }

        /* Extra informational fields (not stored in driver_list table) */
        cJSON_AddStringToObject(drv, "class_name",    WideToUtf8(className).c_str());
        cJSON_AddStringToObject(drv, "manufacturer",  WideToUtf8(mfg).c_str());

        cJSON_AddItemToArray(driversArr, drv);
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
    if (hScm) CloseServiceHandle(hScm);

    cJSON_AddItemToObject(root, "drivers", driversArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}

/*
 * SaveDriverInfo — collect driver info and store field-by-field into SQLite3
 * Input JSON: { "db_path": "C:\\basic.db" }
 * Output JSON: { "snapshot_id": N, "status": "success" }
 */
extern "C" __declspec(dllexport)
char* SaveDriverInfo(const char* paramsJson)
{
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "module", "saveDriverInfo");

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

    char* jsonStr = GetDriverInfo(paramsJson);
    if (!jsonStr)
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", "GetDriverInfo failed");
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

    long long snapId = db.SaveDriverInfo(jsonStr);
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
