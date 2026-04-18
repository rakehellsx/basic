/*
 * Module: Service Information
 * Fields: service_name, display_name, description, executable_path,
 *         start_type, service_type, state, account_name,
 *         publisher, is_signed, sign_valid
 * Uses EnumServicesStatusEx to enumerate all services, then queries SCM
 * and Registry for detailed configuration.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include "../common/Utils.h"
#include "../common/DbStorage.h"

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
    default:                          s = "Unknown";         break;
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

/* Extract the first token from a command line as the executable path.
 * Handles quoted paths ("C:\foo\bar.exe" args) and unquoted paths. */
static std::wstring ExtractExePath(const std::wstring& cmdLine)
{
    if (cmdLine.empty()) return L"";

    std::wstring path;
    if (cmdLine[0] == L'"')
    {
        size_t end = cmdLine.find(L'"', 1);
        if (end != std::wstring::npos)
            path = cmdLine.substr(1, end - 1);
        else
            path = cmdLine.substr(1);
    }
    else
    {
        size_t sp = cmdLine.find(L' ');
        path = (sp != std::wstring::npos) ? cmdLine.substr(0, sp) : cmdLine;
    }

    if (path.find(L'%') != std::wstring::npos)
    {
        wchar_t expanded[1024] = {0};
        ExpandEnvironmentStringsW(path.c_str(), expanded, 1024);
        path = expanded;
    }
    return path;
}

extern "C" __declspec(dllexport)
char* GetServiceInfo(const char* /*paramsJson*/)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "service_info");

    cJSON* servicesArr = cJSON_CreateArray();

    SC_HANDLE hScm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!hScm)
    {
        cJSON_AddStringToObject(root, "status", "error");
        cJSON_AddStringToObject(root, "message", "OpenSCManager failed");
        return SerializeJson(root);
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

    if (GetLastError() == ERROR_MORE_DATA && bytesNeeded > 0)
    {
        std::vector<BYTE> buffer(bytesNeeded);
        ENUM_SERVICE_STATUS_PROCESSW* services = (ENUM_SERVICE_STATUS_PROCESSW*)buffer.data();

        if (EnumServicesStatusExW(hScm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
            (LPBYTE)services, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL))
        {
            for (DWORD i = 0; i < servicesReturned; i++)
            {
                cJSON* svc = cJSON_CreateObject();

                std::wstring serviceName = services[i].lpServiceName;
                std::wstring displayName = services[i].lpDisplayName;
                
                cJSON_AddStringToObject(svc, "service_name", WstrToUtf8(serviceName).c_str());
                cJSON_AddStringToObject(svc, "display_name", WstrToUtf8(displayName).c_str());
                cJSON_AddStringToObject(svc, "service_type", ServiceTypeStr(services[i].ServiceStatusProcess.dwServiceType).c_str());
                cJSON_AddStringToObject(svc, "state",        StateStr(services[i].ServiceStatusProcess.dwCurrentState).c_str());

                /* Open specific service to get config (start_type, account, executable) and description */
                SC_HANDLE hSvc = OpenServiceW(hScm, serviceName.c_str(), SERVICE_QUERY_CONFIG);
                std::wstring executablePath;
                
                if (hSvc)
                {
                    DWORD needed = 0;
                    QueryServiceConfigW(hSvc, NULL, 0, &needed);
                    if (needed > 0)
                    {
                        std::vector<BYTE> cfgBuf(needed);
                        QUERY_SERVICE_CONFIGW* cfg = (QUERY_SERVICE_CONFIGW*)cfgBuf.data();
                        if (QueryServiceConfigW(hSvc, cfg, needed, &needed))
                        {
                            cJSON_AddStringToObject(svc, "start_type",   StartTypeStr(cfg->dwStartType).c_str());
                            cJSON_AddStringToObject(svc, "account_name", WstrToUtf8(cfg->lpServiceStartName ? cfg->lpServiceStartName : L"").c_str());
                            
                            std::wstring binPath = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"";
                            executablePath = ExtractExePath(binPath);
                            cJSON_AddStringToObject(svc, "executable_path", WstrToUtf8(executablePath).c_str());
                        }
                    }
                    else
                    {
                        cJSON_AddStringToObject(svc, "start_type",   "Unknown");
                        cJSON_AddStringToObject(svc, "account_name", "");
                        cJSON_AddStringToObject(svc, "executable_path", "");
                    }

                    needed = 0;
                    QueryServiceConfig2W(hSvc, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &needed);
                    if (needed > 0)
                    {
                        std::vector<BYTE> descBuf(needed);
                        SERVICE_DESCRIPTIONW* desc = (SERVICE_DESCRIPTIONW*)descBuf.data();
                        if (QueryServiceConfig2W(hSvc, SERVICE_CONFIG_DESCRIPTION, (LPBYTE)desc, needed, &needed))
                        {
                            cJSON_AddStringToObject(svc, "description", WstrToUtf8(desc->lpDescription ? desc->lpDescription : L"").c_str());
                        }
                        else cJSON_AddStringToObject(svc, "description", "");
                    }
                    else cJSON_AddStringToObject(svc, "description", "");

                    CloseServiceHandle(hSvc);
                }
                else
                {
                    cJSON_AddStringToObject(svc, "start_type",   "Unknown");
                    cJSON_AddStringToObject(svc, "account_name", "");
                    cJSON_AddStringToObject(svc, "executable_path", "");
                    cJSON_AddStringToObject(svc, "description",  "");
                }

                /* Authenticode Signature */
                if (!executablePath.empty() && GetFileAttributesW(executablePath.c_str()) != INVALID_FILE_ATTRIBUTES)
                {
                    std::string trustStatus = VerifyAuthenticode(executablePath);
                    cJSON_AddStringToObject(svc, "publisher", GetFilePublisherW(executablePath).c_str());
                    cJSON_AddBoolToObject(svc, "is_signed",  (trustStatus != "Unsigned") ? 1 : 0);
                    cJSON_AddBoolToObject(svc, "sign_valid", (trustStatus == "Signed") ? 1 : 0);
                }
                else
                {
                    cJSON_AddStringToObject(svc, "publisher",  "");
                    cJSON_AddBoolToObject(svc, "is_signed",   0);
                    cJSON_AddBoolToObject(svc, "sign_valid",  0);
                }

                cJSON_AddItemToArray(servicesArr, svc);
            }
        }
    }

    CloseServiceHandle(hScm);

    cJSON_AddItemToObject(root, "services", servicesArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}

/*
 * SaveServiceInfo — collect service info and store field-by-field into SQLite3
 * Input JSON: { "db_path": "C:\\basic.db" }
 * Output JSON: { "snapshot_id": N, "status": "success" }
 */
extern "C" __declspec(dllexport)
char* SaveServiceInfo(const char* paramsJson)
{
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "module", "saveServiceInfo");

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

    char* jsonStr = GetServiceInfo(paramsJson);
    if (!jsonStr)
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", "GetServiceInfo failed");
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

    long long snapId = db.SaveServiceInfo(jsonStr);
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
