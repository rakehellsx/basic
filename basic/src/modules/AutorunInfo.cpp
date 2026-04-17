/*
 * Module: Autorun / Persistence Information
 * Fields: source, name, command, file_path, publisher, is_signed, sign_valid,
 *         reg_path, enabled
 * Covers: Run/RunOnce keys, Services, Winlogon, AppInit_DLLs, BootExecute,
 *         Shell context menus, Image File Execution Options (debugger hijack)
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include "../common/Utils.h"
#include "../common/DbStorage.h"

/* Extract the first token from a command line as the executable path.
 * Handles quoted paths ("C:\foo\bar.exe" args) and unquoted paths. */
static std::wstring ExtractExePath(const std::wstring& cmdLine)
{
    if (cmdLine.empty()) return L"";

    std::wstring path;
    if (cmdLine[0] == L'"')
    {
        /* Quoted path */
        size_t end = cmdLine.find(L'"', 1);
        if (end != std::wstring::npos)
            path = cmdLine.substr(1, end - 1);
        else
            path = cmdLine.substr(1);
    }
    else
    {
        /* Unquoted: take up to first space */
        size_t sp = cmdLine.find(L' ');
        path = (sp != std::wstring::npos) ? cmdLine.substr(0, sp) : cmdLine;
    }

    /* Expand environment variables (e.g. %SystemRoot%) */
    if (path.find(L'%') != std::wstring::npos)
    {
        wchar_t expanded[1024] = {0};
        ExpandEnvironmentStringsW(path.c_str(), expanded, 1024);
        path = expanded;
    }
    return path;
}

static std::string AssessRiskLevel(const std::wstring& path, const std::wstring& cmd)
{
    std::wstring lcmd = cmd;
    for (auto& c : lcmd) c = towlower(c);
    
    if (lcmd.find(L"temp") != std::wstring::npos ||
        lcmd.find(L"appdata") != std::wstring::npos ||
        lcmd.find(L"powershell") != std::wstring::npos ||
        lcmd.find(L"cmd.exe") != std::wstring::npos ||
        lcmd.find(L"wscript") != std::wstring::npos ||
        lcmd.find(L"cscript") != std::wstring::npos ||
        lcmd.find(L"mshta") != std::wstring::npos)
    {
        return "高危";
    }
    return "正常";
}

/* Build a single autorun entry JSON object with unified field names.
 * source = full registry path, e.g. HKLM\SOFTWARE\...\Run
 * category = short label, e.g. Run(HKLM) */
static cJSON* MakeAutorunEntry(
    const char*          category,
    const std::wstring&  name,
    const std::wstring&  command,
    const std::wstring&  regPath,
    bool                 enabled = true)
{
    cJSON* item = cJSON_CreateObject();

    /* source: full registry key path (what DbStorage.autorun_items.source expects) */
    cJSON_AddStringToObject(item, "source",   WstrToUtf8(regPath).c_str());
    /* category: short label for human readability */
    cJSON_AddStringToObject(item, "category", category);
    /* name: value name / key name / image name */
    cJSON_AddStringToObject(item, "name",     WstrToUtf8(name).c_str());
    /* command: full command line */
    cJSON_AddStringToObject(item, "command",  WstrToUtf8(command).c_str());
    /* enabled */
    cJSON_AddBoolToObject(item, "enabled", enabled ? 1 : 0);

    /* file_path: extract executable path from command */
    std::wstring exePath = ExtractExePath(command);
    cJSON_AddStringToObject(item, "file_path", WstrToUtf8(exePath).c_str());

    /* publisher / is_signed / sign_valid from PE signature */
    if (!exePath.empty() && GetFileAttributesW(exePath.c_str()) != INVALID_FILE_ATTRIBUTES)
    {
        std::string trustStatus = VerifyAuthenticode(exePath);
        cJSON_AddStringToObject(item, "publisher",
            GetFilePublisherW(exePath).c_str());
        cJSON_AddBoolToObject(item, "is_signed",
            (trustStatus != "Unsigned") ? 1 : 0);
        cJSON_AddBoolToObject(item, "sign_valid",
            (trustStatus == "Signed") ? 1 : 0);
    }
    else
    {
        cJSON_AddStringToObject(item, "publisher",  "");
        cJSON_AddBoolToObject(item, "is_signed",   0);
        cJSON_AddBoolToObject(item, "sign_valid",  0);
    }

    return item;
}

/* Enumerate all values under a registry key and add them to the array.
 * Renamed to avoid conflict with Utils.h EnumRegSubKeys declaration. */
static void EnumAutorunValues(HKEY hRoot, const wchar_t* subKey,
    const char* source, cJSON* arr)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    std::wstring rootPrefix = (hRoot == HKEY_LOCAL_MACHINE) ? L"HKLM\\" :
                              (hRoot == HKEY_CURRENT_USER)  ? L"HKCU\\" : L"HKCR\\";
    std::wstring fullKeyPath = rootPrefix + subKey;

    DWORD index = 0;
    wchar_t valueName[512];
    BYTE   data[2048];
    DWORD  nameLen, dataLen, type;

    while (true)
    {
        nameLen = 512;
        dataLen = sizeof(data);
        memset(valueName, 0, sizeof(valueName));
        memset(data,      0, sizeof(data));

        LONG ret = RegEnumValueW(hKey, index++, valueName, &nameLen,
            NULL, &type, data, &dataLen);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS) continue;

        std::wstring dataStr;
        if (type == REG_SZ || type == REG_EXPAND_SZ)
        {
            dataStr = (wchar_t*)data;
        }
        else if (type == REG_MULTI_SZ)
        {
            /* Join multi-string with semicolons */
            const wchar_t* p = (wchar_t*)data;
            while (p && *p)
            {
                if (!dataStr.empty()) dataStr += L";";
                dataStr += p;
                p += wcslen(p) + 1;
            }
        }
        else if (type == REG_DWORD && dataLen >= 4)
        {
            wchar_t buf[16];
            _snwprintf_s(buf, 16, _TRUNCATE, L"0x%08X", *(DWORD*)data);
            dataStr = buf;
        }
        else
        {
            wchar_t buf[32];
            _snwprintf_s(buf, 32, _TRUNCATE, L"<binary %lu bytes>", dataLen);
            dataStr = buf;
        }

        cJSON* entry = MakeAutorunEntry(source,
            std::wstring(valueName), dataStr, fullKeyPath);
        cJSON_AddItemToArray(arr, entry);
    }
    RegCloseKey(hKey);
}

/* Enumerate sub-keys (e.g. shell context menu handlers) and add to array.
 * Renamed to avoid conflict with Utils.h EnumRegSubKeys declaration. */
static void EnumAutorunSubKeys(HKEY hRoot, const wchar_t* subKey,
    const char* source, cJSON* arr)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    std::wstring rootPrefix = (hRoot == HKEY_LOCAL_MACHINE) ? L"HKLM\\" :
                              (hRoot == HKEY_CURRENT_USER)  ? L"HKCU\\" : L"HKCR\\";

    DWORD index = 0;
    wchar_t keyName[512];
    DWORD   nameLen;

    while (true)
    {
        nameLen = 512;
        LONG ret = RegEnumKeyExW(hKey, index++, keyName, &nameLen,
            NULL, NULL, NULL, NULL);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS) continue;

        std::wstring childPath = std::wstring(subKey) + L"\\" + keyName;
        std::wstring fullPath  = rootPrefix + childPath;

        /* Try to read the command sub-key */
        std::wstring command;
        std::wstring cmdKeyPath = childPath + L"\\command";
        HKEY hCmd = NULL;
        if (RegOpenKeyExW(hRoot, cmdKeyPath.c_str(), 0, KEY_READ, &hCmd) == ERROR_SUCCESS)
        {
            wchar_t cmdVal[1024] = {0};
            DWORD   cmdSize = sizeof(cmdVal);
            DWORD   cmdType = 0;
            if (RegQueryValueExW(hCmd, NULL, NULL, &cmdType,
                (LPBYTE)cmdVal, &cmdSize) == ERROR_SUCCESS)
                command = cmdVal;
            RegCloseKey(hCmd);
        }

        cJSON* entry = MakeAutorunEntry(source,
            std::wstring(keyName), command, fullPath);
        cJSON_AddItemToArray(arr, entry);
    }
    RegCloseKey(hKey);
}

extern "C" __declspec(dllexport)
char* GetAutorunInfo(const char* /*paramsJson*/)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "autorun_info");

    cJSON* autorunArr = cJSON_CreateArray();

    /* ===== 1. Run / RunOnce keys ===== */
    EnumAutorunValues(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Run(HKLM)", autorunArr);
    EnumAutorunValues(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "RunOnce(HKLM)", autorunArr);
    EnumAutorunValues(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Run(HKLM-Wow64)", autorunArr);
    EnumAutorunValues(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "RunOnce(HKLM-Wow64)", autorunArr);
    EnumAutorunValues(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Run(HKCU)", autorunArr);
    EnumAutorunValues(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "RunOnce(HKCU)", autorunArr);

    /* ===== 2. Winlogon ===== */
    EnumAutorunValues(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "Winlogon", autorunArr);

    /* ===== 3. AppInit_DLLs ===== */
    EnumAutorunValues(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "AppInit_DLLs", autorunArr);

    /* ===== 4. Boot Execute ===== */
    EnumAutorunValues(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        "BootExecute", autorunArr);

    /* ===== 5. Shell context menus (Separate Array) ===== */
    cJSON* contextMenuArr = cJSON_CreateArray();
    
    auto EnumContextMenu = [&](HKEY hRoot, const wchar_t* subKey, const std::wstring& rootPrefix) {
        HKEY hKey = NULL;
        if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
        DWORD index = 0;
        wchar_t keyName[512];
        DWORD nameLen;
        while (true) {
            nameLen = 512;
            if (RegEnumKeyExW(hKey, index++, keyName, &nameLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
            
            std::wstring childPath = std::wstring(subKey) + L"\\" + keyName;
            std::wstring fullPath = rootPrefix + childPath;
            std::wstring command;
            std::wstring cmdKeyPath = childPath + L"\\command";
            HKEY hCmd = NULL;
            if (RegOpenKeyExW(hRoot, cmdKeyPath.c_str(), 0, KEY_READ, &hCmd) == ERROR_SUCCESS) {
                wchar_t cmdVal[1024] = {0};
                DWORD cmdSize = sizeof(cmdVal);
                if (RegQueryValueExW(hCmd, NULL, NULL, NULL, (LPBYTE)cmdVal, &cmdSize) == ERROR_SUCCESS) {
                    command = cmdVal;
                }
                RegCloseKey(hCmd);
            }
            
            if (!command.empty()) {
                cJSON* item = cJSON_CreateObject();
                cJSON_AddStringToObject(item, "menu_item", WstrToUtf8(keyName).c_str());
                cJSON_AddStringToObject(item, "reg_path", WstrToUtf8(fullPath).c_str());
                cJSON_AddStringToObject(item, "command", WstrToUtf8(command).c_str());
                std::string risk = AssessRiskLevel(fullPath, command);
                if (risk == "高危") risk = "高危（命令被篡改）";
                cJSON_AddStringToObject(item, "risk_level", risk.c_str());
                cJSON_AddItemToArray(contextMenuArr, item);
            }
        }
        RegCloseKey(hKey);
    };
    
    EnumContextMenu(HKEY_CLASSES_ROOT, L"*\\shell", L"HKCR\\");
    EnumContextMenu(HKEY_CLASSES_ROOT, L"Directory\\shell", L"HKCR\\");
    EnumContextMenu(HKEY_CLASSES_ROOT, L"Directory\\Background\\shell", L"HKCR\\");

    /* ===== 6. Image File Execution Options (Debugger hijack) (Separate Array) ===== */
    cJSON* debuggerArr = cJSON_CreateArray();
    HKEY hIFEO = NULL;
    const wchar_t* ifeoBase = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, ifeoBase, 0, KEY_READ, &hIFEO) == ERROR_SUCCESS)
    {
        DWORD idx = 0;
        wchar_t subKeyName[512];
        DWORD subKeyLen;
        while (true)
        {
            subKeyLen = 512;
            if (RegEnumKeyExW(hIFEO, idx++, subKeyName, &subKeyLen, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;

            std::wstring subPath = std::wstring(ifeoBase) + L"\\" + subKeyName;
            HKEY hSub = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath.c_str(), 0, KEY_READ, &hSub) == ERROR_SUCCESS)
            {
                wchar_t debugger[1024] = {0};
                DWORD dbgSize = sizeof(debugger);
                if (RegQueryValueExW(hSub, L"Debugger", NULL, NULL, (LPBYTE)debugger, &dbgSize) == ERROR_SUCCESS && debugger[0])
                {
                    cJSON* item = cJSON_CreateObject();
                    cJSON_AddStringToObject(item, "target_program", WstrToUtf8(subKeyName).c_str());
                    cJSON_AddStringToObject(item, "debugger_path", WstrToUtf8(debugger).c_str());
                    std::string risk = AssessRiskLevel(L"", debugger);
                    if (risk == "高危") risk = "高危（IFEO劫持）";
                    cJSON_AddStringToObject(item, "risk_level", risk.c_str());
                    cJSON_AddItemToArray(debuggerArr, item);
                }
                RegCloseKey(hSub);
            }
        }
        RegCloseKey(hIFEO);
    }

    cJSON_AddItemToObject(root, "autorun_entries", autorunArr);
    cJSON_AddItemToObject(root, "context_menus", contextMenuArr);
    cJSON_AddItemToObject(root, "debuggers", debuggerArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}

/*
 * SaveAutorunInfo — collect autorun info and store field-by-field into SQLite3
 * Input JSON:  { "db_path": "C:\\basic.db" }
 * Output JSON: { "snapshot_id": N, "status": "success" }
 */
extern "C" __declspec(dllexport)
char* SaveAutorunInfo(const char* paramsJson)
{
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "module", "saveAutorunInfo");

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

    char* jsonStr = GetAutorunInfo(paramsJson);
    if (!jsonStr)
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", "GetAutorunInfo failed");
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

    long long snapId = db.SaveAutorunInfo(jsonStr);
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
