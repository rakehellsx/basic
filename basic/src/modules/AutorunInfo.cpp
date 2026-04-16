/*
 * 模块：自启动信息
 * 指标：自动运行、操作启动(右键菜单、系统调试器)
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include "../common/Utils.h"

// 枚举指定注册表键下的所有值
static void EnumRegValues(HKEY hRoot, const wchar_t* subKey,
    const char* category, cJSON* arr)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    DWORD index = 0;
    wchar_t valueName[512];
    BYTE data[2048];
    DWORD nameLen, dataLen, type;

    while (true)
    {
        nameLen = 512;
        dataLen = sizeof(data);
        memset(valueName, 0, sizeof(valueName));
        memset(data, 0, sizeof(data));

        LONG ret = RegEnumValueW(hKey, index++, valueName, &nameLen,
            NULL, &type, data, &dataLen);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS) continue;

        cJSON* item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "category", category);

        // 注册表路径
        std::wstring fullPath = std::wstring(
            (hRoot == HKEY_LOCAL_MACHINE) ? L"HKLM\\" : L"HKCU\\") + subKey;
        cJSON_AddStringToObject(item, "reg_path", WideToUtf8(fullPath.c_str()).c_str());
        cJSON_AddStringToObject(item, "value_name", WideToUtf8(valueName).c_str());

        std::string dataStr;
        if (type == REG_SZ || type == REG_EXPAND_SZ)
            dataStr = WideToUtf8((wchar_t*)data);
        else if (type == REG_DWORD && dataLen >= 4)
        {
            char buf[16];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%08X", *(DWORD*)data);
            dataStr = buf;
        }
        else
        {
            char buf[16];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "<binary %lu bytes>", dataLen);
            dataStr = buf;
        }
        cJSON_AddStringToObject(item, "value_data", dataStr.c_str());
        cJSON_AddItemToArray(arr, item);
    }
    RegCloseKey(hKey);
}

// 枚举注册表键下的子键（用于右键菜单等）
static void EnumRegSubKeys(HKEY hRoot, const wchar_t* subKey,
    const char* category, cJSON* arr)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return;

    DWORD index = 0;
    wchar_t keyName[512];
    DWORD nameLen;

    while (true)
    {
        nameLen = 512;
        LONG ret = RegEnumKeyExW(hKey, index++, keyName, &nameLen,
            NULL, NULL, NULL, NULL);
        if (ret == ERROR_NO_MORE_ITEMS) break;
        if (ret != ERROR_SUCCESS) continue;

        // 读取子键的默认值和command子键
        std::wstring childPath = std::wstring(subKey) + L"\\" + keyName;
        HKEY hChild = NULL;
        if (RegOpenKeyExW(hRoot, childPath.c_str(), 0, KEY_READ, &hChild) == ERROR_SUCCESS)
        {
            cJSON* item = cJSON_CreateObject();
            cJSON_AddStringToObject(item, "category", category);

            std::wstring fullPath = std::wstring(
                (hRoot == HKEY_LOCAL_MACHINE) ? L"HKLM\\" : L"HKCU\\") + childPath;
            cJSON_AddStringToObject(item, "reg_path", WideToUtf8(fullPath.c_str()).c_str());
            cJSON_AddStringToObject(item, "key_name", WideToUtf8(keyName).c_str());

            // 读取默认值（菜单名称）
            wchar_t defVal[512] = {0};
            DWORD defSize = sizeof(defVal);
            DWORD defType = 0;
            if (RegQueryValueExW(hChild, NULL, NULL, &defType,
                (LPBYTE)defVal, &defSize) == ERROR_SUCCESS)
                cJSON_AddStringToObject(item, "menu_name", WideToUtf8(defVal).c_str());

            // 读取command子键
            HKEY hCmd = NULL;
            std::wstring cmdPath = childPath + L"\\command";
            if (RegOpenKeyExW(hRoot, cmdPath.c_str(), 0, KEY_READ, &hCmd) == ERROR_SUCCESS)
            {
                wchar_t cmdVal[1024] = {0};
                DWORD cmdSize = sizeof(cmdVal);
                DWORD cmdType = 0;
                if (RegQueryValueExW(hCmd, NULL, NULL, &cmdType,
                    (LPBYTE)cmdVal, &cmdSize) == ERROR_SUCCESS)
                    cJSON_AddStringToObject(item, "command", WideToUtf8(cmdVal).c_str());
                RegCloseKey(hCmd);
            }

            RegCloseKey(hChild);
            cJSON_AddItemToArray(arr, item);
        }
    }
    RegCloseKey(hKey);
}

extern "C" __declspec(dllexport)
char* GetAutorunInfo(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "autorun_info");

    cJSON* autorunArr = cJSON_CreateArray();

    // ===== 1. 自动运行（Run/RunOnce）=====
    // HKLM
    EnumRegValues(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Run(HKLM)", autorunArr);
    EnumRegValues(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "RunOnce(HKLM)", autorunArr);
    EnumRegValues(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Run(HKLM-Wow64)", autorunArr);
    EnumRegValues(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "RunOnce(HKLM-Wow64)", autorunArr);
    // HKCU
    EnumRegValues(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Run(HKCU)", autorunArr);
    EnumRegValues(HKEY_CURRENT_USER,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "RunOnce(HKCU)", autorunArr);

    // Services (驱动/服务自启)
    EnumRegValues(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services",
        "Services", autorunArr);

    // Winlogon
    EnumRegValues(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "Winlogon", autorunArr);

    // AppInit_DLLs
    EnumRegValues(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
        "AppInit_DLLs", autorunArr);

    // Boot Execute
    EnumRegValues(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        "BootExecute", autorunArr);

    // ===== 2. 右键菜单（Shell扩展）=====
    EnumRegSubKeys(HKEY_CLASSES_ROOT,
        L"*\\shell",
        "ContextMenu(*\\shell)", autorunArr);
    EnumRegSubKeys(HKEY_CLASSES_ROOT,
        L"*\\shellex\\ContextMenuHandlers",
        "ContextMenuHandler(*)", autorunArr);
    EnumRegSubKeys(HKEY_CLASSES_ROOT,
        L"Directory\\shell",
        "ContextMenu(Directory\\shell)", autorunArr);
    EnumRegSubKeys(HKEY_CLASSES_ROOT,
        L"Directory\\Background\\shell",
        "ContextMenu(Directory\\Background\\shell)", autorunArr);
    EnumRegSubKeys(HKEY_CLASSES_ROOT,
        L"Directory\\shellex\\ContextMenuHandlers",
        "ContextMenuHandler(Directory)", autorunArr);
    EnumRegSubKeys(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Classes\\*\\shellex\\ContextMenuHandlers",
        "ContextMenuHandler(HKLM)", autorunArr);

    // ===== 3. 系统调试器（Image File Execution Options）=====
    HKEY hIFEO = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        0, KEY_READ, &hIFEO) == ERROR_SUCCESS)
    {
        DWORD index = 0;
        wchar_t subKeyName[512];
        DWORD subKeyLen;
        while (true)
        {
            subKeyLen = 512;
            LONG ret = RegEnumKeyExW(hIFEO, index++, subKeyName, &subKeyLen,
                NULL, NULL, NULL, NULL);
            if (ret == ERROR_NO_MORE_ITEMS) break;
            if (ret != ERROR_SUCCESS) continue;

            HKEY hSub = NULL;
            std::wstring subPath = std::wstring(
                L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\")
                + subKeyName;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subPath.c_str(), 0, KEY_READ, &hSub) == ERROR_SUCCESS)
            {
                wchar_t debugger[1024] = {0};
                DWORD dbgSize = sizeof(debugger);
                DWORD dbgType = 0;
                if (RegQueryValueExW(hSub, L"Debugger", NULL, &dbgType,
                    (LPBYTE)debugger, &dbgSize) == ERROR_SUCCESS && debugger[0])
                {
                    cJSON* item = cJSON_CreateObject();
                    cJSON_AddStringToObject(item, "category", "ImageFileExecutionOptions(Debugger)");
                    cJSON_AddStringToObject(item, "reg_path",
                        WideToUtf8(subPath.c_str()).c_str());
                    cJSON_AddStringToObject(item, "image_name",
                        WideToUtf8(subKeyName).c_str());
                    cJSON_AddStringToObject(item, "debugger",
                        WideToUtf8(debugger).c_str());
                    cJSON_AddItemToArray(autorunArr, item);
                }
                RegCloseKey(hSub);
            }
        }
        RegCloseKey(hIFEO);
    }

    cJSON_AddItemToObject(root, "autorun_entries", autorunArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}
