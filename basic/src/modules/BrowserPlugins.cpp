/*
 * 模块：浏览器插件
 * 指标：类型、状态、修改时间、路径
 * 支持：IE/Edge(Legacy)、Chrome、Firefox、Edge(Chromium)
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include "../common/Utils.h"
#include "../common/DbStorage.h"

#pragma comment(lib, "shell32.lib")

static std::string GetModifyTimeA(const std::string& path)
{
    std::wstring wpath = Utf8ToWstr(path);
    WIN32_FILE_ATTRIBUTE_DATA fad = {0};
    if (!GetFileAttributesExW(wpath.c_str(), GetFileExInfoStandard, &fad)) return "";
    return FileTimeToString(fad.ftLastWriteTime);
}

static std::string ExpandEnvPath(const std::string& path)
{
    std::wstring wpath = Utf8ToWstr(path);
    wchar_t expanded[MAX_PATH * 2] = {0};
    ExpandEnvironmentStringsW(wpath.c_str(), expanded, MAX_PATH * 2);
    return WideToUtf8(expanded);
}

/* 读取注册表字符串（局部版，名称与 Utils.h 中的不同） */
static std::string BrowserRegReadStr(HKEY hRoot, const wchar_t* subKey,
    const wchar_t* valueName)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return "";
    wchar_t buf[1024] = {0};
    DWORD sz = sizeof(buf);
    DWORD type = 0;
    std::string result;
    if (RegQueryValueExW(hKey, valueName, NULL, &type, (LPBYTE)buf, &sz) == ERROR_SUCCESS)
        result = WideToUtf8(buf);
    RegCloseKey(hKey);
    return result;
}

/* ===== IE/Edge Legacy BHO & 工具栏 ===== */
static void EnumIEExtensions(cJSON* arr)
{
    HKEY hBHO = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects",
        0, KEY_READ, &hBHO) == ERROR_SUCCESS)
    {
        DWORD idx = 0;
        wchar_t clsid[128];
        DWORD clsidLen;
        while (true)
        {
            clsidLen = 128;
            if (RegEnumKeyExW(hBHO, idx++, clsid, &clsidLen,
                NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;

            cJSON* plugin = cJSON_CreateObject();
            cJSON_AddStringToObject(plugin, "browser", "IE/Edge-Legacy");
            cJSON_AddStringToObject(plugin, "type",    "BHO");
            cJSON_AddStringToObject(plugin, "clsid",   WideToUtf8(clsid).c_str());

            std::wstring clsidKey = std::wstring(L"SOFTWARE\\Classes\\CLSID\\") + clsid;
            std::string desc = BrowserRegReadStr(HKEY_LOCAL_MACHINE, clsidKey.c_str(), NULL);
            cJSON_AddStringToObject(plugin, "description", desc.c_str());

            std::wstring inprocKey = clsidKey + L"\\InprocServer32";
            std::string dllPath = BrowserRegReadStr(HKEY_LOCAL_MACHINE, inprocKey.c_str(), NULL);
            dllPath = ExpandEnvPath(dllPath);
            cJSON_AddStringToObject(plugin, "path",        dllPath.c_str());
            cJSON_AddStringToObject(plugin, "modify_time", GetModifyTimeA(dllPath).c_str());

            HKEY hBHOSub = NULL;
            std::wstring bhoSubKey = std::wstring(
                L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects\\")
                + clsid;
            bool disabled = false;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, bhoSubKey.c_str(),
                0, KEY_READ, &hBHOSub) == ERROR_SUCCESS)
            {
                DWORD noExplorer = 0;
                DWORD sz = sizeof(DWORD);
                if (RegQueryValueExW(hBHOSub, L"NoExplorer", NULL, NULL,
                    (LPBYTE)&noExplorer, &sz) == ERROR_SUCCESS)
                    disabled = (noExplorer != 0);
                RegCloseKey(hBHOSub);
            }
            cJSON_AddStringToObject(plugin, "status", disabled ? "Disabled" : "Enabled");
            cJSON_AddItemToArray(arr, plugin);
        }
        RegCloseKey(hBHO);
    }

    HKEY hTB = NULL;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Internet Explorer\\Toolbar",
        0, KEY_READ, &hTB) == ERROR_SUCCESS)
    {
        DWORD idx = 0;
        wchar_t valName[256];
        BYTE valData[512];
        DWORD nameLen, dataLen, type;
        while (true)
        {
            nameLen = 256; dataLen = sizeof(valData);
            if (RegEnumValueW(hTB, idx++, valName, &nameLen,
                NULL, &type, valData, &dataLen) != ERROR_SUCCESS) break;
            cJSON* plugin = cJSON_CreateObject();
            cJSON_AddStringToObject(plugin, "browser", "IE/Edge-Legacy");
            cJSON_AddStringToObject(plugin, "type",    "Toolbar");
            cJSON_AddStringToObject(plugin, "clsid",   WideToUtf8(valName).c_str());
            cJSON_AddStringToObject(plugin, "status",  "Enabled");
            cJSON_AddItemToArray(arr, plugin);
        }
        RegCloseKey(hTB);
    }
}

/* ===== Chrome/Edge(Chromium) 扩展 ===== */
static void EnumChromiumExtensions(const std::string& profileDir,
    const std::string& browser, cJSON* arr)
{
    std::string extDir = profileDir + "\\Extensions";
    std::wstring wExtDir = Utf8ToWstr(extDir);

    WIN32_FIND_DATAW fd = {0};
    std::wstring searchPath = wExtDir + L"\\*";
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

        std::string extId = WideToUtf8(fd.cFileName);
        if (extId.length() != 32) continue;

        std::wstring extPath = wExtDir + L"\\" + fd.cFileName;
        WIN32_FIND_DATAW vfd = {0};
        HANDLE hVer = FindFirstFileW((extPath + L"\\*").c_str(), &vfd);
        std::string version, manifestPath;
        if (hVer != INVALID_HANDLE_VALUE)
        {
            do {
                if (!(vfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (wcscmp(vfd.cFileName, L".") == 0 || wcscmp(vfd.cFileName, L"..") == 0) continue;
                version = WideToUtf8(vfd.cFileName);
                manifestPath = WideToUtf8((extPath + L"\\" + vfd.cFileName + L"\\manifest.json").c_str());
                break;
            } while (FindNextFileW(hVer, &vfd));
            FindClose(hVer);
        }

        cJSON* plugin = cJSON_CreateObject();
        cJSON_AddStringToObject(plugin, "browser",      browser.c_str());
        cJSON_AddStringToObject(plugin, "type",         "Extension");
        cJSON_AddStringToObject(plugin, "extension_id", extId.c_str());
        cJSON_AddStringToObject(plugin, "version",      version.c_str());
        cJSON_AddStringToObject(plugin, "path",         WideToUtf8(extPath.c_str()).c_str());
        cJSON_AddStringToObject(plugin, "modify_time",  FileTimeToString(fd.ftLastWriteTime).c_str());
        cJSON_AddStringToObject(plugin, "status",       "Installed");

        if (!manifestPath.empty())
        {
            HANDLE hManifest = CreateFileA(manifestPath.c_str(),
                GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
            if (hManifest != INVALID_HANDLE_VALUE)
            {
                DWORD fileSize = GetFileSize(hManifest, NULL);
                if (fileSize > 0 && fileSize < 1024 * 1024)
                {
                    /* 使用 malloc 替代 vector::data() 避免 VS2010 兼容性问题 */
                    char* content = (char*)malloc(fileSize + 1);
                    if (content)
                    {
                        memset(content, 0, fileSize + 1);
                        DWORD bytesRead = 0;
                        ReadFile(hManifest, content, fileSize, &bytesRead, NULL);
                        const char* nameKey = "\"name\"";
                        char* p = strstr(content, nameKey);
                        if (p)
                        {
                            p += strlen(nameKey);
                            while (*p == ' ' || *p == ':') p++;
                            if (*p == '\"')
                            {
                                p++;
                                char nameBuf[256] = {0};
                                int ni = 0;
                                while (*p && *p != '\"' && ni < 255)
                                    nameBuf[ni++] = *p++;
                                cJSON_AddStringToObject(plugin, "name", nameBuf);
                            }
                        }
                        free(content);
                    }
                }
                CloseHandle(hManifest);
            }
        }

        cJSON_AddItemToArray(arr, plugin);
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
}

/* ===== Firefox 扩展 ===== */
static void EnumFirefoxExtensions(cJSON* arr)
{
    wchar_t appData[MAX_PATH] = {0};
    if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData))) return;

    std::wstring ffDir = std::wstring(appData) + L"\\Mozilla\\Firefox\\Profiles";
    WIN32_FIND_DATAW fd = {0};
    HANDLE hFind = FindFirstFileW((ffDir + L"\\*").c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

        std::wstring extPath = ffDir + L"\\" + fd.cFileName + L"\\extensions";
        WIN32_FIND_DATAW efd = {0};
        HANDLE hExt = FindFirstFileW((extPath + L"\\*").c_str(), &efd);
        if (hExt == INVALID_HANDLE_VALUE) continue;

        do {
            std::string extName = WideToUtf8(efd.cFileName);
            if (extName == "." || extName == "..") continue;

            cJSON* plugin = cJSON_CreateObject();
            cJSON_AddStringToObject(plugin, "browser",      "Firefox");
            cJSON_AddStringToObject(plugin, "type",         "Extension");
            cJSON_AddStringToObject(plugin, "extension_id", extName.c_str());
            std::string fullPath = WideToUtf8((extPath + L"\\" + efd.cFileName).c_str());
            cJSON_AddStringToObject(plugin, "path",         fullPath.c_str());
            cJSON_AddStringToObject(plugin, "modify_time",  FileTimeToString(efd.ftLastWriteTime).c_str());
            cJSON_AddStringToObject(plugin, "status",       "Installed");
            cJSON_AddItemToArray(arr, plugin);
        } while (FindNextFileW(hExt, &efd));

        FindClose(hExt);
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
}

extern "C" __declspec(dllexport)
char* GetBrowserPlugins(const char* /*paramsJson*/)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "browser_plugins");

    cJSON* pluginsArr = cJSON_CreateArray();

    EnumIEExtensions(pluginsArr);

    wchar_t localAppData[MAX_PATH] = {0};
    SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);
    std::string localStr = WideToUtf8(localAppData);

    EnumChromiumExtensions(localStr + "\\Google\\Chrome\\User Data\\Default",
        "Chrome", pluginsArr);
    EnumChromiumExtensions(localStr + "\\Microsoft\\Edge\\User Data\\Default",
        "Edge(Chromium)", pluginsArr);
    EnumChromiumExtensions(localStr + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
        "Brave", pluginsArr);

    EnumFirefoxExtensions(pluginsArr);

    cJSON_AddItemToObject(root, "plugins", pluginsArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}

/*
 * SaveBrowserPlugins — 采集浏览器插件并字段级存入 SQLite3
 * 参数 JSON: { "db_path": "C:\\basic.db" }
 * 返回 JSON: { "snapshot_id": N, "rows_inserted": N, "status": "success" }
 */
extern "C" __declspec(dllexport)
char* SaveBrowserPlugins(const char* paramsJson)
{
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "module", "saveBrowserPlugins");

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

    char* jsonStr = GetBrowserPlugins(paramsJson);
    if (!jsonStr)
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", "GetBrowserPlugins failed");
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

    long long snapId = db.SaveBrowserPlugins(jsonStr);
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

