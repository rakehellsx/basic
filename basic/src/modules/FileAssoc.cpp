/*
 * FileAssoc.cpp
 * 文件关联检测模块
 *
 * 功能：
 *   1. 枚举系统中所有已注册的文件扩展名（HKCR 下 .xxx 键）
 *   2. 判断文件后缀名是否为已知/合法类型
 *   3. 提取每个扩展名的默认打开方式（ProgID、命令行、图标）
 *   4. 检测文件关联是否被篡改：
 *      - 对比 HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts
 *        下的 UserChoice 与 HKCR 注册的默认关联是否一致
 *      - 检查命令行中是否包含可疑路径（非系统目录、非 Program Files）
 *      - 检查 ProgID 对应的 shell\open\command 是否被替换为未签名程序
 *
 * 导出接口：
 *   GetFileAssocInfo(paramsJson)   — 枚举所有扩展名关联信息
 *   CheckFileAssoc(paramsJson)     — 检测指定扩展名是否被篡改
 */

#include <windows.h>
#include <shlwapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#include <vector>
#include <set>
#include <algorithm>
#include "../common/Utils.h"

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "wintrust.lib")

/* -----------------------------------------------------------------------
 * 已知合法扩展名白名单（常见系统/办公/媒体类型）
 * --------------------------------------------------------------------- */
static const char* g_knownExts[] = {
    ".exe",".dll",".sys",".drv",".ocx",".cpl",".scr",".msi",".msp",
    ".bat",".cmd",".ps1",".vbs",".js",".wsf",".wsh",".reg",
    ".txt",".log",".ini",".cfg",".xml",".json",".csv",".yaml",".yml",
    ".doc",".docx",".xls",".xlsx",".ppt",".pptx",".pdf",".odt",".ods",
    ".zip",".rar",".7z",".tar",".gz",".cab",".iso",
    ".jpg",".jpeg",".png",".gif",".bmp",".tiff",".ico",".svg",".webp",
    ".mp3",".wav",".flac",".aac",".ogg",".wma",
    ".mp4",".avi",".mkv",".mov",".wmv",".flv",".webm",
    ".htm",".html",".css",".js",".ts",".py",".c",".cpp",".h",".cs",
    ".lnk",".url",".inf",".cat",".cer",".pfx",".p12",".crt",
    ".ttf",".otf",".fon",".woff",".woff2",
    ".db",".sqlite",".mdb",".accdb",
    NULL
};

static bool IsKnownExtension(const std::string& ext)
{
    std::string lower = ext;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (int i = 0; g_knownExts[i]; i++)
        if (lower == g_knownExts[i]) return true;
    return false;
}

/* -----------------------------------------------------------------------
 * 可疑路径判断：命令行不在系统目录或 Program Files 中
 * --------------------------------------------------------------------- */
static bool IsSuspiciousPath(const std::wstring& cmdLine)
{
    if (cmdLine.empty()) return false;

    wchar_t sysDir[MAX_PATH]  = {};
    wchar_t winDir[MAX_PATH]  = {};
    wchar_t pf32[MAX_PATH]    = {};
    wchar_t pf64[MAX_PATH]    = {};

    GetSystemDirectoryW(sysDir, MAX_PATH);
    GetWindowsDirectoryW(winDir, MAX_PATH);
    SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES,   NULL, 0, pf32);
    SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, pf64);

    std::wstring cmd = cmdLine;
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::towlower);

    std::wstring sys = sysDir; std::transform(sys.begin(), sys.end(), sys.begin(), ::towlower);
    std::wstring win = winDir; std::transform(win.begin(), win.end(), win.begin(), ::towlower);
    std::wstring p32 = pf32;   std::transform(p32.begin(), p32.end(), p32.begin(), ::towlower);
    std::wstring p64 = pf64;   std::transform(p64.begin(), p64.end(), p64.begin(), ::towlower);

    /* 如果命令行包含系统路径前缀，则不可疑 */
    if (!sys.empty() && cmd.find(sys) != std::wstring::npos) return false;
    if (!win.empty() && cmd.find(win) != std::wstring::npos) return false;
    if (!p32.empty() && cmd.find(p32) != std::wstring::npos) return false;
    if (!p64.empty() && cmd.find(p64) != std::wstring::npos) return false;

    /* 包含 %SystemRoot%、%ProgramFiles% 等变量也视为合法 */
    if (cmd.find(L"%systemroot%") != std::wstring::npos) return false;
    if (cmd.find(L"%programfiles%") != std::wstring::npos) return false;
    if (cmd.find(L"%windir%") != std::wstring::npos) return false;

    /* 命令行中含有路径（含 :\ 或 \\ ）但不在系统目录，视为可疑 */
    if (cmd.find(L":\\") != std::wstring::npos ||
        cmd.find(L"\\\\") != std::wstring::npos)
        return true;

    return false;
}

/* -----------------------------------------------------------------------
 * 验证可执行文件签名（Authenticode）
 * 返回：true = 有效签名，false = 无签名或签名无效
 * --------------------------------------------------------------------- */
static bool HasValidSignature(const std::wstring& filePath)
{
    if (filePath.empty()) return false;

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct           = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath      = filePath.c_str();

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wtData = {};
    wtData.cbStruct            = sizeof(WINTRUST_DATA);
    wtData.dwUIChoice          = WTD_UI_NONE;
    wtData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtData.dwUnionChoice       = WTD_CHOICE_FILE;
    wtData.pFile               = &fileInfo;
    wtData.dwStateAction       = WTD_STATEACTION_VERIFY;
    wtData.dwProvFlags         = WTD_SAFER_FLAG;

    LONG result = WinVerifyTrust(NULL, &actionGuid, &wtData);

    wtData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGuid, &wtData);

    return (result == ERROR_SUCCESS);
}

/* -----------------------------------------------------------------------
 * 从命令行字符串中提取可执行文件路径
 * 例如：`"C:\Windows\notepad.exe" "%1"` → `C:\Windows\notepad.exe`
 * --------------------------------------------------------------------- */
static std::wstring ExtractExeFromCmd(const std::wstring& cmd)
{
    if (cmd.empty()) return L"";

    std::wstring result;
    if (cmd[0] == L'"')
    {
        size_t end = cmd.find(L'"', 1);
        if (end != std::wstring::npos)
            result = cmd.substr(1, end - 1);
    }
    else
    {
        size_t sp = cmd.find(L' ');
        result = (sp != std::wstring::npos) ? cmd.substr(0, sp) : cmd;
    }

    /* 展开环境变量 */
    wchar_t expanded[MAX_PATH * 2] = {};
    if (ExpandEnvironmentStringsW(result.c_str(), expanded, MAX_PATH * 2) > 0)
        result = expanded;

    return result;
}

/* -----------------------------------------------------------------------
 * 读取注册表字符串值（HKCR 或指定根键）
 * --------------------------------------------------------------------- */
static std::wstring RegGetStr(HKEY hRoot, const std::wstring& subKey,
                              const std::wstring& valueName = L"")
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return L"";

    wchar_t buf[4096] = {};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    LONG rc = RegQueryValueExW(hKey, valueName.c_str(), NULL, &type,
                               (LPBYTE)buf, &size);
    RegCloseKey(hKey);

    if (rc != ERROR_SUCCESS) return L"";
    return buf;
}

/* -----------------------------------------------------------------------
 * 单个扩展名的完整关联信息
 * --------------------------------------------------------------------- */
struct AssocEntry
{
    std::string ext;              // 扩展名，如 ".txt"
    std::string progId;           // ProgID，如 "txtfile"
    std::string progIdDesc;       // ProgID 描述，如 "Text Document"
    std::string openCommand;      // shell\open\command 命令行
    std::string iconPath;         // DefaultIcon 路径
    std::string userChoiceProgId; // HKCU UserChoice ProgID
    bool        isKnown;          // 是否为已知扩展名
    bool        isTampered;       // 是否被篡改
    std::string tamperReason;     // 篡改原因描述
    bool        exeSigned;        // 关联程序是否有有效签名
};

/* -----------------------------------------------------------------------
 * 分析单个扩展名
 * --------------------------------------------------------------------- */
static AssocEntry AnalyzeExt(const std::wstring& extW)
{
    AssocEntry entry;
    entry.ext      = WideToUtf8(extW.c_str());
    entry.isKnown  = IsKnownExtension(entry.ext);
    entry.isTampered = false;
    entry.exeSigned  = false;

    /* 1. 从 HKCR\.<ext> 读取 ProgID */
    std::wstring progIdW = RegGetStr(HKEY_CLASSES_ROOT, extW);
    entry.progId = WideToUtf8(progIdW.c_str());

    /* 2. ProgID 描述 */
    if (!progIdW.empty())
    {
        std::wstring desc = RegGetStr(HKEY_CLASSES_ROOT, progIdW);
        entry.progIdDesc = WideToUtf8(desc.c_str());
    }

    /* 3. shell\open\command */
    std::wstring cmdKey = progIdW + L"\\shell\\open\\command";
    std::wstring cmdW   = RegGetStr(HKEY_CLASSES_ROOT, cmdKey);
    entry.openCommand   = WideToUtf8(cmdW.c_str());

    /* 4. DefaultIcon */
    std::wstring iconKey = progIdW + L"\\DefaultIcon";
    std::wstring iconW   = RegGetStr(HKEY_CLASSES_ROOT, iconKey);
    entry.iconPath       = WideToUtf8(iconW.c_str());

    /* 5. HKCU UserChoice */
    std::wstring ucKey = L"Software\\Microsoft\\Windows\\CurrentVersion"
                         L"\\Explorer\\FileExts\\" + extW + L"\\UserChoice";
    std::wstring ucProgIdW = RegGetStr(HKEY_CURRENT_USER, ucKey, L"ProgId");
    entry.userChoiceProgId = WideToUtf8(ucProgIdW.c_str());

    /* ----------------------------------------------------------------
     * 篡改检测逻辑
     * ---------------------------------------------------------------- */
    std::vector<std::string> reasons;

    /* 规则1：UserChoice ProgID 与 HKCR 默认 ProgID 不一致 */
    if (!ucProgIdW.empty() && !progIdW.empty() &&
        _wcsicmp(ucProgIdW.c_str(), progIdW.c_str()) != 0)
    {
        /* 进一步检查 UserChoice 对应的命令行 */
        std::wstring ucCmdKey = ucProgIdW + L"\\shell\\open\\command";
        std::wstring ucCmdW   = RegGetStr(HKEY_CLASSES_ROOT, ucCmdKey);
        if (!ucCmdW.empty())
        {
            /* 用 UserChoice 的命令行覆盖显示 */
            entry.openCommand = WideToUtf8(ucCmdW.c_str());
            cmdW = ucCmdW;
        }
        reasons.push_back("UserChoice ProgID differs from HKCR default ("
            + entry.userChoiceProgId + " vs " + entry.progId + ")");
    }

    /* 规则2：命令行路径可疑（不在系统目录） */
    if (!cmdW.empty() && IsSuspiciousPath(cmdW))
        reasons.push_back("open command points to non-system path: "
            + WideToUtf8(cmdW.c_str()));

    /* 规则3：关联程序签名验证 */
    if (!cmdW.empty())
    {
        std::wstring exePath = ExtractExeFromCmd(cmdW);
        if (!exePath.empty() && PathFileExistsW(exePath.c_str()))
        {
            entry.exeSigned = HasValidSignature(exePath);
            if (!entry.exeSigned)
                    reasons.push_back("associated executable has no valid signature: "
                    + WideToUtf8(exePath.c_str()));
        }
    }

    /* 规则4：ProgID 为空但扩展名已知（关联被清除） */
    if (progIdW.empty() && entry.isKnown)
        reasons.push_back("known extension has no ProgID registered (association cleared)");

    if (!reasons.empty())
    {
        entry.isTampered = true;
        for (size_t i = 0; i < reasons.size(); i++)
        {
            if (i > 0) entry.tamperReason += "; ";
            entry.tamperReason += reasons[i];
        }
    }

    return entry;
}

/* -----------------------------------------------------------------------
 * 将 AssocEntry 序列化为 cJSON 对象
 * --------------------------------------------------------------------- */
static cJSON* EntryToJson(const AssocEntry& e)
{
    cJSON* item = cJSON_CreateObject();
    cJSON_AddStringToObject(item, "ext",                e.ext.c_str());
    cJSON_AddBoolToObject  (item, "is_known",           e.isKnown);
    cJSON_AddStringToObject(item, "prog_id",            e.progId.c_str());
    cJSON_AddStringToObject(item, "prog_id_desc",       e.progIdDesc.c_str());
    cJSON_AddStringToObject(item, "open_command",       e.openCommand.c_str());
    cJSON_AddStringToObject(item, "icon_path",          e.iconPath.c_str());
    cJSON_AddStringToObject(item, "user_choice_prog_id",e.userChoiceProgId.c_str());
    cJSON_AddBoolToObject  (item, "exe_signed",         e.exeSigned);
    cJSON_AddBoolToObject  (item, "is_tampered",        e.isTampered);
    cJSON_AddStringToObject(item, "tamper_reason",      e.tamperReason.c_str());
    return item;
}

/* -----------------------------------------------------------------------
 * GetFileAssocInfo
 *
 * paramsJson:
 * {
 *   "filter_tampered" : false,   // 可选，true 则只返回被篡改的项
 *   "filter_unknown"  : false,   // 可选，true 则只返回未知扩展名
 *   "max_count"       : 500      // 可选，最多返回条数（默认 500）
 * }
 *
 * 返回：
 * {
 *   "module"          : "file_assoc_info",
 *   "total_scanned"   : 312,
 *   "total_tampered"  : 3,
 *   "total_unknown"   : 15,
 *   "items"           : [ { ... }, ... ],
 *   "status"          : "success"
 * }
 * --------------------------------------------------------------------- */
extern "C" __declspec(dllexport)
char* GetFileAssocInfo(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "file_assoc_info");

    bool filterTampered = GetBoolParam(paramsJson, "filter_tampered", false);
    bool filterUnknown  = GetBoolParam(paramsJson, "filter_unknown",  false);
    int  maxCount       = GetIntParam (paramsJson, "max_count",       500);

    std::vector<AssocEntry> entries;
    int totalTampered = 0;
    int totalUnknown  = 0;

    /* 枚举 HKCR 下所有以 '.' 开头的子键（即扩展名） */
    HKEY hHKCR = NULL;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, L"", 0, KEY_READ, &hHKCR) == ERROR_SUCCESS)
    {
        DWORD index = 0;
        wchar_t subKeyName[256];
        DWORD nameLen;

        while (true)
        {
            nameLen = 256;
            LONG rc = RegEnumKeyExW(hHKCR, index++, subKeyName, &nameLen,
                                    NULL, NULL, NULL, NULL);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) continue;
            if (subKeyName[0] != L'.') continue;

            AssocEntry e = AnalyzeExt(subKeyName);
            if (e.isTampered) totalTampered++;
            if (!e.isKnown)   totalUnknown++;

            entries.push_back(e);
        }
        RegCloseKey(hHKCR);
    }

    cJSON_AddNumberToObject(root, "total_scanned",  (double)entries.size());
    cJSON_AddNumberToObject(root, "total_tampered", (double)totalTampered);
    cJSON_AddNumberToObject(root, "total_unknown",  (double)totalUnknown);

    cJSON* arr = cJSON_CreateArray();
    int count = 0;
    for (size_t ei = 0; ei < entries.size(); ei++)
    {
        if (count >= maxCount) break;
        const AssocEntry& e = entries[ei];
        if (filterTampered && !e.isTampered) continue;
        if (filterUnknown  && e.isKnown)     continue;
        cJSON_AddItemToArray(arr, EntryToJson(e));
        count++;
    }
    cJSON_AddItemToObject(root, "items", arr);
    cJSON_AddStringToObject(root, "status", "success");

    return SerializeJson(root);
}

/* -----------------------------------------------------------------------
 * CheckFileAssoc
 *
 * 检测指定扩展名（或多个）的关联是否被篡改
 *
 * paramsJson:
 * {
 *   "extensions" : [".txt", ".exe", ".bat"]   // 必填，要检测的扩展名列表
 * }
 *
 * 返回：
 * {
 *   "module"  : "check_file_assoc",
 *   "total"   : 3,
 *   "items"   : [ { ... }, ... ],
 *   "status"  : "success"
 * }
 * --------------------------------------------------------------------- */
extern "C" __declspec(dllexport)
char* CheckFileAssoc(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "check_file_assoc");

    cJSON* arr = cJSON_CreateArray();
    int total = 0;

    cJSON* parsed = paramsJson ? cJSON_Parse(paramsJson) : NULL;
    cJSON* extArr = parsed ? cJSON_GetObjectItem(parsed, "extensions") : NULL;

    if (extArr && cJSON_IsArray(extArr))
    {
        int n = cJSON_GetArraySize(extArr);
        for (int i = 0; i < n; i++)
        {
            cJSON* item = cJSON_GetArrayItem(extArr, i);
            if (!item || !cJSON_IsString(item)) continue;

            std::string extStr = item->valuestring;
            /* 确保以 '.' 开头 */
            if (extStr.empty() || extStr[0] != '.')
                extStr = "." + extStr;

            std::wstring extW = Utf8ToWstr(extStr);
            AssocEntry e = AnalyzeExt(extW);
            cJSON_AddItemToArray(arr, EntryToJson(e));
            total++;
        }
    }
    else
    {
        /* 未传 extensions 时，默认检测高危扩展名 */
        static const char* highRisk[] = {
            ".exe",".bat",".cmd",".com",".scr",".pif",".vbs",".js",
            ".wsf",".lnk",".reg",".inf",".msi",".ps1",NULL
        };
        for (int i = 0; highRisk[i]; i++)
        {
            std::wstring extW = Utf8ToWstr(std::string(highRisk[i]));
            AssocEntry e = AnalyzeExt(extW);
            cJSON_AddItemToArray(arr, EntryToJson(e));
            total++;
        }
    }

    if (parsed) cJSON_Delete(parsed);

    cJSON_AddNumberToObject(root, "total", (double)total);
    cJSON_AddItemToObject(root, "items", arr);
    cJSON_AddStringToObject(root, "status", "success");

    return SerializeJson(root);
}
