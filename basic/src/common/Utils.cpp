/*
 * Utils.cpp
 * 公共工具函数实现
 * 兼容 VS2017 (C++14) / Windows SDK 10.0.18362.0
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include "Utils.h"

#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <psapi.h>
#include <shlobj.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")

#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdlib>
#include <cstdarg>
#include <cstdio>
#include <string>
#include <vector>

/* ============================================================
 * 字符串转换
 * ========================================================== */

std::string WideToUtf8(const wchar_t* wstr)
{
    if (!wstr || wstr[0] == L'\0') return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], len, NULL, NULL);
    return result;
}

std::string WstrToUtf8(const std::wstring& wstr)
{
    return WideToUtf8(wstr.c_str());
}

std::string AnsiToUtf8(const char* ansiStr)
{
    if (!ansiStr || ansiStr[0] == '\0') return "";
    int wlen = MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, NULL, 0);
    if (wlen <= 0) return "";
    std::wstring wstr(wlen - 1, L'\0');
    MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, &wstr[0], wlen);
    return WideToUtf8(wstr.c_str());
}

std::wstring Utf8ToWstr(const std::string& str)
{
    if (str.empty()) return L"";
    int wlen = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    if (wlen <= 0) return L"";
    std::wstring result(wlen - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], wlen);
    return result;
}

std::wstring AnsiToWstr(const std::string& str)
{
    if (str.empty()) return L"";
    int wlen = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
    if (wlen <= 0) return L"";
    std::wstring result(wlen - 1, L'\0');
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &result[0], wlen);
    return result;
}

std::string FileTimeToString(const FILETIME& ft)
{
    SYSTEMTIME st = {0};
    FILETIME utcFt = ft;
    FileTimeToSystemTime(&utcFt, &st);
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

std::string SystemTimeToString(const SYSTEMTIME& st)
{
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

std::string LargeIntToString(ULONGLONG val)
{
    char buf[64];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%llu", val);
    return std::string(buf);
}

std::string LargeIntToSignedString(LONGLONG val)
{
    char buf[64];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%lld", val);
    return std::string(buf);
}

std::string LargeIntToHexString(ULONGLONG val)
{
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%016llX", val);
    return std::string(buf);
}

std::string GetCurrentUtcTime()
{
    SYSTEMTIME st = {0};
    GetSystemTime(&st);
    return SystemTimeToString(st);
}

std::string BytesToReadable(ULONGLONG bytes)
{
    char buf[64];
    if (bytes >= (1ULL << 40))
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%.2f TB", (double)bytes / (1ULL << 40));
    else if (bytes >= (1ULL << 30))
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%.2f GB", (double)bytes / (1ULL << 30));
    else if (bytes >= (1ULL << 20))
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%.2f MB", (double)bytes / (1ULL << 20));
    else if (bytes >= (1ULL << 10))
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%.2f KB", (double)bytes / (1ULL << 10));
    else
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%llu B", bytes);
    return std::string(buf);
}

std::string StrFormat(const char* fmt, ...)
{
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args);
    va_end(args);
    return std::string(buf);
}

/* ============================================================
 * 注册表工具
 * ========================================================== */

std::string GetRegString(HKEY hRoot, const wchar_t* subKey, const wchar_t* valName)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return "";

    DWORD type = 0;
    DWORD size = 0;
    if (RegQueryValueExW(hKey, valName, NULL, &type, NULL, &size) != ERROR_SUCCESS
        || (type != REG_SZ && type != REG_EXPAND_SZ)
        || size == 0)
    {
        RegCloseKey(hKey);
        return "";
    }

    std::wstring wval(size / sizeof(wchar_t) + 1, L'\0');
    if (RegQueryValueExW(hKey, valName, NULL, &type,
        reinterpret_cast<LPBYTE>(&wval[0]), &size) != ERROR_SUCCESS)
    {
        RegCloseKey(hKey);
        return "";
    }
    RegCloseKey(hKey);

    // 去掉末尾 null
    while (!wval.empty() && wval.back() == L'\0')
        wval.pop_back();

    return WstrToUtf8(wval);
}

std::string GetRegStringW(HKEY hRoot, const std::wstring& subKey, const std::wstring& valName)
{
    return GetRegString(hRoot, subKey.c_str(), valName.c_str());
}

DWORD GetRegDword(HKEY hRoot, const wchar_t* subKey, const wchar_t* valName, DWORD defaultVal)
{
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return defaultVal;

    DWORD type = 0, val = 0, size = sizeof(DWORD);
    if (RegQueryValueExW(hKey, valName, NULL, &type,
        reinterpret_cast<LPBYTE>(&val), &size) != ERROR_SUCCESS
        || type != REG_DWORD)
    {
        RegCloseKey(hKey);
        return defaultVal;
    }
    RegCloseKey(hKey);
    return val;
}

std::vector<std::wstring> EnumRegSubKeys(HKEY hRoot, const wchar_t* subKey)
{
    std::vector<std::wstring> result;
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return result;

    DWORD idx = 0;
    wchar_t name[256];
    DWORD nameLen = 256;
    while (RegEnumKeyExW(hKey, idx++, name, &nameLen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        result.push_back(std::wstring(name, nameLen));
        nameLen = 256;
    }
    RegCloseKey(hKey);
    return result;
}

std::vector<std::wstring> EnumRegValueNames(HKEY hRoot, const wchar_t* subKey)
{
    std::vector<std::wstring> result;
    HKEY hKey = NULL;
    if (RegOpenKeyExW(hRoot, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return result;

    DWORD idx = 0;
    wchar_t name[256];
    DWORD nameLen = 256;
    DWORD type = 0;
    while (RegEnumValueW(hKey, idx++, name, &nameLen, NULL, &type, NULL, NULL) == ERROR_SUCCESS)
    {
        result.push_back(std::wstring(name, nameLen));
        nameLen = 256;
    }
    RegCloseKey(hKey);
    return result;
}

/* ============================================================
 * 文件 / 签名工具
 * ========================================================== */

std::string VerifyAuthenticode(const std::wstring& filePath)
{
    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct       = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath  = filePath.c_str();

    GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wd = {0};
    wd.cbStruct            = sizeof(WINTRUST_DATA);
    wd.dwUIChoice          = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice       = WTD_CHOICE_FILE;
    wd.pFile               = &fileInfo;
    wd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags         = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = WinVerifyTrust(NULL, &actionGuid, &wd);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &actionGuid, &wd);

    switch (status)
    {
    case ERROR_SUCCESS:              return "Valid";
    case TRUST_E_NOSIGNATURE:        return "NoSignature";
    case TRUST_E_EXPLICIT_DISTRUST:  return "ExplicitDistrust";
    case TRUST_E_SUBJECT_NOT_TRUSTED:return "NotTrusted";
    case CERT_E_EXPIRED:             return "CertExpired";
    case CERT_E_UNTRUSTEDROOT:       return "UntrustedRoot";
    case TRUST_E_BAD_DIGEST:         return "Tampered";
    default:
    {
        char buf[32];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Error(0x%08X)", (unsigned)status);
        return std::string(buf);
    }
    }
}

bool VerifyFileTrustW(const std::wstring& filePath)
{
    return VerifyAuthenticode(filePath) == "Valid";
}

bool VerifyFileTrust(const std::string& filePath)
{
    return VerifyFileTrustW(Utf8ToWstr(filePath));
}

std::string GetFilePublisherW(const std::wstring& filePath)
{
    HCERTSTORE      hStore  = NULL;
    HCRYPTMSG       hMsg    = NULL;
    PCCERT_CONTEXT  pCert   = NULL;
    std::string     result;

    DWORD encoding = 0, contentType = 0, formatType = 0;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE,
        filePath.c_str(),
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0, &encoding, &contentType, &formatType,
        &hStore, &hMsg, NULL))
    {
        return "";
    }

    DWORD signerInfoSize = 0;
    if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &signerInfoSize)
        || signerInfoSize == 0)
        goto cleanup;

    {
        std::vector<BYTE> signerInfoBuf(signerInfoSize);
        CMSG_SIGNER_INFO* pSignerInfo = reinterpret_cast<CMSG_SIGNER_INFO*>(&signerInfoBuf[0]);
        if (!CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &signerInfoSize))
            goto cleanup;

        CERT_INFO certInfo = {0};
        certInfo.Issuer       = pSignerInfo->Issuer;
        certInfo.SerialNumber = pSignerInfo->SerialNumber;

        pCert = CertFindCertificateInStore(hStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0, CERT_FIND_SUBJECT_CERT, &certInfo, NULL);
        if (pCert)
        {
            wchar_t name[256] = {0};
            CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, name, 256);
            result = WstrToUtf8(name);
        }
    }

cleanup:
    if (pCert)  CertFreeCertificateContext(pCert);
    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg)   CryptMsgClose(hMsg);
    return result;
}

std::string GetFilePublisher(const std::string& filePath)
{
    return GetFilePublisherW(Utf8ToWstr(filePath));
}

std::string GetFileVersion(const std::wstring& filePath)
{
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &dummy);
    if (size == 0) return "";

    std::vector<BYTE> buf(size);
    if (!GetFileVersionInfoW(filePath.c_str(), 0, size, &buf[0]))
        return "";

    VS_FIXEDFILEINFO* pInfo = NULL;
    UINT infoLen = 0;
    if (!VerQueryValueW(&buf[0], L"\\", (LPVOID*)&pInfo, &infoLen) || !pInfo)
        return "";

    char ver[32];
    _snprintf_s(ver, sizeof(ver), _TRUNCATE, "%d.%d.%d.%d",
        HIWORD(pInfo->dwFileVersionMS), LOWORD(pInfo->dwFileVersionMS),
        HIWORD(pInfo->dwFileVersionLS), LOWORD(pInfo->dwFileVersionLS));
    return std::string(ver);
}

std::string GetFileDescription(const std::wstring& filePath)
{
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &dummy);
    if (size == 0) return "";

    std::vector<BYTE> buf(size);
    if (!GetFileVersionInfoW(filePath.c_str(), 0, size, &buf[0]))
        return "";

    struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; };
    LANGANDCODEPAGE* pTranslate = NULL;
    UINT cbTranslate = 0;
    if (!VerQueryValueW(&buf[0], L"\\VarFileInfo\\Translation",
        (LPVOID*)&pTranslate, &cbTranslate) || cbTranslate == 0)
        return "";

    wchar_t subBlock[64];
    _snwprintf_s(subBlock, 64, _TRUNCATE,
        L"\\StringFileInfo\\%04x%04x\\FileDescription",
        pTranslate[0].wLanguage, pTranslate[0].wCodePage);

    wchar_t* pDesc = NULL;
    UINT descLen = 0;
    if (!VerQueryValueW(&buf[0], subBlock, (LPVOID*)&pDesc, &descLen) || !pDesc)
        return "";

    return WstrToUtf8(pDesc);
}

std::string GetProcessImagePath(DWORD pid)
{
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return "";

    wchar_t path[MAX_PATH] = {0};
    DWORD len = MAX_PATH;
    std::string result;
    if (QueryFullProcessImageNameW(hProc, 0, path, &len))
        result = WstrToUtf8(path);

    CloseHandle(hProc);
    return result;
}

/* ============================================================
 * cJSON 序列化工具
 * ========================================================== */

char* SerializeJson(cJSON* root)
{
    if (!root) return NULL;
    char* jsonStr = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (!jsonStr) return NULL;

    size_t len = strlen(jsonStr) + 1;
    char* result = (char*)malloc(len);
    if (result) memcpy(result, jsonStr, len);
    cJSON_free(jsonStr);
    return result;
}

void FreeJsonResult(char* p)
{
    if (p) free(p);
}

char* BuildErrorJson(const char* module, const char* errMsg)
{
    cJSON* root = cJSON_CreateObject();
    if (module && module[0])
        cJSON_AddStringToObject(root, "module", module);
    cJSON_AddStringToObject(root, "status", "error");
    cJSON_AddStringToObject(root, "message", errMsg ? errMsg : "unknown error");
    return SerializeJson(root);
}

char* MakeSuccessJson()
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}

/* ============================================================
 * 参数解析工具
 * ========================================================== */

bool GetBoolParam(const char* paramsJson, const char* key, bool defaultVal)
{
    if (!paramsJson || !key) return defaultVal;
    cJSON* root = cJSON_Parse(paramsJson);
    if (!root) return defaultVal;
    cJSON* item = cJSON_GetObjectItem(root, key);
    bool result = defaultVal;
    if (item)
    {
        if (cJSON_IsTrue(item))  result = true;
        if (cJSON_IsFalse(item)) result = false;
    }
    cJSON_Delete(root);
    return result;
}

int GetIntParam(const char* paramsJson, const char* key, int defaultVal)
{
    if (!paramsJson || !key) return defaultVal;
    cJSON* root = cJSON_Parse(paramsJson);
    if (!root) return defaultVal;
    cJSON* item = cJSON_GetObjectItem(root, key);
    int result = defaultVal;
    if (item && cJSON_IsNumber(item)) result = item->valueint;
    cJSON_Delete(root);
    return result;
}

std::string GetStringParam(const char* paramsJson, const char* key, const char* defaultVal)
{
    if (!paramsJson || !key) return defaultVal ? defaultVal : "";
    cJSON* root = cJSON_Parse(paramsJson);
    if (!root) return defaultVal ? defaultVal : "";
    cJSON* item = cJSON_GetObjectItem(root, key);
    std::string result = defaultVal ? defaultVal : "";
    if (item && cJSON_IsString(item) && item->valuestring)
        result = item->valuestring;
    cJSON_Delete(root);
    return result;
}
