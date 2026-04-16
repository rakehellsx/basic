#pragma once
#ifndef UTILS_H
#define UTILS_H

/*
 * Utils.h
 * Common utility function declarations for all detection modules.
 * Compatible with VS2017 (C++14) / Windows SDK 10.0.18362.0
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <cstdarg>

extern "C" {
#include "../../third_party/cJSON/cJSON.h"
}

/* ============================================================
 * String conversion utilities
 * ========================================================== */

/* FILETIME -> "YYYY-MM-DD HH:MM:SS" (UTC) */
std::string FileTimeToString(const FILETIME& ft);

/* SYSTEMTIME -> "YYYY-MM-DD HH:MM:SS" (UTC) */
std::string SystemTimeToString(const SYSTEMTIME& st);

/* wchar_t* / std::wstring -> UTF-8 std::string */
std::string WideToUtf8(const wchar_t* wstr);
std::string WstrToUtf8(const std::wstring& wstr);

/* char* (ANSI/MBCS) -> UTF-8 std::string */
std::string AnsiToUtf8(const char* ansiStr);

/* UTF-8 std::string -> std::wstring */
std::wstring Utf8ToWstr(const std::string& str);

/* ANSI std::string -> std::wstring */
std::wstring AnsiToWstr(const std::string& str);

/* 64-bit integer -> decimal string */
std::string LargeIntToString(ULONGLONG val);
std::string LargeIntToSignedString(LONGLONG val);

/* 64-bit integer -> hex string with "0x" prefix */
std::string LargeIntToHexString(ULONGLONG val);

/* Get current UTC time as string */
std::string GetCurrentUtcTime();

/* Bytes -> human-readable string (e.g. "1.23 GB") */
std::string BytesToReadable(ULONGLONG bytes);

/* Safe string formatting */
std::string StrFormat(const char* fmt, ...);

/* ============================================================
 * Registry utilities
 * ========================================================== */

/* Read registry string value (REG_SZ / REG_EXPAND_SZ), returns "" on failure */
std::string GetRegString(HKEY hRoot, const wchar_t* subKey, const wchar_t* valName);
std::string GetRegStringW(HKEY hRoot, const std::wstring& subKey, const std::wstring& valName);

/* RegReadStr - alias for GetRegString, used by BrowserPlugins and other modules */
inline std::string RegReadStr(HKEY hRoot, const wchar_t* subKey, const wchar_t* valName)
{
    return GetRegString(hRoot, subKey, valName);
}

/* Read registry DWORD value, returns defaultVal on failure */
DWORD GetRegDword(HKEY hRoot, const wchar_t* subKey, const wchar_t* valName, DWORD defaultVal = 0);

/* Enumerate registry subkey names */
std::vector<std::wstring> EnumRegSubKeys(HKEY hRoot, const wchar_t* subKey);

/* Enumerate registry value names */
std::vector<std::wstring> EnumRegValueNames(HKEY hRoot, const wchar_t* subKey);

/* ============================================================
 * File / signature utilities
 * ========================================================== */

/* Get file digital signature publisher, returns "" if unsigned */
std::string GetFilePublisher(const std::string& filePath);
std::string GetFilePublisherW(const std::wstring& filePath);

/* Verify file Authenticode signature, returns true if valid */
bool VerifyFileTrust(const std::string& filePath);
bool VerifyFileTrustW(const std::wstring& filePath);

/* Verify file Authenticode signature, returns human-readable string */
std::string VerifyAuthenticode(const std::wstring& filePath);

/* Get file version string (e.g. "1.2.3.4"), returns "" on failure */
std::string GetFileVersion(const std::wstring& filePath);

/* Get file description string (FileDescription), returns "" on failure */
std::string GetFileDescription(const std::wstring& filePath);

/* Get process executable path (UTF-8), returns "" on failure */
std::string GetProcessImagePath(DWORD pid);

/* ============================================================
 * cJSON serialization utilities
 * ========================================================== */

/*
 * Serialize a cJSON object to a heap-allocated char* (for DLL export return values).
 * Caller must call FreeJsonResult() to release memory.
 * Also calls cJSON_Delete(root) internally.
 */
char* SerializeJson(cJSON* root);

/* Free memory returned by SerializeJson */
void FreeJsonResult(char* p);

/*
 * FreeJsonString - inline forwarder to FreeJsonResult.
 * Used by internal module code. Declared inline to avoid C2375 linkage
 * conflict with the extern "C" BASIC_API declaration in basic.h.
 */
inline void FreeJsonString(char* p) { FreeJsonResult(p); }

/* Build error JSON: { "status":"error", "message":"..." } */
char* BuildErrorJson(const char* module, const char* errMsg);

/* Build success JSON: { "status":"success" } */
char* MakeSuccessJson();

/* ============================================================
 * Parameter parsing utilities
 * ========================================================== */

/* Read bool parameter from JSON string, returns defaultVal on failure */
bool GetBoolParam(const char* paramsJson, const char* key, bool defaultVal);

/* Read int parameter from JSON string, returns defaultVal on failure */
int GetIntParam(const char* paramsJson, const char* key, int defaultVal);

/* Read string parameter from JSON string, returns defaultVal on failure */
std::string GetStringParam(const char* paramsJson, const char* key, const char* defaultVal);

#endif /* UTILS_H */
