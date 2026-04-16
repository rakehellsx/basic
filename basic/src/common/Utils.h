#pragma once
#ifndef UTILS_H
#define UTILS_H

/*
 * Utils.h
 * 公共工具函数声明 — 供所有检测模块使用
 * 兼容 VS2017 (C++14) / Windows SDK 10.0.18362.0
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
 * 字符串转换
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

/* 获取当前 UTC 时间字符串 */
std::string GetCurrentUtcTime();

/* 字节数 -> 可读字符串 (e.g. "1.23 GB") */
std::string BytesToReadable(ULONGLONG bytes);

/* 安全格式化字符串 */
std::string StrFormat(const char* fmt, ...);

/* ============================================================
 * 注册表工具
 * ========================================================== */

/* 读取注册表字符串值 (REG_SZ / REG_EXPAND_SZ)，失败返回 "" */
std::string GetRegString(HKEY hRoot, const wchar_t* subKey, const wchar_t* valName);
std::string GetRegStringW(HKEY hRoot, const std::wstring& subKey, const std::wstring& valName);

/* RegReadStr — GetRegString 的别名，供 BrowserPlugins 等模块使用 */
inline std::string RegReadStr(HKEY hRoot, const wchar_t* subKey, const wchar_t* valName)
{
    return GetRegString(hRoot, subKey, valName);
}

/* 读取注册表 DWORD 值，失败返回 defaultVal */
DWORD GetRegDword(HKEY hRoot, const wchar_t* subKey, const wchar_t* valName, DWORD defaultVal = 0);

/* 枚举注册表子键名称列表 */
std::vector<std::wstring> EnumRegSubKeys(HKEY hRoot, const wchar_t* subKey);

/* 枚举注册表值名称列表 */
std::vector<std::wstring> EnumRegValueNames(HKEY hRoot, const wchar_t* subKey);

/* ============================================================
 * 文件 / 签名工具
 * ========================================================== */

/* 获取文件数字签名发布者，无签名返回 "" */
std::string GetFilePublisher(const std::string& filePath);
std::string GetFilePublisherW(const std::wstring& filePath);

/* 验证文件 Authenticode 签名，返回 true = 有效 */
bool VerifyFileTrust(const std::string& filePath);
bool VerifyFileTrustW(const std::wstring& filePath);

/* 验证文件 Authenticode 签名，返回可读字符串 */
std::string VerifyAuthenticode(const std::wstring& filePath);

/* 获取文件版本字符串 (e.g. "1.2.3.4")，失败返回 "" */
std::string GetFileVersion(const std::wstring& filePath);

/* 获取文件描述字符串 (FileDescription)，失败返回 "" */
std::string GetFileDescription(const std::wstring& filePath);

/* 获取进程可执行文件路径 (UTF-8)，失败返回 "" */
std::string GetProcessImagePath(DWORD pid);

/* ============================================================
 * cJSON 序列化工具
 * ========================================================== */

/*
 * 将 cJSON 对象序列化为堆分配的 char*（DLL 导出函数返回值）
 * 调用者必须调用 FreeJsonResult() 释放内存
 * 同时负责 cJSON_Delete(root)
 */
char* SerializeJson(cJSON* root);

/* 释放 SerializeJson 返回的内存 */
void FreeJsonResult(char* p);

/* 供各模块内部调用：内联转发到 FreeJsonResult，避免与 basic.h 中 extern "C" 声明冲突 */
inline void FreeJsonString(char* p) { FreeJsonResult(p); }

/* 构造错误 JSON: { "status":"error", "message":"..." } */
char* BuildErrorJson(const char* module, const char* errMsg);

/* 构造成功 JSON: { "status":"success" } */
char* MakeSuccessJson();

/* ============================================================
 * 参数解析工具
 * ========================================================== */

/* 从 JSON 字符串中读取 bool 参数，失败返回 defaultVal */
bool GetBoolParam(const char* paramsJson, const char* key, bool defaultVal);

/* 从 JSON 字符串中读取 int 参数，失败返回 defaultVal */
int GetIntParam(const char* paramsJson, const char* key, int defaultVal);

/* 从 JSON 字符串中读取 string 参数，失败返回 defaultVal */
std::string GetStringParam(const char* paramsJson, const char* key, const char* defaultVal);

#endif /* UTILS_H */
