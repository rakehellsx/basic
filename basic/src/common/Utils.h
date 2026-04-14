#pragma once
#ifndef UTILS_H
#define UTILS_H

#include <windows.h>
#include <string>
#include "../../third_party/cJSON/cJSON.h"

// 将FILETIME转为可读字符串 "YYYY-MM-DD HH:MM:SS"
std::string FileTimeToString(const FILETIME& ft);

// 将WCHAR*转为UTF-8 std::string
std::string WideToUtf8(const wchar_t* wstr);

// 将char*（ANSI）转为UTF-8 std::string
std::string AnsiToUtf8(const char* ansiStr);

// 将LARGE_INTEGER转为字节数字符串（如 "500107862016 bytes"）
std::string LargeIntToString(ULONGLONG val);

// 构建统一的错误JSON响应
char* BuildErrorJson(const char* module, const char* errMsg);

// 将cJSON对象序列化为堆分配的字符串（调用方需用FreeJsonString释放）
char* SerializeJson(cJSON* root);

// 解析参数JSON，获取bool型参数，默认值defaultVal
bool GetBoolParam(const char* paramsJson, const char* key, bool defaultVal);

// 解析参数JSON，获取int型参数，默认值defaultVal
int GetIntParam(const char* paramsJson, const char* key, int defaultVal);

// 解析参数JSON，获取string型参数，默认值defaultVal
std::string GetStringParam(const char* paramsJson, const char* key, const char* defaultVal);

#endif // UTILS_H
