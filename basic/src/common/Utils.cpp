#include "Utils.h"
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cstdlib>

std::string FileTimeToString(const FILETIME& ft)
{
    SYSTEMTIME st = {0};
    FILETIME localFt = {0};
    FileTimeToLocalFileTime(&ft, &localFt);
    FileTimeToSystemTime(&localFt, &st);
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

std::string WideToUtf8(const wchar_t* wstr)
{
    if (!wstr || wstr[0] == L'\0') return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return "";
    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], len, NULL, NULL);
    return result;
}

std::string AnsiToUtf8(const char* ansiStr)
{
    if (!ansiStr || ansiStr[0] == '\0') return "";
    // ANSI -> Wide
    int wlen = MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, NULL, 0);
    if (wlen <= 0) return "";
    std::wstring wstr(wlen - 1, L'\0');
    MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, &wstr[0], wlen);
    return WideToUtf8(wstr.c_str());
}

std::string LargeIntToString(ULONGLONG val)
{
    char buf[64];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%llu", val);
    return std::string(buf);
}

char* BuildErrorJson(const char* module, const char* errMsg)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", module ? module : "");
    cJSON_AddStringToObject(root, "status", "error");
    cJSON_AddStringToObject(root, "error", errMsg ? errMsg : "unknown error");
    return SerializeJson(root);
}

char* SerializeJson(cJSON* root)
{
    if (!root) return NULL;
    char* jsonStr = cJSON_Print(root);
    cJSON_Delete(root);
    if (!jsonStr) return NULL;
    // 复制到独立堆内存，由FreeJsonString释放
    size_t len = strlen(jsonStr) + 1;
    char* result = (char*)malloc(len);
    if (result) memcpy(result, jsonStr, len);
    free(jsonStr);
    return result;
}

bool GetBoolParam(const char* paramsJson, const char* key, bool defaultVal)
{
    if (!paramsJson || !key) return defaultVal;
    cJSON* root = cJSON_Parse(paramsJson);
    if (!root) return defaultVal;
    cJSON* item = cJSON_GetObjectItem(root, key);
    bool result = defaultVal;
    if (item) {
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
    if (item && cJSON_IsString(item) && item->valuestring) result = item->valuestring;
    cJSON_Delete(root);
    return result;
}
