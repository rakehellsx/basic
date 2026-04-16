/*
 * 模块：驱动信息
 * 指标：实体硬件、虚拟硬件、发行商、修改时间、映像路径、授信状态
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#include <vector>
#include "../common/Utils.h"
#include "../common/DbStorage.h"

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "version.lib")

/* 获取文件修改时间（局部版，避免与 Utils.h 冲突） */
static std::string GetDrvModifyTime(const wchar_t* path)
{
    if (!path || !path[0]) return "";
    WIN32_FILE_ATTRIBUTE_DATA fad = {0};
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return "";
    return FileTimeToString(fad.ftLastWriteTime);
}

/* 判断是否为虚拟设备 */
static bool IsVirtualDevice(const std::string& desc, const std::string& className)
{
    static const char* keywords[] = {
        "virtual", "vmware", "virtualbox", "hyper-v", "vbox",
        "loopback", "tap-windows", "ndis", "miniport", NULL
    };
    std::string lower = desc;
    for (size_t i = 0; i < lower.size(); i++)
        lower[i] = (char)tolower((unsigned char)lower[i]);
    std::string lowerClass = className;
    for (size_t i = 0; i < lowerClass.size(); i++)
        lowerClass[i] = (char)tolower((unsigned char)lowerClass[i]);

    for (int i = 0; keywords[i]; i++)
    {
        if (lower.find(keywords[i]) != std::string::npos ||
            lowerClass.find(keywords[i]) != std::string::npos)
            return true;
    }
    return false;
}

extern "C" __declspec(dllexport)
char* GetDriverInfo(const char* /*paramsJson*/)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "driver_info");

    cJSON* driversArr = cJSON_CreateArray();

    HDEVINFO hDevInfo = SetupDiGetClassDevsW(NULL, NULL, NULL,
        DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE)
        return BuildErrorJson("driver_info", "SetupDiGetClassDevs failed");

    SP_DEVINFO_DATA devData = {0};
    devData.cbSize = sizeof(devData);

    for (DWORD idx = 0;
        SetupDiEnumDeviceInfo(hDevInfo, idx, &devData); idx++)
    {
        cJSON* drv = cJSON_CreateObject();

        wchar_t devDesc[512]  = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_DEVICEDESC, NULL, (PBYTE)devDesc, sizeof(devDesc), NULL);
        cJSON_AddStringToObject(drv, "device_description", WideToUtf8(devDesc).c_str());

        wchar_t className[256] = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_CLASS, NULL, (PBYTE)className, sizeof(className), NULL);
        cJSON_AddStringToObject(drv, "class_name", WideToUtf8(className).c_str());

        wchar_t hwId[1024] = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_HARDWAREID, NULL, (PBYTE)hwId, sizeof(hwId), NULL);
        cJSON_AddStringToObject(drv, "hardware_id", WideToUtf8(hwId).c_str());

        wchar_t mfg[256] = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_MFG, NULL, (PBYTE)mfg, sizeof(mfg), NULL);
        cJSON_AddStringToObject(drv, "manufacturer", WideToUtf8(mfg).c_str());

        /* 驱动版本信息 */
        SP_DRVINFO_DATA drvInfoData = {0};
        drvInfoData.cbSize = sizeof(drvInfoData);
        if (SetupDiBuildDriverInfoList(hDevInfo, &devData, SPDIT_COMPATDRIVER))
        {
            if (SetupDiEnumDriverInfoW(hDevInfo, &devData,
                SPDIT_COMPATDRIVER, 0, &drvInfoData))
            {
                cJSON_AddStringToObject(drv, "driver_provider",
                    WideToUtf8(drvInfoData.ProviderName).c_str());
                cJSON_AddStringToObject(drv, "driver_description",
                    WideToUtf8(drvInfoData.Description).c_str());
                SYSTEMTIME st = {0};
                FileTimeToSystemTime(&drvInfoData.DriverDate, &st);
                char dateBuf[32];
                _snprintf_s(dateBuf, sizeof(dateBuf), _TRUNCATE,
                    "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
                cJSON_AddStringToObject(drv, "driver_date", dateBuf);
            }
            SetupDiDestroyDriverInfoList(hDevInfo, &devData, SPDIT_COMPATDRIVER);
        }

        /* 驱动映像路径 */
        wchar_t service[256] = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_SERVICE, NULL, (PBYTE)service, sizeof(service), NULL);

        std::wstring imagePath;
        if (service[0])
        {
            std::wstring svcKey = std::wstring(
                L"SYSTEM\\CurrentControlSet\\Services\\") + service;
            HKEY hSvc = NULL;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, svcKey.c_str(),
                0, KEY_READ, &hSvc) == ERROR_SUCCESS)
            {
                wchar_t imgBuf[1024] = {0};
                DWORD imgSize = sizeof(imgBuf);
                DWORD imgType = 0;
                if (RegQueryValueExW(hSvc, L"ImagePath", NULL, &imgType,
                    (LPBYTE)imgBuf, &imgSize) == ERROR_SUCCESS)
                {
                    wchar_t expanded[1024] = {0};
                    ExpandEnvironmentStringsW(imgBuf, expanded, 1024);
                    imagePath = expanded;
                }
                RegCloseKey(hSvc);
            }
        }

        cJSON_AddStringToObject(drv, "service_name", WideToUtf8(service).c_str());
        cJSON_AddStringToObject(drv, "image_path",   WideToUtf8(imagePath.c_str()).c_str());

        if (!imagePath.empty())
        {
            cJSON_AddStringToObject(drv, "publisher",
                GetFilePublisherW(imagePath).c_str());
            cJSON_AddStringToObject(drv, "modify_time",
                GetDrvModifyTime(imagePath.c_str()).c_str());
            cJSON_AddStringToObject(drv, "trust_status",
                VerifyAuthenticode(imagePath).c_str());
        }

        std::string descStr  = WideToUtf8(devDesc);
        std::string classStr = WideToUtf8(className);
        cJSON_AddStringToObject(drv, "device_type",
            IsVirtualDevice(descStr, classStr) ? "Virtual" : "Physical");

        ULONG devStatus = 0, problem = 0;
        CM_Get_DevNode_Status(&devStatus, &problem, devData.DevInst, 0);
        cJSON_AddBoolToObject(drv, "is_present",   (devStatus & DN_STARTED) ? 1 : 0);
        cJSON_AddNumberToObject(drv, "problem_code",(double)problem);

        cJSON_AddItemToArray(driversArr, drv);
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);

    cJSON_AddItemToObject(root, "drivers", driversArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}

/*
 * SaveDriverInfo — 采集驱动信息并字段级存入 SQLite3
 * 参数 JSON: { "db_path": "C:\\basic.db" }
 * 返回 JSON: { "snapshot_id": N, "rows_inserted": N, "status": "success" }
 */
extern "C" __declspec(dllexport)
char* SaveDriverInfo(const char* paramsJson)
{
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "module", "saveDriverInfo");

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

    char* jsonStr = GetDriverInfo(paramsJson);
    if (!jsonStr)
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", "GetDriverInfo failed");
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

    long long snapId = db.SaveDriverInfo(jsonStr);
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

