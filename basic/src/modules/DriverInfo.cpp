/*
 * 模块：驱动信息
 * 指标：实体硬件、虚拟硬件、发行商、修改时间、映像路径、授信状态
 */
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#include <vector>
#include "../../third_party/cJSON/cJSON.h"
#include "../common/Utils.h"

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "version.lib")

static std::string VerifyTrust(const wchar_t* path)
{
    if (!path || !path[0]) return "Unknown";
    WINTRUST_FILE_INFO fi = {0};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = path;
    GUID pg = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA td = {0};
    td.cbStruct = sizeof(td);
    td.dwUIChoice = WTD_UI_NONE;
    td.fdwRevocationChecks = WTD_REVOKE_NONE;
    td.dwUnionChoice = WTD_CHOICE_FILE;
    td.pFile = &fi;
    td.dwStateAction = WTD_STATEACTION_VERIFY;
    td.dwProvFlags = WTD_SAFER_FLAG;
    LONG r = WinVerifyTrust(NULL, &pg, &td);
    td.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &pg, &td);
    switch (r)
    {
    case ERROR_SUCCESS:               return "Trusted";
    case TRUST_E_NOSIGNATURE:         return "Unsigned";
    case TRUST_E_EXPLICIT_DISTRUST:   return "Distrust";
    case TRUST_E_SUBJECT_NOT_TRUSTED: return "NotTrusted";
    default:
        char buf[32];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Unknown(0x%08X)", (unsigned)r);
        return buf;
    }
}

static std::string GetPublisher(const wchar_t* path)
{
    if (!path || !path[0]) return "";
    DWORD dummy = 0;
    DWORD sz = GetFileVersionInfoSizeW(path, &dummy);
    if (!sz) return "";
    std::vector<BYTE> buf(sz);
    if (!GetFileVersionInfoW(path, 0, sz, buf.data())) return "";
    struct LC { WORD lang; WORD cp; };
    LC* lc = NULL; UINT lcsz = 0;
    if (!VerQueryValueW(buf.data(), L"\\VarFileInfo\\Translation",
        (LPVOID*)&lc, &lcsz) || lcsz < sizeof(LC)) return "";
    wchar_t sb[64];
    _snwprintf_s(sb, 64, _TRUNCATE,
        L"\\StringFileInfo\\%04x%04x\\CompanyName", lc[0].lang, lc[0].cp);
    wchar_t* co = NULL; UINT cos = 0;
    if (VerQueryValueW(buf.data(), sb, (LPVOID*)&co, &cos) && co)
        return WideToUtf8(co);
    return "";
}

static std::string GetModifyTime(const wchar_t* path)
{
    if (!path || !path[0]) return "";
    WIN32_FILE_ATTRIBUTE_DATA fad = {0};
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return "";
    return FileTimeToString(fad.ftLastWriteTime);
}

// 判断是否为虚拟设备（通过设备描述或类GUID）
static bool IsVirtualDevice(const std::string& desc, const std::string& className)
{
    // 常见虚拟设备关键字
    static const char* keywords[] = {
        "virtual", "vmware", "virtualbox", "hyper-v", "vbox",
        "loopback", "tap-windows", "ndis", "miniport", NULL
    };
    std::string lower = desc;
    for (auto& c : lower) c = (char)tolower((unsigned char)c);
    std::string lowerClass = className;
    for (auto& c : lowerClass) c = (char)tolower((unsigned char)c);

    for (int i = 0; keywords[i]; i++)
    {
        if (lower.find(keywords[i]) != std::string::npos ||
            lowerClass.find(keywords[i]) != std::string::npos)
            return true;
    }
    return false;
}

extern "C" __declspec(dllexport)
char* GetDriverInfo(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "driver_info");

    cJSON* driversArr = cJSON_CreateArray();

    // 枚举所有设备（含驱动）
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

        // 设备描述
        wchar_t devDesc[512] = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_DEVICEDESC, NULL, (PBYTE)devDesc, sizeof(devDesc), NULL);
        cJSON_AddStringToObject(drv, "device_description",
            WideToUtf8(devDesc).c_str());

        // 设备类名
        wchar_t className[256] = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_CLASS, NULL, (PBYTE)className, sizeof(className), NULL);
        cJSON_AddStringToObject(drv, "class_name",
            WideToUtf8(className).c_str());

        // 硬件ID
        wchar_t hwId[1024] = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_HARDWAREID, NULL, (PBYTE)hwId, sizeof(hwId), NULL);
        cJSON_AddStringToObject(drv, "hardware_id",
            WideToUtf8(hwId).c_str());

        // 制造商
        wchar_t mfg[256] = {0};
        SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData,
            SPDRP_MFG, NULL, (PBYTE)mfg, sizeof(mfg), NULL);
        cJSON_AddStringToObject(drv, "manufacturer",
            WideToUtf8(mfg).c_str());

        // 驱动版本信息（通过SP_DRVINFO_DATA）
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
                // 驱动日期
                SYSTEMTIME st = {0};
                FileTimeToSystemTime(&drvInfoData.DriverDate, &st);
                char dateBuf[32];
                _snprintf_s(dateBuf, sizeof(dateBuf), _TRUNCATE,
                    "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
                cJSON_AddStringToObject(drv, "driver_date", dateBuf);
            }
            SetupDiDestroyDriverInfoList(hDevInfo, &devData, SPDIT_COMPATDRIVER);
        }

        // 驱动映像路径（SERVICE注册表）
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
                    imagePath = imgBuf;
                    // 展开环境变量
                    wchar_t expanded[1024] = {0};
                    ExpandEnvironmentStringsW(imagePath.c_str(), expanded, 1024);
                    imagePath = expanded;
                }
                RegCloseKey(hSvc);
            }
        }

        cJSON_AddStringToObject(drv, "service_name",
            WideToUtf8(service).c_str());
        cJSON_AddStringToObject(drv, "image_path",
            WideToUtf8(imagePath.c_str()).c_str());

        // 发行商、修改时间、授信状态
        if (!imagePath.empty())
        {
            cJSON_AddStringToObject(drv, "publisher",
                GetPublisher(imagePath.c_str()).c_str());
            cJSON_AddStringToObject(drv, "modify_time",
                GetModifyTime(imagePath.c_str()).c_str());
            cJSON_AddStringToObject(drv, "trust_status",
                VerifyTrust(imagePath.c_str()).c_str());
        }

        // 判断实体/虚拟
        std::string descStr = WideToUtf8(devDesc);
        std::string classStr = WideToUtf8(className);
        cJSON_AddStringToObject(drv, "device_type",
            IsVirtualDevice(descStr, classStr) ? "Virtual" : "Physical");

        // 设备状态
        ULONG status2 = 0, problem = 0;
        CM_Get_DevNode_Status(&status2, &problem, devData.DevInst, 0);
        cJSON_AddBoolToObject(drv, "is_present",
            (status2 & DN_STARTED) ? 1 : 0);
        cJSON_AddNumberToObject(drv, "problem_code", (double)problem);

        cJSON_AddItemToArray(driversArr, drv);
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);

    cJSON_AddItemToObject(root, "drivers", driversArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}
