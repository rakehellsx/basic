/*
 * Module: Disk Information
 * Fields: physical disks (vendor, model, serial, capacity, SMART),
 *         logical volumes (including hidden partitions, EFI, Recovery)
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <setupapi.h>
#include <devguid.h>
#include <string>
#include <vector>
#include "../common/Utils.h"
#include "../common/DbStorage.h"

#pragma comment(lib, "setupapi.lib")

/* =======================================================================
 * Physical Disks
 * ======================================================================= */

static bool GetDiskGeometry(HANDLE hDisk, DISK_GEOMETRY_EX& geo)
{
    DWORD bytesReturned = 0;
    return DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        NULL, 0, &geo, sizeof(geo), &bytesReturned, NULL) != FALSE;
}

static void GetSmartAttributes(HANDLE hDisk, cJSON* diskObj)
{
#pragma pack(push, 1)
    struct SENDCMDINPARAMS {
        DWORD cBufferSize;
        struct { DWORD bDriveNumber; BYTE bIDEDeviceMap; BYTE bCommandReg; BYTE bFeaturesReg; BYTE bSectorCountReg; BYTE bSectorNumberReg; BYTE bCylLowReg; BYTE bCylHighReg; BYTE bDriveHeadReg; } irDriveRegs;
        BYTE bDriveNumber;
        BYTE bReserved[3];
        DWORD dwReserved[4];
        BYTE bBuffer[1];
    };
    struct ATTRIBUTEDATA { BYTE id; WORD flags; BYTE current; BYTE worst; BYTE raw[6]; BYTE reserved; };
    struct SMARTDATA { WORD version; WORD reserved; ATTRIBUTEDATA attr[30]; };
    struct SENDCMDOUTPARAMS { DWORD cBufferSize; struct { BYTE bDriverError; BYTE bIDEError; BYTE bReserved[2]; DWORD dwReserved[2]; } DriverStatus; BYTE bBuffer[1]; };
#pragma pack(pop)

    const DWORD MY_SMART_RCV_DRIVE_DATA = 0x0007C088;
    const BYTE MY_SMART_CMD = 0xB0;
    const BYTE MY_READ_ATTRIBUTES = 0xD0;

    SENDCMDINPARAMS inParams = {0};
    inParams.cBufferSize = 512;
    inParams.irDriveRegs.bFeaturesReg = MY_READ_ATTRIBUTES;
    inParams.irDriveRegs.bSectorCountReg = 1;
    inParams.irDriveRegs.bSectorNumberReg = 1;
    inParams.irDriveRegs.bCylLowReg = 0x4F;
    inParams.irDriveRegs.bCylHighReg = 0xC2;
    inParams.irDriveRegs.bDriveHeadReg = 0xA0;
    inParams.irDriveRegs.bCommandReg = MY_SMART_CMD;

    DWORD outSize = sizeof(SENDCMDOUTPARAMS) - 1 + 512;
    BYTE* outBuf = (BYTE*)malloc(outSize);
    if (!outBuf) return;
    memset(outBuf, 0, outSize);

    DWORD bytesReturned = 0;
    if (DeviceIoControl(hDisk, MY_SMART_RCV_DRIVE_DATA,
        &inParams, sizeof(inParams),
        outBuf, outSize, &bytesReturned, NULL))
    {
        SENDCMDOUTPARAMS* pOut = (SENDCMDOUTPARAMS*)outBuf;
        SMARTDATA* smart = (SMARTDATA*)(pOut->bBuffer);
        for (int i = 0; i < 30; i++)
        {
            ATTRIBUTEDATA& a = smart->attr[i];
            if (a.id == 0) continue;
            /* 0x09 = Power-On Hours */
            if (a.id == 0x09)
            {
                DWORD hours = a.raw[0] | ((DWORD)a.raw[1] << 8) | ((DWORD)a.raw[2] << 16);
                cJSON_AddNumberToObject(diskObj, "power_on_hours", (double)hours);
            }
            /* 0x0C = Power Cycle Count */
            if (a.id == 0x0C)
            {
                DWORD cycles = a.raw[0] | ((DWORD)a.raw[1] << 8) | ((DWORD)a.raw[2] << 16);
                cJSON_AddNumberToObject(diskObj, "power_cycle_count", (double)cycles);
            }
        }
    }
    free(outBuf);
}

static void GetStorageProperty(HANDLE hDisk, cJSON* diskObj)
{
    STORAGE_PROPERTY_QUERY query = {0};
    query.PropertyId = StorageDeviceProperty;
    query.QueryType = PropertyStandardQuery;

    BYTE buf[1024] = {0};
    DWORD bytesReturned = 0;
    if (!DeviceIoControl(hDisk, IOCTL_STORAGE_QUERY_PROPERTY,
        &query, sizeof(query), buf, sizeof(buf), &bytesReturned, NULL))
        return;

    STORAGE_DEVICE_DESCRIPTOR* desc = (STORAGE_DEVICE_DESCRIPTOR*)buf;
    if (desc->VendorIdOffset && desc->VendorIdOffset < bytesReturned)
        cJSON_AddStringToObject(diskObj, "vendor",
            AnsiToUtf8((char*)buf + desc->VendorIdOffset).c_str());
    if (desc->ProductIdOffset && desc->ProductIdOffset < bytesReturned)
        cJSON_AddStringToObject(diskObj, "model",
            AnsiToUtf8((char*)buf + desc->ProductIdOffset).c_str());
    if (desc->ProductRevisionOffset && desc->ProductRevisionOffset < bytesReturned)
        cJSON_AddStringToObject(diskObj, "firmware_revision",
            AnsiToUtf8((char*)buf + desc->ProductRevisionOffset).c_str());
    if (desc->SerialNumberOffset && desc->SerialNumberOffset < bytesReturned)
        cJSON_AddStringToObject(diskObj, "serial_number",
            AnsiToUtf8((char*)buf + desc->SerialNumberOffset).c_str());

    const char* busType = "Unknown";
    switch (desc->BusType)
    {
    case BusTypeScsi:    busType = "SCSI"; break;
    case BusTypeAtapi:   busType = "ATAPI"; break;
    case BusTypeAta:     busType = "ATA"; break;
    case BusType1394:    busType = "IEEE1394"; break;
    case BusTypeSsa:     busType = "SSA"; break;
    case BusTypeFibre:   busType = "Fibre"; break;
    case BusTypeUsb:     busType = "USB"; break;
    case BusTypeRAID:    busType = "RAID"; break;
    case BusTypeiScsi:   busType = "iSCSI"; break;
    case BusTypeSas:     busType = "SAS"; break;
    case BusTypeSata:    busType = "SATA"; break;
    case BusTypeSd:      busType = "SD"; break;
    case BusTypeMmc:     busType = "MMC"; break;
    case BusTypeNvme:    busType = "NVMe"; break;
    default: break;
    }
    cJSON_AddStringToObject(diskObj, "bus_type", busType);
    cJSON_AddBoolToObject(diskObj, "removable_media", desc->RemovableMedia ? 1 : 0);
}

/* =======================================================================
 * Logical Volumes (including hidden partitions via FindFirstVolumeW)
 * ======================================================================= */

static void EnumAllVolumes(cJSON* volumesArr)
{
    wchar_t volName[MAX_PATH] = {0};
    HANDLE hVol = FindFirstVolumeW(volName, MAX_PATH);
    if (hVol == INVALID_HANDLE_VALUE) return;

    do
    {
        /* volName looks like: \\?\Volume{GUID}\ */
        size_t len = wcslen(volName);
        if (len > 0 && volName[len - 1] == L'\\')
            volName[len - 1] = L'\0'; /* Remove trailing slash for DeviceIoControl */

        cJSON* volObj = cJSON_CreateObject();
        cJSON_AddStringToObject(volObj, "volume_guid", WstrToUtf8(volName).c_str());

        /* Find Drive Letters mapped to this volume */
        DWORD chNeeded = 0;
        GetVolumePathNamesForVolumeNameW(volName, NULL, 0, &chNeeded);
        std::wstring driveLetters;
        if (chNeeded > 0)
        {
            wchar_t* paths = (wchar_t*)malloc(chNeeded * sizeof(wchar_t));
            if (paths && GetVolumePathNamesForVolumeNameW(volName, paths, chNeeded, &chNeeded))
            {
                for (wchar_t* p = paths; *p; p += wcslen(p) + 1)
                {
                    if (!driveLetters.empty()) driveLetters += L";";
                    driveLetters += p;
                }
            }
            if (paths) free(paths);
        }
        cJSON_AddStringToObject(volObj, "drive_letter", WstrToUtf8(driveLetters).c_str());

        /* Re-add trailing slash for GetVolumeInformation / GetDiskFreeSpace */
        volName[len - 1] = L'\\';

        UINT driveType = GetDriveTypeW(volName);
        const char* typeStr = "Unknown";
        switch (driveType)
        {
        case DRIVE_REMOVABLE: typeStr = "Removable"; break;
        case DRIVE_FIXED:     typeStr = "Fixed"; break;
        case DRIVE_REMOTE:    typeStr = "Network"; break;
        case DRIVE_CDROM:     typeStr = "CDROM"; break;
        case DRIVE_RAMDISK:   typeStr = "RAMDisk"; break;
        }
        cJSON_AddStringToObject(volObj, "drive_type", typeStr);

        wchar_t vName[MAX_PATH] = {0}, fsName[MAX_PATH] = {0};
        DWORD serialNum = 0, maxComp = 0, fsFlags = 0;
        if (GetVolumeInformationW(volName, vName, MAX_PATH, &serialNum,
            &maxComp, &fsFlags, fsName, MAX_PATH))
        {
            cJSON_AddStringToObject(volObj, "volume_name", WstrToUtf8(vName).c_str());
            cJSON_AddStringToObject(volObj, "file_system", WstrToUtf8(fsName).c_str());
            char snStr[32];
            _snprintf_s(snStr, sizeof(snStr), _TRUNCATE, "%08X", serialNum);
            cJSON_AddStringToObject(volObj, "serial_number", snStr);
        }
        else
        {
            /* Might be hidden/unformatted */
            cJSON_AddStringToObject(volObj, "volume_name", "");
            cJSON_AddStringToObject(volObj, "file_system", "");
            cJSON_AddStringToObject(volObj, "serial_number", "");
        }

        ULARGE_INTEGER freeBytesAvail = {0}, totalBytes = {0}, totalFree = {0};
        if (GetDiskFreeSpaceExW(volName, &freeBytesAvail, &totalBytes, &totalFree))
        {
            cJSON_AddStringToObject(volObj, "total_bytes", LargeIntToString(totalBytes.QuadPart).c_str());
            cJSON_AddStringToObject(volObj, "free_bytes",  LargeIntToString(totalFree.QuadPart).c_str());
        }
        else
        {
            cJSON_AddStringToObject(volObj, "total_bytes", "0");
            cJSON_AddStringToObject(volObj, "free_bytes",  "0");
        }

        cJSON_AddItemToArray(volumesArr, volObj);

        /* Restore string for next FindNextVolumeW */
        volName[len - 1] = L'\\';

    } while (FindNextVolumeW(hVol, volName, MAX_PATH));

    FindVolumeClose(hVol);
}

extern "C" __declspec(dllexport)
char* GetDiskInfo(const char* /*paramsJson*/)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "disk_info");

    cJSON* physicalArr = cJSON_CreateArray();

    for (int i = 0; i < 16; i++)
    {
        wchar_t drivePath[32];
        _snwprintf_s(drivePath, 32, _TRUNCATE, L"\\\\.\\PhysicalDrive%d", i);

        HANDLE hDisk = CreateFileW(drivePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);

        if (hDisk == INVALID_HANDLE_VALUE)
        {
            /* Try read-only */
            hDisk = CreateFileW(drivePath,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, 0, NULL);
            if (hDisk == INVALID_HANDLE_VALUE) break;
        }

        cJSON* disk = cJSON_CreateObject();
        char diskName[32];
        _snprintf_s(diskName, sizeof(diskName), _TRUNCATE, "PhysicalDrive%d", i);
        cJSON_AddStringToObject(disk, "device_id", diskName);

        /* Vendor, Model, Serial */
        GetStorageProperty(hDisk, disk);

        /* Capacity */
        DISK_GEOMETRY_EX geo = {0};
        if (GetDiskGeometry(hDisk, geo))
        {
            cJSON_AddStringToObject(disk, "total_bytes",
                LargeIntToString((ULONGLONG)geo.DiskSize.QuadPart).c_str());
        }

        /* SMART (PowerOnHours, PowerCycleCount) */
        GetSmartAttributes(hDisk, disk);

        CloseHandle(hDisk);
        cJSON_AddItemToArray(physicalArr, disk);
    }

    cJSON* logicalArr = cJSON_CreateArray();
    EnumAllVolumes(logicalArr);

    cJSON_AddItemToObject(root, "physical_disks", physicalArr);
    cJSON_AddItemToObject(root, "logical_volumes", logicalArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}

/*
 * SaveDiskInfo - collect and store into SQLite3
 * Input JSON:  { "db_path": "C:\\basic.db" }
 * Output JSON: { "snapshot_id": N, "status": "success" }
 */
extern "C" __declspec(dllexport)
char* SaveDiskInfo(const char* paramsJson)
{
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "module", "saveDiskInfo");

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

    char* jsonStr = GetDiskInfo(paramsJson);
    if (!jsonStr)
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", "GetDiskInfo failed");
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

    long long snapId = db.SaveDiskInfo(jsonStr);
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
