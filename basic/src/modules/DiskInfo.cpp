/*
 * 模块：硬盘信息
 * 指标：厂商、型号、序列号、总容量、分区(含隐藏分区)详情、启动次数、累计使用时间
 */
#include <windows.h>
#include <winioctl.h>
#include <setupapi.h>
#include <devguid.h>
#include <string>
#include <vector>
#include "../../third_party/cJSON/cJSON.h"
#include "../common/Utils.h"

#pragma comment(lib, "setupapi.lib")

// 通过 DeviceIoControl 获取磁盘几何信息
static bool GetDiskGeometry(HANDLE hDisk, DISK_GEOMETRY_EX& geo)
{
    DWORD bytesReturned = 0;
    return DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
        NULL, 0, &geo, sizeof(geo), &bytesReturned, NULL) != FALSE;
}

// 获取磁盘分区布局（含隐藏分区）
static cJSON* GetPartitionLayout(HANDLE hDisk)
{
    cJSON* partArr = cJSON_CreateArray();
    DWORD outSize = sizeof(DRIVE_LAYOUT_INFORMATION_EX) + 128 * sizeof(PARTITION_INFORMATION_EX);
    BYTE* buf = (BYTE*)malloc(outSize);
    if (!buf) return partArr;

    DWORD bytesReturned = 0;
    if (DeviceIoControl(hDisk, IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        NULL, 0, buf, outSize, &bytesReturned, NULL))
    {
        DRIVE_LAYOUT_INFORMATION_EX* layout = (DRIVE_LAYOUT_INFORMATION_EX*)buf;
        const char* partStyle = "Unknown";
        if (layout->PartitionStyle == PARTITION_STYLE_MBR) partStyle = "MBR";
        else if (layout->PartitionStyle == PARTITION_STYLE_GPT) partStyle = "GPT";

        for (DWORD i = 0; i < layout->PartitionCount; i++)
        {
            PARTITION_INFORMATION_EX& p = layout->PartitionEntry[i];
            // 过滤掉大小为0的条目
            if (p.PartitionLength.QuadPart == 0) continue;

            cJSON* part = cJSON_CreateObject();
            cJSON_AddNumberToObject(part, "partition_number", (double)p.PartitionNumber);
            cJSON_AddStringToObject(part, "partition_style", partStyle);
            cJSON_AddStringToObject(part, "starting_offset",
                LargeIntToString((ULONGLONG)p.StartingOffset.QuadPart).c_str());
            cJSON_AddStringToObject(part, "partition_length",
                LargeIntToString((ULONGLONG)p.PartitionLength.QuadPart).c_str());
            cJSON_AddBoolToObject(part, "rewrite_partition", p.RewritePartition ? 1 : 0);

            if (layout->PartitionStyle == PARTITION_STYLE_MBR)
            {
                char typeStr[8];
                _snprintf_s(typeStr, sizeof(typeStr), _TRUNCATE, "0x%02X",
                    p.Mbr.PartitionType);
                cJSON_AddStringToObject(part, "mbr_partition_type", typeStr);
                cJSON_AddBoolToObject(part, "mbr_bootable", p.Mbr.BootIndicator ? 1 : 0);
                // 隐藏分区：类型为0x12, 0x1B, 0x1C, 0x27等
                bool hidden = (p.Mbr.PartitionType == 0x12 ||
                               p.Mbr.PartitionType == 0x1B ||
                               p.Mbr.PartitionType == 0x1C ||
                               p.Mbr.PartitionType == 0x27 ||
                               p.Mbr.PartitionType == 0xDE ||
                               p.Mbr.PartitionType == 0xFE);
                cJSON_AddBoolToObject(part, "is_hidden", hidden ? 1 : 0);
            }
            else if (layout->PartitionStyle == PARTITION_STYLE_GPT)
            {
                // GPT GUID
                wchar_t guidStr[64] = {0};
                StringFromGUID2(p.Gpt.PartitionType, guidStr, 64);
                cJSON_AddStringToObject(part, "gpt_partition_type",
                    WideToUtf8(guidStr).c_str());
                cJSON_AddStringToObject(part, "gpt_partition_name",
                    WideToUtf8(p.Gpt.Name).c_str());
                // GPT隐藏分区：属性位2（PARTITION_ATTRIBUTE_NO_DRIVE_LETTER）
                bool hidden = (p.Gpt.Attributes & 0x4) != 0;
                cJSON_AddBoolToObject(part, "is_hidden", hidden ? 1 : 0);
            }

            cJSON_AddItemToArray(partArr, part);
        }
    }
    free(buf);
    return partArr;
}

// 获取SMART属性（启动次数=0x0C，累计使用时间=0x09）
static void GetSmartAttributes(HANDLE hDisk, cJSON* diskObj)
{
    // SMART命令结构
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

    const DWORD SMART_RCV_DRIVE_DATA = 0x0007C088;
    const BYTE SMART_CMD = 0xB0;
    const BYTE READ_ATTRIBUTES = 0xD0;

    SENDCMDINPARAMS inParams = {0};
    inParams.cBufferSize = 512;
    inParams.irDriveRegs.bFeaturesReg = READ_ATTRIBUTES;
    inParams.irDriveRegs.bSectorCountReg = 1;
    inParams.irDriveRegs.bSectorNumberReg = 1;
    inParams.irDriveRegs.bCylLowReg = 0x4F;
    inParams.irDriveRegs.bCylHighReg = 0xC2;
    inParams.irDriveRegs.bDriveHeadReg = 0xA0;
    inParams.irDriveRegs.bCommandReg = SMART_CMD;

    DWORD outSize = sizeof(SENDCMDOUTPARAMS) - 1 + 512;
    BYTE* outBuf = (BYTE*)malloc(outSize);
    if (!outBuf) return;
    memset(outBuf, 0, outSize);

    DWORD bytesReturned = 0;
    if (DeviceIoControl(hDisk, SMART_RCV_DRIVE_DATA,
        &inParams, sizeof(inParams),
        outBuf, outSize, &bytesReturned, NULL))
    {
        SENDCMDOUTPARAMS* pOut = (SENDCMDOUTPARAMS*)outBuf;
        SMARTDATA* smart = (SMARTDATA*)(pOut->bBuffer);
        for (int i = 0; i < 30; i++)
        {
            ATTRIBUTEDATA& a = smart->attr[i];
            if (a.id == 0) continue;
            // 0x09 = Power-On Hours (累计使用时间)
            if (a.id == 0x09)
            {
                DWORD hours = a.raw[0] | ((DWORD)a.raw[1] << 8) | ((DWORD)a.raw[2] << 16);
                cJSON_AddNumberToObject(diskObj, "power_on_hours", (double)hours);
            }
            // 0x0C = Power Cycle Count (启动次数)
            if (a.id == 0x0C)
            {
                DWORD cycles = a.raw[0] | ((DWORD)a.raw[1] << 8) | ((DWORD)a.raw[2] << 16);
                cJSON_AddNumberToObject(diskObj, "power_cycle_count", (double)cycles);
            }
        }
    }
    free(outBuf);
}

// 通过IOCTL_STORAGE_QUERY_PROPERTY获取磁盘属性
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

extern "C" __declspec(dllexport)
char* GetDiskInfo(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "disk_info");

    cJSON* disksArr = cJSON_CreateArray();

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
            // 尝试只读
            hDisk = CreateFileW(drivePath,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                NULL, OPEN_EXISTING, 0, NULL);
            if (hDisk == INVALID_HANDLE_VALUE) break;
        }

        cJSON* disk = cJSON_CreateObject();
        char diskName[32];
        _snprintf_s(diskName, sizeof(diskName), _TRUNCATE, "PhysicalDrive%d", i);
        cJSON_AddStringToObject(disk, "device", diskName);

        // 存储属性（厂商、型号、序列号）
        GetStorageProperty(hDisk, disk);

        // 磁盘几何（总容量）
        DISK_GEOMETRY_EX geo = {0};
        if (GetDiskGeometry(hDisk, geo))
        {
            cJSON_AddStringToObject(disk, "total_size",
                LargeIntToString((ULONGLONG)geo.DiskSize.QuadPart).c_str());
            cJSON_AddNumberToObject(disk, "bytes_per_sector",
                (double)geo.Geometry.BytesPerSector);
        }

        // SMART属性（启动次数、累计使用时间）
        GetSmartAttributes(hDisk, disk);

        // 分区信息（含隐藏分区）
        cJSON_AddItemToObject(disk, "partitions", GetPartitionLayout(hDisk));

        CloseHandle(hDisk);
        cJSON_AddItemToArray(disksArr, disk);
    }

    // 逻辑驱动器信息
    cJSON* logicalArr = cJSON_CreateArray();
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; i++)
    {
        if (!(drives & (1 << i))) continue;
        wchar_t root[8];
        _snwprintf_s(root, 8, _TRUNCATE, L"%c:\\", L'A' + i);
        UINT driveType = GetDriveTypeW(root);
        if (driveType == DRIVE_NO_ROOT_DIR) continue;

        cJSON* lDisk = cJSON_CreateObject();
        char letter[4];
        _snprintf_s(letter, sizeof(letter), _TRUNCATE, "%c:", 'A' + i);
        cJSON_AddStringToObject(lDisk, "drive_letter", letter);

        const char* typeStr = "Unknown";
        switch (driveType)
        {
        case DRIVE_REMOVABLE: typeStr = "Removable"; break;
        case DRIVE_FIXED:     typeStr = "Fixed"; break;
        case DRIVE_REMOTE:    typeStr = "Network"; break;
        case DRIVE_CDROM:     typeStr = "CDROM"; break;
        case DRIVE_RAMDISK:   typeStr = "RAMDisk"; break;
        }
        cJSON_AddStringToObject(lDisk, "drive_type", typeStr);

        wchar_t volName[256] = {0}, fsName[64] = {0};
        DWORD serialNum = 0, maxComp = 0, fsFlags = 0;
        if (GetVolumeInformationW(root, volName, 256, &serialNum,
            &maxComp, &fsFlags, fsName, 64))
        {
            cJSON_AddStringToObject(lDisk, "volume_name", WideToUtf8(volName).c_str());
            cJSON_AddStringToObject(lDisk, "file_system", WideToUtf8(fsName).c_str());
            char snStr[16];
            _snprintf_s(snStr, sizeof(snStr), _TRUNCATE, "%08X", serialNum);
            cJSON_AddStringToObject(lDisk, "volume_serial", snStr);
        }

        ULARGE_INTEGER freeBytesAvail = {0}, totalBytes = {0}, totalFree = {0};
        if (GetDiskFreeSpaceExW(root, &freeBytesAvail, &totalBytes, &totalFree))
        {
            cJSON_AddStringToObject(lDisk, "total_bytes",
                LargeIntToString(totalBytes.QuadPart).c_str());
            cJSON_AddStringToObject(lDisk, "free_bytes",
                LargeIntToString(totalFree.QuadPart).c_str());
        }

        cJSON_AddItemToArray(logicalArr, lDisk);
    }

    cJSON_AddItemToObject(root, "physical_disks", disksArr);
    cJSON_AddItemToObject(root, "logical_drives", logicalArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}
