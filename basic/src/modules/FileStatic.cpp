/*
 * FileStatic.cpp
 * 文件静态信息获取模块
 *
 * 功能：
 *   1. 基础文件属性（时间戳、发行商、MD5/SHA256，文件类型复用 FileFormat::AnalyzeFile）
 *   2. PE 结构解析（PE头、节区信息含熵值、导入表含风险评级）
 *   3. 可打印字符串提取（写入独立 .txt 文件，SQLite3 只存文件路径）
 *
 * 导出接口：
 *   GetFileStaticInfo(paramsJson)  — 分析单个文件，返回 JSON
 *   SaveFileStaticInfo(paramsJson) — 分析并存入 SQLite3，返回 JSON
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <wincrypt.h>
#include <imagehlp.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

#include "../common/Utils.h"
#include "FileStatic.h"
#include "FileFormat.h"
#include "../../third_party/sqlite3/sqlite3.h"
#include "../../include/basic.h"

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "version.lib")

/* ===================================================================
 * 内部工具函数
 * =================================================================== */

/* 将 FILETIME 转为 UTC 字符串 */
static std::string FileTimeToUtcStr(const FILETIME& ft)
{
    SYSTEMTIME st = {0};
    FileTimeToSystemTime(&ft, &st);
    char buf[64];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%04d-%02d-%02d %02d:%02d:%02d UTC",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

/* 将 time_t（PE编译时间戳）转为 UTC 字符串 */
static std::string TimeTToUtcStr(DWORD t)
{
    if (t == 0) return "";
    time_t tt = (time_t)t;
    struct tm* gmt = gmtime(&tt);
    if (!gmt) return "";
    char buf[64];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "%04d-%02d-%02d %02d:%02d:%02d UTC",
        gmt->tm_year + 1900, gmt->tm_mon + 1, gmt->tm_mday,
        gmt->tm_hour, gmt->tm_min, gmt->tm_sec);
    return std::string(buf);
}

/* 计算文件 MD5 */
static std::string CalcFileMD5(const std::wstring& pathW)
{
    HANDLE hFile = CreateFileW(pathW.c_str(), GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL,
            CRYPT_VERIFYCONTEXT))
    {
        CloseHandle(hFile);
        return "";
    }
    if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return "";
    }

    BYTE buf[65536];
    DWORD read = 0;
    while (ReadFile(hFile, buf, sizeof(buf), &read, NULL) && read > 0)
        CryptHashData(hHash, buf, read, 0);

    BYTE hash[16];
    DWORD hashLen = 16;
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
    {
        char hex[33];
        for (int i = 0; i < 16; i++)
            _snprintf_s(hex + i * 2, 3, _TRUNCATE, "%02x", hash[i]);
        hex[32] = 0;
        result = hex;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return result;
}

/* 计算文件 SHA-256 */
static std::string CalcFileSHA256(const std::wstring& pathW)
{
    HANDLE hFile = CreateFileW(pathW.c_str(), GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return "";

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT))
    {
        CloseHandle(hFile);
        return "";
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return "";
    }

    BYTE buf[65536];
    DWORD read = 0;
    while (ReadFile(hFile, buf, sizeof(buf), &read, NULL) && read > 0)
        CryptHashData(hHash, buf, read, 0);

    BYTE hash[32];
    DWORD hashLen = 32;
    if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
    {
        char hex[65];
        for (int i = 0; i < 32; i++)
            _snprintf_s(hex + i * 2, 3, _TRUNCATE, "%02x", hash[i]);
        hex[64] = 0;
        result = hex;
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return result;
}

/* 获取版本资源字段（CompanyName / FileVersion 等） */
static std::string GetVersionField(const std::wstring& pathW,
                                   const wchar_t* field)
{
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeW(pathW.c_str(), &dummy);
    if (size == 0) return "";

    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(pathW.c_str(), 0, size, &data[0]))
        return "";

    struct LANGANDCODEPAGE { WORD lang; WORD codepage; };
    LANGANDCODEPAGE* lpTranslate = NULL;
    UINT cbTranslate = 0;
    if (!VerQueryValueW(&data[0], L"\\VarFileInfo\\Translation",
            (LPVOID*)&lpTranslate, &cbTranslate))
        return "";

    UINT count = cbTranslate / sizeof(LANGANDCODEPAGE);
    for (UINT i = 0; i < count; i++)
    {
        wchar_t subBlock[256];
        _snwprintf_s(subBlock, 256, _TRUNCATE,
            L"\\StringFileInfo\\%04x%04x\\%s",
            lpTranslate[i].lang, lpTranslate[i].codepage, field);

        LPVOID lpBuffer = NULL;
        UINT cbBuffer = 0;
        if (VerQueryValueW(&data[0], subBlock, &lpBuffer, &cbBuffer)
            && lpBuffer && cbBuffer > 0)
        {
            return WideToUtf8((const wchar_t*)lpBuffer);
        }
    }
    return "";
}

/* ===================================================================
 * PE 解析工具
 * =================================================================== */

/* 计算字节序列的香农熵 */
static double CalcEntropy(const BYTE* data, DWORD size)
{
    if (size == 0) return 0.0;
    DWORD freq[256] = {0};
    for (DWORD i = 0; i < size; i++) freq[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] == 0) continue;
        double p = (double)freq[i] / size;
        entropy -= p * log(p) / log(2.0);
    }
    return entropy;
}

/* 子系统枚举转字符串 */
static std::string SubsystemToStr(WORD sub)
{
    switch (sub)
    {
    case IMAGE_SUBSYSTEM_NATIVE:                  return "Native (Driver)";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:             return "Windows GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:             return "Windows Console";
    case IMAGE_SUBSYSTEM_OS2_CUI:                 return "OS/2 Console";
    case IMAGE_SUBSYSTEM_POSIX_CUI:               return "POSIX Console";
    case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:          return "Windows CE GUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:         return "EFI Application";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return "EFI Boot Driver";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:      return "EFI Runtime Driver";
    case IMAGE_SUBSYSTEM_EFI_ROM:                 return "EFI ROM";
    case IMAGE_SUBSYSTEM_XBOX:                    return "Xbox";
    default:
        char buf[32];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Unknown(%u)", sub);
        return buf;
    }
}

/* 节区特征描述 */
static std::string SectionCharDesc(DWORD ch)
{
    std::string desc;
    if (ch & IMAGE_SCN_MEM_READ)    desc += "R";
    if (ch & IMAGE_SCN_MEM_WRITE)   desc += "W";
    if (ch & IMAGE_SCN_MEM_EXECUTE) desc += "X";
    if (ch & IMAGE_SCN_CNT_CODE)    desc += " | Code";
    if (ch & IMAGE_SCN_CNT_INITIALIZED_DATA)   desc += " | InitData";
    if (ch & IMAGE_SCN_CNT_UNINITIALIZED_DATA) desc += " | UninitData";
    if (desc.empty()) desc = "None";
    return desc;
}

/* 加壳/编译器特征识别（基于节区名和入口点特征） */
static std::string DetectPackerOrCompiler(
    const IMAGE_NT_HEADERS* pNT,
    const IMAGE_SECTION_HEADER* pSec,
    DWORD numSec)
{
    /* 检查节区名特征 */
    for (DWORD i = 0; i < numSec; i++)
    {
        char name[9] = {0};
        memcpy(name, pSec[i].Name, 8);
        if (_stricmp(name, "UPX0") == 0 ||
            _stricmp(name, "UPX1") == 0 ||
            _stricmp(name, "UPX2") == 0)
            return "UPX";
        if (_stricmp(name, ".MPRESS1") == 0 ||
            _stricmp(name, ".MPRESS2") == 0)
            return "MPRESS";
        if (_stricmp(name, ".nsp0") == 0 ||
            _stricmp(name, ".nsp1") == 0)
            return "NsPack";
        if (_stricmp(name, "ASPack") == 0)
            return "ASPack";
        if (_stricmp(name, ".petite") == 0)
            return "Petite";
        if (_stricmp(name, ".themida") == 0 ||
            _stricmp(name, ".winlicen") == 0)
            return "Themida/WinLicense";
        if (_stricmp(name, "Armadillo") == 0)
            return "Armadillo";
        if (_stricmp(name, ".vmp0") == 0 ||
            _stricmp(name, ".vmp1") == 0)
            return "VMProtect";
    }

    /* 根据链接器版本推断编译器 */
    BYTE majVer = pNT->OptionalHeader.MajorLinkerVersion;
    BYTE minVer = pNT->OptionalHeader.MinorLinkerVersion;

    if (majVer == 14 || majVer == 12 || majVer == 11 ||
        majVer == 10 || majVer == 9  || majVer == 8)
        return "MSVC (Visual C++)";
    if (majVer == 2 && minVer == 25)
        return "GCC/MinGW";
    if (majVer == 2 && minVer >= 20)
        return "GCC/MinGW";
    if (majVer == 48)
        return "Borland/Delphi";
    if (majVer == 50 || majVer == 51 || majVer == 52)
        return "Borland C++";
    if (majVer == 6 && minVer == 0)
        return "MSVC 6.0";

    char buf[64];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE,
        "Unknown (Linker %u.%u)", majVer, minVer);
    return buf;
}

/* ===================================================================
 * 高危/中危导入函数表
 * =================================================================== */
struct RiskEntry { const char* func; ImportRisk risk; const char* desc; };

static const RiskEntry g_riskTable[] =
{
    /* 高危：进程注入 / 代码执行 */
    { "VirtualAllocEx",        RISK_HIGH, "远程进程内存分配（进程注入）" },
    { "WriteProcessMemory",    RISK_HIGH, "写入远程进程内存（进程注入）" },
    { "CreateRemoteThread",    RISK_HIGH, "创建远程线程（进程注入）" },
    { "CreateRemoteThreadEx",  RISK_HIGH, "创建远程线程（进程注入）" },
    { "NtCreateThreadEx",      RISK_HIGH, "NT 创建远程线程（进程注入）" },
    { "RtlCreateUserThread",   RISK_HIGH, "创建用户线程（进程注入）" },
    { "SetWindowsHookEx",      RISK_HIGH, "全局钩子注入" },
    { "SetWindowsHookExA",     RISK_HIGH, "全局钩子注入" },
    { "SetWindowsHookExW",     RISK_HIGH, "全局钩子注入" },
    { "QueueUserAPC",          RISK_HIGH, "APC 注入" },
    { "NtQueueApcThread",      RISK_HIGH, "APC 注入（NT）" },
    { "LoadLibraryA",          RISK_HIGH, "加载任意 DLL（DLL 注入）" },
    { "LoadLibraryW",          RISK_HIGH, "加载任意 DLL（DLL 注入）" },
    { "LoadLibraryExA",        RISK_HIGH, "加载任意 DLL（DLL 注入）" },
    { "LoadLibraryExW",        RISK_HIGH, "加载任意 DLL（DLL 注入）" },
    { "ShellExecuteA",         RISK_HIGH, "执行任意程序" },
    { "ShellExecuteW",         RISK_HIGH, "执行任意程序" },
    { "ShellExecuteExA",       RISK_HIGH, "执行任意程序（扩展）" },
    { "ShellExecuteExW",       RISK_HIGH, "执行任意程序（扩展）" },
    { "WinExec",               RISK_HIGH, "执行命令（旧 API）" },
    { "CreateProcessA",        RISK_HIGH, "创建子进程" },
    { "CreateProcessW",        RISK_HIGH, "创建子进程" },
    { "NtUnmapViewOfSection",  RISK_HIGH, "进程空洞化（Process Hollowing）" },
    { "ZwUnmapViewOfSection",  RISK_HIGH, "进程空洞化（Process Hollowing）" },
    { "MapViewOfFile",         RISK_HIGH, "内存映射文件（可用于注入）" },
    { "OpenProcess",           RISK_HIGH, "打开远程进程句柄" },
    { "AdjustTokenPrivileges", RISK_HIGH, "提升进程权限" },
    { "IsDebuggerPresent",     RISK_HIGH, "反调试检测" },
    { "CheckRemoteDebuggerPresent", RISK_HIGH, "反调试检测（远程）" },
    /* 中危：网络通信 */
    { "WSAStartup",            RISK_MEDIUM, "初始化 Winsock（网络通信）" },
    { "connect",               RISK_MEDIUM, "建立 TCP 连接" },
    { "WSAConnect",            RISK_MEDIUM, "建立 TCP 连接（异步）" },
    { "send",                  RISK_MEDIUM, "发送网络数据" },
    { "recv",                  RISK_MEDIUM, "接收网络数据" },
    { "sendto",                RISK_MEDIUM, "发送 UDP 数据" },
    { "recvfrom",              RISK_MEDIUM, "接收 UDP 数据" },
    { "InternetOpenA",         RISK_MEDIUM, "打开 WinInet 会话" },
    { "InternetOpenW",         RISK_MEDIUM, "打开 WinInet 会话" },
    { "InternetConnectA",      RISK_MEDIUM, "连接远程服务器" },
    { "InternetConnectW",      RISK_MEDIUM, "连接远程服务器" },
    { "HttpOpenRequestA",      RISK_MEDIUM, "发起 HTTP 请求" },
    { "HttpOpenRequestW",      RISK_MEDIUM, "发起 HTTP 请求" },
    { "HttpSendRequestA",      RISK_MEDIUM, "发送 HTTP 请求" },
    { "HttpSendRequestW",      RISK_MEDIUM, "发送 HTTP 请求" },
    { "InternetReadFile",      RISK_MEDIUM, "读取远程文件" },
    { "URLDownloadToFileA",    RISK_MEDIUM, "下载远程文件" },
    { "URLDownloadToFileW",    RISK_MEDIUM, "下载远程文件" },
    { "WinHttpOpen",           RISK_MEDIUM, "打开 WinHTTP 会话" },
    { "WinHttpConnect",        RISK_MEDIUM, "连接远程服务器（WinHTTP）" },
    { "WinHttpSendRequest",    RISK_MEDIUM, "发送 HTTP 请求（WinHTTP）" },
    { "gethostbyname",         RISK_MEDIUM, "DNS 解析" },
    { "getaddrinfo",           RISK_MEDIUM, "DNS 解析（新 API）" },
    { NULL, RISK_LOW, NULL }
};

static ImportRisk GetFuncRisk(const char* funcName,
                               std::string& outDesc)
{
    if (!funcName || funcName[0] == 0) return RISK_LOW;
    for (int i = 0; g_riskTable[i].func != NULL; i++)
    {
        if (_stricmp(funcName, g_riskTable[i].func) == 0)
        {
            outDesc = g_riskTable[i].desc;
            return g_riskTable[i].risk;
        }
    }
    return RISK_LOW;
}

/* ===================================================================
 * 核心分析函数
 * =================================================================== */

/* 读取整个文件到内存 */
static std::vector<BYTE> ReadWholeFile(const std::wstring& pathW)
{
    std::vector<BYTE> data;
    HANDLE hFile = CreateFileW(pathW.c_str(), GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return data;

    LARGE_INTEGER sz;
    if (!GetFileSizeEx(hFile, &sz) || sz.QuadPart == 0 ||
        sz.QuadPart > 256 * 1024 * 1024) /* 限制 256 MB */
    {
        CloseHandle(hFile);
        return data;
    }

    data.resize((size_t)sz.QuadPart);
    DWORD read = 0;
    DWORD total = 0;
    while (total < (DWORD)sz.QuadPart)
    {
        if (!ReadFile(hFile, &data[total],
                (DWORD)sz.QuadPart - total, &read, NULL) || read == 0)
            break;
        total += read;
    }
    data.resize(total);
    CloseHandle(hFile);
    return data;
}

/* 分析单个文件，填充 FileStaticResult */
static FileStaticResult AnalyzeFileStatic(
    const std::wstring& pathW,
    const std::string&  strOutputDir)
{
    FileStaticResult res;
    res.pe_header.is_pe = false;

    /* ---------------------------------------------------------------
     * 1. 基础属性
     * ------------------------------------------------------------- */
    res.basic.file_path = WideToUtf8(pathW.c_str());

    /* 文件名 */
    size_t slash = res.basic.file_path.rfind('\\');
    if (slash == std::string::npos)
        slash = res.basic.file_path.rfind('/');
    res.basic.file_name = (slash != std::string::npos)
        ? res.basic.file_path.substr(slash + 1)
        : res.basic.file_path;

    /* 文件大小 */
    WIN32_FILE_ATTRIBUTE_DATA fa;
    if (GetFileAttributesExW(pathW.c_str(), GetFileExInfoStandard, &fa))
    {
        LARGE_INTEGER li;
        li.HighPart = (LONG)fa.nFileSizeHigh;
        li.LowPart  = fa.nFileSizeLow;
        char szBuf[32];
        _snprintf_s(szBuf, sizeof(szBuf), _TRUNCATE,
            "%I64d", li.QuadPart);
        res.basic.file_size   = szBuf;
        res.basic.create_time = FileTimeToUtcStr(fa.ftCreationTime);
        res.basic.modify_time = FileTimeToUtcStr(fa.ftLastWriteTime);
        res.basic.access_time = FileTimeToUtcStr(fa.ftLastAccessTime);
    }
    else
    {
        res.error_msg = "GetFileAttributesEx failed";
        return res;
    }

    /* 版本资源 */
    res.basic.publisher        = GetVersionField(pathW, L"CompanyName");
    res.basic.file_version     = GetVersionField(pathW, L"FileVersion");
    res.basic.product_name     = GetVersionField(pathW, L"ProductName");
    res.basic.original_filename= GetVersionField(pathW, L"OriginalFilename");

    /* 哈希 */
    res.basic.md5    = CalcFileMD5(pathW);
    res.basic.sha256 = CalcFileSHA256(pathW);

    /* 文件类型（复用 FileFormat::AnalyzeFile） */
    FileFormatResult ffr = AnalyzeFile(pathW);
    res.basic.file_type = ffr.detectedFormat;

    /* ---------------------------------------------------------------
     * 2. 读取文件到内存（PE 解析 + 字符串提取共用）
     * ------------------------------------------------------------- */
    std::vector<BYTE> fileData = ReadWholeFile(pathW);
    if (fileData.empty())
    {
        res.error_msg = "Cannot read file content";
        return res;
    }

    const BYTE* pBase = &fileData[0];
    SIZE_T fileSize   = fileData.size();

    /* ---------------------------------------------------------------
     * 3. PE 结构解析
     * ------------------------------------------------------------- */
    if (fileSize >= sizeof(IMAGE_DOS_HEADER))
    {
        const IMAGE_DOS_HEADER* pDOS =
            reinterpret_cast<const IMAGE_DOS_HEADER*>(pBase);

        if (pDOS->e_magic == IMAGE_DOS_SIGNATURE &&
            (SIZE_T)pDOS->e_lfanew + sizeof(IMAGE_NT_HEADERS32) <= fileSize)
        {
            const IMAGE_NT_HEADERS* pNT =
                reinterpret_cast<const IMAGE_NT_HEADERS*>(
                    pBase + pDOS->e_lfanew);

            if (pNT->Signature == IMAGE_NT_SIGNATURE)
            {
                res.pe_header.is_pe = true;
                const IMAGE_FILE_HEADER& fh = pNT->FileHeader;
                const IMAGE_OPTIONAL_HEADER& oh = pNT->OptionalHeader;

                /* 架构 */
                switch (fh.Machine)
                {
                case IMAGE_FILE_MACHINE_I386:   res.pe_header.arch = "x86 (i386)";   break;
                case IMAGE_FILE_MACHINE_AMD64:  res.pe_header.arch = "x64 (AMD64)";  break;
                case IMAGE_FILE_MACHINE_ARM:    res.pe_header.arch = "ARM";           break;
                case IMAGE_FILE_MACHINE_ARM64:  res.pe_header.arch = "ARM64";         break;
                case IMAGE_FILE_MACHINE_IA64:   res.pe_header.arch = "IA-64";         break;
                default:
                    char archBuf[32];
                    _snprintf_s(archBuf, sizeof(archBuf), _TRUNCATE,
                        "Unknown(0x%04X)", fh.Machine);
                    res.pe_header.arch = archBuf;
                    break;
                }

                /* 入口点 / 映像基址 */
                char hexBuf[32];
                _snprintf_s(hexBuf, sizeof(hexBuf), _TRUNCATE,
                    "0x%08X", oh.AddressOfEntryPoint);
                res.pe_header.entry_point = hexBuf;

                if (oh.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                {
                    const IMAGE_OPTIONAL_HEADER64* oh64 =
                        reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(&oh);
                    _snprintf_s(hexBuf, sizeof(hexBuf), _TRUNCATE,
                        "0x%016I64X", oh64->ImageBase);
                    res.pe_header.image_base = hexBuf;
                    res.pe_header.size_of_image   = oh64->SizeOfImage;
                    res.pe_header.size_of_headers = oh64->SizeOfHeaders;
                    res.pe_header.subsystem = SubsystemToStr(oh64->Subsystem);
                    char lv[16];
                    _snprintf_s(lv, sizeof(lv), _TRUNCATE, "%u.%u",
                        oh64->MajorLinkerVersion, oh64->MinorLinkerVersion);
                    res.pe_header.linker_version = lv;
                }
                else
                {
                    _snprintf_s(hexBuf, sizeof(hexBuf), _TRUNCATE,
                        "0x%08X", oh.ImageBase);
                    res.pe_header.image_base = hexBuf;
                    res.pe_header.size_of_image   = oh.SizeOfImage;
                    res.pe_header.size_of_headers = oh.SizeOfHeaders;
                    res.pe_header.subsystem = SubsystemToStr(oh.Subsystem);
                    char lv[16];
                    _snprintf_s(lv, sizeof(lv), _TRUNCATE, "%u.%u",
                        oh.MajorLinkerVersion, oh.MinorLinkerVersion);
                    res.pe_header.linker_version = lv;
                }

                /* 文件特征 */
                res.pe_header.characteristics = fh.Characteristics;
                std::string chDesc;
                if (fh.Characteristics & IMAGE_FILE_DLL)        chDesc += "DLL ";
                if (fh.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) chDesc += "EXE ";
                if (fh.Characteristics & IMAGE_FILE_SYSTEM)     chDesc += "SYS ";
                if (fh.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) chDesc += "LARGEADDR ";
                if (chDesc.empty()) chDesc = "Unknown";
                res.pe_header.characteristics_desc = chDesc;

                /* 编译时间戳 */
                res.pe_header.compile_time = TimeTToUtcStr(fh.TimeDateStamp);
                res.basic.compile_timestamp = res.pe_header.compile_time;

                res.pe_header.number_of_sections = fh.NumberOfSections;

                /* 数据目录特征 */
                DWORD numDir = oh.NumberOfRvaAndSizes;
                if (numDir > IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
                    numDir = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

                res.pe_header.has_tls = (numDir > IMAGE_DIRECTORY_ENTRY_TLS &&
                    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0);
                res.pe_header.has_resources = (numDir > IMAGE_DIRECTORY_ENTRY_RESOURCE &&
                    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress != 0);
                res.pe_header.has_debug = (numDir > IMAGE_DIRECTORY_ENTRY_DEBUG &&
                    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress != 0);
                res.pe_header.has_reloc = (numDir > IMAGE_DIRECTORY_ENTRY_BASERELOC &&
                    oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0);

                /* 节区表指针 */
                const IMAGE_SECTION_HEADER* pSec =
                    IMAGE_FIRST_SECTION(pNT);

                /* 加壳/编译器特征 */
                res.pe_header.packer_or_compiler =
                    DetectPackerOrCompiler(pNT, pSec, fh.NumberOfSections);

                /* -------------------------------------------------------
                 * 3a. 节区信息
                 * ----------------------------------------------------- */
                for (WORD si = 0; si < fh.NumberOfSections; si++)
                {
                    const IMAGE_SECTION_HEADER& sh = pSec[si];
                    SectionInfo sec;

                    char secName[9] = {0};
                    memcpy(secName, sh.Name, 8);
                    sec.name = secName;

                    char rva[16];
                    _snprintf_s(rva, sizeof(rva), _TRUNCATE,
                        "0x%08X", sh.VirtualAddress);
                    sec.virtual_addr = rva;
                    sec.virtual_size = sh.Misc.VirtualSize;
                    sec.raw_size     = sh.SizeOfRawData;

                    char chHex[16];
                    _snprintf_s(chHex, sizeof(chHex), _TRUNCATE,
                        "0x%08X", sh.Characteristics);
                    sec.characteristics = chHex;
                    sec.char_desc = SectionCharDesc(sh.Characteristics);

                    /* 计算节区熵值 */
                    if (sh.PointerToRawData != 0 &&
                        sh.SizeOfRawData != 0 &&
                        (SIZE_T)sh.PointerToRawData + sh.SizeOfRawData <= fileSize)
                    {
                        sec.entropy = CalcEntropy(
                            pBase + sh.PointerToRawData,
                            sh.SizeOfRawData);
                    }
                    else
                    {
                        sec.entropy = 0.0;
                    }

                    /* 节区状态判断 */
                    bool isExec  = (sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
                    bool isWrite = (sh.Characteristics & IMAGE_SCN_MEM_WRITE)   != 0;

                    if (sec.entropy >= 7.0)
                    {
                        sec.status = SECTION_HIGH_ENTROPY;
                        sec.status_desc = "高熵（疑似加密/压缩）";
                    }
                    else if (isExec && isWrite)
                    {
                        sec.status = SECTION_SUSPICIOUS;
                        sec.status_desc = "可疑（可执行且可写）";
                    }
                    else if (sh.Misc.VirtualSize > 0 &&
                             sh.SizeOfRawData > sh.Misc.VirtualSize * 2)
                    {
                        sec.status = SECTION_ABNORMAL;
                        sec.status_desc = "异常（原始大小远大于虚拟大小）";
                    }
                    else
                    {
                        sec.status = SECTION_NORMAL;
                        sec.status_desc = "正常";
                    }

                    res.sections.push_back(sec);
                }

                /* -------------------------------------------------------
                 * 3b. 导入表
                 * ----------------------------------------------------- */
                if (numDir > IMAGE_DIRECTORY_ENTRY_IMPORT)
                {
                    DWORD impRva = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                    DWORD impSize= oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;

                    if (impRva != 0 && impSize != 0)
                    {
                        /* RVA → 文件偏移 */
                        auto RvaToOffset = [&](DWORD rva) -> const BYTE*
                        {
                            for (WORD si2 = 0; si2 < fh.NumberOfSections; si2++)
                            {
                                DWORD vStart = pSec[si2].VirtualAddress;
                                DWORD vEnd   = vStart + pSec[si2].SizeOfRawData;
                                if (rva >= vStart && rva < vEnd)
                                {
                                    DWORD offset = rva - vStart +
                                        pSec[si2].PointerToRawData;
                                    if (offset + 1 <= fileSize)
                                        return pBase + offset;
                                }
                            }
                            return NULL;
                        };

                        const IMAGE_IMPORT_DESCRIPTOR* pImp =
                            reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                                RvaToOffset(impRva));

                        while (pImp &&
                               (const BYTE*)pImp + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= pBase + fileSize &&
                               pImp->Name != 0)
                        {
                            ImportDll dll;
                            const BYTE* pName = RvaToOffset(pImp->Name);
                            if (pName)
                                dll.dll_name = reinterpret_cast<const char*>(pName);

                            dll.max_risk = RISK_LOW;

                            /* 遍历 INT（Import Name Table） */
                            DWORD intRva = pImp->OriginalFirstThunk
                                ? pImp->OriginalFirstThunk
                                : pImp->FirstThunk;

                            const BYTE* pINT = RvaToOffset(intRva);
                            if (pINT)
                            {
                                bool is64 = (oh.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
                                SIZE_T thunkSize = is64 ? 8 : 4;

                                for (SIZE_T ti = 0; ; ti++)
                                {
                                    const BYTE* pThunk = pINT + ti * thunkSize;
                                    if (pThunk + thunkSize > pBase + fileSize) break;

                                    ULONGLONG thunkVal = 0;
                                    if (is64)
                                        thunkVal = *reinterpret_cast<const ULONGLONG*>(pThunk);
                                    else
                                        thunkVal = *reinterpret_cast<const DWORD*>(pThunk);

                                    if (thunkVal == 0) break;

                                    ImportFunction func;
                                    func.ordinal  = 0;
                                    func.risk     = RISK_LOW;

                                    ULONGLONG ordinalFlag = is64
                                        ? IMAGE_ORDINAL_FLAG64
                                        : IMAGE_ORDINAL_FLAG32;

                                    if (thunkVal & ordinalFlag)
                                    {
                                        /* 按序号导入 */
                                        func.ordinal   = (WORD)(thunkVal & 0xFFFF);
                                        char ordBuf[32];
                                        _snprintf_s(ordBuf, sizeof(ordBuf), _TRUNCATE,
                                            "#%u", func.ordinal);
                                        func.func_name = ordBuf;
                                    }
                                    else
                                    {
                                        /* 按名称导入 */
                                        const BYTE* pHint = RvaToOffset((DWORD)thunkVal);
                                        if (pHint && pHint + 2 < pBase + fileSize)
                                        {
                                            const char* name =
                                                reinterpret_cast<const char*>(pHint + 2);
                                            /* 安全截断 */
                                            size_t maxLen = (pBase + fileSize) - (const BYTE*)name;
                                            size_t len = strnlen(name, maxLen < 256 ? maxLen : 256);
                                            func.func_name = std::string(name, len);
                                        }
                                    }

                                    /* 风险评估 */
                                    func.risk = GetFuncRisk(
                                        func.func_name.c_str(), func.risk_desc);
                                    if (func.risk > dll.max_risk)
                                        dll.max_risk = func.risk;

                                    dll.functions.push_back(func);
                                }
                            }

                            res.imports.push_back(dll);
                            pImp++;
                        }
                    }
                }
            } /* if NT_SIGNATURE */
        } /* if e_magic */
    } /* if fileSize >= DOS_HEADER */

    /* ---------------------------------------------------------------
     * 4. 可打印字符串提取（写入独立文件）
     * ------------------------------------------------------------- */
    {
        /* 生成输出文件路径：<strOutputDir>\<md5>_strings.txt */
        std::string outDir = strOutputDir;
        if (outDir.empty()) outDir = ".";

        std::string strFilePath = outDir + "\\" + res.basic.md5 + "_strings.txt";
        std::wstring strFilePathW = Utf8ToWstr(strFilePath.c_str());

        FILE* fp = NULL;
        _wfopen_s(&fp, strFilePathW.c_str(), L"w, ccs=UTF-8");
        if (fp)
        {
            fprintf(fp, "# File: %s\n", res.basic.file_path.c_str());
            fprintf(fp, "# MD5:  %s\n", res.basic.md5.c_str());
            fprintf(fp, "# SHA256: %s\n\n", res.basic.sha256.c_str());
            fprintf(fp, "=== ASCII Strings ===\n");

            /* ASCII 可打印字符串（最短 4 字符） */
            int asciiCount = 0;
            std::string cur;
            for (SIZE_T i = 0; i < fileSize; i++)
            {
                BYTE b = pBase[i];
                if (b >= 0x20 && b <= 0x7E)
                {
                    cur += (char)b;
                }
                else
                {
                    if (cur.size() >= 4)
                    {
                        fprintf(fp, "%s\n", cur.c_str());
                        res.strings.ascii_strings.push_back(cur);
                        asciiCount++;
                    }
                    cur.clear();
                }
            }
            if (cur.size() >= 4)
            {
                fprintf(fp, "%s\n", cur.c_str());
                res.strings.ascii_strings.push_back(cur);
                asciiCount++;
            }

            fprintf(fp, "\n=== Unicode (UTF-16LE) Strings ===\n");

            /* Unicode 可打印字符串（最短 4 字符） */
            int unicodeCount = 0;
            std::wstring wcur;
            for (SIZE_T i = 0; i + 1 < fileSize; i += 2)
            {
                WORD wc = pBase[i] | ((WORD)pBase[i + 1] << 8);
                if (wc >= 0x0020 && wc <= 0x007E)
                {
                    wcur += (wchar_t)wc;
                }
                else
                {
                    if (wcur.size() >= 4)
                    {
                        std::string u8 = WideToUtf8(wcur.c_str());
                        fprintf(fp, "%s\n", u8.c_str());
                        res.strings.unicode_strings.push_back(u8);
                        unicodeCount++;
                    }
                    wcur.clear();
                }
            }
            if (wcur.size() >= 4)
            {
                std::string u8 = WideToUtf8(wcur.c_str());
                fprintf(fp, "%s\n", u8.c_str());
                res.strings.unicode_strings.push_back(u8);
                unicodeCount++;
            }

            res.strings.total_count = asciiCount + unicodeCount;
            fclose(fp);

            /* 存储字符串文件路径 */
            res.strings.strings_file_path = strFilePath;
        }
        else
        {
            res.strings.strings_file_path = "";
            res.strings.total_count = 0;
        }
    }

    return res;
}

/* ===================================================================
 * JSON 序列化
 * =================================================================== */
#include "../../third_party/cJSON/cJSON.h"

static const char* RiskStr(ImportRisk r)
{
    switch (r)
    {
    case RISK_HIGH:   return "high";
    case RISK_MEDIUM: return "medium";
    default:          return "low";
    }
}

static const char* RiskLabel(ImportRisk r)
{
    switch (r)
    {
    case RISK_HIGH:   return "高危（进程注入/代码执行）";
    case RISK_MEDIUM: return "中危（网络通信）";
    default:          return "低风险";
    }
}

static std::string SerializeResult(const FileStaticResult& res)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "file_static_info");

    /* ---- 基础属性 ---- */
    cJSON* basic = cJSON_CreateObject();
    cJSON_AddStringToObject(basic, "file_path",         res.basic.file_path.c_str());
    cJSON_AddStringToObject(basic, "file_name",         res.basic.file_name.c_str());
    cJSON_AddStringToObject(basic, "file_size",         res.basic.file_size.c_str());
    cJSON_AddStringToObject(basic, "create_time",       res.basic.create_time.c_str());
    cJSON_AddStringToObject(basic, "modify_time",       res.basic.modify_time.c_str());
    cJSON_AddStringToObject(basic, "access_time",       res.basic.access_time.c_str());
    cJSON_AddStringToObject(basic, "compile_timestamp", res.basic.compile_timestamp.c_str());
    cJSON_AddStringToObject(basic, "publisher",         res.basic.publisher.c_str());
    cJSON_AddStringToObject(basic, "file_version",      res.basic.file_version.c_str());
    cJSON_AddStringToObject(basic, "product_name",      res.basic.product_name.c_str());
    cJSON_AddStringToObject(basic, "original_filename", res.basic.original_filename.c_str());
    cJSON_AddStringToObject(basic, "md5",               res.basic.md5.c_str());
    cJSON_AddStringToObject(basic, "sha256",            res.basic.sha256.c_str());
    cJSON_AddStringToObject(basic, "file_type",         res.basic.file_type.c_str());
    cJSON_AddItemToObject(root, "basic", basic);

    /* ---- PE 头 ---- */
    cJSON* pe = cJSON_CreateObject();
    cJSON_AddBoolToObject(pe, "is_pe", res.pe_header.is_pe ? 1 : 0);
    if (res.pe_header.is_pe)
    {
        cJSON_AddStringToObject(pe, "arch",                res.pe_header.arch.c_str());
        cJSON_AddStringToObject(pe, "entry_point",         res.pe_header.entry_point.c_str());
        cJSON_AddStringToObject(pe, "image_base",          res.pe_header.image_base.c_str());
        cJSON_AddStringToObject(pe, "subsystem",           res.pe_header.subsystem.c_str());
        cJSON_AddStringToObject(pe, "linker_version",      res.pe_header.linker_version.c_str());
        cJSON_AddStringToObject(pe, "characteristics_desc",res.pe_header.characteristics_desc.c_str());
        cJSON_AddStringToObject(pe, "packer_or_compiler",  res.pe_header.packer_or_compiler.c_str());
        cJSON_AddStringToObject(pe, "compile_time",        res.pe_header.compile_time.c_str());
        cJSON_AddNumberToObject(pe, "number_of_sections",  (double)res.pe_header.number_of_sections);
        cJSON_AddNumberToObject(pe, "size_of_image",       (double)res.pe_header.size_of_image);
        cJSON_AddBoolToObject(pe, "has_tls",       res.pe_header.has_tls ? 1 : 0);
        cJSON_AddBoolToObject(pe, "has_resources", res.pe_header.has_resources ? 1 : 0);
        cJSON_AddBoolToObject(pe, "has_debug",     res.pe_header.has_debug ? 1 : 0);
        cJSON_AddBoolToObject(pe, "has_reloc",     res.pe_header.has_reloc ? 1 : 0);
    }
    cJSON_AddItemToObject(root, "pe_header", pe);

    /* ---- 节区 ---- */
    cJSON* sections = cJSON_CreateArray();
    for (size_t i = 0; i < res.sections.size(); i++)
    {
        const SectionInfo& s = res.sections[i];
        cJSON* sec = cJSON_CreateObject();
        cJSON_AddStringToObject(sec, "name",             s.name.c_str());
        cJSON_AddStringToObject(sec, "virtual_addr",     s.virtual_addr.c_str());
        cJSON_AddNumberToObject(sec, "virtual_size",     (double)s.virtual_size);
        cJSON_AddNumberToObject(sec, "raw_size",         (double)s.raw_size);
        cJSON_AddStringToObject(sec, "characteristics",  s.characteristics.c_str());
        cJSON_AddStringToObject(sec, "char_desc",        s.char_desc.c_str());
        cJSON_AddNumberToObject(sec, "entropy",          s.entropy);
        cJSON_AddStringToObject(sec, "status",           s.status_desc.c_str());
        cJSON_AddItemToArray(sections, sec);
    }
    cJSON_AddItemToObject(root, "sections", sections);

    /* ---- 导入表 ---- */
    cJSON* imports = cJSON_CreateArray();
    for (size_t i = 0; i < res.imports.size(); i++)
    {
        const ImportDll& d = res.imports[i];
        cJSON* dll = cJSON_CreateObject();
        cJSON_AddStringToObject(dll, "dll_name",  d.dll_name.c_str());
        cJSON_AddStringToObject(dll, "max_risk",  RiskStr(d.max_risk));
        cJSON_AddStringToObject(dll, "max_risk_label", RiskLabel(d.max_risk));

        cJSON* funcs = cJSON_CreateArray();
        for (size_t j = 0; j < d.functions.size(); j++)
        {
            const ImportFunction& f = d.functions[j];
            cJSON* fn = cJSON_CreateObject();
            cJSON_AddStringToObject(fn, "func_name", f.func_name.c_str());
            cJSON_AddStringToObject(fn, "risk",      RiskStr(f.risk));
            if (!f.risk_desc.empty())
                cJSON_AddStringToObject(fn, "risk_desc", f.risk_desc.c_str());
            cJSON_AddItemToArray(funcs, fn);
        }
        cJSON_AddItemToObject(dll, "functions", funcs);
        cJSON_AddItemToArray(imports, dll);
    }
    cJSON_AddItemToObject(root, "imports", imports);

    /* ---- 字符串摘要 ---- */
    cJSON* strs = cJSON_CreateObject();
    cJSON_AddNumberToObject(strs, "total_count",    (double)res.strings.total_count);
    cJSON_AddNumberToObject(strs, "ascii_count",    (double)res.strings.ascii_strings.size());
    cJSON_AddNumberToObject(strs, "unicode_count",  (double)res.strings.unicode_strings.size());
    cJSON_AddStringToObject(strs, "strings_file",   res.strings.strings_file_path.c_str());
    cJSON_AddItemToObject(root, "strings_summary", strs);

    if (!res.error_msg.empty())
        cJSON_AddStringToObject(root, "error", res.error_msg.c_str());

    cJSON_AddStringToObject(root, "status",
        res.error_msg.empty() ? "success" : "error");

    char* raw = cJSON_PrintUnformatted(root);
    std::string out = raw ? raw : "{}";
    cJSON_free(raw);
    cJSON_Delete(root);
    return out;
}

/* ===================================================================
 * SQLite3 存储
 * =================================================================== */

static bool EnsureStaticTable(sqlite3* db)
{
    const char* sql =
        "CREATE TABLE IF NOT EXISTS file_static_results ("
        "  id            INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  file_path     TEXT NOT NULL,"
        "  file_name     TEXT,"
        "  file_size     TEXT,"
        "  create_time   TEXT,"
        "  modify_time   TEXT,"
        "  compile_time  TEXT,"
        "  publisher     TEXT,"
        "  file_version  TEXT,"
        "  md5           TEXT,"
        "  sha256        TEXT,"
        "  file_type     TEXT,"
        "  is_pe         INTEGER,"
        "  arch          TEXT,"
        "  entry_point   TEXT,"
        "  subsystem     TEXT,"
        "  packer        TEXT,"
        "  section_count INTEGER,"
        "  import_count  INTEGER,"
        "  strings_file  TEXT,"
        "  strings_count INTEGER,"
        "  result_json   TEXT,"
        "  created_at    TEXT"
        ");";
    char* err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

static long long SaveToDb(sqlite3* db, const FileStaticResult& res,
                          const std::string& jsonStr)
{
    if (!EnsureStaticTable(db)) return -1;

    /* 获取当前 UTC 时间 */
    SYSTEMTIME st;
    GetSystemTime(&st);
    char now[32];
    _snprintf_s(now, sizeof(now), _TRUNCATE,
        "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    const char* sql =
        "INSERT INTO file_static_results "
        "(file_path,file_name,file_size,create_time,modify_time,"
        " compile_time,publisher,file_version,md5,sha256,file_type,"
        " is_pe,arch,entry_point,subsystem,packer,"
        " section_count,import_count,strings_file,strings_count,"
        " result_json,created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    int col = 1;
    sqlite3_bind_text(stmt, col++, res.basic.file_path.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.basic.file_name.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.basic.file_size.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.basic.create_time.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.basic.modify_time.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.basic.compile_timestamp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.basic.publisher.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.basic.file_version.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.basic.md5.c_str(),          -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.basic.sha256.c_str(),       -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.basic.file_type.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, col++, res.pe_header.is_pe ? 1 : 0);
    sqlite3_bind_text(stmt, col++, res.pe_header.arch.c_str(),     -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.pe_header.entry_point.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.pe_header.subsystem.c_str(),-1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, res.pe_header.packer_or_compiler.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, col++, (int)res.sections.size());
    sqlite3_bind_int (stmt, col++, (int)res.imports.size());
    sqlite3_bind_text(stmt, col++, res.strings.strings_file_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, col++, res.strings.total_count);
    sqlite3_bind_text(stmt, col++, jsonStr.c_str(),                -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, col++, now,                            -1, SQLITE_TRANSIENT);

    sqlite3_step(stmt);
    long long rowId = sqlite3_last_insert_rowid(db);
    sqlite3_finalize(stmt);
    return rowId;
}

/* ===================================================================
 * 导出接口实现
 * =================================================================== */

/*
 * GetFileStaticInfo
 * 参数 JSON：
 * {
 *   "file_path"      : "C:\\path\\to\\file.exe",
 *   "strings_output_dir" : "C:\\strings"   // 可选，默认与文件同目录
 * }
 */
BASIC_API const char* GetFileStaticInfo(const char* paramsJson)
{
    cJSON* params = cJSON_Parse(paramsJson ? paramsJson : "{}");
    std::string filePath, strOutDir;

    cJSON* jp = cJSON_GetObjectItem(params, "file_path");
    if (jp && jp->valuestring) filePath = jp->valuestring;

    cJSON* jd = cJSON_GetObjectItem(params, "strings_output_dir");
    if (jd && jd->valuestring) strOutDir = jd->valuestring;
    cJSON_Delete(params);

    if (filePath.empty())
    {
        static const char* err =
            "{\"status\":\"error\",\"error\":\"file_path is required\"}";
        return err;
    }

    /* 默认字符串输出目录 = 文件所在目录 */
    if (strOutDir.empty())
    {
        size_t slash = filePath.rfind('\\');
        if (slash == std::string::npos) slash = filePath.rfind('/');
        strOutDir = (slash != std::string::npos)
            ? filePath.substr(0, slash) : ".";
    }

    std::wstring pathW = Utf8ToWstr(filePath.c_str());
    FileStaticResult res = AnalyzeFileStatic(pathW, strOutDir);
    std::string json = SerializeResult(res);

    char* buf = (char*)malloc(json.size() + 1);
    if (!buf) return "{}";
    memcpy(buf, json.c_str(), json.size() + 1);
    return buf;
}

/*
 * SaveFileStaticInfo
 * 参数 JSON：
 * {
 *   "file_path"          : "C:\\path\\to\\file.exe",
 *   "db_path"            : "C:\\basic.db",
 *   "strings_output_dir" : "C:\\strings"   // 可选
 * }
 */
BASIC_API const char* SaveFileStaticInfo(const char* paramsJson)
{
    cJSON* params = cJSON_Parse(paramsJson ? paramsJson : "{}");
    std::string filePath, dbPath, strOutDir;

    cJSON* jp = cJSON_GetObjectItem(params, "file_path");
    if (jp && jp->valuestring) filePath = jp->valuestring;

    cJSON* jdb = cJSON_GetObjectItem(params, "db_path");
    if (jdb && jdb->valuestring) dbPath = jdb->valuestring;

    cJSON* jd = cJSON_GetObjectItem(params, "strings_output_dir");
    if (jd && jd->valuestring) strOutDir = jd->valuestring;
    cJSON_Delete(params);

    if (filePath.empty() || dbPath.empty())
    {
        static const char* err =
            "{\"status\":\"error\",\"error\":\"file_path and db_path are required\"}";
        return err;
    }

    if (strOutDir.empty())
    {
        size_t slash = filePath.rfind('\\');
        if (slash == std::string::npos) slash = filePath.rfind('/');
        strOutDir = (slash != std::string::npos)
            ? filePath.substr(0, slash) : ".";
    }

    std::wstring pathW = Utf8ToWstr(filePath.c_str());
    FileStaticResult res = AnalyzeFileStatic(pathW, strOutDir);
    std::string json = SerializeResult(res);

    /* 存入 SQLite3 */
    sqlite3* db = NULL;
    long long rowId = -1;
    std::string saveStatus = "error";

    if (sqlite3_open(dbPath.c_str(), &db) == SQLITE_OK)
    {
        rowId = SaveToDb(db, res, json);
        saveStatus = (rowId > 0) ? "success" : "error";
        sqlite3_close(db);
    }

    /* 在返回 JSON 中追加存储状态 */
    cJSON* root = cJSON_Parse(json.c_str());
    if (root)
    {
        cJSON_AddStringToObject(root, "save_status", saveStatus.c_str());
        cJSON_AddNumberToObject(root, "record_id",   (double)rowId);
        char* raw = cJSON_PrintUnformatted(root);
        std::string out = raw ? raw : json;
        cJSON_free(raw);
        cJSON_Delete(root);

        char* buf = (char*)malloc(out.size() + 1);
        if (!buf) return "{}";
        memcpy(buf, out.c_str(), out.size() + 1);
        return buf;
    }

    char* buf = (char*)malloc(json.size() + 1);
    if (!buf) return "{}";
    memcpy(buf, json.c_str(), json.size() + 1);
    return buf;
}
