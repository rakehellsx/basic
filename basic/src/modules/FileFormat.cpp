/*
 * FileFormat.cpp
 * 文件格式检测模块
 *
 * 功能：
 *   1. 通过魔数（Magic Number/文件头字节）识别文件真实格式
 *   2. 检测文件扩展名与真实格式是否一致（格式伪装检测）
 *   3. 检测恶意特征：宏、嵌入对象、加密、可疑字符串
 *   4. 覆盖6大类：可执行、脚本、文档、压缩、多媒体、复合文件
 *   5. 将检测结果存入 SQLite3 专属表 file_format_results
 *
 * 导出接口：
 *   DetectFileFormat(paramsJson)      — 检测单个或多个文件格式
 *   ScanDirectoryFormat(paramsJson)   — 扫描目录下所有文件格式
 */

#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <set>
#include <map>
#include <algorithm>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "../../third_party/sqlite3/sqlite3.h"
#include "../common/Utils.h"
#include "FileFormat.h"

#pragma comment(lib, "shlwapi.lib")

/* ===================================================================
 * 魔数签名表（按优先级排列，长魔数优先）
 * =================================================================== */
static const uint8_t MZ[]      = {0x4D,0x5A};
static const uint8_t ELF[]     = {0x7F,0x45,0x4C,0x46};
static const uint8_t MACHO32[] = {0xCE,0xFA,0xED,0xFE};
static const uint8_t MACHO64[] = {0xCF,0xFA,0xED,0xFE};
static const uint8_t MACHO_BE[]= {0xFE,0xED,0xFA,0xCE};
/* OLE2 复合文档 (doc/xls/ppt/msi/msg) */
static const uint8_t OLE2[]    = {0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1};
/* ZIP (docx/xlsx/pptx/odt/jar/apk/zip) */
static const uint8_t ZIP_PK[]  = {0x50,0x4B,0x03,0x04};
static const uint8_t ZIP_EMPTY[]={0x50,0x4B,0x05,0x06};
static const uint8_t ZIP_SPAN[]= {0x50,0x4B,0x07,0x08};
/* RAR */
static const uint8_t RAR4[]    = {0x52,0x61,0x72,0x21,0x1A,0x07,0x00};
static const uint8_t RAR5[]    = {0x52,0x61,0x72,0x21,0x1A,0x07,0x01,0x00};
/* 7-Zip */
static const uint8_t SEVENZIP[]= {0x37,0x7A,0xBC,0xAF,0x27,0x1C};
/* GZIP */
static const uint8_t GZIP[]    = {0x1F,0x8B};
/* BZIP2 */
static const uint8_t BZIP2[]   = {0x42,0x5A,0x68};
/* XZ */
static const uint8_t XZ[]      = {0xFD,0x37,0x7A,0x58,0x5A,0x00};
/* TAR (ustar) */
static const uint8_t TAR_USTAR[]= {0x75,0x73,0x74,0x61,0x72};
/* CAB */
static const uint8_t CAB[]     = {0x4D,0x53,0x43,0x46};
/* ISO 9660 */
static const uint8_t ISO[]     = {0x43,0x44,0x30,0x30,0x31};
/* WIM */
static const uint8_t WIM[]     = {0x4D,0x53,0x57,0x49,0x4D,0x00,0x00,0x00};
/* ARJ */
static const uint8_t ARJ[]     = {0x60,0xEA};
/* LZH */
static const uint8_t LZH[]     = {0x2D,0x6C,0x68};
/* PDF */
static const uint8_t PDF[]     = {0x25,0x50,0x44,0x46};
/* RTF */
static const uint8_t RTF[]     = {0x7B,0x5C,0x72,0x74,0x66};
/* CHM */
static const uint8_t CHM[]     = {0x49,0x54,0x53,0x46};
/* OFD (ZIP-based, 需检查内部结构) */
/* PNG */
static const uint8_t PNG[]     = {0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A};
/* JPEG */
static const uint8_t JPEG[]    = {0xFF,0xD8,0xFF};
/* GIF87a / GIF89a */
static const uint8_t GIF87[]   = {0x47,0x49,0x46,0x38,0x37,0x61};
static const uint8_t GIF89[]   = {0x47,0x49,0x46,0x38,0x39,0x61};
/* BMP */
static const uint8_t BMP[]     = {0x42,0x4D};
/* TIFF LE/BE */
static const uint8_t TIFF_LE[] = {0x49,0x49,0x2A,0x00};
static const uint8_t TIFF_BE[] = {0x4D,0x4D,0x00,0x2A};
/* ICO */
static const uint8_t ICO[]     = {0x00,0x00,0x01,0x00};
/* WebP */
static const uint8_t WEBP_RIFF[]={0x52,0x49,0x46,0x46};
/* SWF compressed/uncompressed */
static const uint8_t SWF_FWS[] = {0x46,0x57,0x53};
static const uint8_t SWF_CWS[] = {0x43,0x57,0x53};
static const uint8_t SWF_ZWS[] = {0x5A,0x57,0x53};
/* MP3 */
static const uint8_t MP3_ID3[] = {0x49,0x44,0x33};
static const uint8_t MP3_SYNC[]= {0xFF,0xFB};
/* MP4/MOV (ftyp box) */
static const uint8_t MP4_FTYP[]= {0x66,0x74,0x79,0x70};
/* AVI (RIFF) */
static const uint8_t AVI_RIFF[]= {0x52,0x49,0x46,0x46};
/* WMV/WMA/ASF */
static const uint8_t ASF[]     = {0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11};
/* FLV */
static const uint8_t FLV[]     = {0x46,0x4C,0x56,0x01};
/* MKV/WEBM (EBML) */
static const uint8_t EBML[]    = {0x1A,0x45,0xDF,0xA3};
/* VOB/MPEG */
static const uint8_t MPEG_PS[] = {0x00,0x00,0x01,0xBA};
static const uint8_t MPEG_TS[] = {0x47};
/* WAV (RIFF) */
static const uint8_t WAV_RIFF[]= {0x52,0x49,0x46,0x46};
/* FLAC */
static const uint8_t FLAC[]    = {0x66,0x4C,0x61,0x43};
/* OGG */
static const uint8_t OGG[]     = {0x4F,0x67,0x67,0x53};
/* AAC ADTS */
static const uint8_t AAC[]     = {0xFF,0xF1};
/* EML/MIME */
static const uint8_t EML_FROM[]= {0x46,0x72,0x6F,0x6D,0x20};  /* "From " */
static const uint8_t EML_MIME[]= {0x4D,0x49,0x4D,0x45,0x2D};  /* "MIME-" */
/* MSG (OLE2 based, same as OLE2) */
/* XML */
static const uint8_t XML[]     = {0x3C,0x3F,0x78,0x6D,0x6C};
/* UTF-8 BOM */
static const uint8_t UTF8_BOM[]= {0xEF,0xBB,0xBF};
/* UTF-16 LE BOM */
static const uint8_t UTF16_LE[]= {0xFF,0xFE};
/* UTF-16 BE BOM */
static const uint8_t UTF16_BE[]= {0xFE,0xFF};
/* LNK (Windows Shortcut) */
static const uint8_t LNK[]     = {0x4C,0x00,0x00,0x00,0x01,0x14,0x02,0x00};
/* MSI (OLE2 based) */
/* REG */
static const uint8_t REG_V5[]  = {0xFF,0xFE,0x57,0x69};  /* UTF-16 LE "Wi" */
/* SQLITE */
static const uint8_t SQLITE3[] = {0x53,0x51,0x4C,0x69,0x74,0x65,0x20,0x66};

/* -----------------------------------------------------------------------
 * 魔数表（offset=0 除非特别注明）
 * --------------------------------------------------------------------- */
static const MagicEntry g_magicTable[] =
{
    /* ===== 可执行文件 ===== */
    {ELF,      4,  0, "ELF Executable",          "executable", FC_EXECUTABLE, "application/x-elf",         ".elf,.so,.bin"},
    {MACHO64,  4,  0, "Mach-O 64-bit",           "executable", FC_EXECUTABLE, "application/x-mach-binary", ".macho"},
    {MACHO32,  4,  0, "Mach-O 32-bit",           "executable", FC_EXECUTABLE, "application/x-mach-binary", ".macho"},
    {MACHO_BE, 4,  0, "Mach-O BE",               "executable", FC_EXECUTABLE, "application/x-mach-binary", ".macho"},
    {MZ,       2,  0, "PE Executable (MZ)",       "executable", FC_EXECUTABLE, "application/x-msdownload",  ".exe,.dll,.sys,.drv,.ocx,.scr,.cpl,.com"},
    {LNK,      8,  0, "Windows Shortcut (LNK)",   "executable", FC_EXECUTABLE, "application/x-ms-shortcut", ".lnk"},

    /* ===== 文档文件 ===== */
    {OLE2,     8,  0, "OLE2 Compound Document",   "document",   FC_DOCUMENT,   "application/msword",        ".doc,.xls,.ppt,.msi,.msg,.wps,.et,.dps"},
    {RTF,      5,  0, "Rich Text Format (RTF)",   "document",   FC_DOCUMENT,   "application/rtf",           ".rtf"},
    {PDF,      4,  0, "PDF Document",             "document",   FC_DOCUMENT,   "application/pdf",           ".pdf"},
    {CHM,      4,  0, "CHM Help File",            "document",   FC_DOCUMENT,   "application/vnd.ms-htmlhelp",".chm"},

    /* ===== 压缩/归档文件 ===== */
    {RAR5,     8,  0, "RAR Archive v5",           "archive",    FC_ARCHIVE,    "application/x-rar-compressed",".rar"},
    {RAR4,     7,  0, "RAR Archive v4",           "archive",    FC_ARCHIVE,    "application/x-rar-compressed",".rar"},
    {SEVENZIP, 6,  0, "7-Zip Archive",            "archive",    FC_ARCHIVE,    "application/x-7z-compressed", ".7z"},
    {WIM,      8,  0, "Windows Imaging (WIM)",    "archive",    FC_ARCHIVE,    "application/x-ms-wim",       ".wim"},
    {CAB,      4,  0, "Cabinet Archive (CAB)",    "archive",    FC_ARCHIVE,    "application/vnd.ms-cab-compressed",".cab"},
    {XZ,       6,  0, "XZ Archive",               "archive",    FC_ARCHIVE,    "application/x-xz",           ".xz"},
    {BZIP2,    3,  0, "BZip2 Archive",            "archive",    FC_ARCHIVE,    "application/x-bzip2",        ".bz2,.bzip2"},
    {GZIP,     2,  0, "GZip Archive",             "archive",    FC_ARCHIVE,    "application/gzip",           ".gz,.tgz"},
    {ARJ,      2,  0, "ARJ Archive",              "archive",    FC_ARCHIVE,    "application/x-arj",          ".arj"},
    {ZIP_PK,   4,  0, "ZIP Archive",              "archive",    FC_ARCHIVE,    "application/zip",            ".zip,.docx,.xlsx,.pptx,.jar,.apk,.odt,.ods,.odp,.ofd,.wps,.et,.dps"},
    {ZIP_EMPTY,4,  0, "ZIP Archive (empty)",      "archive",    FC_ARCHIVE,    "application/zip",            ".zip"},
    {ZIP_SPAN, 4,  0, "ZIP Archive (spanned)",    "archive",    FC_ARCHIVE,    "application/zip",            ".zip"},

    /* ===== 多媒体文件 ===== */
    {PNG,      8,  0, "PNG Image",                "multimedia", FC_MULTIMEDIA, "image/png",                  ".png"},
    {GIF89,    6,  0, "GIF89a Image",             "multimedia", FC_MULTIMEDIA, "image/gif",                  ".gif"},
    {GIF87,    6,  0, "GIF87a Image",             "multimedia", FC_MULTIMEDIA, "image/gif",                  ".gif"},
    {JPEG,     3,  0, "JPEG Image",               "multimedia", FC_MULTIMEDIA, "image/jpeg",                 ".jpg,.jpeg"},
    {TIFF_LE,  4,  0, "TIFF Image (LE)",          "multimedia", FC_MULTIMEDIA, "image/tiff",                 ".tif,.tiff"},
    {TIFF_BE,  4,  0, "TIFF Image (BE)",          "multimedia", FC_MULTIMEDIA, "image/tiff",                 ".tif,.tiff"},
    {ICO,      4,  0, "ICO Icon",                 "multimedia", FC_MULTIMEDIA, "image/x-icon",               ".ico"},
    {BMP,      2,  0, "BMP Image",                "multimedia", FC_MULTIMEDIA, "image/bmp",                  ".bmp"},
    {SWF_FWS,  3,  0, "SWF Flash (uncompressed)", "multimedia", FC_MULTIMEDIA, "application/x-shockwave-flash",".swf"},
    {SWF_CWS,  3,  0, "SWF Flash (ZLIB)",        "multimedia", FC_MULTIMEDIA, "application/x-shockwave-flash",".swf"},
    {SWF_ZWS,  3,  0, "SWF Flash (LZMA)",        "multimedia", FC_MULTIMEDIA, "application/x-shockwave-flash",".swf"},
    {ASF,      8,  0, "ASF/WMV/WMA Media",        "multimedia", FC_MULTIMEDIA, "video/x-ms-asf",             ".wmv,.wma,.asf"},
    {FLV,      4,  0, "FLV Flash Video",          "multimedia", FC_MULTIMEDIA, "video/x-flv",                ".flv"},
    {EBML,     4,  0, "MKV/WebM (EBML)",          "multimedia", FC_MULTIMEDIA, "video/x-matroska",           ".mkv,.webm"},
    {MPEG_PS,  4,  0, "MPEG Program Stream",      "multimedia", FC_MULTIMEDIA, "video/mpeg",                 ".mpg,.mpeg,.vob"},
    {FLAC,     4,  0, "FLAC Audio",               "multimedia", FC_MULTIMEDIA, "audio/flac",                 ".flac"},
    {OGG,      4,  0, "OGG Container",            "multimedia", FC_MULTIMEDIA, "audio/ogg",                  ".ogg,.ogv,.oga"},
    {MP3_ID3,  3,  0, "MP3 Audio (ID3)",          "multimedia", FC_MULTIMEDIA, "audio/mpeg",                 ".mp3"},
    {MP3_SYNC, 2,  0, "MP3 Audio (sync)",         "multimedia", FC_MULTIMEDIA, "audio/mpeg",                 ".mp3"},
    {AAC,      2,  0, "AAC Audio (ADTS)",         "multimedia", FC_MULTIMEDIA, "audio/aac",                  ".aac"},

    /* ===== 复合/邮件文件 ===== */
    {EML_FROM, 5,  0, "EML Email (mbox)",         "compound",   FC_COMPOUND,   "message/rfc822",             ".eml,.mbox"},
    {EML_MIME, 5,  0, "EML Email (MIME)",         "compound",   FC_COMPOUND,   "message/rfc822",             ".eml"},

    /* ===== 其他常见 ===== */
    {SQLITE3,  8,  0, "SQLite3 Database",         "database",   FC_UNKNOWN,    "application/x-sqlite3",      ".db,.sqlite,.sqlite3"},
    {XML,      5,  0, "XML Document",             "document",   FC_DOCUMENT,   "application/xml",            ".xml,.svg,.xhtml"},

    {NULL, 0, 0, NULL, NULL, FC_UNKNOWN, NULL, NULL}
};

/* ===================================================================
 * ISO 9660 魔数在偏移 0x8001 处
 * =================================================================== */
static bool CheckISO(const std::vector<uint8_t>& buf)
{
    if (buf.size() < 0x8006) return false;
    return memcmp(buf.data() + 0x8001, ISO, 5) == 0;
}

/* ===================================================================
 * TAR ustar 魔数在偏移 257 处
 * =================================================================== */
static bool CheckTAR(const std::vector<uint8_t>& buf)
{
    if (buf.size() < 262) return false;
    return memcmp(buf.data() + 257, TAR_USTAR, 5) == 0;
}

/* ===================================================================
 * RIFF 容器区分：AVI / WAV / WebP
 * =================================================================== */
static std::string CheckRIFF(const std::vector<uint8_t>& buf)
{
    if (buf.size() < 12) return "";
    if (memcmp(buf.data(), AVI_RIFF, 4) != 0) return "";
    std::string fourcc(buf.begin() + 8, buf.begin() + 12);
    if (fourcc == "AVI ") return "AVI Video";
    if (fourcc == "WAVE") return "WAV Audio";
    if (fourcc == "WEBP") return "WebP Image";
    return "RIFF Container";
}

/* ===================================================================
 * MP4/MOV ftyp box 在偏移 4 处
 * =================================================================== */
static bool CheckMP4(const std::vector<uint8_t>& buf)
{
    if (buf.size() < 8) return false;
    return memcmp(buf.data() + 4, MP4_FTYP, 4) == 0;
}

/* ===================================================================
 * 读取文件头（最多 64KB）
 * =================================================================== */
static std::vector<uint8_t> ReadFileHeader(const std::wstring& path,
                                            size_t maxBytes = 65536)
{
    std::vector<uint8_t> buf;
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return buf;

    buf.resize(maxBytes);
    DWORD read = 0;
    ReadFile(hFile, buf.data(), (DWORD)maxBytes, &read, NULL);
    buf.resize(read);
    CloseHandle(hFile);
    return buf;
}

/* ===================================================================
 * 获取文件大小
 * =================================================================== */
static long long GetFileSize64(const std::wstring& path)
{
    WIN32_FILE_ATTRIBUTE_DATA fa = {};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fa))
        return -1;
    LARGE_INTEGER li;
    li.HighPart = (LONG)fa.nFileSizeHigh;
    li.LowPart  = fa.nFileSizeLow;
    return li.QuadPart;
}

/* ===================================================================
 * 文件头前16字节转十六进制字符串
 * =================================================================== */
static std::string ToHexStr(const std::vector<uint8_t>& buf, int n = 16)
{
    char hex[64] = {};
    int cnt = (int)buf.size() < n ? (int)buf.size() : n;
    for (int i = 0; i < cnt; i++)
        sprintf_s(hex + i * 3, 4, "%02X ", buf[i]);
    if (cnt > 0 && hex[cnt * 3 - 1] == ' ')
        hex[cnt * 3 - 1] = '\0';
    return hex;
}

/* ===================================================================
 * 脚本文件检测（通过 shebang 或关键字）
 * =================================================================== */
struct ScriptSig
{
    const char* keyword;
    const char* format;
    const char* ext;
};

static const ScriptSig g_scriptSigs[] =
{
    {"#!/bin/bash",       "Bash Shell Script",      ".sh"},
    {"#!/bin/sh",         "Shell Script",           ".sh"},
    {"#!/usr/bin/env bash","Bash Shell Script",     ".sh"},
    {"#!/usr/bin/env sh",  "Shell Script",          ".sh"},
    {"#!/usr/bin/python",  "Python Script",         ".py"},
    {"#!/usr/bin/env python","Python Script",       ".py"},
    {"import os",          "Python Script",         ".py"},
    {"import sys",         "Python Script",         ".py"},
    {"def ",               "Python Script",         ".py"},
    {"<#",                 "PowerShell Script",     ".ps1"},
    {"param(",             "PowerShell Script",     ".ps1"},
    {"function ",          "PowerShell/VBS Script", ".ps1,.vbs"},
    {"@echo off",          "Batch Script",          ".bat,.cmd"},
    {"@ECHO OFF",          "Batch Script",          ".bat,.cmd"},
    {"echo off",           "Batch Script",          ".bat,.cmd"},
    {"Set-ExecutionPolicy","PowerShell Script",     ".ps1"},
    {"Invoke-Expression",  "PowerShell Script",     ".ps1"},
    {"WScript.Shell",      "VBScript",              ".vbs"},
    {"CreateObject",       "VBScript/JScript",      ".vbs,.js"},
    {"On Error Resume",    "VBScript",              ".vbs"},
    {"<script",            "HTML/JavaScript",       ".html,.js"},
    {"var ",               "JavaScript",            ".js"},
    {"function(",          "JavaScript",            ".js"},
    {"require(",           "Node.js Script",        ".js"},
    {NULL, NULL, NULL}
};

static std::string DetectScript(const std::vector<uint8_t>& buf,
                                 const std::string& ext)
{
    if (buf.size() < 4) return "";

    /* 转为字符串（取前 4KB）*/
    size_t checkLen = buf.size() < 4096 ? buf.size() : 4096;
    std::string text(buf.begin(), buf.begin() + checkLen);

    for (int i = 0; g_scriptSigs[i].keyword; i++)
    {
        if (text.find(g_scriptSigs[i].keyword) != std::string::npos)
            return g_scriptSigs[i].format;
    }

    /* 通过扩展名兜底 */
    std::string lext = ext;
    std::transform(lext.begin(), lext.end(), lext.begin(), ::tolower);
    if (lext == ".bat" || lext == ".cmd") return "Batch Script";
    if (lext == ".ps1") return "PowerShell Script";
    if (lext == ".vbs") return "VBScript";
    if (lext == ".js")  return "JavaScript";
    if (lext == ".py")  return "Python Script";
    if (lext == ".sh")  return "Shell Script";
    if (lext == ".rb")  return "Ruby Script";
    if (lext == ".pl")  return "Perl Script";
    if (lext == ".lua") return "Lua Script";

    return "";
}

/* ===================================================================
 * OLE2 内部结构分析：检测宏、加密、嵌入对象
 * =================================================================== */
static void AnalyzeOLE2(const std::vector<uint8_t>& buf,
                         FileFormatResult& result)
{
    if (buf.size() < 8) return;
    if (memcmp(buf.data(), OLE2, 8) != 0) return;

    std::string text(buf.begin(), buf.end());

    /* 宏检测：VBA 流标记 */
    if (text.find("VBA") != std::string::npos ||
        text.find("vba") != std::string::npos ||
        text.find("_VBA_PROJECT") != std::string::npos ||
        text.find("ThisDocument") != std::string::npos ||
        text.find("ThisWorkbook") != std::string::npos)
    {
        result.hasMacro = true;
        result.structureInfo += "[OLE2:VBA宏] ";
    }

    /* 加密检测 */
    if (text.find("EncryptionInfo") != std::string::npos ||
        text.find("EncryptedPackage") != std::string::npos)
    {
        result.hasEncryption = true;
        result.structureInfo += "[OLE2:加密] ";
    }

    /* 嵌入对象 */
    if (text.find("ObjInfo") != std::string::npos ||
        text.find("\x01Ole") != std::string::npos ||
        text.find("Package") != std::string::npos)
    {
        result.hasEmbedded = true;
        result.structureInfo += "[OLE2:嵌入对象] ";
    }

    /* 邮件（MSG）特征 */
    if (text.find("__substg1") != std::string::npos ||
        text.find("__properties") != std::string::npos)
        result.structureInfo += "[OLE2:MSG邮件] ";
}

/* ===================================================================
 * ZIP 内部结构分析：检测 Office Open XML 宏、OFD、嵌入对象
 * =================================================================== */
static void AnalyzeZIP(const std::vector<uint8_t>& buf,
                        FileFormatResult& result)
{
    if (buf.size() < 4) return;
    if (memcmp(buf.data(), ZIP_PK, 4) != 0) return;

    std::string text(buf.begin(), buf.end());

    /* Office Open XML 宏 (xlsm/docm/pptm) */
    if (text.find("vbaProject.bin") != std::string::npos ||
        text.find("vbaData.xml") != std::string::npos)
    {
        result.hasMacro = true;
        result.structureInfo += "[ZIP:VBA宏(OOXML)] ";
    }

    /* 加密 ZIP */
    /* 检查 Local File Header 的 General Purpose Bit Flag bit 0 */
    if (buf.size() >= 8)
    {
        uint16_t flags = (uint16_t)(buf[6] | (buf[7] << 8));
        if (flags & 0x0001)
        {
            result.hasEncryption = true;
            result.structureInfo += "[ZIP:加密] ";
        }
    }

    /* OFD 特征 */
    if (text.find("OFD.xml") != std::string::npos ||
        text.find("ofd.xml") != std::string::npos)
        result.structureInfo += "[ZIP:OFD文档] ";

    /* EPUB */
    if (text.find("mimetype") != std::string::npos &&
        text.find("epub") != std::string::npos)
        result.structureInfo += "[ZIP:EPUB电子书] ";

    /* APK/JAR */
    if (text.find("AndroidManifest.xml") != std::string::npos)
        result.structureInfo += "[ZIP:Android APK] ";
    else if (text.find("META-INF/MANIFEST.MF") != std::string::npos)
        result.structureInfo += "[ZIP:Java JAR] ";

    /* 嵌入对象（OOXML 中的 embeddings） */
    if (text.find("embeddings/") != std::string::npos ||
        text.find("oleObject") != std::string::npos)
    {
        result.hasEmbedded = true;
        result.structureInfo += "[ZIP:嵌入OLE对象] ";
    }

    /* 判断 OOXML 具体类型 */
    if (text.find("word/document.xml") != std::string::npos)
        result.detectedFormat = "DOCX/DOCM (Word OOXML)";
    else if (text.find("xl/workbook.xml") != std::string::npos)
        result.detectedFormat = "XLSX/XLSM (Excel OOXML)";
    else if (text.find("ppt/presentation.xml") != std::string::npos)
        result.detectedFormat = "PPTX/PPTM (PowerPoint OOXML)";
    else if (text.find("OFD.xml") != std::string::npos)
        result.detectedFormat = "OFD Document";
}

/* ===================================================================
 * PDF 内部结构分析：检测 JavaScript、嵌入文件、加密
 * =================================================================== */
static void AnalyzePDF(const std::vector<uint8_t>& buf,
                        FileFormatResult& result)
{
    if (buf.size() < 4) return;
    if (memcmp(buf.data(), PDF, 4) != 0) return;

    std::string text(buf.begin(), buf.end());

    if (text.find("/JavaScript") != std::string::npos ||
        text.find("/JS ") != std::string::npos)
    {
        result.hasSuspiciousStr = true;
        result.suspiciousDetail += "[PDF:内嵌JavaScript] ";
    }
    if (text.find("/EmbeddedFile") != std::string::npos ||
        text.find("/Filespec") != std::string::npos)
    {
        result.hasEmbedded = true;
        result.structureInfo += "[PDF:嵌入文件] ";
    }
    if (text.find("/Encrypt") != std::string::npos)
    {
        result.hasEncryption = true;
        result.structureInfo += "[PDF:加密] ";
    }
    if (text.find("/Launch") != std::string::npos ||
        text.find("/OpenAction") != std::string::npos)
    {
        result.hasSuspiciousStr = true;
        result.suspiciousDetail += "[PDF:自动执行动作] ";
    }
    if (text.find("/AcroForm") != std::string::npos)
        result.structureInfo += "[PDF:表单] ";
}

/* ===================================================================
 * 通用可疑字符串检测（脚本、PE 等）
 * =================================================================== */
static const char* g_suspiciousStrings[] = {
    "cmd.exe", "powershell", "wscript", "cscript",
    "mshta", "regsvr32", "rundll32", "certutil",
    "bitsadmin", "wmic", "net user", "net localgroup",
    "mimikatz", "sekurlsa", "lsadump", "hashdump",
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
    "ShellExecute", "WinExec", "CreateProcess",
    "base64", "frombase64", "invoke-expression",
    "downloadstring", "downloadfile", "webclient",
    "http://", "https://", "ftp://",
    NULL
};

static void CheckSuspiciousStrings(const std::vector<uint8_t>& buf,
                                    FileFormatResult& result)
{
    if (buf.empty()) return;
    size_t checkLen = buf.size() < 65536 ? buf.size() : 65536;
    std::string text(buf.begin(), buf.begin() + checkLen);
    /* 转小写副本 */
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    std::vector<std::string> found;
    for (int i = 0; g_suspiciousStrings[i]; i++)
    {
        std::string kw = g_suspiciousStrings[i];
        if (lower.find(kw) != std::string::npos)
            found.push_back(kw);
    }
    if (!found.empty())
    {
        result.hasSuspiciousStr = true;
        for (size_t i = 0; i < found.size() && i < 5; i++)
        {
            if (i > 0) result.suspiciousDetail += ", ";
            result.suspiciousDetail += found[i];
        }
        if (found.size() > 5)
        {
            char cntBuf[32];
            _snprintf_s(cntBuf, sizeof(cntBuf), _TRUNCATE, " ...(%d total)", (int)found.size());
            result.suspiciousDetail += cntBuf;
        }
    }
}

/* ===================================================================
 * 扩展名白名单映射（格式名 → 合法扩展名集合）
 * =================================================================== */
static bool IsExtMatchFormat(const std::string& ext,
                              const std::string& format,
                              const std::string& allowedExts)
{
    if (ext.empty()) return true;  // 无扩展名不判定为伪装
    std::string lext = ext;
    std::transform(lext.begin(), lext.end(), lext.begin(), ::tolower);

    /* 从 allowedExts（逗号分隔）中查找 */
    std::string exts = allowedExts;
    size_t pos = 0;
    while (pos < exts.size())
    {
        size_t comma = exts.find(',', pos);
        std::string e = (comma == std::string::npos)
                        ? exts.substr(pos)
                        : exts.substr(pos, comma - pos);
        if (e == lext) return true;
        pos = (comma == std::string::npos) ? exts.size() : comma + 1;
    }

    /* OLE2 特殊处理：doc/xls/ppt/wps/et/dps/msi/msg 都合法 */
    if (format.find("OLE2") != std::string::npos)
    {
        static const char* ole2Exts[] = {
            ".doc",".xls",".ppt",".wps",".et",".dps",
            ".msi",".msg",".pub",".vsd",NULL
        };
        for (int i = 0; ole2Exts[i]; i++)
            if (lext == ole2Exts[i]) return true;
    }

    /* ZIP 特殊处理 */
    if (format.find("ZIP") != std::string::npos ||
        format.find("OOXML") != std::string::npos ||
        format.find("DOCX") != std::string::npos ||
        format.find("XLSX") != std::string::npos ||
        format.find("PPTX") != std::string::npos)
    {
        static const char* zipExts[] = {
            ".zip",".docx",".xlsx",".pptx",".docm",".xlsm",".pptm",
            ".odt",".ods",".odp",".jar",".apk",".wps",".et",".dps",
            ".ofd",".epub",NULL
        };
        for (int i = 0; zipExts[i]; i++)
            if (lext == zipExts[i]) return true;
    }

    return false;
}

/* ===================================================================
 * 核心检测函数：分析单个文件
 * =================================================================== */
FileFormatResult AnalyzeFile(const std::wstring& pathW)
{
    FileFormatResult result;
    result.filePath      = WideToUtf8(pathW.c_str());
    result.categoryId    = FC_UNKNOWN;
    result.hasMacro      = false;
    result.hasEmbedded   = false;
    result.hasEncryption = false;
    result.hasSuspiciousStr = false;
    result.extMismatch   = false;
    result.fileSize      = GetFileSize64(pathW);

    /* 提取扩展名 */
    std::string path8 = result.filePath;
    size_t dot = path8.rfind('.');
    if (dot != std::string::npos)
        result.fileExt = path8.substr(dot);
    std::transform(result.fileExt.begin(), result.fileExt.end(),
                   result.fileExt.begin(), ::tolower);

    /* 读取文件头 */
    std::vector<uint8_t> buf = ReadFileHeader(pathW);
    if (buf.empty())
    {
        result.errorMessage = "Cannot read file (access denied or empty)";
        result.detectedFormat = "Unknown";
        result.detectedCategory = "unknown";
        return result;
    }

    result.magicHex = ToHexStr(buf);

    /* ---------------------------------------------------------------
     * 1. 特殊偏移魔数检测（ISO、TAR）
     * ------------------------------------------------------------- */
    if (CheckISO(buf))
    {
        result.detectedFormat   = "ISO 9660 Image";
        result.detectedCategory = "archive";
        result.categoryId       = FC_ARCHIVE;
        result.mimeType         = "application/x-iso9660-image";
        goto DONE_MAGIC;
    }
    if (CheckTAR(buf))
    {
        result.detectedFormat   = "TAR Archive";
        result.detectedCategory = "archive";
        result.categoryId       = FC_ARCHIVE;
        result.mimeType         = "application/x-tar";
        goto DONE_MAGIC;
    }

    /* ---------------------------------------------------------------
     * 2. RIFF 容器区分
     * ------------------------------------------------------------- */
    {
        std::string riff = CheckRIFF(buf);
        if (!riff.empty())
        {
            result.detectedFormat   = riff;
            result.detectedCategory = "multimedia";
            result.categoryId       = FC_MULTIMEDIA;
            if (riff == "WAV Audio")
                result.mimeType = "audio/wav";
            else if (riff == "WebP Image")
                result.mimeType = "image/webp";
            else
                result.mimeType = "video/x-msvideo";
            goto DONE_MAGIC;
        }
    }

    /* ---------------------------------------------------------------
     * 3. MP4/MOV (ftyp at offset 4)
     * ------------------------------------------------------------- */
    if (CheckMP4(buf))
    {
        result.detectedFormat   = "MP4/MOV Video";
        result.detectedCategory = "multimedia";
        result.categoryId       = FC_MULTIMEDIA;
        result.mimeType         = "video/mp4";
        goto DONE_MAGIC;
    }

    /* ---------------------------------------------------------------
     * 4. 遍历魔数表
     * ------------------------------------------------------------- */
    for (int i = 0; g_magicTable[i].magic; i++)
    {
        const MagicEntry& e = g_magicTable[i];
        if ((int)buf.size() < e.offset + e.magicLen) continue;
        if (memcmp(buf.data() + e.offset, e.magic, e.magicLen) == 0)
        {
            result.detectedFormat   = e.format;
            result.detectedCategory = e.category;
            result.categoryId       = e.categoryId;
            result.mimeType         = e.mimeType;

            /* 扩展名匹配检测 */
            result.extMismatch = !IsExtMatchFormat(
                result.fileExt, result.detectedFormat, e.ext);
            break;
        }
    }

DONE_MAGIC:
    /* ---------------------------------------------------------------
     * 5. 脚本检测（无魔数，通过内容关键字）
     * ------------------------------------------------------------- */
    if (result.detectedFormat.empty() || result.categoryId == FC_UNKNOWN)
    {
        std::string scriptFmt = DetectScript(buf, result.fileExt);
        if (!scriptFmt.empty())
        {
            result.detectedFormat   = scriptFmt;
            result.detectedCategory = "script";
            result.categoryId       = FC_SCRIPT;
            result.mimeType         = "text/plain";
        }
    }

    /* ---------------------------------------------------------------
     * 6. 深度结构分析
     * ------------------------------------------------------------- */
    if (result.categoryId == FC_DOCUMENT || result.categoryId == FC_COMPOUND)
    {
        AnalyzeOLE2(buf, result);
        AnalyzePDF(buf, result);
    }
    if (result.categoryId == FC_ARCHIVE)
    {
        AnalyzeZIP(buf, result);
    }
    /* ZIP 容器可能是 OOXML 文档 */
    if (result.detectedFormat == "ZIP Archive" ||
        result.detectedFormat == "ZIP Archive (empty)")
    {
        AnalyzeZIP(buf, result);
        if (result.detectedFormat.find("DOCX") != std::string::npos ||
            result.detectedFormat.find("XLSX") != std::string::npos ||
            result.detectedFormat.find("PPTX") != std::string::npos ||
            result.detectedFormat.find("OFD")  != std::string::npos)
        {
            result.detectedCategory = "document";
            result.categoryId       = FC_DOCUMENT;
        }
    }

    /* ---------------------------------------------------------------
     * 7. 可疑字符串检测（脚本、PE、宏文档）
     * ------------------------------------------------------------- */
    if (result.categoryId == FC_SCRIPT ||
        result.categoryId == FC_EXECUTABLE ||
        result.hasMacro)
    {
        CheckSuspiciousStrings(buf, result);
    }

    /* ---------------------------------------------------------------
     * 8. 兜底：仍未识别
     * ------------------------------------------------------------- */
    if (result.detectedFormat.empty())
    {
        result.detectedFormat   = "Unknown";
        result.detectedCategory = "unknown";
        result.categoryId       = FC_UNKNOWN;
    }

    return result;
}

/* ===================================================================
 * SQLite3 存储：建表 + 插入
 * =================================================================== */
static bool EnsureTable(sqlite3* db)
{
    const char* sql =
        "CREATE TABLE IF NOT EXISTS file_format_results ("
        "  id               INTEGER PRIMARY KEY AUTOINCREMENT,"
        "  file_path        TEXT,"
        "  file_ext         TEXT,"
        "  file_size        INTEGER,"
        "  detected_format  TEXT,"
        "  category         TEXT,"
        "  category_id      INTEGER,"
        "  mime_type        TEXT,"
        "  magic_hex        TEXT,"
        "  ext_mismatch     INTEGER,"
        "  has_macro        INTEGER,"
        "  has_embedded     INTEGER,"
        "  has_encryption   INTEGER,"
        "  has_suspicious   INTEGER,"
        "  suspicious_detail TEXT,"
        "  structure_info   TEXT,"
        "  error_message    TEXT,"
        "  scan_time        TEXT"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_ffr_path "
        "  ON file_format_results(file_path);"
        "CREATE INDEX IF NOT EXISTS idx_ffr_format "
        "  ON file_format_results(detected_format);";

    char* errMsg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &errMsg);
    if (errMsg) sqlite3_free(errMsg);
    return rc == SQLITE_OK;
}

static long long InsertResult(sqlite3* db, const FileFormatResult& r)
{
    const char* sql =
        "INSERT INTO file_format_results "
        "(file_path,file_ext,file_size,detected_format,category,category_id,"
        " mime_type,magic_hex,ext_mismatch,has_macro,has_embedded,"
        " has_encryption,has_suspicious,suspicious_detail,structure_info,"
        " error_message,scan_time) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    time_t t = time(NULL);
    struct tm tm2;
    gmtime_s(&tm2, &t);
    char now[32];
    strftime(now, sizeof(now), "%Y-%m-%d %H:%M:%S", &tm2);

    sqlite3_bind_text   (stmt,  1, r.filePath.c_str(),        -1, SQLITE_TRANSIENT);
    sqlite3_bind_text   (stmt,  2, r.fileExt.c_str(),         -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64  (stmt,  3, r.fileSize);
    sqlite3_bind_text   (stmt,  4, r.detectedFormat.c_str(),  -1, SQLITE_TRANSIENT);
    sqlite3_bind_text   (stmt,  5, r.detectedCategory.c_str(),-1, SQLITE_TRANSIENT);
    sqlite3_bind_int    (stmt,  6, r.categoryId);
    sqlite3_bind_text   (stmt,  7, r.mimeType.c_str(),        -1, SQLITE_TRANSIENT);
    sqlite3_bind_text   (stmt,  8, r.magicHex.c_str(),        -1, SQLITE_TRANSIENT);
    sqlite3_bind_int    (stmt,  9, r.extMismatch ? 1 : 0);
    sqlite3_bind_int    (stmt, 10, r.hasMacro ? 1 : 0);
    sqlite3_bind_int    (stmt, 11, r.hasEmbedded ? 1 : 0);
    sqlite3_bind_int    (stmt, 12, r.hasEncryption ? 1 : 0);
    sqlite3_bind_int    (stmt, 13, r.hasSuspiciousStr ? 1 : 0);
    sqlite3_bind_text   (stmt, 14, r.suspiciousDetail.c_str(),-1, SQLITE_TRANSIENT);
    sqlite3_bind_text   (stmt, 15, r.structureInfo.c_str(),   -1, SQLITE_TRANSIENT);
    sqlite3_bind_text   (stmt, 16, r.errorMessage.c_str(),    -1, SQLITE_TRANSIENT);
    sqlite3_bind_text   (stmt, 17, now,                       -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) return -1;
    return (long long)sqlite3_last_insert_rowid(db);
}

/* ===================================================================
 * 将 FileFormatResult 序列化为 cJSON 对象
 * =================================================================== */
static cJSON* ResultToJson(const FileFormatResult& r, long long dbId = -1)
{
    cJSON* item = cJSON_CreateObject();
    if (dbId >= 0)
        cJSON_AddNumberToObject(item, "db_id",           (double)dbId);
    cJSON_AddStringToObject(item, "file_path",           r.filePath.c_str());
    cJSON_AddStringToObject(item, "file_ext",            r.fileExt.c_str());
    cJSON_AddNumberToObject(item, "file_size",           (double)r.fileSize);
    cJSON_AddStringToObject(item, "detected_format",     r.detectedFormat.c_str());
    cJSON_AddStringToObject(item, "category",            r.detectedCategory.c_str());
    cJSON_AddNumberToObject(item, "category_id",         (double)r.categoryId);
    cJSON_AddStringToObject(item, "mime_type",           r.mimeType.c_str());
    cJSON_AddStringToObject(item, "magic_hex",           r.magicHex.c_str());
    cJSON_AddBoolToObject  (item, "ext_mismatch",        r.extMismatch);
    cJSON_AddBoolToObject  (item, "has_macro",           r.hasMacro);
    cJSON_AddBoolToObject  (item, "has_embedded",        r.hasEmbedded);
    cJSON_AddBoolToObject  (item, "has_encryption",      r.hasEncryption);
    cJSON_AddBoolToObject  (item, "has_suspicious_str",  r.hasSuspiciousStr);
    cJSON_AddStringToObject(item, "suspicious_detail",   r.suspiciousDetail.c_str());
    cJSON_AddStringToObject(item, "structure_info",      r.structureInfo.c_str());
    if (!r.errorMessage.empty())
        cJSON_AddStringToObject(item, "error_message",   r.errorMessage.c_str());
    return item;
}

/* ===================================================================
 * 打开 SQLite3 数据库（公共辅助）
 * =================================================================== */
static sqlite3* OpenDb(const std::string& dbPath)
{
    sqlite3* db = NULL;
    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK)
    {
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_exec(db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    EnsureTable(db);
    return db;
}

/* ===================================================================
 * 导出接口：DetectFileFormat
 *
 * paramsJson:
 * {
 *   "files"     : ["C:\\test.exe", "C:\\doc.pdf"],  // 必填，文件路径列表
 *   "db_path"   : "C:\\basic_detect.db",            // 可选，数据库路径
 *   "save_to_db": true                              // 可选，是否存库（默认true）
 * }
 * =================================================================== */
extern "C" __declspec(dllexport)
char* DetectFileFormat(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "detect_file_format");

    std::string dbPath  = GetStringParam(paramsJson, "db_path",
                            "C:\\basic_detect.db");
    bool saveToDb = GetBoolParam(paramsJson, "save_to_db", true);

    cJSON_AddStringToObject(root, "db_path", dbPath.c_str());

    /* 解析文件列表 */
    cJSON* parsed  = paramsJson ? cJSON_Parse(paramsJson) : NULL;
    cJSON* filesArr= parsed ? cJSON_GetObjectItem(parsed, "files") : NULL;

    if (!filesArr || !cJSON_IsArray(filesArr) ||
        cJSON_GetArraySize(filesArr) == 0)
    {
        cJSON_AddStringToObject(root, "status", "error");
        cJSON_AddStringToObject(root, "error_message",
            "\"files\" array is required and must not be empty");
        if (parsed) cJSON_Delete(parsed);
        return SerializeJson(root);
    }

    /* 打开数据库 */
    sqlite3* db = NULL;
    if (saveToDb) db = OpenDb(dbPath);

    cJSON* arr = cJSON_CreateArray();
    int total = 0, saved = 0, errors = 0;
    int tampered = 0, hasMacro = 0, hasEmbed = 0;

    int n = cJSON_GetArraySize(filesArr);
    for (int i = 0; i < n; i++)
    {
        cJSON* item = cJSON_GetArrayItem(filesArr, i);
        if (!item || !cJSON_IsString(item)) continue;

        std::wstring pathW = Utf8ToWstr(item->valuestring);
        FileFormatResult r = AnalyzeFile(pathW);

        long long dbId = -1;
        if (db) dbId = InsertResult(db, r);
        if (dbId >= 0) saved++;
        if (!r.errorMessage.empty()) errors++;
        if (r.extMismatch)  tampered++;
        if (r.hasMacro)     hasMacro++;
        if (r.hasEmbedded)  hasEmbed++;

        cJSON_AddItemToArray(arr, ResultToJson(r, dbId));
        total++;
    }

    if (db) sqlite3_close(db);
    if (parsed) cJSON_Delete(parsed);

    /* 汇总统计 */
    cJSON* summary = cJSON_CreateObject();
    cJSON_AddNumberToObject(summary, "total",          (double)total);
    cJSON_AddNumberToObject(summary, "saved_to_db",    (double)saved);
    cJSON_AddNumberToObject(summary, "errors",         (double)errors);
    cJSON_AddNumberToObject(summary, "ext_mismatch",   (double)tampered);
    cJSON_AddNumberToObject(summary, "has_macro",      (double)hasMacro);
    cJSON_AddNumberToObject(summary, "has_embedded",   (double)hasEmbed);
    cJSON_AddItemToObject(root, "summary", summary);

    cJSON_AddItemToObject(root, "results", arr);
    cJSON_AddStringToObject(root, "status", "success");

    return SerializeJson(root);
}

/* ===================================================================
 * 导出接口：ScanDirectoryFormat
 *
 * paramsJson:
 * {
 *   "directory"     : "C:\\ScanTarget",   // 必填，扫描目录
 *   "recursive"     : true,               // 可选，是否递归（默认true）
 *   "max_files"     : 1000,               // 可选，最多扫描文件数（默认1000）
 *   "filter_category": "executable",      // 可选，只返回指定大类
 *   "db_path"       : "C:\\basic_detect.db",
 *   "save_to_db"    : true
 * }
 * =================================================================== */
extern "C" __declspec(dllexport)
char* ScanDirectoryFormat(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "scan_directory_format");

    std::string dirStr      = GetStringParam(paramsJson, "directory",      "");
    bool        recursive   = GetBoolParam  (paramsJson, "recursive",      true);
    int         maxFiles    = GetIntParam   (paramsJson, "max_files",      1000);
    std::string filterCat   = GetStringParam(paramsJson, "filter_category","");
    std::string dbPath      = GetStringParam(paramsJson, "db_path",
                                "C:\\basic_detect.db");
    bool        saveToDb    = GetBoolParam  (paramsJson, "save_to_db",     true);

    cJSON_AddStringToObject(root, "directory", dirStr.c_str());
    cJSON_AddStringToObject(root, "db_path",   dbPath.c_str());

    if (dirStr.empty())
    {
        cJSON_AddStringToObject(root, "status", "error");
        cJSON_AddStringToObject(root, "error_message",
            "\"directory\" is required");
        return SerializeJson(root);
    }

    std::wstring dirW = Utf8ToWstr(dirStr);

    /* 收集文件列表 */
    std::vector<std::wstring> files;
    std::vector<std::wstring> dirs;
    dirs.push_back(dirW);

    while (!dirs.empty() && (int)files.size() < maxFiles)
    {
        std::wstring cur = dirs.back();
        dirs.pop_back();

        std::wstring pattern = cur + L"\\*";
        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) continue;

        do {
            if (wcscmp(fd.cFileName, L".") == 0 ||
                wcscmp(fd.cFileName, L"..") == 0) continue;

            std::wstring full = cur + L"\\" + fd.cFileName;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                if (recursive) dirs.push_back(full);
            }
            else
            {
                files.push_back(full);
                if ((int)files.size() >= maxFiles) break;
            }
        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
    }

    /* 打开数据库 */
    sqlite3* db = NULL;
    if (saveToDb) db = OpenDb(dbPath);

    cJSON* arr = cJSON_CreateArray();
    int total = 0, saved = 0, errors = 0;
    int tampered = 0, hasMacro = 0, hasEmbed = 0;

    /* 分类计数 */
    std::map<std::string, int> catCount;

    for (size_t fi = 0; fi < files.size(); fi++)
    {
        const std::wstring& fp = files[fi];
        FileFormatResult r = AnalyzeFile(fp);

        /* 大类过滤 */
        if (!filterCat.empty() && r.detectedCategory != filterCat)
            continue;

        long long dbId = -1;
        if (db) dbId = InsertResult(db, r);
        if (dbId >= 0) saved++;
        if (!r.errorMessage.empty()) errors++;
        if (r.extMismatch)  tampered++;
        if (r.hasMacro)     hasMacro++;
        if (r.hasEmbedded)  hasEmbed++;

        catCount[r.detectedCategory]++;
        cJSON_AddItemToArray(arr, ResultToJson(r, dbId));
        total++;
    }

    if (db) sqlite3_close(db);

    /* 汇总 */
    cJSON* summary = cJSON_CreateObject();
    cJSON_AddNumberToObject(summary, "total",        (double)total);
    cJSON_AddNumberToObject(summary, "saved_to_db",  (double)saved);
    cJSON_AddNumberToObject(summary, "errors",       (double)errors);
    cJSON_AddNumberToObject(summary, "ext_mismatch", (double)tampered);
    cJSON_AddNumberToObject(summary, "has_macro",    (double)hasMacro);
    cJSON_AddNumberToObject(summary, "has_embedded", (double)hasEmbed);

    cJSON* cats = cJSON_CreateObject();
    for (std::map<std::string,int>::iterator it = catCount.begin(); it != catCount.end(); ++it)
        cJSON_AddNumberToObject(cats, it->first.c_str(), (double)it->second);
    cJSON_AddItemToObject(summary, "by_category", cats);
    cJSON_AddItemToObject(root, "summary", summary);

    cJSON_AddItemToObject(root, "results", arr);
    cJSON_AddStringToObject(root, "status", "success");

    return SerializeJson(root);
}
