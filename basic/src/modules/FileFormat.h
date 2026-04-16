#pragma once
/*
 * FileFormat.h
 * 文件格式检测模块 — 内部数据结构与魔数定义
 */
#ifndef FILE_FORMAT_H
#define FILE_FORMAT_H

#include <string>
#include <vector>
#include <stdint.h>

/* -----------------------------------------------------------------------
 * 文件大类枚举
 * --------------------------------------------------------------------- */
enum FileCategory
{
    FC_UNKNOWN      = 0,
    FC_EXECUTABLE   = 1,   // 可执行文件
    FC_SCRIPT       = 2,   // 脚本文件
    FC_DOCUMENT     = 3,   // 文档文件
    FC_ARCHIVE      = 4,   // 压缩/归档文件
    FC_MULTIMEDIA   = 5,   // 多媒体文件
    FC_COMPOUND     = 6,   // 复合文件（OLE/ZIP容器）
};

/* -----------------------------------------------------------------------
 * 单个文件的格式检测结果
 * --------------------------------------------------------------------- */
struct FileFormatResult
{
    std::string filePath;         // 文件路径
    std::string fileExt;          // 文件扩展名（小写）
    std::string detectedFormat;   // 通过魔数识别的真实格式
    std::string detectedCategory; // 大类名称
    int         categoryId;       // 大类 ID（FileCategory 枚举值）
    std::string mimeType;         // MIME 类型
    std::string magicHex;         // 文件头前16字节十六进制
    bool        extMismatch;      // 扩展名与真实格式不符（格式伪装）
    bool        hasMacro;         // 是否包含宏（Office/OLE）
    bool        hasEmbedded;      // 是否包含嵌入对象
    bool        hasEncryption;    // 是否加密
    bool        hasSuspiciousStr; // 是否包含可疑字符串
    std::string suspiciousDetail; // 可疑字符串详情
    std::string structureInfo;    // 格式结构附加信息
    long long   fileSize;         // 文件大小（字节）
    std::string errorMessage;     // 错误信息（无法读取时）
};

/* -----------------------------------------------------------------------
 * 魔数签名表条目
 * --------------------------------------------------------------------- */
struct MagicEntry
{
    const uint8_t* magic;         // 魔数字节序列
    int            magicLen;      // 魔数长度
    int            offset;        // 在文件中的偏移量
    const char*    format;        // 格式名称
    const char*    category;      // 大类名称
    int            categoryId;    // 大类 ID
    const char*    mimeType;      // MIME 类型
    const char*    ext;           // 对应扩展名（逗号分隔）
};

#endif /* FILE_FORMAT_H */
