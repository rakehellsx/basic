#pragma once
#ifndef FILE_STATIC_H
#define FILE_STATIC_H

/*
 * FileStatic.h
 * 文件静态信息获取模块 — 内部数据结构定义
 * 覆盖：基础属性 / PE结构解析 / 可打印字符串提取
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>

/* ------------------------------------------------------------------ */
/* 1. 基础文件属性                                                      */
/* ------------------------------------------------------------------ */
struct FileBasicInfo
{
    std::string file_path;          // 完整路径
    std::string file_name;          // 文件名
    std::string file_size;          // 文件大小（字节，字符串）
    std::string create_time;        // 创建时间 UTC
    std::string modify_time;        // 最后修改时间 UTC
    std::string access_time;        // 最后访问时间 UTC
    std::string compile_timestamp;  // PE编译时间戳 UTC（非PE文件为空）
    std::string publisher;          // 发行商（版本资源 CompanyName）
    std::string file_version;       // 文件版本
    std::string product_name;       // 产品名称
    std::string original_filename;  // 原始文件名
    std::string md5;                // MD5 哈希
    std::string sha256;             // SHA-256 哈希
    std::string file_type;          // 文件类型（PE32/PE64/ELF/Script/...）
};

/* ------------------------------------------------------------------ */
/* 2. PE 头信息                                                         */
/* ------------------------------------------------------------------ */
struct PeHeaderInfo
{
    bool        is_pe;              // 是否为有效 PE 文件
    std::string arch;               // 目标架构（x86 / x64 / ARM / ARM64）
    std::string entry_point;        // 入口点 RVA（十六进制）
    std::string image_base;         // 映像基址（十六进制）
    std::string subsystem;          // 子系统（Console / GUI / Driver / ...）
    std::string linker_version;     // 链接器版本
    DWORD       characteristics;    // 文件特征值
    std::string characteristics_desc; // 特征描述（DLL / EXE / ...）
    std::string packer_or_compiler; // 加壳/编译器特征（UPX / MPRESS / MSVC / GCC / ...）
    std::string compile_time;       // 编译时间戳（UTC）
    DWORD       number_of_sections; // 节区数量
    DWORD       size_of_image;      // 映像大小
    DWORD       size_of_headers;    // 头部大小
    bool        has_tls;            // 是否含 TLS 目录
    bool        has_resources;      // 是否含资源目录
    bool        has_debug;          // 是否含调试目录
    bool        has_reloc;          // 是否含重定位表
};

/* ------------------------------------------------------------------ */
/* 3. 节区信息                                                          */
/* ------------------------------------------------------------------ */
enum SectionStatus
{
    SECTION_NORMAL = 0,   // 正常
    SECTION_HIGH_ENTROPY, // 高熵（疑似加密/压缩）
    SECTION_SUSPICIOUS,   // 可疑（可执行且可写）
    SECTION_ABNORMAL      // 异常（名称异常/大小不匹配）
};

struct SectionInfo
{
    std::string name;           // 节区名（最多8字节）
    std::string virtual_addr;   // 虚拟地址（十六进制 RVA）
    DWORD       virtual_size;   // 虚拟大小
    DWORD       raw_size;       // 原始大小
    std::string characteristics;// 特征（十六进制）
    std::string char_desc;      // 特征描述（R/W/X 组合）
    double      entropy;        // 熵值（0.0 ~ 8.0）
    SectionStatus status;       // 节区状态
    std::string status_desc;    // 状态描述
};

/* ------------------------------------------------------------------ */
/* 4. 导入表条目                                                        */
/* ------------------------------------------------------------------ */
enum ImportRisk
{
    RISK_LOW    = 0,  // 低风险
    RISK_MEDIUM = 1,  // 中危（网络通信）
    RISK_HIGH   = 2   // 高危（进程注入/代码执行）
};

struct ImportFunction
{
    std::string func_name;    // 函数名
    WORD        ordinal;      // 序号（按序号导入时有效）
    ImportRisk  risk;         // 风险等级
    std::string risk_desc;    // 风险描述
};

struct ImportDll
{
    std::string dll_name;                   // DLL 名称
    std::vector<ImportFunction> functions;  // 导入函数列表
    ImportRisk  max_risk;                   // 该 DLL 最高风险等级
};

/* ------------------------------------------------------------------ */
/* 5. 可打印字符串                                                      */
/* ------------------------------------------------------------------ */
struct ExtractedStrings
{
    std::vector<std::string> ascii_strings;   // ASCII 可打印字符串
    std::vector<std::string> unicode_strings; // Unicode 可打印字符串
    int total_count;                          // 总数量
    std::string strings_file_path;            // 字符串输出文件路径（SQLite3 中只存该路径）
};

/* ------------------------------------------------------------------ */
/* 6. 完整静态分析结果                                                  */
/* ------------------------------------------------------------------ */
struct FileStaticResult
{
    FileBasicInfo           basic;
    PeHeaderInfo            pe_header;
    std::vector<SectionInfo> sections;
    std::vector<ImportDll>  imports;
    ExtractedStrings        strings;
    std::string             error_msg;  // 错误信息（成功时为空）
};

#endif /* FILE_STATIC_H */
