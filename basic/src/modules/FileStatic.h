#pragma once
#ifndef FILE_STATIC_H
#define FILE_STATIC_H

/*
 * FileStatic.h
 * File static information module - internal data structure definitions.
 * Covers: basic attributes / PE structure parsing / printable string extraction.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>

/* ------------------------------------------------------------------ */
/* 1. Basic file attributes                                             */
/* ------------------------------------------------------------------ */
struct FileBasicInfo
{
    std::string file_path;          // Full path
    std::string file_name;          // File name
    std::string file_size;          // File size in bytes (string)
    std::string create_time;        // Creation time (UTC)
    std::string modify_time;        // Last write time (UTC)
    std::string access_time;        // Last access time (UTC)
    std::string compile_timestamp;  // PE compile timestamp UTC (empty for non-PE)
    std::string publisher;          // Publisher (version resource CompanyName)
    std::string file_version;       // File version string
    std::string product_name;       // Product name
    std::string original_filename;  // Original filename
    std::string md5;                // MD5 hash
    std::string sha256;             // SHA-256 hash
    std::string file_type;          // File type (PE32/PE64/ELF/Script/...)
};

/* ------------------------------------------------------------------ */
/* 2. PE header information                                             */
/* ------------------------------------------------------------------ */
struct PeHeaderInfo
{
    bool        is_pe;              // Whether it is a valid PE file
    std::string arch;               // Target architecture (x86/x64/ARM/ARM64)
    std::string entry_point;        // Entry point RVA (hex)
    std::string image_base;         // Image base address (hex)
    std::string subsystem;          // Subsystem (Console/GUI/Driver/...)
    std::string linker_version;     // Linker version string
    DWORD       characteristics;    // File characteristics flags
    std::string characteristics_desc; // Characteristics description (DLL/EXE/...)
    std::string packer_or_compiler; // Packer/compiler hint (UPX/MPRESS/MSVC/GCC/...)
    std::string compile_time;       // Compile timestamp (UTC)
    DWORD       number_of_sections; // Number of sections
    DWORD       size_of_image;      // Size of image in memory
    DWORD       size_of_headers;    // Size of headers
    bool        has_tls;            // Has TLS directory
    bool        has_resources;      // Has resource directory
    bool        has_debug;          // Has debug directory
    bool        has_reloc;          // Has relocation table
};

/* ------------------------------------------------------------------ */
/* 3. Section information                                               */
/* ------------------------------------------------------------------ */
enum SectionStatus
{
    SECTION_NORMAL = 0,   // Normal
    SECTION_HIGH_ENTROPY, // High entropy (possibly encrypted/compressed)
    SECTION_SUSPICIOUS,   // Suspicious (executable and writable)
    SECTION_ABNORMAL      // Abnormal (unusual name or size mismatch)
};

struct SectionInfo
{
    std::string name;           // Section name (up to 8 bytes)
    std::string virtual_addr;   // Virtual address (hex RVA)
    DWORD       virtual_size;   // Virtual size
    DWORD       raw_size;       // Raw size on disk
    std::string characteristics;// Characteristics flags (hex)
    std::string char_desc;      // Characteristics description (R/W/X combination)
    double      entropy;        // Shannon entropy (0.0 ~ 8.0)
    SectionStatus status;       // Section status classification
    std::string status_desc;    // Status description string
};

/* ------------------------------------------------------------------ */
/* 4. Import table entries                                              */
/* ------------------------------------------------------------------ */
enum ImportRisk
{
    RISK_LOW    = 0,  // Low risk
    RISK_MEDIUM = 1,  // Medium risk (network communication)
    RISK_HIGH   = 2   // High risk (process injection / code execution)
};

struct ImportFunction
{
    std::string func_name;    // Function name
    WORD        ordinal;      // Ordinal (valid when imported by ordinal)
    ImportRisk  risk;         // Risk level
    std::string risk_desc;    // Risk description
};

struct ImportDll
{
    std::string dll_name;                   // DLL name
    std::vector<ImportFunction> functions;  // Imported function list
    ImportRisk  max_risk;                   // Highest risk level in this DLL
};

/* ------------------------------------------------------------------ */
/* 5. Extracted printable strings                                       */
/* ------------------------------------------------------------------ */
struct ExtractedStrings
{
    std::vector<std::string> ascii_strings;   // ASCII printable strings
    std::vector<std::string> unicode_strings; // Unicode printable strings
    int total_count;                          // Total string count
    std::string strings_file_path;            // Output file path (SQLite3 stores only this path)
};

/* ------------------------------------------------------------------ */
/* 6. Complete static analysis result                                   */
/* ------------------------------------------------------------------ */
struct FileStaticResult
{
    FileBasicInfo            basic;
    PeHeaderInfo             pe_header;
    std::vector<SectionInfo> sections;
    std::vector<ImportDll>   imports;
    ExtractedStrings         strings;
    std::string              error_msg;  // Error message (empty on success)
};

#endif /* FILE_STATIC_H */
