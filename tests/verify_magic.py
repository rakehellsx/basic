#!/usr/bin/env python3
"""
verify_magic.py
文件格式魔数验证脚本 — 模拟 FileFormat.cpp 的检测逻辑
验证测试文件的魔数识别、分类、伪装检测是否正确
"""

import os
import sys
import json
import struct
import zipfile
import datetime
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).parent / "test_files"
DB_PATH  = Path(__file__).parent / "test_results.db"
REPORT_PATH = Path(__file__).parent / "test_report.md"

# ============================================================
# 魔数表（与 FileFormat.cpp 保持一致）
# ============================================================
MAGIC_TABLE = [
    # (magic_bytes, offset, format_name, category, mime, allowed_exts)
    (bytes([0x7F,0x45,0x4C,0x46]),          0, "ELF Executable",           "executable", "application/x-elf",              [".elf",".so",".bin"]),
    (bytes([0xCF,0xFA,0xED,0xFE]),          0, "Mach-O 64-bit",            "executable", "application/x-mach-binary",      [".macho"]),
    (bytes([0xCE,0xFA,0xED,0xFE]),          0, "Mach-O 32-bit",            "executable", "application/x-mach-binary",      [".macho"]),
    (b'MZ',                                 0, "PE Executable (MZ)",        "executable", "application/x-msdownload",       [".exe",".dll",".sys",".drv",".ocx",".scr",".cpl",".com"]),
    (bytes([0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1]), 0, "OLE2 Compound Document", "document", "application/msword", [".doc",".xls",".ppt",".msi",".msg",".wps",".et",".dps"]),
    (b'{\\rtf',                             0, "Rich Text Format (RTF)",    "document",   "application/rtf",                [".rtf"]),
    (b'%PDF',                               0, "PDF Document",              "document",   "application/pdf",                [".pdf"]),
    (bytes([0x49,0x54,0x53,0x46]),          0, "CHM Help File",             "document",   "application/vnd.ms-htmlhelp",    [".chm"]),
    (bytes([0x52,0x61,0x72,0x21,0x1A,0x07,0x01,0x00]), 0, "RAR Archive v5","archive",   "application/x-rar-compressed",   [".rar"]),
    (bytes([0x52,0x61,0x72,0x21,0x1A,0x07,0x00]),      0, "RAR Archive v4","archive",   "application/x-rar-compressed",   [".rar"]),
    (bytes([0x37,0x7A,0xBC,0xAF,0x27,0x1C]),           0, "7-Zip Archive", "archive",   "application/x-7z-compressed",    [".7z"]),
    (bytes([0x4D,0x53,0x57,0x49,0x4D,0x00,0x00,0x00]), 0, "Windows Imaging (WIM)", "archive", "application/x-ms-wim",    [".wim"]),
    (bytes([0x4D,0x53,0x43,0x46]),          0, "Cabinet Archive (CAB)",     "archive",   "application/vnd.ms-cab-compressed",[".cab"]),
    (bytes([0xFD,0x37,0x7A,0x58,0x5A,0x00]),           0, "XZ Archive",    "archive",   "application/x-xz",               [".xz"]),
    (bytes([0x42,0x5A,0x68]),               0, "BZip2 Archive",             "archive",   "application/x-bzip2",            [".bz2",".bzip2"]),
    (bytes([0x1F,0x8B]),                    0, "GZip Archive",              "archive",   "application/gzip",               [".gz",".tgz"]),
    (bytes([0x60,0xEA]),                    0, "ARJ Archive",               "archive",   "application/x-arj",              [".arj"]),
    (bytes([0x50,0x4B,0x03,0x04]),          0, "ZIP Archive",               "archive",   "application/zip",                [".zip",".docx",".xlsx",".pptx",".docm",".xlsm",".pptm",".odt",".ods",".odp",".jar",".apk",".wps",".et",".dps",".ofd",".epub"]),
    (bytes([0x50,0x4B,0x05,0x06]),          0, "ZIP Archive (empty)",       "archive",   "application/zip",                [".zip"]),
    (bytes([0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A]), 0, "PNG Image",    "multimedia","image/png",                       [".png"]),
    (bytes([0x47,0x49,0x46,0x38,0x39,0x61]),           0, "GIF89a Image",  "multimedia","image/gif",                       [".gif"]),
    (bytes([0x47,0x49,0x46,0x38,0x37,0x61]),           0, "GIF87a Image",  "multimedia","image/gif",                       [".gif"]),
    (bytes([0xFF,0xD8,0xFF]),               0, "JPEG Image",                "multimedia","image/jpeg",                      [".jpg",".jpeg"]),
    (bytes([0x49,0x49,0x2A,0x00]),          0, "TIFF Image (LE)",           "multimedia","image/tiff",                      [".tif",".tiff"]),
    (bytes([0x4D,0x4D,0x00,0x2A]),          0, "TIFF Image (BE)",           "multimedia","image/tiff",                      [".tif",".tiff"]),
    (bytes([0x00,0x00,0x01,0x00]),          0, "ICO Icon",                  "multimedia","image/x-icon",                    [".ico"]),
    (bytes([0x42,0x4D]),                    0, "BMP Image",                 "multimedia","image/bmp",                       [".bmp"]),
    (bytes([0x46,0x57,0x53]),               0, "SWF Flash (uncompressed)",  "multimedia","application/x-shockwave-flash",   [".swf"]),
    (bytes([0x43,0x57,0x53]),               0, "SWF Flash (ZLIB)",          "multimedia","application/x-shockwave-flash",   [".swf"]),
    (bytes([0x5A,0x57,0x53]),               0, "SWF Flash (LZMA)",          "multimedia","application/x-shockwave-flash",   [".swf"]),
    (bytes([0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11]), 0, "ASF/WMV/WMA Media","multimedia","video/x-ms-asf",             [".wmv",".wma",".asf"]),
    (bytes([0x46,0x4C,0x56,0x01]),          0, "FLV Flash Video",           "multimedia","video/x-flv",                     [".flv"]),
    (bytes([0x1A,0x45,0xDF,0xA3]),          0, "MKV/WebM (EBML)",           "multimedia","video/x-matroska",                [".mkv",".webm"]),
    (bytes([0x00,0x00,0x01,0xBA]),          0, "MPEG Program Stream",       "multimedia","video/mpeg",                      [".mpg",".mpeg",".vob"]),
    (bytes([0x66,0x4C,0x61,0x43]),          0, "FLAC Audio",                "multimedia","audio/flac",                      [".flac"]),
    (bytes([0x4F,0x67,0x67,0x53]),          0, "OGG Container",             "multimedia","audio/ogg",                       [".ogg",".ogv",".oga"]),
    (bytes([0x49,0x44,0x33]),               0, "MP3 Audio (ID3)",           "multimedia","audio/mpeg",                      [".mp3"]),
    (bytes([0xFF,0xFB]),                    0, "MP3 Audio (sync)",          "multimedia","audio/mpeg",                      [".mp3"]),
    (bytes([0xFF,0xF1]),                    0, "AAC Audio (ADTS)",          "multimedia","audio/aac",                       [".aac"]),
    (b'From ',                              0, "EML Email (mbox)",          "compound",  "message/rfc822",                  [".eml",".mbox"]),
    (b'MIME-',                              0, "EML Email (MIME)",          "compound",  "message/rfc822",                  [".eml"]),
    (bytes([0x53,0x51,0x4C,0x69,0x74,0x65,0x20,0x66]), 0, "SQLite3 Database","database","application/x-sqlite3",          [".db",".sqlite",".sqlite3"]),
]

SCRIPT_KEYWORDS = [
    ("#!/bin/bash",         "Bash Shell Script",    "script"),
    ("#!/bin/sh",           "Shell Script",         "script"),
    ("#!/usr/bin/python",   "Python Script",        "script"),
    ("#!/usr/bin/env python","Python Script",       "script"),
    ("import os",           "Python Script",        "script"),
    ("import sys",          "Python Script",        "script"),
    ("def ",                "Python Script",        "script"),
    ("<#",                  "PowerShell Script",    "script"),
    ("param(",              "PowerShell Script",    "script"),
    ("@echo off",           "Batch Script",         "script"),
    ("@ECHO OFF",           "Batch Script",         "script"),
    ("WScript.Shell",       "VBScript",             "script"),
    ("CreateObject",        "VBScript/JScript",     "script"),
    ("On Error Resume",     "VBScript",             "script"),
    ("var ",                "JavaScript",           "script"),
    ("function(",           "JavaScript",           "script"),
    ("require(",            "Node.js Script",       "script"),
]

EXT_SCRIPT_MAP = {
    ".bat": "Batch Script",  ".cmd": "Batch Script",
    ".ps1": "PowerShell Script",
    ".vbs": "VBScript",
    ".js":  "JavaScript",
    ".py":  "Python Script",
    ".sh":  "Shell Script",
    ".rb":  "Ruby Script",
    ".pl":  "Perl Script",
    ".lua": "Lua Script",
}

def read_header(path, n=65536):
    try:
        with open(path, 'rb') as f:
            return f.read(n)
    except Exception:
        return b''

def detect_magic(data, ext):
    """返回 (format, category, mime, allowed_exts)"""
    # 特殊：ISO 9660
    if len(data) >= 0x8006 and data[0x8001:0x8006] == b'CD001':
        return "ISO 9660 Image", "archive", "application/x-iso9660-image", [".iso"]
    # 特殊：TAR ustar
    if len(data) >= 262 and data[257:262] == b'ustar':
        return "TAR Archive", "archive", "application/x-tar", [".tar"]
    # RIFF 容器
    if len(data) >= 12 and data[:4] == bytes([0x52,0x49,0x46,0x46]):
        fourcc = data[8:12]
        if fourcc == b'AVI ':
            return "AVI Video", "multimedia", "video/x-msvideo", [".avi"]
        if fourcc == b'WAVE':
            return "WAV Audio", "multimedia", "audio/wav", [".wav"]
        if fourcc == b'WEBP':
            return "WebP Image", "multimedia", "image/webp", [".webp"]
        return "RIFF Container", "multimedia", "application/octet-stream", []
    # MP4/MOV (ftyp at offset 4)
    if len(data) >= 8 and data[4:8] == bytes([0x66,0x74,0x79,0x70]):
        return "MP4/MOV Video", "multimedia", "video/mp4", [".mp4",".mov",".m4v"]
    # 遍历魔数表
    for magic, offset, fmt, cat, mime, exts in MAGIC_TABLE:
        if len(data) >= offset + len(magic):
            if data[offset:offset+len(magic)] == magic:
                return fmt, cat, mime, exts
    # 脚本检测
    try:
        text = data[:4096].decode('utf-8', errors='replace')
        for kw, fmt, cat in SCRIPT_KEYWORDS:
            if kw in text:
                return fmt, cat, "text/plain", []
    except Exception:
        pass
    if ext in EXT_SCRIPT_MAP:
        return EXT_SCRIPT_MAP[ext], "script", "text/plain", []
    return "Unknown", "unknown", "application/octet-stream", []

def analyze_ooxml(data):
    """ZIP内部结构分析"""
    info = {}
    try:
        text = data.decode('latin-1', errors='replace')
        if 'vbaProject.bin' in text or 'vbaData.xml' in text:
            info['has_macro'] = True
        if 'word/document.xml' in text:
            info['ooxml_type'] = 'DOCX/DOCM'
        elif 'xl/workbook.xml' in text:
            info['ooxml_type'] = 'XLSX/XLSM'
        elif 'ppt/presentation.xml' in text:
            info['ooxml_type'] = 'PPTX/PPTM'
        elif 'OFD.xml' in text or 'ofd.xml' in text:
            info['ooxml_type'] = 'OFD'
        if 'embeddings/' in text or 'oleObject' in text:
            info['has_embedded'] = True
        # 加密标志
        if len(data) >= 8:
            flags = data[6] | (data[7] << 8)
            if flags & 0x0001:
                info['has_encryption'] = True
    except Exception:
        pass
    return info

def analyze_ole2(data):
    info = {}
    try:
        text = data.decode('latin-1', errors='replace')
        if '_VBA_PROJECT' in text or 'ThisDocument' in text or 'ThisWorkbook' in text:
            info['has_macro'] = True
        if 'EncryptionInfo' in text or 'EncryptedPackage' in text:
            info['has_encryption'] = True
        if '__substg1' in text or '__properties' in text:
            info['is_email_msg'] = True
        if '\x01Ole' in text or 'Package' in text:
            info['has_embedded'] = True
    except Exception:
        pass
    return info

def analyze_pdf(data):
    info = {}
    try:
        text = data.decode('latin-1', errors='replace')
        if '/JavaScript' in text or '/JS ' in text:
            info['has_js'] = True
        if '/EmbeddedFile' in text:
            info['has_embedded'] = True
        if '/Encrypt' in text:
            info['has_encryption'] = True
        if '/Launch' in text or '/OpenAction' in text:
            info['has_auto_action'] = True
    except Exception:
        pass
    return info

def check_ext_mismatch(ext, fmt, allowed_exts):
    if not ext:
        return False
    ext = ext.lower()
    return ext not in [e.lower() for e in allowed_exts] if allowed_exts else False

def analyze_file(filepath):
    path = Path(filepath)
    ext  = path.suffix.lower()
    data = read_header(filepath)
    size = os.path.getsize(filepath)
    magic_hex = ' '.join(f'{b:02X}' for b in data[:16])

    fmt, cat, mime, allowed_exts = detect_magic(data, ext)

    ext_mismatch = check_ext_mismatch(ext, fmt, allowed_exts)

    extra = {}
    if fmt.startswith("OLE2"):
        extra = analyze_ole2(data)
    elif fmt.startswith("ZIP") or fmt in ("DOCX/DOCM","XLSX/XLSM","PPTX/PPTM","OFD Document"):
        extra = analyze_ooxml(data)
    elif fmt == "PDF Document":
        extra = analyze_pdf(data)

    return {
        "file_path":        str(filepath),
        "file_name":        path.name,
        "file_ext":         ext,
        "file_size":        size,
        "detected_format":  fmt,
        "category":         cat,
        "mime_type":        mime,
        "magic_hex":        magic_hex,
        "ext_mismatch":     ext_mismatch,
        "has_macro":        extra.get("has_macro", False),
        "has_embedded":     extra.get("has_embedded", False),
        "has_encryption":   extra.get("has_encryption", False),
        "ooxml_type":       extra.get("ooxml_type", ""),
        "is_email_msg":     extra.get("is_email_msg", False),
        "has_js":           extra.get("has_js", False),
        "has_auto_action":  extra.get("has_auto_action", False),
    }

def init_db(db_path):
    conn = sqlite3.connect(str(db_path))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS file_format_results (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path       TEXT,
            file_name       TEXT,
            file_ext        TEXT,
            file_size       INTEGER,
            detected_format TEXT,
            category        TEXT,
            mime_type       TEXT,
            magic_hex       TEXT,
            ext_mismatch    INTEGER,
            has_macro       INTEGER,
            has_embedded    INTEGER,
            has_encryption  INTEGER,
            ooxml_type      TEXT,
            is_email_msg    INTEGER,
            has_js          INTEGER,
            has_auto_action INTEGER,
            scan_time       TEXT
        )
    """)
    conn.commit()
    return conn

def insert_result(conn, r):
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
        INSERT INTO file_format_results
        (file_path,file_name,file_ext,file_size,detected_format,category,
         mime_type,magic_hex,ext_mismatch,has_macro,has_embedded,has_encryption,
         ooxml_type,is_email_msg,has_js,has_auto_action,scan_time)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        r["file_path"], r["file_name"], r["file_ext"], r["file_size"],
        r["detected_format"], r["category"], r["mime_type"], r["magic_hex"],
        1 if r["ext_mismatch"] else 0,
        1 if r["has_macro"] else 0,
        1 if r["has_embedded"] else 0,
        1 if r["has_encryption"] else 0,
        r["ooxml_type"],
        1 if r["is_email_msg"] else 0,
        1 if r["has_js"] else 0,
        1 if r["has_auto_action"] else 0,
        now
    ))
    conn.commit()

# ============================================================
# 预期结果表（用于断言验证）
# ============================================================
EXPECTED = {
    # 可执行文件
    "test_elf.elf":    ("ELF Executable",          "executable", False),
    "test_so.so":      ("ELF Executable",          "executable", False),
    "test_pe.exe":     ("PE Executable (MZ)",       "executable", False),
    "test_dll.dll":    ("PE Executable (MZ)",       "executable", False),
    "test_sys.sys":    ("PE Executable (MZ)",       "executable", False),
    "test_bin.bin":    ("ELF Executable",           "executable", False),
    # 脚本文件
    "test_bat.bat":    ("Batch Script",             "script",     False),
    "test_vbs.vbs":    ("VBScript/JScript",         "script",     False),
    "test_ps1.ps1":    ("PowerShell Script",        "script",     False),
    "test_py.py":      ("Python Script",            "script",     False),
    "test_js.js":      ("JavaScript",               "script",     False),
    "test_sh.sh":      ("Bash Shell Script",        "script",     False),
    # 文档文件
    "test_pdf.pdf":    ("PDF Document",             "document",   False),
    "test_rtf.rtf":    ("Rich Text Format (RTF)",   "document",   False),
    "test_doc.doc":    ("OLE2 Compound Document",   "document",   False),
    "test_chm.chm":    ("CHM Help File",            "document",   False),
    "test_docx.docx":  ("ZIP Archive",              "archive",    False),
    "test_xlsx.xlsx":  ("ZIP Archive",              "archive",    False),
    "test_pptx.pptx":  ("ZIP Archive",              "archive",    False),
    "test_ofd.ofd":    ("ZIP Archive",              "archive",    False),
    # 压缩文件
    "test_zip.zip":    ("ZIP Archive",              "archive",    False),
    "test_gz.gz":      ("GZip Archive",             "archive",    False),
    "test_bz2.bz2":    ("BZip2 Archive",            "archive",    False),
    "test_xz.xz":      ("XZ Archive",               "archive",    False),
    "test_7z.7z":      ("7-Zip Archive",            "archive",    False),
    "test_rar4.rar":   ("RAR Archive v4",           "archive",    False),
    "test_rar5.rar":   ("RAR Archive v5",           "archive",    False),
    "test_cab.cab":    ("Cabinet Archive (CAB)",    "archive",    False),
    "test_wim.wim":    ("Windows Imaging (WIM)",    "archive",    False),
    "test_arj.arj":    ("ARJ Archive",              "archive",    False),
    "test_iso.iso":    ("ISO 9660 Image",           "archive",    False),
    "test_tar.tar":    ("TAR Archive",              "archive",    False),
    # 多媒体文件
    "test_png.png":    ("PNG Image",                "multimedia", False),
    "test_jpg.jpg":    ("JPEG Image",               "multimedia", False),
    "test_gif.gif":    ("GIF89a Image",             "multimedia", False),
    "test_bmp.bmp":    ("BMP Image",                "multimedia", False),
    "test_swf.swf":    ("SWF Flash (uncompressed)", "multimedia", False),
    "test_mp3.mp3":    ("MP3 Audio (ID3)",          "multimedia", False),
    "test_avi.avi":    ("AVI Video",                "multimedia", False),
    "test_wmv.wmv":    ("ASF/WMV/WMA Media",        "multimedia", False),
    "test_mp4.mp4":    ("MP4/MOV Video",            "multimedia", False),
    "test_mkv.mkv":    ("MKV/WebM (EBML)",          "multimedia", False),
    "test_vob.vob":    ("MPEG Program Stream",      "multimedia", False),
    "test_wav.wav":    ("WAV Audio",                "multimedia", False),
    # 复合文件
    "test_eml.eml":    ("EML Email (mbox)",         "compound",   False),
    "test_msg.msg":    ("OLE2 Compound Document",   "document",   False),
    # 伪装文件（ext_mismatch=True）
    "elf_disguised_as.txt":  ("ELF Executable",     "executable", True),
    "pe_disguised_as.jpg":   ("PE Executable (MZ)", "executable", True),
    "zip_disguised_as.doc":  ("ZIP Archive",        "archive",    True),
    "pdf_disguised_as.png":  ("PDF Document",       "document",   True),
}

def main():
    print("=" * 70)
    print("  文件格式魔数验证测试")
    print(f"  测试时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # 收集所有测试文件
    all_files = list(BASE_DIR.rglob("*"))
    all_files = [f for f in all_files if f.is_file()]
    all_files.sort()

    # 初始化数据库
    conn = init_db(DB_PATH)

    results = []
    passed = 0
    failed = 0
    skipped = 0

    for filepath in all_files:
        r = analyze_file(filepath)
        insert_result(conn, r)
        results.append(r)

        fname = filepath.name
        expected = EXPECTED.get(fname)

        if expected:
            exp_fmt, exp_cat, exp_mismatch = expected
            # 格式名允许部分匹配（因为 OOXML 可能被进一步细化）
            fmt_ok = (r["detected_format"] == exp_fmt or
                      exp_fmt in r["detected_format"] or
                      r["detected_format"] in exp_fmt)
            cat_ok = r["category"] == exp_cat
            mis_ok = r["ext_mismatch"] == exp_mismatch

            if fmt_ok and cat_ok and mis_ok:
                status = "PASS"
                passed += 1
            else:
                status = "FAIL"
                failed += 1
        else:
            status = "INFO"
            skipped += 1

        icon = {"PASS": "✓", "FAIL": "✗", "INFO": "·"}[status]
        mismatch_flag = " [DISGUISED!]" if r["ext_mismatch"] else ""
        macro_flag    = " [MACRO]"      if r["has_macro"]    else ""
        print(f"  {icon} [{status}] {fname:<35} → {r['detected_format']:<30} ({r['category']}){mismatch_flag}{macro_flag}")

    conn.close()

    total = len(results)
    print()
    print("=" * 70)
    print(f"  总计: {total} 个文件  |  通过: {passed}  |  失败: {failed}  |  信息: {skipped}")
    print(f"  数据库: {DB_PATH}")
    print("=" * 70)

    # ============================================================
    # 分类统计
    # ============================================================
    from collections import Counter
    cat_count = Counter(r["category"] for r in results)
    fmt_count = Counter(r["detected_format"] for r in results)
    mismatch_list = [r for r in results if r["ext_mismatch"]]
    macro_list    = [r for r in results if r["has_macro"]]

    print("\n  分类统计:")
    for cat, cnt in sorted(cat_count.items()):
        print(f"    {cat:<20} : {cnt} 个")

    print(f"\n  格式伪装文件: {len(mismatch_list)} 个")
    for r in mismatch_list:
        print(f"    - {r['file_name']}: 扩展名={r['file_ext']}  真实格式={r['detected_format']}")

    print(f"\n  含宏文件: {len(macro_list)} 个")
    for r in macro_list:
        print(f"    - {r['file_name']}")

    # ============================================================
    # 生成 Markdown 测试报告
    # ============================================================
    generate_report(results, passed, failed, skipped, cat_count, mismatch_list, macro_list)
    print(f"\n  测试报告已生成: {REPORT_PATH}")

    return 0 if failed == 0 else 1

def generate_report(results, passed, failed, skipped, cat_count, mismatch_list, macro_list):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
    lines.append("# 文件格式检测模块 — 测试报告\n")
    lines.append(f"**测试时间**: {now}  \n")
    lines.append(f"**测试文件总数**: {len(results)}  \n")
    lines.append(f"**通过**: {passed}  |  **失败**: {failed}  |  **信息**: {skipped}\n\n")
    lines.append("---\n\n")

    lines.append("## 分类统计\n\n")
    lines.append("| 大类 | 文件数 |\n|---|---|\n")
    for cat, cnt in sorted(cat_count.items()):
        lines.append(f"| {cat} | {cnt} |\n")
    lines.append("\n")

    lines.append("## 详细检测结果\n\n")
    lines.append("| 文件名 | 扩展名 | 检测格式 | 大类 | 格式伪装 | 含宏 | 含嵌入 | 加密 | 验证结果 |\n")
    lines.append("|---|---|---|---|---|---|---|---|---|\n")

    for r in results:
        fname   = r["file_name"]
        ext     = r["file_ext"]
        fmt     = r["detected_format"]
        cat     = r["category"]
        mismatch= "**是**" if r["ext_mismatch"] else "否"
        macro   = "**是**" if r["has_macro"]    else "否"
        embed   = "**是**" if r["has_embedded"] else "否"
        enc     = "**是**" if r["has_encryption"] else "否"

        expected = EXPECTED.get(fname)
        if expected:
            exp_fmt, exp_cat, exp_mis = expected
            fmt_ok = (fmt == exp_fmt or exp_fmt in fmt or fmt in exp_fmt)
            ok = fmt_ok and (cat == exp_cat) and (r["ext_mismatch"] == exp_mis)
            verdict = "✓ PASS" if ok else "✗ FAIL"
        else:
            verdict = "· INFO"

        lines.append(f"| `{fname}` | `{ext}` | {fmt} | {cat} | {mismatch} | {macro} | {embed} | {enc} | {verdict} |\n")

    lines.append("\n")

    lines.append("## 格式伪装文件\n\n")
    if mismatch_list:
        lines.append("| 文件名 | 扩展名 | 真实格式 | 说明 |\n|---|---|---|---|\n")
        for r in mismatch_list:
            lines.append(f"| `{r['file_name']}` | `{r['file_ext']}` | {r['detected_format']} | 扩展名与真实格式不符，疑似伪装 |\n")
    else:
        lines.append("无格式伪装文件。\n")
    lines.append("\n")

    lines.append("## 含宏文件\n\n")
    if macro_list:
        lines.append("| 文件名 | 格式 | 说明 |\n|---|---|---|\n")
        for r in macro_list:
            lines.append(f"| `{r['file_name']}` | {r['detected_format']} | 检测到 VBA 宏代码 |\n")
    else:
        lines.append("无含宏文件。\n")
    lines.append("\n")

    lines.append("## SQLite3 数据库\n\n")
    lines.append(f"检测结果已存入: `{DB_PATH}`  \n")
    lines.append("表名: `file_format_results`  \n\n")
    lines.append("```sql\n")
    lines.append("SELECT detected_format, category, COUNT(*) as cnt\n")
    lines.append("FROM file_format_results\n")
    lines.append("GROUP BY detected_format\n")
    lines.append("ORDER BY cnt DESC;\n")
    lines.append("```\n\n")

    lines.append("## 魔数覆盖范围\n\n")
    lines.append("| 大类 | 支持格式 |\n|---|---|\n")
    lines.append("| **可执行文件** | EXE、DLL、SYS、BIN、ELF、SO、Mach-O、LNK |\n")
    lines.append("| **脚本文件** | BAT、CMD、VBS、PS1、PY、JS、SH、RB、PL、LUA |\n")
    lines.append("| **文档文件** | DOC、XLS、PPT（OLE2）、DOCX、XLSX、PPTX、DOCM（OOXML）、PDF、RTF、CHM、OFD、WPS、ET、DPS |\n")
    lines.append("| **压缩文件** | ZIP、RAR4、RAR5、7Z、GZ、BZ2、XZ、CAB、WIM、ARJ、ISO、TAR |\n")
    lines.append("| **多媒体文件** | PNG、JPEG、GIF、BMP、SWF、MP3、MP4、MOV、AVI、WMV、WAV、MKV、VOB、FLAC、OGG、AAC |\n")
    lines.append("| **复合文件** | EML、MSG（OLE2邮件）、文档内嵌宏（VBA）、OOXML嵌入OLE对象 |\n")

    with open(REPORT_PATH, 'w', encoding='utf-8') as f:
        f.writelines(lines)

if __name__ == "__main__":
    sys.exit(main())
