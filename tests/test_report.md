# 文件格式检测模块 — 测试报告
**测试时间**: 2026-04-15 21:10:11  
**测试文件总数**: 56  
**通过**: 50  |  **失败**: 0  |  **信息**: 6

---

## 分类统计

| 大类 | 文件数 |
|---|---|
| archive | 18 |
| compound | 1 |
| document | 8 |
| executable | 8 |
| multimedia | 12 |
| script | 8 |
| unknown | 1 |

## 详细检测结果

| 文件名 | 扩展名 | 检测格式 | 大类 | 格式伪装 | 含宏 | 含嵌入 | 加密 | 验证结果 |
|---|---|---|---|---|---|---|---|---|
| `test_7z.7z` | `.7z` | 7-Zip Archive | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_arj.arj` | `.arj` | ARJ Archive | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_bz2.bz2` | `.bz2` | BZip2 Archive | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_cab.cab` | `.cab` | Cabinet Archive (CAB) | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_gz.gz` | `.gz` | GZip Archive | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_iso.iso` | `.iso` | ISO 9660 Image | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_rar4.rar` | `.rar` | RAR Archive v4 | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_rar5.rar` | `.rar` | RAR Archive v5 | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_tar.tar` | `.tar` | TAR Archive | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_wim.wim` | `.wim` | Windows Imaging (WIM) | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_xz.xz` | `.xz` | XZ Archive | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_zip.zip` | `.zip` | ZIP Archive | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_eml.eml` | `.eml` | EML Email (mbox) | compound | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_macro_doc.doc` | `.doc` | OLE2 Compound Document | document | 否 | **是** | 否 | 否 | · INFO |
| `test_msg.msg` | `.msg` | OLE2 Compound Document | document | 否 | 否 | 否 | 否 | ✓ PASS |
| `elf_disguised_as.txt` | `.txt` | ELF Executable | executable | **是** | 否 | 否 | 否 | ✓ PASS |
| `normal_text.txt` | `.txt` | Unknown | unknown | 否 | 否 | 否 | 否 | · INFO |
| `pdf_disguised_as.png` | `.png` | PDF Document | document | **是** | 否 | 否 | 否 | ✓ PASS |
| `pe_disguised_as.jpg` | `.jpg` | PE Executable (MZ) | executable | **是** | 否 | 否 | 否 | ✓ PASS |
| `zip_disguised_as.doc` | `.doc` | ZIP Archive | archive | **是** | 否 | 否 | 否 | ✓ PASS |
| `test_chm.chm` | `.chm` | CHM Help File | document | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_doc.doc` | `.doc` | OLE2 Compound Document | document | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_doc_macro.doc` | `.doc` | OLE2 Compound Document | document | 否 | **是** | 否 | 否 | · INFO |
| `test_docm.docm` | `.docm` | ZIP Archive | archive | 否 | **是** | 否 | 否 | · INFO |
| `test_docx.docx` | `.docx` | ZIP Archive | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_ofd.ofd` | `.ofd` | ZIP Archive | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_pdf.pdf` | `.pdf` | PDF Document | document | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_pptx.pptx` | `.pptx` | ZIP Archive | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_rtf.rtf` | `.rtf` | Rich Text Format (RTF) | document | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_xlsx.xlsx` | `.xlsx` | ZIP Archive | archive | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_bin.bin` | `.bin` | ELF Executable | executable | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_dll.dll` | `.dll` | PE Executable (MZ) | executable | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_elf.elf` | `.elf` | ELF Executable | executable | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_pe.exe` | `.exe` | PE Executable (MZ) | executable | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_so.so` | `.so` | ELF Executable | executable | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_sys.sys` | `.sys` | PE Executable (MZ) | executable | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_avi.avi` | `.avi` | AVI Video | multimedia | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_bmp.bmp` | `.bmp` | BMP Image | multimedia | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_gif.gif` | `.gif` | GIF89a Image | multimedia | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_jpg.jpg` | `.jpg` | JPEG Image | multimedia | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_mkv.mkv` | `.mkv` | MKV/WebM (EBML) | multimedia | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_mp3.mp3` | `.mp3` | MP3 Audio (ID3) | multimedia | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_mp4.mp4` | `.mp4` | MP4/MOV Video | multimedia | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_png.png` | `.png` | PNG Image | multimedia | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_swf.swf` | `.swf` | SWF Flash (uncompressed) | multimedia | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_vob.vob` | `.vob` | MPEG Program Stream | multimedia | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_wav.wav` | `.wav` | WAV Audio | multimedia | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_wmv.wmv` | `.wmv` | ASF/WMV/WMA Media | multimedia | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_bat.bat` | `.bat` | Batch Script | script | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_js.js` | `.js` | JavaScript | script | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_pl.pl` | `.pl` | Perl Script | script | 否 | 否 | 否 | 否 | · INFO |
| `test_ps1.ps1` | `.ps1` | PowerShell Script | script | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_py.py` | `.py` | Python Script | script | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_rb.rb` | `.rb` | Ruby Script | script | 否 | 否 | 否 | 否 | · INFO |
| `test_sh.sh` | `.sh` | Bash Shell Script | script | 否 | 否 | 否 | 否 | ✓ PASS |
| `test_vbs.vbs` | `.vbs` | VBScript | script | 否 | 否 | 否 | 否 | ✓ PASS |

## 格式伪装文件

| 文件名 | 扩展名 | 真实格式 | 说明 |
|---|---|---|---|
| `elf_disguised_as.txt` | `.txt` | ELF Executable | 扩展名与真实格式不符，疑似伪装 |
| `pdf_disguised_as.png` | `.png` | PDF Document | 扩展名与真实格式不符，疑似伪装 |
| `pe_disguised_as.jpg` | `.jpg` | PE Executable (MZ) | 扩展名与真实格式不符，疑似伪装 |
| `zip_disguised_as.doc` | `.doc` | ZIP Archive | 扩展名与真实格式不符，疑似伪装 |

## 含宏文件

| 文件名 | 格式 | 说明 |
|---|---|---|
| `test_macro_doc.doc` | OLE2 Compound Document | 检测到 VBA 宏代码 |
| `test_doc_macro.doc` | OLE2 Compound Document | 检测到 VBA 宏代码 |
| `test_docm.docm` | ZIP Archive | 检测到 VBA 宏代码 |

## SQLite3 数据库

检测结果已存入: `/home/ubuntu/basic_project/tests/test_results.db`  
表名: `file_format_results`  

```sql
SELECT detected_format, category, COUNT(*) as cnt
FROM file_format_results
GROUP BY detected_format
ORDER BY cnt DESC;
```

## 魔数覆盖范围

| 大类 | 支持格式 |
|---|---|
| **可执行文件** | EXE、DLL、SYS、BIN、ELF、SO、Mach-O、LNK |
| **脚本文件** | BAT、CMD、VBS、PS1、PY、JS、SH、RB、PL、LUA |
| **文档文件** | DOC、XLS、PPT（OLE2）、DOCX、XLSX、PPTX、DOCM（OOXML）、PDF、RTF、CHM、OFD、WPS、ET、DPS |
| **压缩文件** | ZIP、RAR4、RAR5、7Z、GZ、BZ2、XZ、CAB、WIM、ARJ、ISO、TAR |
| **多媒体文件** | PNG、JPEG、GIF、BMP、SWF、MP3、MP4、MOV、AVI、WMV、WAV、MKV、VOB、FLAC、OGG、AAC |
| **复合文件** | EML、MSG（OLE2邮件）、文档内嵌宏（VBA）、OOXML嵌入OLE对象 |
