#ifndef BASIC_H
#define BASIC_H

#ifdef BASIC_EXPORTS
#define BASIC_API __declspec(dllexport)
#else
#define BASIC_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------------------------------------------
 * 生命周期
 * ---------------------------------------------------------------- */

/** 初始化检测系统，返回 0 表示成功 */
BASIC_API int  InitDetectSystem();

/** 清理检测系统资源 */
BASIC_API void CleanupDetectSystem();

/**
 * 释放由各模块接口返回的 JSON 字符串内存。
 * 所有返回 char* 的接口均须通过此函数释放，切勿直接 free()。
 */
BASIC_API void FreeJsonString(char* jsonStr);


/* ----------------------------------------------------------------
 * 模块 01 — 系统信息
 * 指标：系统版本、安装时间、计算机名称、账户
 * paramsJson: {} （暂无额外参数）
 * ---------------------------------------------------------------- */
BASIC_API char* GetSysInfo(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 02 — 网络信息
 * 指标：所有网卡、IP、子网掩码、网关、MAC
 * paramsJson: {} （暂无额外参数）
 * ---------------------------------------------------------------- */
BASIC_API char* GetNetworkInfo(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 03 — 硬盘信息
 * 指标：厂商、型号、序列号、总容量、分区（含隐藏分区）详情、
 *       启动次数、累计使用时间
 * paramsJson: {} （暂无额外参数）
 * ---------------------------------------------------------------- */
BASIC_API char* GetDiskInfo(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 04 — 自启动信息
 * 指标：自动运行、操作启动（右键菜单、系统调试器）
 * paramsJson: {} （暂无额外参数）
 * ---------------------------------------------------------------- */
BASIC_API char* GetAutorunInfo(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 05 — 进程信息
 * 指标：进程、模块、线程、文件句柄、发行商、修改时间、映像路径、授信状态
 * paramsJson:
 *   {
 *     "include_modules": true,   // 是否枚举每个进程的模块列表（默认 true）
 *     "include_threads": true    // 是否枚举每个进程的线程列表（默认 true）
 *   }
 * ---------------------------------------------------------------- */
BASIC_API char* GetProcessInfo(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 06 — 计划任务
 * 指标：所有条目、状态
 * paramsJson: {} （暂无额外参数）
 * ---------------------------------------------------------------- */
BASIC_API char* GetScheduledTasks(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 07 — 端口信息
 * 指标：所有端口，支持进程/端口/IP 关联，
 *       包括进程发行商、协议、端口、状态、映像路径、本地IP、远程IP
 * paramsJson: {} （暂无额外参数）
 * ---------------------------------------------------------------- */
BASIC_API char* GetPortInfo(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 08 — 共享资源
 * 指标：共享名称、种类、当前用户、映像路径
 * paramsJson: {} （暂无额外参数）
 * ---------------------------------------------------------------- */
BASIC_API char* GetSharedResources(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 09 — 驱动信息
 * 指标：实体硬件、虚拟硬件、发行商、修改时间、映像路径、授信状态
 * paramsJson: {} （暂无额外参数）
 * ---------------------------------------------------------------- */
BASIC_API char* GetDriverInfo(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 10 — 浏览器插件
 * 指标：类型、状态、修改时间、路径
 *       支持 IE/Edge-Legacy、Chrome、Edge(Chromium)、Brave、Firefox
 * paramsJson: {} （暂无额外参数）
 * ---------------------------------------------------------------- */
BASIC_API char* GetBrowserPlugins(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 11 — 内存映像（系统）
 * 指标：内存运行状态、内核模块基址、映像大小、标志、序号、路径、授信状态
 * paramsJson:
 *   {
 *     "save_dump" : false,              // 是否保存内存转储（默认 false）
 *     "dump_pid"  : 1234,               // 目标进程 PID（save_dump=true 时必填）
 *     "dump_path" : "C:\\memdump.dmp"   // 转储输出路径（默认 C:\memdump.dmp）
 *   }
 * ---------------------------------------------------------------- */
BASIC_API char* GetMemoryImageInfo(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 12 — 数字证书检测
 * 指标：
 *   - 签名是否有效（Authenticode 验证结果）
 *   - 文件在签名后是否被篡改（哈希比对）
 *   - 证书时间戳（签名时间，RFC3161 / PKCS#9 countersignature）
 *   - 证书序列号
 *   - 使用者（Subject DN）
 *   - 有效起始日期 / 有效截止日期
 *   - 颁发者（Issuer DN）
 *   - 签名算法
 *   - 证书指纹（SHA-1 / SHA-256）
 *   - 完整证书链
 *
 * paramsJson:
 *   {
 *     "file_path"       : "C:\\Windows\\System32\\ntdll.dll",  // 必填
 *     "check_revocation": false,  // 是否联网检查吊销（默认 false）
 *     "include_chain"   : true    // 是否返回完整证书链（默认 true）
 *   }
 *
 * 返回示例（精简）：
 *   {
 *     "module"           : "cert_info",
 *     "file_path"        : "C:\\...",
 *     "file_hash"        : { "sha1": "...", "sha256": "..." },
 *     "has_signature"    : true,
 *     "signature_valid"  : true,
 *     "verify_result"    : "Valid",
 *     "verify_hresult"   : "0x00000000",
 *     "file_tampered"    : false,
 *     "signature_details": {
 *       "timestamp"      : "2024-01-15 08:30:00 UTC",
 *       "hash_algorithm" : "sha256",
 *       "signer_certificate": {
 *         "subject"        : "CN=Microsoft Windows, O=Microsoft Corporation, ...",
 *         "issuer"         : "CN=Microsoft Windows Production PCA 2011, ...",
 *         "serial_number"  : "330000045...",
 *         "not_before"     : "2023-10-12 18:31:02 UTC",
 *         "not_after"      : "2024-10-11 18:31:02 UTC",
 *         "not_expired"    : true,
 *         "signature_algorithm": "sha256RSA",
 *         "thumbprint_sha1"   : "...",
 *         "thumbprint_sha256" : "...",
 *         "is_ca"          : false
 *       },
 *       "certificate_chain": [ ... ]
 *     },
 *     "status": "success"
 *   }
 * ---------------------------------------------------------------- */
BASIC_API char* GetCertInfo(const char* paramsJson);

/**
 * 批量数字证书检测
 * paramsJson:
 *   {
 *     "files"           : ["C:\\a.exe", "C:\\b.dll"],
 *     "check_revocation": false,
 *     "include_chain"   : false
 *   }
 */
BASIC_API char* BatchGetCertInfo(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 13 — 统一查询与持久化
 * 按模块名调用任意检测模块，并将结果存入 SQLite3 数据库
 *
 * QueryModuleAndSave paramsJson:
 *   {
 *     "module_name"  : "system_info",         // 必填，目标模块名称
 *     "module_params": {},                    // 可选，传递给目标模块的参数
 *     "db_path"      : "C:\\basic_detect.db",  // 可选，数据库路径
 *     "save_to_db"   : true                   // 可选，是否存库（默认 true）
 *   }
 *
 * 可用 module_name 列表：
 *   system_info, network_info, disk_info, autorun_info, process_info,
 *   scheduled_tasks, port_info, shared_resources, driver_info,
 *   browser_plugins, memory_image, cert_info, batch_cert_info
 *
 * QueryHistory paramsJson:
 *   {
 *     "module_name" : "system_info",  // 可选，为空则查全部模块
 *     "db_path"     : "C:\\basic_detect.db",
 *     "limit"       : 50              // 可选，默认 100
 *   }
 * ---------------------------------------------------------------- */
BASIC_API char* QueryModuleAndSave(const char* paramsJson);
BASIC_API char* QueryHistory(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 14 — 文件关联检测
 * 文件执行体合后缀名是否已知、默认打开方式、被篡改项检测
 *
 * GetFileAssocInfo paramsJson:
 *   {
 *     "filter_tampered" : false,  // 可选，true 则只返回被篡改的项
 *     "filter_unknown"  : false,  // 可选，true 则只返回未知扩展名
 *     "max_count"       : 500     // 可选，最多返回条数
 *   }
 *
 * CheckFileAssoc paramsJson:
 *   {
 *     "extensions" : [".txt", ".exe", ".bat"]  // 必填，要检测的扩展名列表
 *   }
 *   若不传 extensions，默认检测高危扩展名（.exe/.bat/.cmd 等）
 * ---------------------------------------------------------------- */
BASIC_API char* GetFileAssocInfo(const char* paramsJson);
BASIC_API char* CheckFileAssoc(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 15 — 文件格式检测
 * 通过魔数识别文件真实格式，检测格式伪装、恶意宏、嵌入对象等
 * 支持六大类型：可执行、脚本、文档、压缩、多媒体、复合文件
 * 检测结果存入 SQLite3 file_format_results 表
 *
 * DetectFileFormat paramsJson:
 *   {
 *     "files"     : ["C:\\test.exe", "C:\\doc.pdf"],
 *     "db_path"   : "C:\\basic_detect.db",
 *     "save_to_db": true
 *   }
 *
 * ScanDirectoryFormat paramsJson:
 *   {
 *     "directory"      : "C:\\ScanTarget",
 *     "recursive"      : true,
 *     "max_files"      : 1000,
 *     "filter_category": "executable",  // 可选，大类过滤
 *     "db_path"        : "C:\\basic_detect.db",
 *     "save_to_db"     : true
 *   }
 * ---------------------------------------------------------------- */
BASIC_API char* DetectFileFormat(const char* paramsJson);
BASIC_API char* ScanDirectoryFormat(const char* paramsJson);


/* ----------------------------------------------------------------
 * 模块 16 — 文件静态信息获取
 * 功能：
 *   1. 基础属性：创建时间、修改时间、PE 编译时间戳、发行商、MD5、SHA256、文件类型
 *   2. PE 结构解析：目标架构、入口点、子系统、加壳/编译器特征、
 *              节区信息（名称/虚拟地址/大小/熵値/状态）、
 *              导入表（DLL/函数/风险评级）
 *   3. 可打印字符串提取（写入独立 .txt 文件，SQLite3 中只存文件路径）
 *
 * GetFileStaticInfo  — 分析单个文件，返回 JSON（不入库）
 * SaveFileStaticInfo — 分析并将结果存入 SQLite3
 *
 * paramsJson 示例：
 *   {
 *     "file_path"          : "C:\\path\\to\\file.exe",
 *     "strings_output_dir" : "C:\\strings",  // 可选，默认与文件同目录
 *     "db_path"            : "C:\\basic.db"  // 仅 SaveFileStaticInfo 需要
 *   }
 * ---------------------------------------------------------------- */
BASIC_API const char* GetFileStaticInfo(const char* paramsJson);
BASIC_API const char* SaveFileStaticInfo(const char* paramsJson);


#ifdef __cplusplus
}
#endif

#endif /* BASIC_H */
