/*
 * basic DLL 测试程序
 * 演示如何加载 DLL 并调用各模块接口（含 Save* 字段级 SQLite3 存储接口）
 *
 * 用法：
 *   TestMain.exe                    -- 测试所有模块（含 Save* 存储）
 *   TestMain.exe sysinfo            -- 仅测试系统信息（Get* 查询）
 *   TestMain.exe save_sysinfo       -- 仅测试系统信息存储（Save*）
 *   TestMain.exe cert C:\a.exe      -- 测试指定文件的数字证书
 *   TestMain.exe certbatch          -- 批量测试数字证书
 *   TestMain.exe fileformat C:\a.exe -- 测试文件格式检测
 *   TestMain.exe filestatic C:\a.exe -- 测试文件静态信息
 *   TestMain.exe fileassoc          -- 测试文件关联检测
 *
 * 可用 Get* 模块名：
 *   sysinfo  network  disk  autorun  process  tasks
 *   port     share    driver  browser  memory
 *   cert     certbatch  fileassoc  fileformat  filestatic
 *
 * 可用 Save* 模块名：
 *   save_sysinfo    save_network    save_disk       save_autorun
 *   save_process    save_tasks      save_port       save_share
 *   save_driver     save_browser    save_memory     save_cert
 *   save_fileassoc  save_filestatic
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <string>

/* ----------------------------------------------------------------
 * 默认数据库路径（测试用）
 * ---------------------------------------------------------------- */
#define DEFAULT_DB_PATH "C:\\basic_test.db"

/* ----------------------------------------------------------------
 * 函数指针类型定义 — Get* 查询接口
 * ---------------------------------------------------------------- */
typedef int   (*PFN_InitDetectSystem)();
typedef void  (*PFN_CleanupDetectSystem)();
typedef void  (*PFN_FreeJsonString)(char*);
typedef char* (*PFN_GetSysInfo)(const char*);
typedef char* (*PFN_GetNetworkInfo)(const char*);
typedef char* (*PFN_GetDiskInfo)(const char*);
typedef char* (*PFN_GetAutorunInfo)(const char*);
typedef char* (*PFN_GetProcessInfo)(const char*);
typedef char* (*PFN_GetScheduledTasks)(const char*);
typedef char* (*PFN_GetPortInfo)(const char*);
typedef char* (*PFN_GetSharedResources)(const char*);
typedef char* (*PFN_GetDriverInfo)(const char*);
typedef char* (*PFN_GetBrowserPlugins)(const char*);
typedef char* (*PFN_GetMemoryImageInfo)(const char*);
typedef char* (*PFN_GetCertInfo)(const char*);
typedef char* (*PFN_BatchGetCertInfo)(const char*);
typedef char* (*PFN_GetFileAssocInfo)(const char*);
typedef char* (*PFN_CheckFileAssoc)(const char*);
typedef char* (*PFN_DetectFileFormat)(const char*);
typedef char* (*PFN_ScanDirectoryFormat)(const char*);
typedef char* (*PFN_GetFileStaticInfo)(const char*);

/* ----------------------------------------------------------------
 * 函数指针类型定义 — Save* 字段级存储接口
 * ---------------------------------------------------------------- */
typedef char* (*PFN_SaveSysInfo)(const char*);
typedef char* (*PFN_SaveNetworkInfo)(const char*);
typedef char* (*PFN_SaveDiskInfo)(const char*);
typedef char* (*PFN_SaveAutorunInfo)(const char*);
typedef char* (*PFN_SaveProcessInfo)(const char*);
typedef char* (*PFN_SaveScheduledTasks)(const char*);
typedef char* (*PFN_SavePortInfo)(const char*);
typedef char* (*PFN_SaveSharedResources)(const char*);
typedef char* (*PFN_SaveDriverInfo)(const char*);
typedef char* (*PFN_SaveBrowserPlugins)(const char*);
typedef char* (*PFN_SaveMemoryImageInfo)(const char*);
typedef char* (*PFN_SaveCertInfo)(const char*);
typedef char* (*PFN_SaveFileAssocInfo)(const char*);
typedef char* (*PFN_SaveFileStaticInfo)(const char*);

/* ----------------------------------------------------------------
 * 辅助：判断是否需要测试某个模块
 * ---------------------------------------------------------------- */
static bool ShouldTest(int argc, char* argv[], bool testAll, const char* name)
{
    if (testAll) return true;
    for (int i = 1; i < argc; i++)
        if (_stricmp(argv[i], name) == 0) return true;
    return false;
}

/* ----------------------------------------------------------------
 * 辅助：打印结果（超长截断）
 * ---------------------------------------------------------------- */
static void PrintResult(const char* moduleName,
                        char* result,
                        PFN_FreeJsonString freeFunc)
{
    printf("\n========== %s ==========\n", moduleName);
    if (result)
    {
        size_t len = strlen(result);
        if (len > 3000)
        {
            char buf[3001] = {0};
            memcpy(buf, result, 3000);
            printf("%s\n... (truncated, total %zu bytes)\n", buf, len);
        }
        else
            printf("%s\n", result);
        freeFunc(result);
    }
    else
        printf("(null result)\n");
}

/* ----------------------------------------------------------------
 * 辅助：构造含 db_path 的 JSON 参数
 * ---------------------------------------------------------------- */
static std::string MakeDbParam(const char* dbPath = DEFAULT_DB_PATH,
                               const char* extra = NULL)
{
    std::string s = "{\"db_path\":\"";
    for (const char* p = dbPath; *p; p++)
        if (*p == '\\') s += "\\\\";
        else s += *p;
    s += "\"";
    if (extra && extra[0]) { s += ","; s += extra; }
    s += "}";
    return s;
}

/* ----------------------------------------------------------------
 * 辅助：构造含 file_path + db_path 的 JSON 参数
 * ---------------------------------------------------------------- */
static std::string MakeFileDbParam(const char* filePath,
                                   const char* dbPath = DEFAULT_DB_PATH)
{
    std::string s = "{\"file_path\":\"";
    for (const char* p = filePath; *p; p++)
        if (*p == '\\') s += "\\\\";
        else s += *p;
    s += "\",\"db_path\":\"";
    for (const char* p = dbPath; *p; p++)
        if (*p == '\\') s += "\\\\";
        else s += *p;
    s += "\"}";
    return s;
}

/* ================================================================
 * 主函数
 * ================================================================ */
int main(int argc, char* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    printf("basic DLL Test Program\n");
    printf("================================\n");
    printf("Database path: %s\n", DEFAULT_DB_PATH);

    /* 加载 DLL */
    HMODULE hDll = LoadLibraryW(L"basic.dll");
    if (!hDll)
    {
        fprintf(stderr, "Failed to load basic.dll, error: %lu\n",
                GetLastError());
        return 1;
    }
    printf("DLL loaded successfully.\n");

/* 获取函数指针宏 */
#define GET_PROC(name) \
    PFN_##name pfn##name = (PFN_##name)GetProcAddress(hDll, #name); \
    if (!pfn##name) fprintf(stderr, "  [WARN] GetProcAddress failed: " #name "\n");

    /* Get* 查询接口 */
    GET_PROC(InitDetectSystem)
    GET_PROC(CleanupDetectSystem)
    GET_PROC(FreeJsonString)
    GET_PROC(GetSysInfo)
    GET_PROC(GetNetworkInfo)
    GET_PROC(GetDiskInfo)
    GET_PROC(GetAutorunInfo)
    GET_PROC(GetProcessInfo)
    GET_PROC(GetScheduledTasks)
    GET_PROC(GetPortInfo)
    GET_PROC(GetSharedResources)
    GET_PROC(GetDriverInfo)
    GET_PROC(GetBrowserPlugins)
    GET_PROC(GetMemoryImageInfo)
    GET_PROC(GetCertInfo)
    GET_PROC(BatchGetCertInfo)
    GET_PROC(GetFileAssocInfo)
    GET_PROC(CheckFileAssoc)
    GET_PROC(DetectFileFormat)
    GET_PROC(ScanDirectoryFormat)
    GET_PROC(GetFileStaticInfo)

    /* Save* 字段级存储接口 */
    GET_PROC(SaveSysInfo)
    GET_PROC(SaveNetworkInfo)
    GET_PROC(SaveDiskInfo)
    GET_PROC(SaveAutorunInfo)
    GET_PROC(SaveProcessInfo)
    GET_PROC(SaveScheduledTasks)
    GET_PROC(SavePortInfo)
    GET_PROC(SaveSharedResources)
    GET_PROC(SaveDriverInfo)
    GET_PROC(SaveBrowserPlugins)
    GET_PROC(SaveMemoryImageInfo)
    GET_PROC(SaveCertInfo)
    GET_PROC(SaveFileAssocInfo)
    GET_PROC(SaveFileStaticInfo)

    /* 初始化 */
    if (pfnInitDetectSystem) pfnInitDetectSystem();

    /* 判断是否测试所有模块 */
    bool testAll = (argc == 1);

    /* ==============================================================
     * 第一部分：Get* 查询接口测试
     * ============================================================== */
    printf("\n\n");
    printf("##############################################\n");
    printf("##  Part 1: Get* Query Interface Tests      ##\n");
    printf("##############################################\n");

    /* ---- 模块 01：系统信息 ---- */
    if (ShouldTest(argc, argv, testAll, "sysinfo") && pfnGetSysInfo && pfnFreeJsonString)
        PrintResult("GetSysInfo",
            pfnGetSysInfo("{}"), pfnFreeJsonString);

    /* ---- 模块 02：网络信息 ---- */
    if (ShouldTest(argc, argv, testAll, "network") && pfnGetNetworkInfo && pfnFreeJsonString)
        PrintResult("GetNetworkInfo",
            pfnGetNetworkInfo("{}"), pfnFreeJsonString);

    /* ---- 模块 03：硬盘信息 ---- */
    if (ShouldTest(argc, argv, testAll, "disk") && pfnGetDiskInfo && pfnFreeJsonString)
        PrintResult("GetDiskInfo",
            pfnGetDiskInfo("{}"), pfnFreeJsonString);

    /* ---- 模块 04：自启动 ---- */
    if (ShouldTest(argc, argv, testAll, "autorun") && pfnGetAutorunInfo && pfnFreeJsonString)
        PrintResult("GetAutorunInfo",
            pfnGetAutorunInfo("{}"), pfnFreeJsonString);

    /* ---- 模块 05：进程信息（不含模块/线程详情，加快速度）---- */
    if (ShouldTest(argc, argv, testAll, "process") && pfnGetProcessInfo && pfnFreeJsonString)
    {
        const char* params = "{\"include_modules\":false,\"include_threads\":false}";
        PrintResult("GetProcessInfo",
            pfnGetProcessInfo(params), pfnFreeJsonString);
    }

    /* ---- 模块 06：计划任务 ---- */
    if (ShouldTest(argc, argv, testAll, "tasks") && pfnGetScheduledTasks && pfnFreeJsonString)
        PrintResult("GetScheduledTasks",
            pfnGetScheduledTasks("{}"), pfnFreeJsonString);

    /* ---- 模块 07：端口信息 ---- */
    if (ShouldTest(argc, argv, testAll, "port") && pfnGetPortInfo && pfnFreeJsonString)
        PrintResult("GetPortInfo",
            pfnGetPortInfo("{}"), pfnFreeJsonString);

    /* ---- 模块 08：共享资源 ---- */
    if (ShouldTest(argc, argv, testAll, "share") && pfnGetSharedResources && pfnFreeJsonString)
        PrintResult("GetSharedResources",
            pfnGetSharedResources("{}"), pfnFreeJsonString);

    /* ---- 模块 09：驱动信息 ---- */
    if (ShouldTest(argc, argv, testAll, "driver") && pfnGetDriverInfo && pfnFreeJsonString)
        PrintResult("GetDriverInfo",
            pfnGetDriverInfo("{}"), pfnFreeJsonString);

    /* ---- 模块 10：浏览器插件 ---- */
    if (ShouldTest(argc, argv, testAll, "browser") && pfnGetBrowserPlugins && pfnFreeJsonString)
        PrintResult("GetBrowserPlugins",
            pfnGetBrowserPlugins("{}"), pfnFreeJsonString);

    /* ---- 模块 11：内存映像（不保存 dump）---- */
    if (ShouldTest(argc, argv, testAll, "memory") && pfnGetMemoryImageInfo && pfnFreeJsonString)
    {
        const char* params = "{\"save_dump\":false}";
        PrintResult("GetMemoryImageInfo",
            pfnGetMemoryImageInfo(params), pfnFreeJsonString);
    }

    /* ---- 模块 12：数字证书 — 单文件 ---- */
    if (ShouldTest(argc, argv, testAll, "cert") && pfnGetCertInfo && pfnFreeJsonString)
    {
        const char* defaults[] = {
            "C:\\Windows\\System32\\ntdll.dll",
            "C:\\Windows\\System32\\kernel32.dll",
            "C:\\Windows\\explorer.exe",
            NULL
        };
        for (int di = 0; defaults[di]; di++)
        {
            std::string jsonParam = "{\"file_path\":\"";
            for (const char* cp = defaults[di]; *cp; cp++)
                if (*cp == '\\') jsonParam += "\\\\";
                else jsonParam += *cp;
            jsonParam += "\",\"check_revocation\":false,\"include_chain\":true}";

            char label[128];
            _snprintf_s(label, sizeof(label), _TRUNCATE,
                "GetCertInfo(%s)", defaults[di]);
            PrintResult(label,
                pfnGetCertInfo(jsonParam.c_str()),
                pfnFreeJsonString);
        }
    }

    /* ---- 模块 12：数字证书 — 批量 ---- */
    if (ShouldTest(argc, argv, testAll, "certbatch") && pfnBatchGetCertInfo && pfnFreeJsonString)
    {
        const char* batchParam =
            "{"
            "\"files\":["
            "\"C:\\\\Windows\\\\System32\\\\ntdll.dll\","
            "\"C:\\\\Windows\\\\System32\\\\kernel32.dll\","
            "\"C:\\\\Windows\\\\System32\\\\advapi32.dll\","
            "\"C:\\\\Windows\\\\explorer.exe\","
            "\"C:\\\\Windows\\\\System32\\\\svchost.exe\""
            "],"
            "\"check_revocation\":false,"
            "\"include_chain\":false"
            "}";
        PrintResult("BatchGetCertInfo",
            pfnBatchGetCertInfo(batchParam),
            pfnFreeJsonString);
    }

    /* ---- 模块 14：文件关联 ---- */
    if (ShouldTest(argc, argv, testAll, "fileassoc") && pfnGetFileAssocInfo && pfnFreeJsonString)
        PrintResult("GetFileAssocInfo",
            pfnGetFileAssocInfo("{\"check_high_risk_only\":true}"),
            pfnFreeJsonString);

    /* ---- 模块 15：文件格式检测 ---- */
    if (ShouldTest(argc, argv, testAll, "fileformat") && pfnDetectFileFormat && pfnFreeJsonString)
    {
        /* 命令行第二参数为文件路径，否则使用默认 */
        const char* targetFile = "C:\\Windows\\System32\\ntdll.dll";
        for (int i = 1; i < argc - 1; i++)
            if (_stricmp(argv[i], "fileformat") == 0 && argv[i+1][0] != '\0')
            { targetFile = argv[i+1]; break; }

        std::string jsonParam = "{\"file_path\":\"";
        for (const char* cp = targetFile; *cp; cp++)
            if (*cp == '\\') jsonParam += "\\\\";
            else jsonParam += *cp;
        jsonParam += "\"}";

        char label[256];
        _snprintf_s(label, sizeof(label), _TRUNCATE,
            "DetectFileFormat(%s)", targetFile);
        PrintResult(label,
            pfnDetectFileFormat(jsonParam.c_str()),
            pfnFreeJsonString);
    }

    /* ---- 模块 16：文件静态信息 ---- */
    if (ShouldTest(argc, argv, testAll, "filestatic") && pfnGetFileStaticInfo && pfnFreeJsonString)
    {
        const char* targetFile = "C:\\Windows\\System32\\ntdll.dll";
        for (int i = 1; i < argc - 1; i++)
            if (_stricmp(argv[i], "filestatic") == 0 && argv[i+1][0] != '\0')
            { targetFile = argv[i+1]; break; }

        std::string jsonParam = "{\"file_path\":\"";
        for (const char* cp = targetFile; *cp; cp++)
            if (*cp == '\\') jsonParam += "\\\\";
            else jsonParam += *cp;
        jsonParam += "\",\"extract_strings\":true,\"strings_dir\":\"C:\\\\basic_strings\"}";

        char label[256];
        _snprintf_s(label, sizeof(label), _TRUNCATE,
            "GetFileStaticInfo(%s)", targetFile);
        PrintResult(label,
            pfnGetFileStaticInfo(jsonParam.c_str()),
            pfnFreeJsonString);
    }

    /* ==============================================================
     * 第二部分：Save* 字段级 SQLite3 存储接口测试
     * ============================================================== */
    printf("\n\n");
    printf("##############################################\n");
    printf("##  Part 2: Save* SQLite3 Storage Tests     ##\n");
    printf("##############################################\n");
    printf("All results will be saved to: %s\n", DEFAULT_DB_PATH);

    /* ---- Save 01：系统信息 ---- */
    if (ShouldTest(argc, argv, testAll, "save_sysinfo") && pfnSaveSysInfo && pfnFreeJsonString)
    {
        std::string p = MakeDbParam();
        PrintResult("SaveSysInfo -> table[sys_info]",
            pfnSaveSysInfo(p.c_str()), pfnFreeJsonString);
    }

    /* ---- Save 02：网络信息 ---- */
    if (ShouldTest(argc, argv, testAll, "save_network") && pfnSaveNetworkInfo && pfnFreeJsonString)
    {
        std::string p = MakeDbParam();
        PrintResult("SaveNetworkInfo -> table[network_adapters]",
            pfnSaveNetworkInfo(p.c_str()), pfnFreeJsonString);
    }

    /* ---- Save 03：硬盘信息 ---- */
    if (ShouldTest(argc, argv, testAll, "save_disk") && pfnSaveDiskInfo && pfnFreeJsonString)
    {
        std::string p = MakeDbParam();
        PrintResult("SaveDiskInfo -> table[disk_info]",
            pfnSaveDiskInfo(p.c_str()), pfnFreeJsonString);
    }

    /* ---- Save 04：自启动 ---- */
    if (ShouldTest(argc, argv, testAll, "save_autorun") && pfnSaveAutorunInfo && pfnFreeJsonString)
    {
        std::string p = MakeDbParam();
        PrintResult("SaveAutorunInfo -> table[autorun_items]",
            pfnSaveAutorunInfo(p.c_str()), pfnFreeJsonString);
    }

    /* ---- Save 05：进程信息 ---- */
    if (ShouldTest(argc, argv, testAll, "save_process") && pfnSaveProcessInfo && pfnFreeJsonString)
    {
        /* 不含模块/线程详情，加快速度 */
        std::string p = MakeDbParam(DEFAULT_DB_PATH,
            "\"include_modules\":false,\"include_threads\":false");
        PrintResult("SaveProcessInfo -> table[process_list]",
            pfnSaveProcessInfo(p.c_str()), pfnFreeJsonString);
    }

    /* ---- Save 06：计划任务 ---- */
    if (ShouldTest(argc, argv, testAll, "save_tasks") && pfnSaveScheduledTasks && pfnFreeJsonString)
    {
        std::string p = MakeDbParam();
        PrintResult("SaveScheduledTasks -> table[scheduled_tasks]",
            pfnSaveScheduledTasks(p.c_str()), pfnFreeJsonString);
    }

    /* ---- Save 07：端口信息 ---- */
    if (ShouldTest(argc, argv, testAll, "save_port") && pfnSavePortInfo && pfnFreeJsonString)
    {
        std::string p = MakeDbParam();
        PrintResult("SavePortInfo -> table[port_list]",
            pfnSavePortInfo(p.c_str()), pfnFreeJsonString);
    }

    /* ---- Save 08：共享资源 ---- */
    if (ShouldTest(argc, argv, testAll, "save_share") && pfnSaveSharedResources && pfnFreeJsonString)
    {
        std::string p = MakeDbParam();
        PrintResult("SaveSharedResources -> table[shared_resources]",
            pfnSaveSharedResources(p.c_str()), pfnFreeJsonString);
    }

    /* ---- Save 09：驱动信息 ---- */
    if (ShouldTest(argc, argv, testAll, "save_driver") && pfnSaveDriverInfo && pfnFreeJsonString)
    {
        std::string p = MakeDbParam();
        PrintResult("SaveDriverInfo -> table[driver_list]",
            pfnSaveDriverInfo(p.c_str()), pfnFreeJsonString);
    }

    /* ---- Save 10：浏览器插件 ---- */
    if (ShouldTest(argc, argv, testAll, "save_browser") && pfnSaveBrowserPlugins && pfnFreeJsonString)
    {
        std::string p = MakeDbParam();
        PrintResult("SaveBrowserPlugins -> table[browser_plugins]",
            pfnSaveBrowserPlugins(p.c_str()), pfnFreeJsonString);
    }

    /* ---- Save 11：内存映像 ---- */
    if (ShouldTest(argc, argv, testAll, "save_memory") && pfnSaveMemoryImageInfo && pfnFreeJsonString)
    {
        std::string p = MakeDbParam(DEFAULT_DB_PATH, "\"save_dump\":false");
        PrintResult("SaveMemoryImageInfo -> table[memory_modules]",
            pfnSaveMemoryImageInfo(p.c_str()), pfnFreeJsonString);
    }

    /* ---- Save 12：数字证书 ---- */
    if (ShouldTest(argc, argv, testAll, "save_cert") && pfnSaveCertInfo && pfnFreeJsonString)
    {
        /* 对三个系统文件批量采集并存库 */
        const char* certFiles[] = {
            "C:\\Windows\\System32\\ntdll.dll",
            "C:\\Windows\\System32\\kernel32.dll",
            "C:\\Windows\\explorer.exe",
            NULL
        };
        for (int di = 0; certFiles[di]; di++)
        {
            std::string p = "{\"file_path\":\"";
            for (const char* cp = certFiles[di]; *cp; cp++)
                if (*cp == '\\') p += "\\\\";
                else p += *cp;
            p += "\",\"db_path\":\"" DEFAULT_DB_PATH "\","
                 "\"check_revocation\":false,\"include_chain\":false}";

            char label[128];
            _snprintf_s(label, sizeof(label), _TRUNCATE,
                "SaveCertInfo(%s) -> table[cert_info]", certFiles[di]);
            PrintResult(label,
                pfnSaveCertInfo(p.c_str()), pfnFreeJsonString);
        }
    }

    /* ---- Save 14：文件关联 ---- */
    if (ShouldTest(argc, argv, testAll, "save_fileassoc") && pfnSaveFileAssocInfo && pfnFreeJsonString)
    {
        std::string p = MakeDbParam(DEFAULT_DB_PATH,
            "\"check_high_risk_only\":true");
        PrintResult("SaveFileAssocInfo -> table[file_assoc]",
            pfnSaveFileAssocInfo(p.c_str()), pfnFreeJsonString);
    }

    /* ---- Save 16：文件静态信息 ---- */
    if (ShouldTest(argc, argv, testAll, "save_filestatic") && pfnSaveFileStaticInfo && pfnFreeJsonString)
    {
        const char* targetFile = "C:\\Windows\\System32\\ntdll.dll";
        for (int i = 1; i < argc - 1; i++)
            if (_stricmp(argv[i], "save_filestatic") == 0 && argv[i+1][0] != '\0')
            { targetFile = argv[i+1]; break; }

        std::string p = "{\"file_path\":\"";
        for (const char* cp = targetFile; *cp; cp++)
            if (*cp == '\\') p += "\\\\";
            else p += *cp;
        p += "\",\"db_path\":\"" DEFAULT_DB_PATH "\","
             "\"extract_strings\":true,"
             "\"strings_dir\":\"C:\\\\basic_strings\"}";

        char label[256];
        _snprintf_s(label, sizeof(label), _TRUNCATE,
            "SaveFileStaticInfo(%s) -> table[file_static_results]", targetFile);
        PrintResult(label,
            pfnSaveFileStaticInfo(p.c_str()), pfnFreeJsonString);
    }

    /* ==============================================================
     * 清理
     * ============================================================== */
    if (pfnCleanupDetectSystem) pfnCleanupDetectSystem();
    FreeLibrary(hDll);

    printf("\n================================\n");
    printf("All tests completed.\n");
    printf("SQLite3 database: %s\n", DEFAULT_DB_PATH);
    printf("================================\n");
    return 0;
}
