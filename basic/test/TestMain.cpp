/*
 * basic DLL 测试程序
 * 演示如何加载 DLL 并调用各模块接口
 *
 * 用法：
 *   TestMain.exe                    -- 测试所有模块
 *   TestMain.exe sysinfo            -- 仅测试系统信息
 *   TestMain.exe cert C:\a.exe      -- 测试指定文件的数字证书
 *   TestMain.exe certbatch          -- 批量测试数字证书（内置示例文件）
 *
 * 可用模块名：
 *   sysinfo  network  disk  autorun  process  tasks
 *   port     share    driver  browser  memory
 *   cert     certbatch
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <string>

/* ----------------------------------------------------------------
 * 函数指针类型定义
 * ---------------------------------------------------------------- */
typedef int   (*PFN_InitDetectSystem)();
typedef void  (*PFN_CleanupDetectSystem)();
typedef void  (*PFN_FreeJsonString)(char*);
typedef char* (*PFN_GetSystemInfo)(const char*);
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
 * 主函数
 * ---------------------------------------------------------------- */
int main(int argc, char* argv[])
{
    SetConsoleOutputCP(CP_UTF8);

    printf("basic DLL Test Program\n");
    printf("================================\n");

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
    if (!pfn##name) fprintf(stderr, "GetProcAddress failed: " #name "\n");

    GET_PROC(InitDetectSystem)
    GET_PROC(CleanupDetectSystem)
    GET_PROC(FreeJsonString)
    GET_PROC(GetSystemInfo)
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

    /* 初始化 */
    if (pfnInitDetectSystem) pfnInitDetectSystem();

    /* 判断是否测试某个模块 */
    bool testAll = (argc == 1);
    auto ShouldTest = [&](const char* name) -> bool {
        if (testAll) return true;
        for (int i = 1; i < argc; i++)
            if (_stricmp(argv[i], name) == 0) return true;
        return false;
    };

    /* ---- 模块 01：系统信息 ---- */
    if (ShouldTest("sysinfo") && pfnGetSystemInfo && pfnFreeJsonString)
        PrintResult("SystemInfo",
            pfnGetSystemInfo("{}"), pfnFreeJsonString);

    /* ---- 模块 02：网络信息 ---- */
    if (ShouldTest("network") && pfnGetNetworkInfo && pfnFreeJsonString)
        PrintResult("NetworkInfo",
            pfnGetNetworkInfo("{}"), pfnFreeJsonString);

    /* ---- 模块 03：硬盘信息 ---- */
    if (ShouldTest("disk") && pfnGetDiskInfo && pfnFreeJsonString)
        PrintResult("DiskInfo",
            pfnGetDiskInfo("{}"), pfnFreeJsonString);

    /* ---- 模块 04：自启动 ---- */
    if (ShouldTest("autorun") && pfnGetAutorunInfo && pfnFreeJsonString)
        PrintResult("AutorunInfo",
            pfnGetAutorunInfo("{}"), pfnFreeJsonString);

    /* ---- 模块 05：进程信息（不含模块/线程详情，加快速度）---- */
    if (ShouldTest("process") && pfnGetProcessInfo && pfnFreeJsonString)
    {
        const char* params =
            "{\"include_modules\":false,\"include_threads\":false}";
        PrintResult("ProcessInfo",
            pfnGetProcessInfo(params), pfnFreeJsonString);
    }

    /* ---- 模块 06：计划任务 ---- */
    if (ShouldTest("tasks") && pfnGetScheduledTasks && pfnFreeJsonString)
        PrintResult("ScheduledTasks",
            pfnGetScheduledTasks("{}"), pfnFreeJsonString);

    /* ---- 模块 07：端口信息 ---- */
    if (ShouldTest("port") && pfnGetPortInfo && pfnFreeJsonString)
        PrintResult("PortInfo",
            pfnGetPortInfo("{}"), pfnFreeJsonString);

    /* ---- 模块 08：共享资源 ---- */
    if (ShouldTest("share") && pfnGetSharedResources && pfnFreeJsonString)
        PrintResult("SharedResources",
            pfnGetSharedResources("{}"), pfnFreeJsonString);

    /* ---- 模块 09：驱动信息 ---- */
    if (ShouldTest("driver") && pfnGetDriverInfo && pfnFreeJsonString)
        PrintResult("DriverInfo",
            pfnGetDriverInfo("{}"), pfnFreeJsonString);

    /* ---- 模块 10：浏览器插件 ---- */
    if (ShouldTest("browser") && pfnGetBrowserPlugins && pfnFreeJsonString)
        PrintResult("BrowserPlugins",
            pfnGetBrowserPlugins("{}"), pfnFreeJsonString);

    /* ---- 模块 11：内存映像（不保存 dump）---- */
    if (ShouldTest("memory") && pfnGetMemoryImageInfo && pfnFreeJsonString)
    {
        const char* params = "{\"save_dump\":false}";
        PrintResult("MemoryImageInfo",
            pfnGetMemoryImageInfo(params), pfnFreeJsonString);
    }

    /* ================================================================
     * 模块 12：数字证书检测
     * ================================================================ */

    /* 单文件检测：命令行指定路径，或默认使用 ntdll.dll */
    if (ShouldTest("cert") && pfnGetCertInfo && pfnFreeJsonString)
    {
        /* 若命令行第二个参数是文件路径则使用它，否则用默认路径 */
        std::string targetFile;
        for (int i = 1; i < argc - 1; i++)
        {
            if (_stricmp(argv[i], "cert") == 0 && argv[i + 1][0] != '\0')
            {
                targetFile = argv[i + 1];
                break;
            }
        }
        if (targetFile.empty())
        {
            /* 默认测试三个典型文件 */
            const char* defaults[] = {
                "C:\\Windows\\System32\\ntdll.dll",
                "C:\\Windows\\System32\\kernel32.dll",
                "C:\\Windows\\explorer.exe",
                NULL
            };
            for (int di = 0; defaults[di]; di++)
            {
                /* 构造参数 JSON */
                char paramBuf[512];
                _snprintf_s(paramBuf, sizeof(paramBuf), _TRUNCATE,
                    "{\"file_path\":\"%s\","
                    "\"check_revocation\":false,"
                    "\"include_chain\":true}",
                    defaults[di]);
                /* 转义反斜杠 */
                std::string p = paramBuf;
                std::string escaped;
                for (char c : p)
                    if (c == '\\') escaped += "\\\\";
                    else escaped += c;
                /* 重新构造 */
                char paramBuf2[512];
                _snprintf_s(paramBuf2, sizeof(paramBuf2), _TRUNCATE,
                    "{\"file_path\":\"%s\","
                    "\"check_revocation\":false,"
                    "\"include_chain\":true}",
                    defaults[di]);
                /* 直接传原始路径（cJSON 内部处理转义）*/
                cJSON_style_workaround:;
                /* 使用宽字符路径构造 */
                char label[128];
                _snprintf_s(label, sizeof(label), _TRUNCATE,
                    "CertInfo(%s)", defaults[di]);

                /* 构造合法 JSON（手动转义路径中的反斜杠）*/
                std::string jsonParam = "{\"file_path\":\"";
                for (const char* cp = defaults[di]; *cp; cp++)
                    if (*cp == '\\') jsonParam += "\\\\";
                    else jsonParam += *cp;
                jsonParam += "\",\"check_revocation\":false,\"include_chain\":true}";

                PrintResult(label,
                    pfnGetCertInfo(jsonParam.c_str()),
                    pfnFreeJsonString);
            }
        }
        else
        {
            /* 用户指定文件 */
            std::string jsonParam = "{\"file_path\":\"";
            for (char c : targetFile)
                if (c == '\\') jsonParam += "\\\\";
                else jsonParam += c;
            jsonParam += "\",\"check_revocation\":false,\"include_chain\":true}";

            char label[256];
            _snprintf_s(label, sizeof(label), _TRUNCATE,
                "CertInfo(%s)", targetFile.c_str());
            PrintResult(label,
                pfnGetCertInfo(jsonParam.c_str()),
                pfnFreeJsonString);
        }
    }

    /* 批量检测：对系统目录下几个典型文件批量扫描 */
    if (ShouldTest("certbatch") && pfnBatchGetCertInfo && pfnFreeJsonString)
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
        PrintResult("BatchCertInfo",
            pfnBatchGetCertInfo(batchParam),
            pfnFreeJsonString);
    }

    /* 清理 */
    if (pfnCleanupDetectSystem) pfnCleanupDetectSystem();
    FreeLibrary(hDll);

    printf("\nAll tests completed.\n");
    return 0;
}
