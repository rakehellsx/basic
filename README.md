# basic - 基础信息获取动态库

`basic` 是一个基于 VS2017 (C/C++) 开发的基础信息获取动态链接库（DLL）。该库提供了一套标准的接口，能够对 Windows 系统的各类软硬件资产及运行状态进行深度采集与分析。系统以模块化的方式提供参数输入，并统一以 JSON 格式输出检测结果，为上层分析平台或安全人员提供结构化、可扩展的数据支撑。

---

## 核心特性

- **模块化设计**：系统划分为 12 个独立的功能模块，涵盖系统、网络、磁盘、进程、内存、驱动及数字证书等关键领域。
- **标准化接口**：所有模块均提供统一的 C 语言导出接口（`const char* paramsJson`），输入和输出均采用标准 JSON 格式，便于跨语言调用。
- **轻量级依赖**：JSON 解析采用极轻量的开源库 `cJSON`，核心功能全部依赖 Windows 原生 API，无需额外安装庞大的第三方库。
- **深度检测能力**：支持数字证书的完整性校验（Authenticode）、内存映像基址提取、进程模块与线程枚举、隐藏分区探测等高级安全检测功能。

---

## 工程结构

```text
basic_project/
├── basic.sln                     ← Visual Studio 2017 解决方案文件
├── basic/                        ← DLL 主工程目录
│   ├── basic.vcxproj             ← 项目配置文件（输出 basic.dll / basic.lib）
│   ├── include/basic.h           ← 统一导出接口头文件
│   ├── src/
│   │   ├── dllmain.cpp           ← DLL 入口文件
│   │   ├── common/               ← 公共工具类（字符编码转换等）
│   │   └── modules/              ← 12个核心检测模块的实现源码
│   └── third_party/cJSON/        ← cJSON 源码（JSON解析核心）
└── basicTest/
    ├── basicTest.vcxproj         ← 测试程序项目配置文件
    └── src/TestMain.cpp          ← 测试可执行程序源码（用于验证 DLL 接口调用）
```

---

## 模块功能与指标覆盖

本系统共包含 12 个检测模块，具体指标覆盖如下：

| 模块名称 | 导出接口 | 核心检测指标 |
| :--- | :--- | :--- |
| **01 系统信息** | `GetSystemInfo` | 系统版本、安装时间、计算机名称、系统账户等。 |
| **02 网络信息** | `GetNetworkInfo` | 所有网卡设备、IP地址、子网掩码、默认网关、MAC地址等。 |
| **03 硬盘信息** | `GetDiskInfo` | 硬盘厂商、型号、序列号、总容量、分区详情（含隐藏分区探测）、启动次数、累计使用时间等。 |
| **04 自启动信息** | `GetAutorunInfo` | 注册表自动运行项、操作启动项（右键菜单、系统调试器等）。 |
| **05 进程信息** | `GetProcessInfo` | 进程列表、加载模块、线程信息、文件句柄、发行商、映像修改时间、映像路径及授信状态。 |
| **06 计划任务** | `GetScheduledTasks` | 系统中所有的计划任务条目及其当前状态。 |
| **07 端口信息** | `GetPortInfo` | 所有开放端口、进程/端口/IP 关联信息、协议类型、状态、映像路径、本地与远程 IP。 |
| **08 共享资源** | `GetSharedResources` | 共享名称、资源种类、当前访问用户、映像路径。 |
| **09 驱动信息** | `GetDriverInfo` | 实体硬件驱动、虚拟硬件驱动、发行商、修改时间、映像路径及授信状态。 |
| **10 浏览器插件** | `GetBrowserPlugins` | 插件类型、状态、修改时间、路径（支持 IE、Chrome、Edge、Brave、Firefox 等主流浏览器）。 |
| **11 内存映像** | `GetMemoryImageInfo` | 内存运行状态、内核模块基址、映像大小、标志、序号、路径及授信状态（支持导出进程 dump）。 |
| **12 数字证书** | `GetCertInfo`<br>`BatchGetCertInfo` | 签名有效性验证（Authenticode）、文件篡改检测、证书时间戳、序列号、使用者、颁发者、有效期、签名算法及证书链指纹。 |
| **13 统一查询与持久化** | `QueryModuleAndSave`<br>`QueryHistory` | 按模块名调用任意检测模块，将结果自动写入 SQLite3 数据库；支持按模块名查询历史检测记录。 |
| **14 文件关联检测** | `GetFileAssocInfo`<br>`CheckFileAssoc` | 枚举所有已注册扩展名，判断是否为已知类型，提取默认打开方式（ProgID、命令行、图标），检测 UserChoice 与 HKCR 是否一致、关联程序路径是否可疑、可执行文件是否具有有效数字签名。 |
| **15 文件格式检测** | `DetectFileFormat`<br>`ScanDirectoryFormat` | 通过魔数（Magic Number）识别文件真实格式，检测扩展名与真实格式是否一致（格式伪装）；支持六大类型：可执行文件（EXE/DLL/SYS/ELF/BIN等）、脚本文件（BAT/VBS/PS1/PY/JS/SH等）、文档文件（DOC/DOCX/PDF/OFD/CHM等）、压缩文件（ZIP/RAR/7Z/ISO/CAB等）、多媒体文件（SWF/PNG/MP3/MP4/AVI等）、复合文件（邮件内嵌/文档内嵌宏）；检测恶意宏、嵌入对象、加密、可疑字符串；结果存入 SQLite3 file_format_results 表。 |
| **16 文件静态信息** | `GetFileStaticInfo`<br>`SaveFileStaticInfo` | **基础属性**：创建时间、修改时间、PE 编译时间戳、发行商、文件版本、MD5、SHA256、文件类型（复用模块 15 魔数识别）。**PE 结构解析**：目标架构（x86/x64/ARM/ARM64）、入口点、映像基址、子系统、链接器版本、加壳/编译器特征（UPX/MPRESS/VMProtect/MSVC/GCC 等）、节区详情（名称/虚拟地址/大小/熵值/状态判断：正常/高熵痕似加密/可疑）、导入表（DLL/函数/风险评级：高危进程注入/中危网络通信）。**字符串提取**：ASCII + UTF-16LE 可打印字符串，写入独立 .txt 文件，SQLite3 中只存文件路径。 |

---

## 编译说明

1. 环境要求：Windows 10 及以上系统，安装 **Visual Studio 2017**（需包含 C++ 桌面开发工作负载）。
2. 双击打开 `basic.sln`。
3. 在顶部工具栏选择所需的配置（如 `Release`）和平台（如 `x64` 或 `x86`）。
4. 右键点击解决方案，选择 **生成解决方案**。
5. 编译成功后，生成的 `basic.dll`、`basic.lib` 及测试程序 `basicTest.exe` 将位于 `bin/Release/x64/` 目录下。

---

## 接口调用示例

所有接口均定义在 `include/basic.h` 中，以下为调用数字证书检测模块的 C++ 示例：

```cpp
#include <iostream>
#include <windows.h>
#include "basic.h"

// 声明函数指针类型
typedef char* (*GetCertInfoFunc)(const char*);
typedef void (*FreeJsonStringFunc)(char*);

int main() {
    // 加载 DLL
    HMODULE hDll = LoadLibraryW(L"basic.dll");
    if (!hDll) {
        std::cerr << "Failed to load basic.dll" << std::endl;
        return 1;
    }

    // 获取函数地址
    GetCertInfoFunc GetCertInfo = (GetCertInfoFunc)GetProcAddress(hDll, "GetCertInfo");
    FreeJsonStringFunc FreeJsonString = (FreeJsonStringFunc)GetProcAddress(hDll, "FreeJsonString");

    if (GetCertInfo && FreeJsonString) {
        // 构造 JSON 参数
        const char* params = R"({"file_path": "C:\\Windows\\System32\\ntdll.dll", "include_chain": true})";
        
        // 调用接口获取结果
        char* resultJson = GetCertInfo(params);
        if (resultJson) {
            std::cout << "Result: \n" << resultJson << std::endl;
            
            // 必须调用 DLL 提供的释放接口释放内存，避免跨模块内存泄漏
            FreeJsonString(resultJson);
        }
    }

    FreeLibrary(hDll);
    return 0;
}
```

### 注意事项
1. **内存管理**：由 DLL 接口返回的 JSON 字符串指针（`char*`），**必须**调用 `FreeJsonString` 接口进行释放，切勿在调用方直接使用 `free()` 或 `delete`，以免引发跨模块内存堆崩溃。
2. **字符编码**：DLL 内部处理统一使用宽字符（UTF-16LE），与外部交互的 JSON 字符串均采用 **UTF-8** 编码。

---

## 依赖库

- `cJSON`：一个超轻量级的 C 语言 JSON 解析器（基于 MIT 许可证）。
- `SQLite3`：嵌入式关系型数据库，以 amalgamation 单文件形式集成（`sqlite3.c` / `sqlite3.h`），无需额外安装，基于 Public Domain 许可证。
- `Windows API`：依赖 `netapi32.lib`、`advapi32.lib`、`iphlpapi.lib`、`wintrust.lib`、`crypt32.lib`、`imagehlp.lib` 等系统核心库。

---

## Save* 字段级存储接口

所有模块均提供独立的 `Save*` 导出接口，调用后自动采集数据并将**每个字段单独写入 SQLite3 专属表**（非 JSON 整体存储），支持字段级查询与分析。

| 接口 | 对应模块 | 专属数据表 |
|---|---|---|
| `SaveSysInfo` | 01 系统信息 | `sys_info` |
| `SaveNetworkInfo` | 02 网络信息 | `network_adapters` |
| `SaveDiskInfo` | 03 硬盘信息 | `disk_info` |
| `SaveAutorunInfo` | 04 自启动信息 | `autorun_items` |
| `SaveProcessInfo` | 05 进程信息 | `process_list` |
| `SaveScheduledTasks` | 06 计划任务 | `scheduled_tasks` |
| `SavePortInfo` | 07 端口信息 | `port_list` |
| `SaveSharedResources` | 08 共享资源 | `shared_resources` |
| `SaveDriverInfo` | 09 驱动信息 | `driver_list` |
| `SaveBrowserPlugins` | 10 浏览器插件 | `browser_plugins` |
| `SaveMemoryImageInfo` | 11 内存映像 | `memory_modules` |
| `SaveCertInfo` | 12 数字证书 | `cert_info` |
| `SaveFileAssocInfo` | 14 文件关联 | `file_assoc` |
| `SaveFileStaticInfo` | 16 文件静态信息 | `file_static_results` |

**调用示例（SaveProcessInfo）：**

```json
// 输入参数
{ "db_path": "C:\\basic_detect.db" }

// 返回结果
{ "snapshot_id": 3, "status": "success" }
```

---

## 数据库持久化说明

`QueryModuleAndSave` 接口提供了统一的模块调度与结果持久化能力，数据库表结构如下：

```sql
CREATE TABLE detection_results (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  module_name TEXT    NOT NULL,   -- 模块名称，如 "system_info"
  params_json TEXT,               -- 调用时传入的参数 JSON
  result_json TEXT,               -- 模块返回的完整检测结果 JSON
  created_at  TEXT                -- 记录时间（UTC，格式：YYYY-MM-DD HH:MM:SS）
);
```

**调用示例（QueryModuleAndSave）：**

```json
// 输入参数
{
  "module_name"  : "process_info",
  "module_params": {},
  "db_path"      : "C:\\basic_detect.db",
  "save_to_db"   : true
}

// 返回结果
{
  "module"      : "query_module_and_save",
  "module_name" : "process_info",
  "db_path"     : "C:\\basic_detect.db",
  "record_id"   : 5,
  "save_status" : "success",
  "result"      : { ... },
  "status"      : "success"
}
```

**调用示例（QueryHistory）：**

```json
// 输入参数
{
  "module_name" : "process_info",
  "db_path"     : "C:\\basic_detect.db",
  "limit"       : 20
}

// 返回结果
{
  "module"      : "query_history",
  "module_name" : "process_info",
  "total"       : 3,
  "records"     : [
    {
      "id"         : 5,
      "module_name": "process_info",
      "params_json": "{}",
      "result"     : { ... },
      "created_at" : "2025-04-13 10:00:00"
    }
  ],
  "status"      : "success"
}
```
