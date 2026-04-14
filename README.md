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
- `Windows API`：依赖 `netapi32.lib`、`advapi32.lib`、`iphlpapi.lib`、`wintrust.lib`、`crypt32.lib`、`imagehlp.lib` 等系统核心库。
