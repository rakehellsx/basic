/*
 * basic.dll - 恶意代码辅助检测系统动态库
 * 主入口文件
 */
#include <windows.h>
#include <cstdlib>
#include "../include/basic.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport)
int InitDetectSystem()
{
    // 预留初始化逻辑（如COM初始化、日志系统等）
    return 0;
}

extern "C" __declspec(dllexport)
void CleanupDetectSystem()
{
    // 预留清理逻辑
}

extern "C" __declspec(dllexport)
void FreeJsonString(char* jsonStr)
{
    if (jsonStr) free(jsonStr);
}
