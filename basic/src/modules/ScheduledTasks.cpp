/*
 * 模块：计划任务
 * 指标：所有条目、状态
 * 使用 Task Scheduler COM API (ITaskService)
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <taskschd.h>
#include <comdef.h>
#include <string>
#include "../common/Utils.h"

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

static std::string BstrToUtf8(BSTR bstr)
{
    if (!bstr) return "";
    return WideToUtf8(bstr);
}

static std::string GetTaskStateStr(TASK_STATE state)
{
    switch (state)
    {
    case TASK_STATE_UNKNOWN:  return "Unknown";
    case TASK_STATE_DISABLED: return "Disabled";
    case TASK_STATE_QUEUED:   return "Queued";
    case TASK_STATE_READY:    return "Ready";
    case TASK_STATE_RUNNING:  return "Running";
    default: return "Unknown";
    }
}

static std::string GetTriggerTypeStr(TASK_TRIGGER_TYPE2 type)
{
    switch (type)
    {
    case TASK_TRIGGER_EVENT:               return "Event";
    case TASK_TRIGGER_TIME:                return "Time";
    case TASK_TRIGGER_DAILY:               return "Daily";
    case TASK_TRIGGER_WEEKLY:              return "Weekly";
    case TASK_TRIGGER_MONTHLY:             return "Monthly";
    case TASK_TRIGGER_MONTHLYDOW:          return "MonthlyDOW";
    case TASK_TRIGGER_IDLE:                return "Idle";
    case TASK_TRIGGER_REGISTRATION:        return "Registration";
    case TASK_TRIGGER_BOOT:                return "Boot";
    case TASK_TRIGGER_LOGON:               return "Logon";
    case TASK_TRIGGER_SESSION_STATE_CHANGE: return "SessionStateChange";
    default: return "Unknown";
    }
}

// 递归枚举任务文件夹
static void EnumTaskFolder(ITaskFolder* pFolder, const std::string& folderPath, cJSON* arr)
{
    // 枚举当前文件夹中的任务
    IRegisteredTaskCollection* pTaskColl = NULL;
    if (SUCCEEDED(pFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskColl)) && pTaskColl)
    {
        LONG count = 0;
        pTaskColl->get_Count(&count);
        for (LONG i = 1; i <= count; i++)
        {
            IRegisteredTask* pTask = NULL;
            VARIANT idx;
            idx.vt = VT_INT;
            idx.intVal = i;
            if (FAILED(pTaskColl->get_Item(idx, &pTask)) || !pTask) continue;

            cJSON* taskObj = cJSON_CreateObject();
            cJSON_AddStringToObject(taskObj, "folder", folderPath.c_str());

            BSTR name = NULL;
            if (SUCCEEDED(pTask->get_Name(&name)))
            {
                cJSON_AddStringToObject(taskObj, "name", BstrToUtf8(name).c_str());
                SysFreeString(name);
            }

            BSTR path = NULL;
            if (SUCCEEDED(pTask->get_Path(&path)))
            {
                cJSON_AddStringToObject(taskObj, "path", BstrToUtf8(path).c_str());
                SysFreeString(path);
            }

            TASK_STATE state;
            if (SUCCEEDED(pTask->get_State(&state)))
                cJSON_AddStringToObject(taskObj, "state", GetTaskStateStr(state).c_str());

            VARIANT_BOOL enabled;
            if (SUCCEEDED(pTask->get_Enabled(&enabled)))
                cJSON_AddBoolToObject(taskObj, "enabled", enabled ? 1 : 0);

            DATE lastRunTime = 0;
            if (SUCCEEDED(pTask->get_LastRunTime(&lastRunTime)))
            {
                /* DATE 是 double，转为 SYSTEMTIME 再输出 */
                SYSTEMTIME stLast = {0};
                char timeBuf[32] = {0};
                if (VariantTimeToSystemTime(lastRunTime, &stLast))
                    _snprintf_s(timeBuf, sizeof(timeBuf), _TRUNCATE,
                        "%04d-%02d-%02d %02d:%02d:%02d",
                        stLast.wYear, stLast.wMonth, stLast.wDay,
                        stLast.wHour, stLast.wMinute, stLast.wSecond);
                else
                    _snprintf_s(timeBuf, sizeof(timeBuf), _TRUNCATE, "N/A");
                cJSON_AddStringToObject(taskObj, "last_run_time", timeBuf);
            }

            DATE nextRunTime = 0;
            if (SUCCEEDED(pTask->get_NextRunTime(&nextRunTime)))
            {
                SYSTEMTIME stNext = {0};
                char timeBuf[32] = {0};
                if (VariantTimeToSystemTime(nextRunTime, &stNext))
                    _snprintf_s(timeBuf, sizeof(timeBuf), _TRUNCATE,
                        "%04d-%02d-%02d %02d:%02d:%02d",
                        stNext.wYear, stNext.wMonth, stNext.wDay,
                        stNext.wHour, stNext.wMinute, stNext.wSecond);
                else
                    _snprintf_s(timeBuf, sizeof(timeBuf), _TRUNCATE, "N/A");
                cJSON_AddStringToObject(taskObj, "next_run_time", timeBuf);
            }

            HRESULT lastResult;
            if (SUCCEEDED(pTask->get_LastTaskResult(&lastResult)))
            {
                char buf[16];
                _snprintf_s(buf, sizeof(buf), _TRUNCATE, "0x%08X", (unsigned)lastResult);
                cJSON_AddStringToObject(taskObj, "last_result", buf);
            }

            // 获取任务定义
            ITaskDefinition* pDef = NULL;
            if (SUCCEEDED(pTask->get_Definition(&pDef)) && pDef)
            {
                // 触发器
                ITriggerCollection* pTriggers = NULL;
                if (SUCCEEDED(pDef->get_Triggers(&pTriggers)) && pTriggers)
                {
                    LONG tCount = 0;
                    pTriggers->get_Count(&tCount);
                    cJSON* trigArr = cJSON_CreateArray();
                    for (LONG t = 1; t <= tCount; t++)
                    {
                        ITrigger* pTrig = NULL;
                        if (SUCCEEDED(pTriggers->get_Item((long)t, &pTrig)) && pTrig)
                        {
                            TASK_TRIGGER_TYPE2 ttype;
                            cJSON* trigObj = cJSON_CreateObject();
                            if (SUCCEEDED(pTrig->get_Type(&ttype)))
                                cJSON_AddStringToObject(trigObj, "type",
                                    GetTriggerTypeStr(ttype).c_str());
                            BSTR startBoundary = NULL;
                            if (SUCCEEDED(pTrig->get_StartBoundary(&startBoundary)))
                            {
                                cJSON_AddStringToObject(trigObj, "start_boundary",
                                    BstrToUtf8(startBoundary).c_str());
                                SysFreeString(startBoundary);
                            }
                            VARIANT_BOOL trigEnabled;
                            if (SUCCEEDED(pTrig->get_Enabled(&trigEnabled)))
                                cJSON_AddBoolToObject(trigObj, "enabled", trigEnabled ? 1 : 0);
                            cJSON_AddItemToArray(trigArr, trigObj);
                            pTrig->Release();
                        }
                    }
                    cJSON_AddItemToObject(taskObj, "triggers", trigArr);
                    pTriggers->Release();
                }

                // 动作
                IActionCollection* pActions = NULL;
                if (SUCCEEDED(pDef->get_Actions(&pActions)) && pActions)
                {
                    LONG aCount = 0;
                    pActions->get_Count(&aCount);
                    cJSON* actArr = cJSON_CreateArray();
                    for (LONG a = 1; a <= aCount; a++)
                    {
                        IAction* pAct = NULL;
                        if (SUCCEEDED(pActions->get_Item((long)a, &pAct)) && pAct)
                        {
                            TASK_ACTION_TYPE atype;
                            cJSON* actObj = cJSON_CreateObject();
                            if (SUCCEEDED(pAct->get_Type(&atype)) && atype == TASK_ACTION_EXEC)
                            {
                                cJSON_AddStringToObject(actObj, "type", "Exec");
                                IExecAction* pExec = NULL;
                                if (SUCCEEDED(pAct->QueryInterface(IID_IExecAction, (void**)&pExec)) && pExec)
                                {
                                    BSTR exePath = NULL;
                                    if (SUCCEEDED(pExec->get_Path(&exePath)))
                                    {
                                        cJSON_AddStringToObject(actObj, "path",
                                            BstrToUtf8(exePath).c_str());
                                        SysFreeString(exePath);
                                    }
                                    BSTR args = NULL;
                                    if (SUCCEEDED(pExec->get_Arguments(&args)))
                                    {
                                        cJSON_AddStringToObject(actObj, "arguments",
                                            BstrToUtf8(args).c_str());
                                        SysFreeString(args);
                                    }
                                    pExec->Release();
                                }
                            }
                            cJSON_AddItemToArray(actArr, actObj);
                            pAct->Release();
                        }
                    }
                    cJSON_AddItemToObject(taskObj, "actions", actArr);
                    pActions->Release();
                }

                // 主体（运行账户）
                IPrincipal* pPrincipal = NULL;
                if (SUCCEEDED(pDef->get_Principal(&pPrincipal)) && pPrincipal)
                {
                    BSTR userId = NULL;
                    if (SUCCEEDED(pPrincipal->get_UserId(&userId)))
                    {
                        cJSON_AddStringToObject(taskObj, "run_as_user",
                            BstrToUtf8(userId).c_str());
                        SysFreeString(userId);
                    }
                    TASK_RUNLEVEL_TYPE rl;
                    if (SUCCEEDED(pPrincipal->get_RunLevel(&rl)))
                        cJSON_AddStringToObject(taskObj, "run_level",
                            rl == TASK_RUNLEVEL_HIGHEST ? "Highest" : "LUA");
                    pPrincipal->Release();
                }

                pDef->Release();
            }

            cJSON_AddItemToArray(arr, taskObj);
            pTask->Release();
        }
        pTaskColl->Release();
    }

    // 递归子文件夹
    ITaskFolderCollection* pSubFolders = NULL;
    if (SUCCEEDED(pFolder->GetFolders(0, &pSubFolders)) && pSubFolders)
    {
        LONG fCount = 0;
        pSubFolders->get_Count(&fCount);
        for (LONG i = 1; i <= fCount; i++)
        {
            ITaskFolder* pSub = NULL;
            VARIANT fidx; fidx.vt = VT_INT; fidx.intVal = i;
            if (SUCCEEDED(pSubFolders->get_Item(fidx, &pSub)) && pSub)
            {
                BSTR subName = NULL;
                std::string subPath = folderPath;
                if (SUCCEEDED(pSub->get_Name(&subName)))
                {
                    subPath += "/" + BstrToUtf8(subName);
                    SysFreeString(subName);
                }
                EnumTaskFolder(pSub, subPath, arr);
                pSub->Release();
            }
        }
        pSubFolders->Release();
    }
}

extern "C" __declspec(dllexport)
char* GetScheduledTasks(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "scheduled_tasks");

    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    bool comInit = SUCCEEDED(hr);

    ITaskService* pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
        IID_ITaskService, (void**)&pService);
    if (FAILED(hr) || !pService)
    {
        if (comInit) CoUninitialize();
        return BuildErrorJson("scheduled_tasks", "CoCreateInstance ITaskService failed");
    }

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr))
    {
        pService->Release();
        if (comInit) CoUninitialize();
        return BuildErrorJson("scheduled_tasks", "ITaskService::Connect failed");
    }

    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
    if (FAILED(hr) || !pRootFolder)
    {
        pService->Release();
        if (comInit) CoUninitialize();
        return BuildErrorJson("scheduled_tasks", "GetFolder failed");
    }

    cJSON* tasksArr = cJSON_CreateArray();
    EnumTaskFolder(pRootFolder, "\\", tasksArr);

    pRootFolder->Release();
    pService->Release();
    if (comInit) CoUninitialize();

    cJSON_AddItemToObject(root, "tasks", tasksArr);
    cJSON_AddStringToObject(root, "status", "success");
    return SerializeJson(root);
}
