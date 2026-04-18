/*
 * 模块：端口信息
 * 指标：所有端口，支持进程、端口、IP关联，包括进程发行商、协议、端口、状态、映像路径、本地IP、远程IP
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <map>
#include <vector>
#include "../common/Utils.h"
#include "../common/DbStorage.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")

static std::string AddrToStr(DWORD addr)
{
    in_addr ia;
    ia.s_addr = addr;
    char buf[64] = {0};
    inet_ntop(AF_INET, &ia, buf, sizeof(buf));
    return std::string(buf);
}

static std::string Addr6ToStr(const BYTE* addr)
{
    char buf[64] = {0};
    inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    return std::string(buf);
}

static std::string GetTcpStateStr(DWORD state)
{
    switch (state)
    {
    case MIB_TCP_STATE_CLOSED:      return "CLOSED";
    case MIB_TCP_STATE_LISTEN:      return "LISTEN";
    case MIB_TCP_STATE_SYN_SENT:    return "SYN_SENT";
    case MIB_TCP_STATE_SYN_RCVD:    return "SYN_RCVD";
    case MIB_TCP_STATE_ESTAB:       return "ESTABLISHED";
    case MIB_TCP_STATE_FIN_WAIT1:   return "FIN_WAIT1";
    case MIB_TCP_STATE_FIN_WAIT2:   return "FIN_WAIT2";
    case MIB_TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
    case MIB_TCP_STATE_CLOSING:     return "CLOSING";
    case MIB_TCP_STATE_LAST_ACK:    return "LAST_ACK";
    case MIB_TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
    case MIB_TCP_STATE_DELETE_TCB:  return "DELETE_TCB";
    default: return "UNKNOWN";
    }
}

/* 获取进程映像路径（局部版，避免与 Utils.h 中 GetProcessImagePath 冲突） */
static std::string GetPortProcImagePath(DWORD pid)
{
    if (pid == 0) return "System Idle";
    if (pid == 4) return "System";
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return "";
    wchar_t path[MAX_PATH] = {0};
    DWORD len = MAX_PATH;
    QueryFullProcessImageNameW(hProc, 0, path, &len);
    CloseHandle(hProc);
    return WideToUtf8(path);
}

/* 获取进程名称 */
static std::string GetPortProcName(DWORD pid)
{
    if (pid == 0) return "System Idle";
    if (pid == 4) return "System";
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return "";
    PROCESSENTRY32W pe = {0};
    pe.dwSize = sizeof(pe);
    std::string name;
    if (Process32FirstW(hSnap, &pe))
    {
        do {
            if (pe.th32ProcessID == pid)
            {
                name = WideToUtf8(pe.szExeFile);
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return name;
}

/* 填充进程相关字段 */
static void FillProcFields(cJSON* entry, DWORD pid)
{
    std::string imgPath = GetPortProcImagePath(pid);
    cJSON_AddStringToObject(entry, "process_name", GetPortProcName(pid).c_str());
    cJSON_AddStringToObject(entry, "process_path", imgPath.c_str());
    cJSON_AddStringToObject(entry, "image_path",   imgPath.c_str());

    if (!imgPath.empty())
    {
        std::wstring wpath = Utf8ToWstr(imgPath);
        cJSON_AddStringToObject(entry, "publisher",
            GetFilePublisherW(wpath).c_str());
    }
    else
    {
        cJSON_AddStringToObject(entry, "publisher", "");
    }
}

extern "C" __declspec(dllexport)
char* GetPortInfo(const char* /*paramsJson*/)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "port_info");

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    cJSON* portsArr = cJSON_CreateArray();

    /* ===== TCP IPv4 ===== */
    ULONG tcpSize = 0;
    GetExtendedTcpTable(NULL, &tcpSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCPTABLE_OWNER_PID* pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(tcpSize);
    if (pTcpTable)
    {
        if (GetExtendedTcpTable(pTcpTable, &tcpSize, TRUE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++)
            {
                MIB_TCPROW_OWNER_PID& row = pTcpTable->table[i];
                cJSON* entry = cJSON_CreateObject();
                cJSON_AddStringToObject(entry, "protocol",    "TCP");
                cJSON_AddStringToObject(entry, "local_ip",    AddrToStr(row.dwLocalAddr).c_str());
                cJSON_AddNumberToObject (entry, "local_port", (double)ntohs((u_short)row.dwLocalPort));
                cJSON_AddStringToObject(entry, "remote_ip",   AddrToStr(row.dwRemoteAddr).c_str());
                cJSON_AddNumberToObject (entry, "remote_port",(double)ntohs((u_short)row.dwRemotePort));
                cJSON_AddStringToObject(entry, "state",       GetTcpStateStr(row.dwState).c_str());
                cJSON_AddNumberToObject (entry, "pid",        (double)row.dwOwningPid);
                FillProcFields(entry, row.dwOwningPid);
                cJSON_AddItemToArray(portsArr, entry);
            }
        }
        free(pTcpTable);
    }

    /* ===== TCP IPv6 ===== */
    ULONG tcp6Size = 0;
    GetExtendedTcpTable(NULL, &tcp6Size, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCP6TABLE_OWNER_PID* pTcp6Table = (MIB_TCP6TABLE_OWNER_PID*)malloc(tcp6Size);
    if (pTcp6Table)
    {
        if (GetExtendedTcpTable(pTcp6Table, &tcp6Size, TRUE, AF_INET6,
            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        {
            for (DWORD i = 0; i < pTcp6Table->dwNumEntries; i++)
            {
                MIB_TCP6ROW_OWNER_PID& row = pTcp6Table->table[i];
                cJSON* entry = cJSON_CreateObject();
                cJSON_AddStringToObject(entry, "protocol",    "TCPv6");
                cJSON_AddStringToObject(entry, "local_ip",    Addr6ToStr(row.ucLocalAddr).c_str());
                cJSON_AddNumberToObject (entry, "local_port", (double)ntohs((u_short)row.dwLocalPort));
                cJSON_AddStringToObject(entry, "remote_ip",   Addr6ToStr(row.ucRemoteAddr).c_str());
                cJSON_AddNumberToObject (entry, "remote_port",(double)ntohs((u_short)row.dwRemotePort));
                cJSON_AddStringToObject(entry, "state",       GetTcpStateStr(row.dwState).c_str());
                cJSON_AddNumberToObject (entry, "pid",        (double)row.dwOwningPid);
                FillProcFields(entry, row.dwOwningPid);
                cJSON_AddItemToArray(portsArr, entry);
            }
        }
        free(pTcp6Table);
    }

    /* ===== UDP IPv4 ===== */
    ULONG udpSize = 0;
    GetExtendedUdpTable(NULL, &udpSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    MIB_UDPTABLE_OWNER_PID* pUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(udpSize);
    if (pUdpTable)
    {
        if (GetExtendedUdpTable(pUdpTable, &udpSize, TRUE, AF_INET,
            UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
        {
            for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++)
            {
                MIB_UDPROW_OWNER_PID& row = pUdpTable->table[i];
                cJSON* entry = cJSON_CreateObject();
                cJSON_AddStringToObject(entry, "protocol",    "UDP");
                cJSON_AddStringToObject(entry, "local_ip",    AddrToStr(row.dwLocalAddr).c_str());
                cJSON_AddNumberToObject (entry, "local_port", (double)ntohs((u_short)row.dwLocalPort));
                cJSON_AddStringToObject(entry, "remote_ip",   "*");
                cJSON_AddNumberToObject (entry, "remote_port",0.0);
                cJSON_AddStringToObject(entry, "state",       "LISTEN");
                cJSON_AddNumberToObject (entry, "pid",        (double)row.dwOwningPid);
                FillProcFields(entry, row.dwOwningPid);
                cJSON_AddItemToArray(portsArr, entry);
            }
        }
        free(pUdpTable);
    }

    /* ===== UDP IPv6 ===== */
    ULONG udp6Size = 0;
    GetExtendedUdpTable(NULL, &udp6Size, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    MIB_UDP6TABLE_OWNER_PID* pUdp6Table = (MIB_UDP6TABLE_OWNER_PID*)malloc(udp6Size);
    if (pUdp6Table)
    {
        if (GetExtendedUdpTable(pUdp6Table, &udp6Size, TRUE, AF_INET6,
            UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
        {
            for (DWORD i = 0; i < pUdp6Table->dwNumEntries; i++)
            {
                MIB_UDP6ROW_OWNER_PID& row = pUdp6Table->table[i];
                cJSON* entry = cJSON_CreateObject();
                cJSON_AddStringToObject(entry, "protocol",    "UDPv6");
                cJSON_AddStringToObject(entry, "local_ip",    Addr6ToStr(row.ucLocalAddr).c_str());
                cJSON_AddNumberToObject (entry, "local_port", (double)ntohs((u_short)row.dwLocalPort));
                cJSON_AddStringToObject(entry, "remote_ip",   "*");
                cJSON_AddNumberToObject (entry, "remote_port",0.0);
                cJSON_AddStringToObject(entry, "state",       "LISTEN");
                cJSON_AddNumberToObject (entry, "pid",        (double)row.dwOwningPid);
                FillProcFields(entry, row.dwOwningPid);
                cJSON_AddItemToArray(portsArr, entry);
            }
        }
        free(pUdp6Table);
    }

    cJSON_AddItemToObject(root, "ports", portsArr);
    cJSON_AddStringToObject(root, "status", "success");

    WSACleanup();
    return SerializeJson(root);
}

/*
 * SavePortInfo — 采集端口信息并字段级存入 SQLite3
 * 参数 JSON: { "db_path": "C:\\basic.db" }
 * 返回 JSON: { "snapshot_id": N, "rows_inserted": N, "status": "success" }
 */
extern "C" __declspec(dllexport)
char* SavePortInfo(const char* paramsJson)
{
    cJSON* result = cJSON_CreateObject();
    cJSON_AddStringToObject(result, "module", "savePortInfo");

    std::string dbPath = "basic_detect.db";
    if (paramsJson && paramsJson[0])
    {
        cJSON* p = cJSON_Parse(paramsJson);
        if (p)
        {
            cJSON* dp = cJSON_GetObjectItem(p, "db_path");
            if (dp && cJSON_IsString(dp) && dp->valuestring)
                dbPath = dp->valuestring;
            cJSON_Delete(p);
        }
    }

    char* jsonStr = GetPortInfo(paramsJson);
    if (!jsonStr)
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", "GetPortInfo failed");
        return SerializeJson(result);
    }

    DbStorage db;
    if (!db.Open(dbPath))
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", db.LastError().c_str());
        FreeJsonString(jsonStr);
        return SerializeJson(result);
    }

    long long snapId = db.SavePortInfo(jsonStr);
    FreeJsonString(jsonStr);

    if (snapId < 0)
    {
        cJSON_AddStringToObject(result, "status", "error");
        cJSON_AddStringToObject(result, "message", db.LastError().c_str());
    }
    else
    {
        cJSON_AddNumberToObject(result, "snapshot_id", (double)snapId);
        cJSON_AddStringToObject(result, "status", "success");
    }
    return SerializeJson(result);
}

