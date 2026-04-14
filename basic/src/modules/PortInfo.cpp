/*
 * 模块：端口信息
 * 指标：所有端口，支持进程、端口、IP关联，包括进程发行商、协议、端口、状态、映像路径、本地IP、远程IP
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <map>
#include "../../third_party/cJSON/cJSON.h"
#include "../common/Utils.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")

static std::string AddrToStr(DWORD addr)
{
    in_addr ia;
    ia.s_addr = addr;
    char buf[64];
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

// 获取进程映像路径
static std::string GetProcessImagePath(DWORD pid)
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

// 获取进程名称
static std::string GetProcessName(DWORD pid)
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
            if (pe.th32ProcessID == pid) {
                name = WideToUtf8(pe.szExeFile);
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    return name;
}

// 获取文件发行商（复用）
static std::string GetFilePublisherForPort(const wchar_t* filePath);

extern "C" __declspec(dllexport)
char* GetPortInfo(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "port_info");

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    cJSON* portsArr = cJSON_CreateArray();

    // ===== TCP IPv4 =====
    ULONG tcpSize = 0;
    GetExtendedTcpTable(NULL, &tcpSize, TRUE, AF_INET,
        TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCPTABLE_OWNER_PID* pTcpTable =
        (MIB_TCPTABLE_OWNER_PID*)malloc(tcpSize);
    if (pTcpTable)
    {
        if (GetExtendedTcpTable(pTcpTable, &tcpSize, TRUE, AF_INET,
            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        {
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++)
            {
                MIB_TCPROW_OWNER_PID& row = pTcpTable->table[i];
                cJSON* entry = cJSON_CreateObject();
                cJSON_AddStringToObject(entry, "protocol", "TCP");
                cJSON_AddStringToObject(entry, "local_ip",
                    AddrToStr(row.dwLocalAddr).c_str());
                cJSON_AddNumberToObject(entry, "local_port",
                    (double)ntohs((u_short)row.dwLocalPort));
                cJSON_AddStringToObject(entry, "remote_ip",
                    AddrToStr(row.dwRemoteAddr).c_str());
                cJSON_AddNumberToObject(entry, "remote_port",
                    (double)ntohs((u_short)row.dwRemotePort));
                cJSON_AddStringToObject(entry, "state",
                    GetTcpStateStr(row.dwState).c_str());
                cJSON_AddNumberToObject(entry, "pid", (double)row.dwOwningPid);
                std::string procName = GetProcessName(row.dwOwningPid);
                cJSON_AddStringToObject(entry, "process_name", procName.c_str());
                std::string imgPath = GetProcessImagePath(row.dwOwningPid);
                cJSON_AddStringToObject(entry, "image_path", imgPath.c_str());
                // 发行商
                if (!imgPath.empty())
                {
                    int wlen = MultiByteToWideChar(CP_UTF8, 0, imgPath.c_str(), -1, NULL, 0);
                    std::wstring wpath(wlen - 1, L'\0');
                    MultiByteToWideChar(CP_UTF8, 0, imgPath.c_str(), -1, &wpath[0], wlen);
                    // 复用GetFilePublisher逻辑
                    DWORD dummy = 0;
                    DWORD vsz = GetFileVersionInfoSizeW(wpath.c_str(), &dummy);
                    std::string pub;
                    if (vsz > 0)
                    {
                        std::vector<BYTE> vbuf(vsz);
                        if (GetFileVersionInfoW(wpath.c_str(), 0, vsz, vbuf.data()))
                        {
                            struct LC { WORD lang; WORD cp; };
                            LC* lc = NULL; UINT lcsz = 0;
                            if (VerQueryValueW(vbuf.data(), L"\\VarFileInfo\\Translation",
                                (LPVOID*)&lc, &lcsz) && lcsz >= sizeof(LC))
                            {
                                wchar_t sb[64];
                                _snwprintf_s(sb, 64, _TRUNCATE,
                                    L"\\StringFileInfo\\%04x%04x\\CompanyName",
                                    lc[0].lang, lc[0].cp);
                                wchar_t* co = NULL; UINT cos = 0;
                                if (VerQueryValueW(vbuf.data(), sb, (LPVOID*)&co, &cos) && co)
                                    pub = WideToUtf8(co);
                            }
                        }
                    }
                    cJSON_AddStringToObject(entry, "publisher", pub.c_str());
                }
                cJSON_AddItemToArray(portsArr, entry);
            }
        }
        free(pTcpTable);
    }

    // ===== TCP IPv6 =====
    ULONG tcp6Size = 0;
    GetExtendedTcpTable(NULL, &tcp6Size, TRUE, AF_INET6,
        TCP_TABLE_OWNER_PID_ALL, 0);
    MIB_TCP6TABLE_OWNER_PID* pTcp6Table =
        (MIB_TCP6TABLE_OWNER_PID*)malloc(tcp6Size);
    if (pTcp6Table)
    {
        if (GetExtendedTcpTable(pTcp6Table, &tcp6Size, TRUE, AF_INET6,
            TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        {
            for (DWORD i = 0; i < pTcp6Table->dwNumEntries; i++)
            {
                MIB_TCP6ROW_OWNER_PID& row = pTcp6Table->table[i];
                cJSON* entry = cJSON_CreateObject();
                cJSON_AddStringToObject(entry, "protocol", "TCPv6");
                cJSON_AddStringToObject(entry, "local_ip",
                    Addr6ToStr(row.ucLocalAddr).c_str());
                cJSON_AddNumberToObject(entry, "local_port",
                    (double)ntohs((u_short)row.dwLocalPort));
                cJSON_AddStringToObject(entry, "remote_ip",
                    Addr6ToStr(row.ucRemoteAddr).c_str());
                cJSON_AddNumberToObject(entry, "remote_port",
                    (double)ntohs((u_short)row.dwRemotePort));
                cJSON_AddStringToObject(entry, "state",
                    GetTcpStateStr(row.dwState).c_str());
                cJSON_AddNumberToObject(entry, "pid", (double)row.dwOwningPid);
                cJSON_AddStringToObject(entry, "process_name",
                    GetProcessName(row.dwOwningPid).c_str());
                cJSON_AddStringToObject(entry, "image_path",
                    GetProcessImagePath(row.dwOwningPid).c_str());
                cJSON_AddItemToArray(portsArr, entry);
            }
        }
        free(pTcp6Table);
    }

    // ===== UDP IPv4 =====
    ULONG udpSize = 0;
    GetExtendedUdpTable(NULL, &udpSize, TRUE, AF_INET,
        UDP_TABLE_OWNER_PID, 0);
    MIB_UDPTABLE_OWNER_PID* pUdpTable =
        (MIB_UDPTABLE_OWNER_PID*)malloc(udpSize);
    if (pUdpTable)
    {
        if (GetExtendedUdpTable(pUdpTable, &udpSize, TRUE, AF_INET,
            UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
        {
            for (DWORD i = 0; i < pUdpTable->dwNumEntries; i++)
            {
                MIB_UDPROW_OWNER_PID& row = pUdpTable->table[i];
                cJSON* entry = cJSON_CreateObject();
                cJSON_AddStringToObject(entry, "protocol", "UDP");
                cJSON_AddStringToObject(entry, "local_ip",
                    AddrToStr(row.dwLocalAddr).c_str());
                cJSON_AddNumberToObject(entry, "local_port",
                    (double)ntohs((u_short)row.dwLocalPort));
                cJSON_AddStringToObject(entry, "remote_ip", "*");
                cJSON_AddNumberToObject(entry, "remote_port", 0.0);
                cJSON_AddStringToObject(entry, "state", "LISTEN");
                cJSON_AddNumberToObject(entry, "pid", (double)row.dwOwningPid);
                cJSON_AddStringToObject(entry, "process_name",
                    GetProcessName(row.dwOwningPid).c_str());
                cJSON_AddStringToObject(entry, "image_path",
                    GetProcessImagePath(row.dwOwningPid).c_str());
                cJSON_AddItemToArray(portsArr, entry);
            }
        }
        free(pUdpTable);
    }

    // ===== UDP IPv6 =====
    ULONG udp6Size = 0;
    GetExtendedUdpTable(NULL, &udp6Size, TRUE, AF_INET6,
        UDP_TABLE_OWNER_PID, 0);
    MIB_UDP6TABLE_OWNER_PID* pUdp6Table =
        (MIB_UDP6TABLE_OWNER_PID*)malloc(udp6Size);
    if (pUdp6Table)
    {
        if (GetExtendedUdpTable(pUdp6Table, &udp6Size, TRUE, AF_INET6,
            UDP_TABLE_OWNER_PID, 0) == NO_ERROR)
        {
            for (DWORD i = 0; i < pUdp6Table->dwNumEntries; i++)
            {
                MIB_UDP6ROW_OWNER_PID& row = pUdp6Table->table[i];
                cJSON* entry = cJSON_CreateObject();
                cJSON_AddStringToObject(entry, "protocol", "UDPv6");
                cJSON_AddStringToObject(entry, "local_ip",
                    Addr6ToStr(row.ucLocalAddr).c_str());
                cJSON_AddNumberToObject(entry, "local_port",
                    (double)ntohs((u_short)row.dwLocalPort));
                cJSON_AddStringToObject(entry, "remote_ip", "*");
                cJSON_AddNumberToObject(entry, "remote_port", 0.0);
                cJSON_AddStringToObject(entry, "state", "LISTEN");
                cJSON_AddNumberToObject(entry, "pid", (double)row.dwOwningPid);
                cJSON_AddStringToObject(entry, "process_name",
                    GetProcessName(row.dwOwningPid).c_str());
                cJSON_AddStringToObject(entry, "image_path",
                    GetProcessImagePath(row.dwOwningPid).c_str());
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

// 占位，避免链接错误
static std::string GetFilePublisherForPort(const wchar_t* filePath)
{
    return "";
}
