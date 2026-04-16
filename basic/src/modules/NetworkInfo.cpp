/*
 * 模块：网络信息
 * 指标：所有网卡、IP、子网掩码、网关、MAC
 */
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <string>
#include "../common/Utils.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static std::string MacToString(const BYTE* mac, DWORD len)
{
    if (!mac || len == 0) return "";
    char buf[64] = {0};
    char* p = buf;
    for (DWORD i = 0; i < len; i++)
    {
        if (i > 0) *p++ = '-';
        p += sprintf_s(p, 4, "%02X", mac[i]);
    }
    return std::string(buf);
}

static std::string AddrToString(SOCKADDR* addr)
{
    if (!addr) return "";
    char buf[128] = {0};
    DWORD bufLen = sizeof(buf);
    if (WSAAddressToStringA(addr, (addr->sa_family == AF_INET6) ?
        sizeof(SOCKADDR_IN6) : sizeof(SOCKADDR_IN),
        NULL, buf, &bufLen) == 0)
        return std::string(buf);
    return "";
}

static std::string GetAdapterType(UINT type)
{
    switch (type)
    {
    case IF_TYPE_ETHERNET_CSMACD: return "Ethernet";
    case IF_TYPE_ISO88025_TOKENRING: return "TokenRing";
    case IF_TYPE_PPP: return "PPP";
    case IF_TYPE_SOFTWARE_LOOPBACK: return "Loopback";
    case IF_TYPE_ATM: return "ATM";
    case IF_TYPE_IEEE80211: return "WiFi(802.11)";
    case IF_TYPE_TUNNEL: return "Tunnel";
    case IF_TYPE_IEEE1394: return "IEEE1394";
    default: return "Other";
    }
}

static std::string GetOperStatus(IF_OPER_STATUS status)
{
    switch (status)
    {
    case IfOperStatusUp:             return "Up";
    case IfOperStatusDown:           return "Down";
    case IfOperStatusTesting:        return "Testing";
    case IfOperStatusUnknown:        return "Unknown";
    case IfOperStatusDormant:        return "Dormant";
    case IfOperStatusNotPresent:     return "NotPresent";
    case IfOperStatusLowerLayerDown: return "LowerLayerDown";
    default: return "Unknown";
    }
}

extern "C" __declspec(dllexport)
char* GetNetworkInfo(const char* paramsJson)
{
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "module", "network_info");

    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 使用 GetAdaptersAddresses 获取完整网络适配器信息
    ULONG bufLen = 15 * 1024;
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG ret = ERROR_BUFFER_OVERFLOW;
    int attempts = 0;

    while (ret == ERROR_BUFFER_OVERFLOW && attempts < 3)
    {
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
        if (!pAddresses) break;
        ret = GetAdaptersAddresses(AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
            NULL, pAddresses, &bufLen);
        if (ret == ERROR_BUFFER_OVERFLOW) { free(pAddresses); pAddresses = NULL; }
        attempts++;
    }

    cJSON* adapters = cJSON_CreateArray();

    if (ret == NO_ERROR && pAddresses)
    {
        PIP_ADAPTER_ADDRESSES pCur = pAddresses;
        while (pCur)
        {
            cJSON* adapter = cJSON_CreateObject();

            // 基本信息
            cJSON_AddStringToObject(adapter, "adapter_name",
                AnsiToUtf8(pCur->AdapterName).c_str());
            cJSON_AddStringToObject(adapter, "friendly_name",
                WideToUtf8(pCur->FriendlyName).c_str());
            cJSON_AddStringToObject(adapter, "description",
                WideToUtf8(pCur->Description).c_str());
            cJSON_AddStringToObject(adapter, "type",
                GetAdapterType(pCur->IfType).c_str());
            cJSON_AddStringToObject(adapter, "oper_status",
                GetOperStatus(pCur->OperStatus).c_str());
            cJSON_AddNumberToObject(adapter, "if_index",
                (double)pCur->IfIndex);
            cJSON_AddStringToObject(adapter, "mac_address",
                MacToString(pCur->PhysicalAddress, pCur->PhysicalAddressLength).c_str());
            cJSON_AddNumberToObject(adapter, "mtu", (double)pCur->Mtu);
            cJSON_AddStringToObject(adapter, "transmit_link_speed",
                LargeIntToString(pCur->TransmitLinkSpeed).c_str());
            cJSON_AddStringToObject(adapter, "receive_link_speed",
                LargeIntToString(pCur->ReceiveLinkSpeed).c_str());

            // IP地址列表（含子网掩码前缀长度）
            cJSON* ipList = cJSON_CreateArray();
            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCur->FirstUnicastAddress;
            while (pUnicast)
            {
                cJSON* ipItem = cJSON_CreateObject();
                cJSON_AddStringToObject(ipItem, "address",
                    AddrToString(pUnicast->Address.lpSockaddr).c_str());
                cJSON_AddNumberToObject(ipItem, "prefix_length",
                    (double)pUnicast->OnLinkPrefixLength);
                cJSON_AddStringToObject(ipItem, "family",
                    pUnicast->Address.lpSockaddr->sa_family == AF_INET ? "IPv4" : "IPv6");
                cJSON_AddItemToArray(ipList, ipItem);
                pUnicast = pUnicast->Next;
            }
            cJSON_AddItemToObject(adapter, "unicast_addresses", ipList);

            // DNS服务器
            cJSON* dnsList = cJSON_CreateArray();
            PIP_ADAPTER_DNS_SERVER_ADDRESS pDns = pCur->FirstDnsServerAddress;
            while (pDns)
            {
                cJSON_AddItemToArray(dnsList,
                    cJSON_CreateString(AddrToString(pDns->Address.lpSockaddr).c_str()));
                pDns = pDns->Next;
            }
            cJSON_AddItemToObject(adapter, "dns_servers", dnsList);

            // 网关
            cJSON* gwList = cJSON_CreateArray();
            PIP_ADAPTER_GATEWAY_ADDRESS pGw = pCur->FirstGatewayAddress;
            while (pGw)
            {
                cJSON_AddItemToArray(gwList,
                    cJSON_CreateString(AddrToString(pGw->Address.lpSockaddr).c_str()));
                pGw = pGw->Next;
            }
            cJSON_AddItemToObject(adapter, "gateways", gwList);

            // DNS后缀
            cJSON_AddStringToObject(adapter, "dns_suffix",
                WideToUtf8(pCur->DnsSuffix).c_str());

            cJSON_AddItemToArray(adapters, adapter);
            pCur = pCur->Next;
        }
        free(pAddresses);
    }
    else
    {
        char errBuf[64];
        _snprintf_s(errBuf, sizeof(errBuf), _TRUNCATE,
            "GetAdaptersAddresses failed: %lu", ret);
        cJSON_AddStringToObject(root, "error", errBuf);
    }

    cJSON_AddItemToObject(root, "adapters", adapters);
    cJSON_AddStringToObject(root, "status", "success");

    WSACleanup();
    return SerializeJson(root);
}
