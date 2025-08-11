# app/allowlist.py
# Common “safe” processes users/IT expect to see.
WHITELIST_NAMES = {
    # Browsers & dev
    "firefox.exe", "chrome.exe", "msedge.exe", "code.exe", "python.exe",
    # Windows core
    "explorer.exe", "taskmgr.exe", "conhost.exe", "svchost.exe",
    "runtimebroker.exe", "smartscreen.exe", "ctfmon.exe", "dwm.exe",
    "searchindexer.exe", "searchprotocolhost.exe",
    # Defender / security
    "msmpeng.exe", "nisrv.exe", "securityhealthservice.exe",
    "mpdefendercoreservice.exe",   # ← NEW (the one you saw)
    # Misc platform helpers
    "onedrive.exe",
}

# If the executable path contains any of these, treat as trusted.
SAFE_PATH_KEYWORDS = [
    r"\\windows\\system32\\",
    r"\\windows\\syswow64\\",
    r"\\program files\\",
    r"\\program files (x86)\\",
    r"\\users\\.+\\appdata\\local\\microsoft\\onedrive\\",
    r"\\users\\.+\\appdata\\local\\programs\\microsoft vs code\\",
    r"\\users\\.+\\.vscode\\extensions\\",
    r"\\program files\\mozilla firefox\\",
    r"\\program files\\microsoft\\edge\\",
    r"\\programdata\\microsoft\\windows defender\\platform\\",  # ← NEW hint
]
