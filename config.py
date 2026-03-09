"""
Configuration Module – Lightweight EDR
All detection thresholds and tunable settings in one place.
"""

import os


class EDRConfig:

    # ===========================
    # Process Monitoring
    # ===========================
    SCAN_INTERVAL = 2.0           # Seconds between process scans

    # ===========================
    # Detection Thresholds
    # ===========================
    CPU_THRESHOLD = 80.0          # CPU % → WARNING
    CPU_CRITICAL_THRESHOLD = 90.0 # CPU % → CRITICAL (instant, no consecutive needed)
    CPU_CONSECUTIVE_CHECKS = 3    # Consecutive scans above CPU_THRESHOLD → CRITICAL
    COMBINED_CPU_THRESHOLD = 50.0

    MEMORY_THRESHOLD = 30.0               # Legacy alias
    MEMORY_WARNING_THRESHOLD = 50.0       # Memory % → WARNING
    MEMORY_CRITICAL_THRESHOLD = 70.0      # Memory % → CRITICAL

    # ===========================
    # Protected System Processes (Bug 6 fix)
    # These processes are NEVER terminated, even on CRITICAL alerts.
    # ===========================
    PROTECTED_PROCESSES = [
        "systemd", "gnome-shell", "lightdm", "xfce4-session",
        "dbus-daemon", "NetworkManager", "Xorg", "X", "gdm",
        "gdm3", "sddm", "plasmashell", "kwin_x11", "kwin_wayland",
        "pulseaudio", "pipewire", "wpa_supplicant", "avahi-daemon",
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "lsass.exe", "services.exe", "explorer.exe",
    ]

    # ===========================
    # Safe / Trusted Processes  (Bug 2 fix)
    # These are NEVER analyzed – trusted system/desktop processes
    # that would otherwise generate false positives.
    # ===========================
    SAFE_PROCESSES = [
        "zsh", "bash", "sh", "dash", "fish",
        "systemd", "systemd-journal", "systemd-udevd", "systemd-logind",
        "gnome-shell", "gnome-session", "gnome-keyring-d",
        "xdg-desktop-portal", "xdg-desktop-por",
        "Xorg", "xwayland",
        "dbus-daemon", "dbus-launch",
        "NetworkManager",
        "lightdm", "gdm", "gdm3", "sddm",
        "xfce4-session", "kwin_x11", "kwin_wayland", "plasmashell",
        "pulseaudio", "pipewire", "pipewire-pulse",
        "wpa_supplicant", "avahi-daemon",
        "kthreadd", "kworker", "ksoftirqd",
    ]

    # ===========================
    # Suspicious Process Names
    # ===========================
    SUSPICIOUS_KEYWORDS = [
        "crypto", "miner", "xmrig", "malware",
        "hacktool", "rootkit", "ransomware", "keylogger",
        "trojan", "exploit", "payload", "reverse_shell",
        "nc.exe", "netcat", "mimikatz", "fake_malware",
    ]

    # ===========================
    # Spawn Rate Detection
    # ===========================
    SPAWN_RATE_THRESHOLD = 20
    SPAWN_TIME_WINDOW = 5.0

    # ===========================
    # Sensitive File Paths
    # ===========================
    SENSITIVE_PATHS = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/root", "/boot", "/proc/kcore",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\config\\SYSTEM",
    ]

    # ===========================
    # Alert Cooldown
    # ===========================
    ALERT_COOLDOWN_SECONDS = 20   # Shorter cooldown so simulations trigger quickly

    # ===========================
    # File Monitoring
    # ===========================
    FILE_EVENT_THRESHOLD = 10
    FILE_CHANGE_THRESHOLD = 10    # alias
    TIME_WINDOW = 5.0
    FILE_TIME_WINDOW = 5.0        # alias
    MONITOR_DIRECTORY = "testing_malware"

    # ===========================
    # Response
    # ===========================
    AUTO_TERMINATE = True
    GRACEFUL_TIMEOUT = 3
    SUSPEND_ON_WARNING = False

    ACTION_ALERT_ONLY = "ALERT_ONLY"
    ACTION_TERMINATE  = "TERMINATE_PROCESS"
    ACTION_SUSPEND    = "SUSPEND_PROCESS"

    # ===========================
    # Debug
    # ===========================
    DEBUG_MODE = False

    # ===========================
    # Logging
    # ===========================
    LOG_DIR      = "logs"
    LOG_FILE     = "logs/edr.log"
    JSON_LOG_FILE = "logs/edr_structured.json"
    EVENTS_LOG   = "logs/edr_events.log"   # human-friendly event log (Issue 7)
    LOG_LEVEL    = "INFO"

    # ===========================
    # Severity
    # ===========================
    SEVERITY_INFO     = "INFO"
    SEVERITY_WARNING  = "WARNING"
    SEVERITY_CRITICAL = "CRITICAL"

    # ===========================
    # GUI
    # ===========================
    GUI_REFRESH_INTERVAL = 2000
    GUI_TOP_PROCESSES    = 10
    GUI_MAX_ALERTS       = 50
    GUI_MAX_LOGS         = 200

    # ===========================
    # Terminal Dashboard
    # ===========================
    TERMINAL_DASHBOARD_INTERVAL = 5
