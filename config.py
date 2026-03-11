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
    # Protected System Processes
    # These processes are NEVER terminated or suspended, even on CRITICAL alerts.
    # Covers Linux desktop environments, display managers, and Windows core services.
    # ===========================
    PROTECTED_PROCESSES = [
        # --- Requested mandatory list ---
        "systemd", "init", "dbus-daemon", "NetworkManager",
        "Xorg", "xfce4-session", "xfce4-power-manager",
        "xfwm4", "xfce4-panel", "tumblerd", "lightdm",
        "wrapper-2.0", "pulseaudio", "gvfsd",
        # --- Extended desktop / display-manager protection ---
        "gnome-shell", "gnome-session", "gdm", "gdm3", "sddm",
        "plasmashell", "kwin_x11", "kwin_wayland",
        "X", "xwayland",
        "xfce4-terminal", "xfce4-whiskermenu",
        # --- System daemons ---
        "dbus-launch", "pipewire", "pipewire-pulse",
        "wpa_supplicant", "avahi-daemon",
        "systemd-journald", "systemd-logind", "systemd-udevd",
        "kthreadd", "kworker",
        "gvfsd-fuse", "gvfsd-trash",
        # --- Windows core processes ---
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "lsass.exe", "services.exe", "explorer.exe",
        "svchost.exe", "dwm.exe",
    ]

    # ===========================
    # Safe / Trusted Processes
    # These are NEVER analyzed – trusted system/desktop processes
    # that would otherwise generate false positives.
    # Kept as a superset of PROTECTED_PROCESSES for analysis skip.
    # ===========================
    SAFE_PROCESSES = [
        # Shells
        "zsh", "bash", "sh", "dash", "fish",
        # Systemd family
        "systemd", "systemd-journal", "systemd-udevd",
        "systemd-logind", "systemd-journald",
        # Desktop environments
        "gnome-shell", "gnome-session", "gnome-keyring-d",
        "xdg-desktop-portal", "xdg-desktop-por",
        "xfce4-session", "xfce4-panel", "xfce4-power-manager",
        "xfwm4", "xfce4-terminal", "xfce4-whiskermenu",
        "kwin_x11", "kwin_wayland", "plasmashell",
        # Display infrastructure
        "Xorg", "xwayland", "X", "lightdm", "gdm", "gdm3", "sddm",
        "wrapper-2.0",
        # D-Bus / IPC
        "dbus-daemon", "dbus-launch",
        # Network
        "NetworkManager", "wpa_supplicant", "avahi-daemon",
        # init
        "init",
        # Audio / media
        "pulseaudio", "pipewire", "pipewire-pulse",
        # GVFS
        "gvfsd", "gvfsd-fuse", "gvfsd-trash", "tumblerd",
        # Kernel threads (exact names – prefix variants handled by SAFE_PROCESS_PREFIXES)
        "kthreadd", "kworker", "ksoftirqd", "migration",
        "rcu_sched", "rcu_bh", "rcu_preempt", "watchdog",
        "events", "khelper", "kdevtmpfs", "netns",
        # Windows core
        "system", "smss.exe", "csrss.exe", "wininit.exe",
        "winlogon.exe", "lsass.exe", "services.exe",
        "explorer.exe", "svchost.exe", "dwm.exe",
        # ── EDR self-exclusion ──────────────────────────────────────────
        # The EDR itself runs as 'python' / 'python3' and may spike CPU
        # while scanning.  Excluding it prevents the monitor from flagging
        # its own activity as suspicious.
        "python", "python3", "python3.11", "python3.12",
        "python3.10", "python3.9", "python2", "python2.7",
        "main.py",   # in case psutil reports the script name
    ]

    # ===========================
    # Safe Process Name PREFIXES
    # ===========================
    # Processes whose name STARTS WITH any of these strings are treated as
    # safe regardless of the suffix (e.g. "kworker/0:1", "ksoftirqd/3").
    # This is needed because kernel threads carry CPU/core numbers in their
    # names, so exact-name matching misses them.
    SAFE_PROCESS_PREFIXES = [
        "kworker/",
        "ksoftirqd/",
        "migration/",
        "rcu_",
        "watchdog/",
        "cpuhp/",
        "idle_inject/",
        "kthread",
        "irq/",
        "scsi_",
        "nvme",
        "xfsalloc",
        "xfs_",
        "jbd2/",
        "ext4-",
        "mmcqd/",
        "kswapd",
        "khugepaged",
        "kcompactd",
        "khungtaskd",
        "oom_reaper",
        "writeback",
        "bdi-default",
        "kintegrityd",
        "kblockd",
        "blkcg_punt_bio",
        "edac-poller",
        "devfreq_wq",
        # NOTE: 'python' is NOT listed here intentionally – a broad 'python'
        # prefix would suppress any process starting with 'python', which
        # could include malware.  Python self-exclusion is handled via
        # exact names in SAFE_PROCESSES and by PID in EDR_OWN_PID.
    ]

    # ===========================
    # EDR Own PID (set at runtime)
    # ===========================
    # Populated by main.py at startup so the scanner/analyzer can skip
    # the EDR process itself even if psutil reports a different name.
    EDR_OWN_PID: int = os.getpid()

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
    # Detects rapid spawning FROM THE SAME PARENT process.
    # Threshold: >30 child processes in 5 seconds from one parent.
    # ===========================
    SPAWN_RATE_THRESHOLD = 30   # child processes per parent per window
    SPAWN_TIME_WINDOW = 5.0     # seconds

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

    # GUI mode – set True when --gui is passed.
    # Adds an extra safety layer: HIGH severity is capped at SUSPEND, never TERMINATE.
    GUI_MODE = False

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
    # Severity – Four-Tier Response Model
    # ===========================
    #
    #  LOW      → log only (no process action)
    #  MEDIUM   → alert (console/GUI notification, no process action)
    #  HIGH     → suspend process (SIGSTOP on Linux, skip on Windows)
    #  CRITICAL → terminate process (graceful → force-kill)
    #
    # Legacy aliases kept for backward compat with existing code:
    #   INFO    → LOW
    #   WARNING → MEDIUM
    #
    SEVERITY_LOW      = "LOW"
    SEVERITY_MEDIUM   = "MEDIUM"
    SEVERITY_HIGH     = "HIGH"
    SEVERITY_CRITICAL = "CRITICAL"

    # Legacy aliases (backward compat)
    SEVERITY_INFO    = "LOW"
    SEVERITY_WARNING = "MEDIUM"

    # ===========================
    # GUI
    # ===========================
    # GUI (only active with --gui)
    # ===========================
    GUI_REFRESH_INTERVAL = 3000   # ms between root.after() ticks (point 9)
    GUI_TOP_PROCESSES    = 10
    GUI_MAX_ALERTS       = 50
    GUI_MAX_LOGS         = 200

    # ===========================
    # Terminal Dashboard (CLI mode only, never in GUI mode)
    # ===========================
    TERMINAL_DASHBOARD_INTERVAL = 5   # seconds between prints (point 8: 3-5s)
