"""
Configuration Module
Centralized configuration for the Lightweight EDR system.
All detection thresholds and settings are adjustable here.
"""

import os


class EDRConfig:
    """
    Centralized configuration for all EDR components.
    Modify these values to tune detection sensitivity.
    """

    # ===========================
    # Process Monitoring Config
    # ===========================
    SCAN_INTERVAL = 2.0          # Seconds between process scans (1-2 recommended)

    # ===========================
    # Detection Thresholds
    # ===========================
    CPU_THRESHOLD = 80.0         # CPU usage % to flag a process as suspicious
    CPU_CONSECUTIVE_CHECKS = 5   # How many consecutive high-CPU scans before alerting
    COMBINED_CPU_THRESHOLD = 50.0  # CPU% used in combined CPU+Memory check

    # Memory thresholds (independent detection)
    MEMORY_THRESHOLD = 30.0              # Legacy/combined check threshold
    MEMORY_WARNING_THRESHOLD = 50.0      # Memory % → WARNING
    MEMORY_CRITICAL_THRESHOLD = 70.0     # Memory % → CRITICAL

    # ===========================
    # Suspicious Process Names
    # ===========================
    # Processes whose names contain these keywords will be flagged
    SUSPICIOUS_KEYWORDS = [
        "crypto", "miner", "xmrig", "malware",
        "hacktool", "rootkit", "ransomware", "keylogger",
        "trojan", "exploit", "payload", "reverse_shell",
        "nc.exe", "netcat", "mimikatz",
    ]

    # ===========================
    # Process Spawn Rate Detection
    # ===========================
    SPAWN_RATE_THRESHOLD = 20    # Number of new processes in TIME_WINDOW to trigger alert
    SPAWN_TIME_WINDOW = 5.0      # Seconds to watch for rapid process spawning

    # ===========================
    # Sensitive File/Path Access
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
    ALERT_COOLDOWN_SECONDS = 30  # Suppress repeat alerts for same PID within this window

    # ===========================
    # File Monitoring Config
    # ===========================
    FILE_EVENT_THRESHOLD = 10    # File events needed to trigger ransomware alert
    FILE_CHANGE_THRESHOLD = 10   # Alias kept for backwards compatibility
    TIME_WINDOW = 5.0            # Time window in seconds for file event counting
    FILE_TIME_WINDOW = 5.0       # Alias kept for backwards compatibility
    MONITOR_DIRECTORY = "testing_malware"  # Directory watched by file monitor

    # ===========================
    # Response Config
    # ===========================
    AUTO_TERMINATE = True         # Automatically terminate CRITICAL processes
    GRACEFUL_TIMEOUT = 3          # Seconds to wait for graceful termination before force-kill
    SUSPEND_ON_WARNING = False    # Suspend (SIGSTOP) process on WARNING (Linux only)

    # ===========================
    # Response Action Types
    # ===========================
    ACTION_ALERT_ONLY = "ALERT_ONLY"
    ACTION_TERMINATE = "TERMINATE_PROCESS"
    ACTION_SUSPEND = "SUSPEND_PROCESS"

    # ===========================
    # Debug Config
    # ===========================
    DEBUG_MODE = False            # Set True for verbose detection output

    # ===========================
    # Logging Config
    # ===========================
    LOG_DIR = "logs"
    LOG_FILE = "logs/edr.log"
    JSON_LOG_FILE = "logs/edr_structured.json"
    LOG_LEVEL = "INFO"

    # ===========================
    # Severity Levels
    # ===========================
    SEVERITY_INFO = "INFO"
    SEVERITY_WARNING = "WARNING"
    SEVERITY_CRITICAL = "CRITICAL"

    # ===========================
    # GUI Config
    # ===========================
    GUI_REFRESH_INTERVAL = 2000   # ms between dashboard refreshes
    GUI_TOP_PROCESSES = 10        # Top-N processes shown by CPU
    GUI_MAX_ALERTS = 50           # Max alerts kept in memory for display
    GUI_MAX_LOGS = 200            # Max log lines displayed in GUI

    # ===========================
    # Terminal Dashboard (no-GUI mode)
    # ===========================
    TERMINAL_DASHBOARD_INTERVAL = 5  # Seconds between terminal dashboard redraws
