"""
Configuration Module
Centralized configuration for the EDR system.
"""

class EDRConfig:
    """
    Centralized configuration for all EDR components.
    """
    
    # ===========================
    # Process Monitoring Config
    # ===========================
    SCAN_INTERVAL = 1.0  # Seconds between process scans
    
    # ===========================
    # Detection Thresholds
    # ===========================
    CPU_THRESHOLD = 80.0  # CPU usage percentage threshold
    CPU_CONSECUTIVE_CHECKS = 5  # Number of consecutive high CPU checks required
    
    MEMORY_THRESHOLD = 70.0  # Memory usage percentage threshold
    COMBINED_CPU_THRESHOLD = 50.0  # CPU threshold for combined detection
    
    # ===========================
    # Alert Cooldown
    # ===========================
    ALERT_COOLDOWN_SECONDS = 30  # Cooldown period for same PID alerts
    
    # ===========================
    # File Monitoring Config
    # ===========================
    FILE_CHANGE_THRESHOLD = 10  # Number of file changes to trigger alert
    FILE_TIME_WINDOW = 5.0  # Time window in seconds
    MONITOR_DIRECTORY = "monitored"  # Directory to monitor
    
    # ===========================
    # Response Config
    # ===========================
    AUTO_TERMINATE = True  # Enable automatic process termination
    GRACEFUL_TIMEOUT = 3  # Seconds to wait for graceful termination
    
    # ===========================
    # Logging Config
    # ===========================
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
    GUI_REFRESH_INTERVAL = 2000  # Milliseconds
    GUI_TOP_PROCESSES = 10  # Number of top processes to display
    GUI_MAX_ALERTS = 20  # Maximum alerts to display
    GUI_MAX_LOGS = 100  # Maximum log entries to display
