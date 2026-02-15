# Process-Based Behavioral Monitoring System (Lightweight EDR)

---
## 🚀 **UPGRADED VERSION AVAILABLE!**

**This project has been upgraded with major improvements:**
- ✅ Improved detection accuracy (consecutive checks, combined indicators, cooldown)
- ✅ Enhanced response system (severity levels, JSON logs, safe termination)
- ✅ Professional GUI Dashboard (Tkinter-based with live monitoring)

**See [README_UPGRADED.md](README_UPGRADED.md) for the new features and usage!**

**Quick Start (Upgraded Version):**
```bash
python main.py --gui
```
---

## Project Overview

This is an educational mini-project implementing a lightweight Endpoint Detection and Response (EDR) system. The system monitors running processes and file system activity in real-time, using behavior-based detection (not signature-based) to identify suspicious activities. When threats are detected, the system automatically responds by terminating malicious processes.

**Target Environment:** Kali Linux (VMware)  
**Language:** Python 3.10.11  
**Purpose:** Educational OS + Security project

## Architecture

The system is built with a modular architecture consisting of four main components:

```
Process_Behavior_Monitor/
│
├── scanner/          # Process scanning module
│   └── process_scanner.py
│
├── analyzer/         # Behavior analysis module
│   └── behavior_analyzer.py
│
├── monitor/          # File system monitoring module
│   └── file_monitor.py
│
├── response/         # Alert handling and response module
│   └── responder.py
│
├── logs/             # Log files directory
│   └── edr.log
│
├── main.py           # Main entry point
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

### Module Responsibilities

#### 1. Process Scanner (`scanner/process_scanner.py`)
- Continuously scans all running system processes
- Collects detailed process information:
  - Process ID (PID)
  - Process name
  - CPU usage percentage
  - Memory usage percentage
  - Process status
  - Creation time
  - Executable path
  - Username
- Maintains process history cache for behavior tracking
- Handles process termination and access permission errors gracefully

#### 2. Behavior Analyzer (`analyzer/behavior_analyzer.py`)
- Applies rule-based detection logic to identify suspicious processes
- Detection Rules:
  - **High CPU Usage:** Process with CPU usage > 80% for more than 5 seconds
  - **High Memory Usage:** Process with memory usage > 70%
- Tracks process behavior over time to detect sustained high resource usage
- Returns detailed reasons for why a process is flagged as suspicious

#### 3. File Monitor (`monitor/file_monitor.py`)
- Monitors a directory for rapid file system changes
- Detects ransomware-like behavior patterns:
  - Rapid file creation/modification/deletion
  - Threshold: 10+ file changes within 5 seconds
- Uses the `watchdog` library for efficient file system event monitoring
- Provides callback mechanism for alert handling

#### 4. Responder (`response/responder.py`)
- Handles security alerts from both process and file monitoring
- Automatically terminates suspicious processes (if enabled)
- Maintains detailed logs with timestamps
- Provides console output for real-time alerts
- Attempts graceful termination before force-killing processes
- Handles permission errors and provides helpful error messages

#### 5. Main System (`main.py`)
- Integrates all modules into a cohesive EDR system
- Manages the monitoring loop
- Handles graceful shutdown (CTRL+C)
- Coordinates between process scanning and file monitoring
- Provides system initialization and configuration

## OS & Security Concepts Used

### Operating System Concepts

1. **Process Management:**
   - Process enumeration and monitoring
   - Process information retrieval (PID, CPU, memory)
   - Process termination (graceful and forced)
   - Process lifecycle tracking

2. **File System Monitoring:**
   - Real-time file system event detection
   - Directory monitoring with recursive watching
   - File operation tracking (create, modify, delete, move)

3. **System Resource Monitoring:**
   - CPU usage tracking per process
   - Memory usage tracking per process
   - Resource threshold monitoring

4. **Signal Handling:**
   - Graceful shutdown on SIGINT (CTRL+C)
   - Clean resource cleanup

### Security Concepts

1. **Behavior-Based Detection:**
   - Anomaly detection based on resource usage patterns
   - Heuristic analysis rather than signature matching
   - Real-time threat detection

2. **Endpoint Detection and Response (EDR):**
   - Continuous monitoring
   - Automated threat response
   - Security event logging

3. **Ransomware Detection:**
   - Pattern recognition for rapid file encryption/modification
   - File system activity analysis
   - Behavioral indicators of compromise (IOCs)

4. **Threat Response:**
   - Automated process termination
   - Alert generation
   - Audit logging

## Installation

### Prerequisites

- Python 3.10.11 or higher
- Kali Linux (or any Linux distribution)
- Root/sudo privileges (required for process termination)

### Step 1: Clone or Download the Project

```bash
cd /path/to/your/projects
# Extract or clone the Process_Behavior_Monitor directory
```

### Step 2: Install Dependencies

```bash
cd Process_Behavior_Monitor
pip3 install -r requirements.txt
```

Or install manually:

```bash
pip3 install psutil==5.9.6 watchdog==3.0.0
```

### Step 3: Verify Installation

```bash
python3 --version  # Should be 3.10.11 or higher
python3 -c "import psutil, watchdog; print('Dependencies OK')"
```

## Usage

### Basic Usage

Run the EDR system with default settings:

```bash
python3 main.py
```

**Note:** For full functionality (process termination), run with elevated privileges:

```bash
sudo python3 main.py
```

### Configuration

You can modify the configuration in `main.py`:

```python
SCAN_INTERVAL = 1.0          # Time between scans (seconds)
MONITOR_DIRECTORY = None     # Directory to monitor (default: ./monitored)
AUTO_KILL = True             # Auto-kill suspicious processes
```

### Detection Thresholds

Default thresholds can be modified in `analyzer/behavior_analyzer.py`:

```python
cpu_threshold = 80.0              # CPU usage threshold (%)
memory_threshold = 70.0           # Memory usage threshold (%)
cpu_duration_threshold = 5.0      # Duration for CPU alert (seconds)
```

File monitoring thresholds in `monitor/file_monitor.py`:

```python
file_change_threshold = 10        # Number of changes to trigger alert
time_window = 5.0                 # Time window in seconds
```

### Stopping the System

Press `CTRL+C` to gracefully stop the monitoring system.

## Output and Logging

### Console Output

The system provides real-time console output:
- Initialization messages
- Alert notifications with detailed information
- Response actions (process termination)
- Error messages

### Log Files

All events are logged to `logs/edr.log` with timestamps:
- Suspicious process detections
- File system alerts
- Process terminations
- System start/stop events
- Errors and warnings

Example log entry:
```
2025-12-13 16:30:45 - WARNING - Suspicious process detected - PID: 1234, Name: suspicious_proc, CPU: 85.50%, Memory: 45.20%, Reasons: High CPU usage: 85.50% for 6.23 seconds
```

## Limitations

1. **Permission Requirements:**
   - Process termination requires root/sudo privileges
   - Some system processes may not be accessible

2. **False Positives:**
   - Legitimate high-CPU processes (compilers, video encoding) may trigger alerts
   - System processes with high memory usage may be flagged

3. **Detection Scope:**
   - Only monitors processes and file system activity
   - Does not detect network-based threats
   - Does not analyze process code or signatures

4. **Performance Impact:**
   - Continuous scanning may consume system resources
   - File monitoring adds overhead to file system operations

5. **Platform Specific:**
   - Designed for Linux systems
   - May require modifications for other operating systems

6. **No Persistence:**
   - Does not survive system reboots
   - Must be manually started

## Future Enhancements

1. **Enhanced Detection:**
   - Network activity monitoring
   - Process relationship analysis (parent-child)
   - Registry/configuration file monitoring
   - Suspicious command-line argument detection

2. **Machine Learning:**
   - ML-based anomaly detection
   - Adaptive threshold adjustment
   - Pattern learning from historical data

3. **User Interface:**
   - Web-based dashboard
   - Real-time visualization of threats
   - Historical data analysis

4. **Advanced Response:**
   - Process quarantine
   - File restoration from backups
   - Network isolation
   - Automated incident reporting

5. **Persistence:**
   - Systemd service integration
   - Auto-start on boot
   - Service management commands

6. **Configuration:**
   - Configuration file support (YAML/JSON)
   - Runtime threshold adjustment
   - Whitelist/blacklist support

7. **Reporting:**
   - HTML report generation
   - Email alerts
   - Integration with SIEM systems

## Security Considerations

⚠️ **Important Notes:**

1. This is an **educational project** and should not be used in production environments without proper testing and hardening.

2. The auto-kill feature can terminate legitimate processes. Use with caution.

3. Always test in a controlled environment (VM) before deploying.

4. Review and adjust detection thresholds based on your system's normal behavior.

5. Consider adding process whitelisting for critical system processes.

## Troubleshooting

### Permission Denied Errors

```bash
# Run with sudo
sudo python3 main.py
```

### Module Not Found Errors

```bash
# Ensure you're in the project directory
cd Process_Behavior_Monitor

# Reinstall dependencies
pip3 install -r requirements.txt
```

### File Monitor Not Working

- Ensure the monitored directory exists
- Check file permissions
- Verify watchdog library is installed correctly

### High False Positive Rate

- Adjust thresholds in `behavior_analyzer.py`
- Monitor your system's normal behavior first
- Consider adding whitelist functionality

## License

This is an educational project. Use at your own risk.

## Author

Created as part of an OS + Security mini-project for educational purposes.

---

**Last Updated:** December 2025

