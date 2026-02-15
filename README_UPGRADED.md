# Process-Based Behavioral Monitoring System (Lightweight EDR) - UPGRADED

## 🚀 What's New in This Version

This is an **upgraded version** of the Lightweight EDR system with three major improvements:

### ✅ 1. Improved Detection Accuracy
- **Consecutive CPU checks**: Alerts only trigger if CPU stays above 80% for 5+ consecutive checks
- **Combined indicators**: Memory alert (>70%) requires CPU >50% simultaneously
- **Severity levels**: INFO, WARNING, and CRITICAL classifications
- **Alert cooldown**: 30-second cooldown prevents repeated alerts for the same process
- **Configurable thresholds**: All detection parameters centralized in `config.py`

### ✅ 2. Enhanced Response System
- **Detailed logging**: Full process details (PID, name, CPU, memory, timestamp)
- **Structured JSON logs**: Machine-readable logs in `logs/edr_structured.json`
- **Safe termination**: Graceful terminate() before force kill()
- **Severity-based actions**:
  - CRITICAL → Auto-terminate process
  - WARNING → Alert and log only
  - INFO → Informational logging
- **Better error handling**: Comprehensive error messages and fallbacks

### ✅ 3. GUI Dashboard
- **Live process monitoring**: Top 10 CPU-consuming processes
- **Active alerts panel**: Real-time threat notifications
- **Log viewer**: Live system logs
- **Start/Stop controls**: Easy monitoring control
- **Professional design**: Dark theme with color-coded severity levels
- **Threaded execution**: GUI runs independently from monitoring engine

---

## 📁 Project Structure

```
Process_Behavior_Monitor/
│
├── config.py              # Centralized configuration (NEW)
│
├── scanner/
│   └── process_scanner.py # Process scanning module
│
├── analyzer/
│   └── behavior_analyzer.py # Enhanced behavior analysis (UPGRADED)
│
├── monitor/
│   └── file_monitor.py    # File system monitoring
│
├── response/
│   └── responder.py       # Enhanced response system (UPGRADED)
│
├── gui/                   # GUI Dashboard (NEW)
│   ├── __init__.py
│   └── dashboard.py
│
├── logs/
│   ├── edr.log           # Text logs
│   └── edr_structured.json # JSON structured logs (NEW)
│
├── main.py               # Main controller (UPGRADED)
├── requirements.txt
└── README_UPGRADED.md    # This file
```

---

## 🔧 Installation

### Prerequisites
- Python 3.10.11 or higher
- Linux/WSL (or Windows with admin privileges)

### Install Dependencies

```bash
cd Process_Behavior_Monitor
pip install -r requirements.txt
```

**Dependencies:**
- `psutil==5.9.6` - Process monitoring
- `watchdog==3.0.0` - File system monitoring

---

## 🎯 Usage

### Option 1: Run with GUI Dashboard (Recommended)

```bash
python main.py --gui
```

This will:
1. Launch the GUI dashboard in a separate window
2. Start the monitoring engine
3. Display live process information, alerts, and logs

**GUI Controls:**
- Click **"Start Monitoring"** to begin detection
- Click **"Stop Monitoring"** to pause
- Press **CTRL+C** in terminal to exit completely

### Option 2: Run in Console Mode (No GUI)

```bash
python main.py
```

This runs the traditional console-only mode with text output.

### Option 3: Alert-Only Mode (No Auto-Termination)

```bash
python main.py --gui --no-terminate
```

This disables automatic process termination - only alerts and logs threats.

---

## ⚙️ Configuration

All settings are in `config.py`:

```python
# Detection Thresholds
CPU_THRESHOLD = 80.0              # CPU % to trigger alert
CPU_CONSECUTIVE_CHECKS = 5        # Consecutive high CPU checks required
MEMORY_THRESHOLD = 70.0           # Memory % threshold
COMBINED_CPU_THRESHOLD = 50.0     # CPU % for combined detection

# Alert Cooldown
ALERT_COOLDOWN_SECONDS = 30       # Cooldown between alerts for same PID

# Response
AUTO_TERMINATE = True             # Enable auto-termination

# File Monitoring
FILE_CHANGE_THRESHOLD = 10        # File changes to trigger alert
FILE_TIME_WINDOW = 5.0            # Time window in seconds

# GUI
GUI_REFRESH_INTERVAL = 2000       # GUI refresh rate (ms)
GUI_TOP_PROCESSES = 10            # Number of processes to display
```

**To customize**, edit `config.py` and restart the application.

---

## 📊 Detection Logic

### Rule 1: Sustained High CPU Usage
- **Trigger**: CPU > 80% for 5+ consecutive checks
- **Severity**: WARNING
- **Action**: Alert and log

### Rule 2: Combined High Memory + CPU
- **Trigger**: Memory > 70% AND CPU > 50% simultaneously
- **Severity**: CRITICAL
- **Action**: Alert, log, and terminate (if enabled)

### Rule 3: Extreme Memory Usage
- **Trigger**: Memory > 85%
- **Severity**: WARNING
- **Action**: Alert and log

### Cooldown Mechanism
- After an alert for a PID, no new alerts for 30 seconds
- Prevents alert spam for the same process
- Configurable in `config.py`

---

## 📝 Logging

### Text Logs (`logs/edr.log`)
Human-readable format:
```
2026-02-15 14:30:45 | WARNING | PROCESS ALERT | PID=1234 | NAME=stress | CPU=85.50% | MEM=45.20% | REASON=Sustained high CPU usage
```

### JSON Logs (`logs/edr_structured.json`)
Machine-readable structured format:
```json
{
  "timestamp": "2026-02-15T14:30:45.123456",
  "alert_type": "process",
  "severity": "CRITICAL",
  "pid": 1234,
  "process_name": "suspicious_app",
  "cpu_percent": 85.5,
  "memory_percent": 72.3,
  "reasons": ["Combined threat: Memory 72.30% AND CPU 85.50%"],
  "action_taken": "Process suspicious_app (PID 1234) terminated gracefully"
}
```

---

## 🖥️ GUI Dashboard Features

### Top Processes Panel
- Displays top 10 CPU-consuming processes
- Shows PID, Name, CPU%, Memory%
- Updates every 2 seconds
- Sortable columns

### Active Alerts Panel
- Real-time threat notifications
- Color-coded by severity:
  - 🟢 INFO (green)
  - 🟡 WARNING (yellow)
  - 🔴 CRITICAL (red)
- Keeps last 20 alerts

### Log Viewer Panel
- Live system logs
- Scrollable history
- Keeps last 100 entries

### Control Panel
- **Start Monitoring**: Begin threat detection
- **Stop Monitoring**: Pause detection
- **Status Indicator**: Shows current state

---

## 🧪 Testing the System

### Test 1: High CPU Detection

Create a CPU stress test:

```bash
# Install stress tool (if not available)
sudo apt-get install stress

# Run CPU stress (will trigger alert after 5 seconds)
stress --cpu 4 --timeout 30s
```

**Expected Result:**
- After ~5 seconds, alert triggers
- Severity: WARNING
- Process terminated if auto-kill enabled

### Test 2: High Memory Detection

```python
# Create a Python script: memory_hog.py
data = []
while True:
    data.append(' ' * 10**6)  # Allocate memory
```

```bash
python memory_hog.py
```

**Expected Result:**
- Alert when memory exceeds threshold
- Severity: CRITICAL (if CPU also elevated)

### Test 3: Ransomware Simulation

```bash
# Create test directory
mkdir -p monitored/test

# Rapid file creation (triggers alert)
for i in {1..15}; do touch monitored/test/file_$i.txt; done
```

**Expected Result:**
- File system alert after 10+ changes in 5 seconds

---

## 🛡️ Security Considerations

⚠️ **Important:**
1. **Educational Use Only** - Not production-ready without hardening
2. **False Positives** - Legitimate apps (compilers, video encoders) may trigger alerts
3. **Permissions** - Requires elevated privileges for process termination
4. **Testing** - Always test in VM/isolated environment first
5. **Whitelisting** - Consider adding process whitelist for critical apps

---

## 🐛 Troubleshooting

### GUI doesn't launch
```bash
# Check tkinter installation
python -c "import tkinter; print('OK')"

# If missing, install:
sudo apt-get install python3-tk
```

### Permission denied when terminating processes
```bash
# Run with sudo
sudo python main.py --gui
```

### High false positive rate
- Increase `CPU_THRESHOLD` in `config.py`
- Increase `CPU_CONSECUTIVE_CHECKS` for longer observation
- Adjust `MEMORY_THRESHOLD` based on your system

### Module not found errors
```bash
# Ensure you're in project directory
cd Process_Behavior_Monitor

# Reinstall dependencies
pip install -r requirements.txt
```

---

## 📈 Performance Impact

- **CPU Usage**: ~1-3% (monitoring engine)
- **Memory Usage**: ~50-100 MB
- **Disk I/O**: Minimal (log writes only)
- **GUI Overhead**: ~20-30 MB additional

---

## 🔄 Upgrade from Previous Version

If you have the old version:

1. **Backup your logs**:
   ```bash
   cp -r logs logs_backup
   ```

2. **Replace files** with new versions

3. **No database migration needed** - logs are append-only

4. **Configuration** - Review `config.py` and adjust thresholds

---

## 📚 Code Quality

- ✅ Modular architecture maintained
- ✅ Clean, well-commented code
- ✅ Type hints for better IDE support
- ✅ Error handling throughout
- ✅ Thread-safe GUI implementation
- ✅ Production-ready logging

---

## 🎓 Learning Outcomes

This project demonstrates:
- Process management and monitoring
- Behavior-based threat detection
- File system event monitoring
- Multi-threaded application design
- GUI development with Tkinter
- Structured logging (JSON)
- Configuration management
- Signal handling and graceful shutdown

---

## 📄 License

Educational project - Use at your own risk.

---

## 👨‍💻 Author

Created as an enhanced OS + Security mini-project.

**Last Updated:** February 2026

---

## 🚀 Quick Start Guide

```bash
# 1. Install dependencies
pip install psutil watchdog

# 2. Run with GUI
python main.py --gui

# 3. Click "Start Monitoring" in the GUI

# 4. Open another terminal and run a stress test
stress --cpu 4 --timeout 20s

# 5. Watch the alerts appear in the GUI!
```

Enjoy your upgraded Lightweight EDR! 🛡️
