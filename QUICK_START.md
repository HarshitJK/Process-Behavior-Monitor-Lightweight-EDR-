# 🚀 QUICK START GUIDE - Upgraded Lightweight EDR

## ⚡ 30-Second Setup

### Step 1: Verify Dependencies
```bash
cd "d:\Mini Project\OOS\Process_Behavior_Monitor"
pip install psutil watchdog
```

### Step 2: Launch with GUI
```bash
python main.py --gui
```

### Step 3: Start Monitoring
- Click **"▶ Start Monitoring"** button in the GUI
- Watch the dashboard populate with live data

### Step 4: Test It (Optional)
Open a new terminal and run:
```bash
python test_edr.py
```

---

## 📋 Usage Modes

### Mode 1: GUI Dashboard (Recommended)
```bash
python main.py --gui
```
**Features:**
- ✅ Visual interface
- ✅ Live process monitoring
- ✅ Real-time alerts
- ✅ Log viewer
- ✅ Start/Stop controls

### Mode 2: Console Only
```bash
python main.py
```
**Features:**
- ✅ Text-based output
- ✅ Lightweight
- ✅ Server-friendly

### Mode 3: Alert-Only (No Auto-Kill)
```bash
python main.py --gui --no-terminate
```
**Features:**
- ✅ Detects threats
- ✅ Logs everything
- ❌ Doesn't terminate processes

---

## 🎯 What to Expect

### When You Start the EDR:
```
=== Lightweight EDR Started ===

Configuration:
  CPU Threshold: 80.0%
  Memory Threshold: 70.0%
  Consecutive Checks Required: 5
  Alert Cooldown: 30s
  Auto-Terminate: True
  Monitoring Directory: monitored

[FILE MONITOR] Monitoring directory: d:\...\monitored
[FILE MONITOR] Alert if ≥ 10 events within 5.0 seconds
[INFO] GUI Dashboard launched in separate thread
```

### GUI Dashboard Shows:
1. **Top 10 Processes** - Live CPU/Memory usage
2. **Active Alerts** - Color-coded threat notifications
3. **Log Viewer** - System events and actions
4. **Control Panel** - Start/Stop buttons

---

## 🧪 Testing the System

### Test 1: CPU Stress (Easy)
```bash
# Terminal 1: Run EDR
python main.py --gui

# Terminal 2: Run test
python test_edr.py
# Select option 1
```

**Expected Result:**
- After ~5 seconds, you'll see a WARNING alert
- Process will be logged but NOT terminated (WARNING level)

### Test 2: File Activity (Easy)
```bash
# Terminal 2: Run test
python test_edr.py
# Select option 3
```

**Expected Result:**
- CRITICAL alert for ransomware-like activity
- 15 files created rapidly
- Alert appears in GUI

### Test 3: Combined Threat (Advanced)
Run a program that uses both high CPU AND high memory:
```bash
# This will trigger CRITICAL severity
# Process will be terminated
```

---

## 🎨 GUI Dashboard Guide

### Layout:
```
┌─────────────────────────────────────────────────────────┐
│         Lightweight EDR Dashboard                       │
├─────────────────────────────────────────────────────────┤
│  [▶ Start]  [⏸ Stop]  ● Running                        │
├──────────────┬──────────────┬──────────────────────────┤
│ Top 10       │ Active       │ Log Viewer               │
│ Processes    │ Alerts       │                          │
│              │              │                          │
│ PID | Name   │ [CRITICAL]   │ [14:30:45] [INFO]       │
│ 1234| chrome │ PID 5678...  │ Monitoring started      │
│ 5678| python │              │                          │
│ ...          │ [WARNING]    │ [14:30:50] [WARNING]    │
│              │ High CPU...  │ Process alert...        │
└──────────────┴──────────────┴──────────────────────────┘
│ Ready                              2026-02-15 14:30:45 │
└─────────────────────────────────────────────────────────┘
```

### Color Coding:
- 🟢 **Green** - INFO (normal operations)
- 🟡 **Yellow** - WARNING (suspicious but not critical)
- 🔴 **Red** - CRITICAL (immediate threat, will terminate)

---

## ⚙️ Customization

### Change Detection Thresholds
Edit `config.py`:
```python
# More sensitive (catches more threats, more false positives)
CPU_THRESHOLD = 70.0
CPU_CONSECUTIVE_CHECKS = 3

# Less sensitive (fewer false positives, might miss threats)
CPU_THRESHOLD = 90.0
CPU_CONSECUTIVE_CHECKS = 10
```

### Disable Auto-Termination
```python
# In config.py
AUTO_TERMINATE = False
```
Or use command-line:
```bash
python main.py --gui --no-terminate
```

---

## 📊 Understanding Alerts

### Severity Levels:

#### INFO
- Normal system operations
- No action taken
- Example: "Monitoring started"

#### WARNING
- Suspicious activity detected
- Logged but NOT terminated
- Examples:
  - Sustained high CPU (>80% for 5+ checks)
  - Extreme memory usage (>85%)

#### CRITICAL
- Confirmed threat
- Process WILL be terminated
- Examples:
  - Combined high memory (>70%) AND CPU (>50%)
  - Ransomware-like file activity

---

## 🔍 Viewing Logs

### Text Logs
```bash
# View live logs
tail -f logs/edr.log

# On Windows PowerShell
Get-Content logs/edr.log -Wait
```

### JSON Logs (Structured)
```bash
# View formatted JSON
python -m json.tool logs/edr_structured.json

# Count alerts by severity
# (Use jq or Python script)
```

---

## 🛑 Stopping the EDR

### GUI Mode:
1. Click **"⏸ Stop Monitoring"** button
2. Close the GUI window
3. Or press **CTRL+C** in terminal

### Console Mode:
- Press **CTRL+C**

---

## ❓ Troubleshooting

### GUI doesn't open
```bash
# Check tkinter
python -c "import tkinter; print('OK')"

# If error, install:
# Linux/WSL:
sudo apt-get install python3-tk

# Windows: Reinstall Python with Tk/Tcl option
```

### "Permission denied" when terminating
```bash
# Run with admin/sudo
# Windows (PowerShell as Admin):
python main.py --gui

# Linux/WSL:
sudo python main.py --gui
```

### Too many false positives
```python
# Edit config.py
CPU_THRESHOLD = 90.0  # Increase
CPU_CONSECUTIVE_CHECKS = 10  # Increase
ALERT_COOLDOWN_SECONDS = 60  # Increase
```

### Process not detected
```python
# Edit config.py
CPU_THRESHOLD = 70.0  # Decrease
CPU_CONSECUTIVE_CHECKS = 3  # Decrease
```

---

## 📚 Next Steps

1. ✅ Run the EDR with GUI
2. ✅ Test with test_edr.py
3. ✅ Customize thresholds in config.py
4. ✅ Review logs in logs/ directory
5. ✅ Read README_UPGRADED.md for details
6. ✅ Check UPGRADE_SUMMARY.md for changes

---

## 🎓 Learning Resources

- **Detection Logic:** See `analyzer/behavior_analyzer.py`
- **Response Actions:** See `response/responder.py`
- **GUI Implementation:** See `gui/dashboard.py`
- **Configuration:** See `config.py`

---

## 💡 Pro Tips

1. **Start with alert-only mode** to understand your system's normal behavior
2. **Adjust thresholds** based on your hardware and workload
3. **Use the test suite** to validate configuration changes
4. **Monitor the JSON logs** for detailed threat intelligence
5. **Run in a VM** when testing aggressive settings

---

## 🎯 Common Use Cases

### Use Case 1: Development Machine
```python
# config.py - Less aggressive
CPU_THRESHOLD = 90.0
MEMORY_THRESHOLD = 80.0
AUTO_TERMINATE = False  # Alert only
```

### Use Case 2: Production Server
```python
# config.py - More aggressive
CPU_THRESHOLD = 75.0
MEMORY_THRESHOLD = 65.0
AUTO_TERMINATE = True
ALERT_COOLDOWN_SECONDS = 60
```

### Use Case 3: Security Testing
```python
# config.py - Very sensitive
CPU_THRESHOLD = 60.0
CPU_CONSECUTIVE_CHECKS = 3
MEMORY_THRESHOLD = 60.0
```

---

**Ready to protect your system? Let's go! 🛡️**

```bash
python main.py --gui
```

---

**Questions?** Check README_UPGRADED.md for comprehensive documentation.
