# 🏗️ ARCHITECTURE DIAGRAM - Upgraded Lightweight EDR

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         LIGHTWEIGHT EDR SYSTEM                          │
│                         (Enhanced Version)                              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │
                    ┌───────────────┴───────────────┐
                    │                               │
                    ▼                               ▼
        ┌───────────────────────┐       ┌───────────────────────┐
        │   MAIN CONTROLLER     │       │   GUI DASHBOARD       │
        │   (main.py)           │◄──────┤   (gui/dashboard.py)  │
        │                       │       │   [Separate Thread]   │
        │  - LightweightEDR     │       │                       │
        │  - Command-line args  │       │  - Process Display    │
        │  - Thread management  │       │  - Alerts Panel       │
        └───────────┬───────────┘       │  - Log Viewer         │
                    │                   │  - Start/Stop Control │
                    │                   └───────────────────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
        ▼                       ▼
┌───────────────┐       ┌───────────────┐
│  CONFIG       │       │  MODULES      │
│  (config.py)  │       │               │
│               │       │               │
│ - Thresholds  │       │               │
│ - Settings    │       │               │
│ - Severity    │       │               │
└───────────────┘       └───────┬───────┘
                                │
                ┌───────────────┼───────────────┬───────────────┐
                │               │               │               │
                ▼               ▼               ▼               ▼
        ┌───────────┐   ┌───────────┐   ┌───────────┐   ┌───────────┐
        │  SCANNER  │   │ ANALYZER  │   │  MONITOR  │   │ RESPONDER │
        │           │   │           │   │           │   │           │
        │ Process   │──▶│ Behavior  │──▶│   File    │   │ Response  │
        │ Scanner   │   │ Analyzer  │   │  Monitor  │   │  Handler  │
        └───────────┘   └───────────┘   └───────────┘   └───────────┘
             │                 │               │               │
             │                 │               │               │
             ▼                 ▼               ▼               ▼
        ┌────────────────────────────────────────────────────────┐
        │                    SYSTEM RESOURCES                    │
        │  - Running Processes                                   │
        │  - CPU/Memory Usage                                    │
        │  - File System Events                                  │
        └────────────────────────────────────────────────────────┘
                                │
                                ▼
                        ┌───────────────┐
                        │  LOG FILES    │
                        │               │
                        │ - edr.log     │
                        │ - edr_*.json  │
                        └───────────────┘
```

---

## Component Details

### 1. Main Controller (main.py)
```
┌─────────────────────────────────────────┐
│      LightweightEDR Class               │
├─────────────────────────────────────────┤
│ Responsibilities:                       │
│  • Initialize all modules               │
│  • Start/stop monitoring                │
│  • Coordinate components                │
│  • Handle signals (CTRL+C)              │
│  • Launch GUI thread                    │
│  • Main monitoring loop                 │
├─────────────────────────────────────────┤
│ Methods:                                │
│  • start()                              │
│  • stop()                               │
│  • _monitoring_loop()                   │
│  • _start_gui()                         │
│  • _graceful_exit()                     │
└─────────────────────────────────────────┘
```

### 2. Configuration (config.py)
```
┌─────────────────────────────────────────┐
│         EDRConfig Class                 │
├─────────────────────────────────────────┤
│ Detection Thresholds:                   │
│  • CPU_THRESHOLD = 80.0                 │
│  • CPU_CONSECUTIVE_CHECKS = 5           │
│  • MEMORY_THRESHOLD = 70.0              │
│  • COMBINED_CPU_THRESHOLD = 50.0        │
│  • ALERT_COOLDOWN_SECONDS = 30          │
├─────────────────────────────────────────┤
│ File Monitoring:                        │
│  • FILE_CHANGE_THRESHOLD = 10           │
│  • FILE_TIME_WINDOW = 5.0               │
│  • MONITOR_DIRECTORY = "monitored"      │
├─────────────────────────────────────────┤
│ Response:                               │
│  • AUTO_TERMINATE = True                │
│  • GRACEFUL_TIMEOUT = 3                 │
├─────────────────────────────────────────┤
│ Severity Levels:                        │
│  • SEVERITY_INFO = "INFO"               │
│  • SEVERITY_WARNING = "WARNING"         │
│  • SEVERITY_CRITICAL = "CRITICAL"       │
└─────────────────────────────────────────┘
```

### 3. Process Scanner (scanner/process_scanner.py)
```
┌─────────────────────────────────────────┐
│      ProcessScanner Class               │
├─────────────────────────────────────────┤
│ Function:                               │
│  Scans all running processes            │
├─────────────────────────────────────────┤
│ Collects:                               │
│  • PID                                  │
│  • Process name                         │
│  • CPU usage %                          │
│  • Memory usage %                       │
│  • Status                               │
│  • Timestamp                            │
├─────────────────────────────────────────┤
│ Features:                               │
│  • Process history cache (last 10)      │
│  • Automatic cleanup of dead processes  │
│  • Error handling for access denied     │
└─────────────────────────────────────────┘
```

### 4. Behavior Analyzer (analyzer/behavior_analyzer.py) ⭐ UPGRADED
```
┌─────────────────────────────────────────┐
│     BehaviorAnalyzer Class              │
├─────────────────────────────────────────┤
│ Detection Rules:                        │
│                                         │
│ Rule 1: Sustained High CPU              │
│  ├─ Condition: CPU > 80%                │
│  ├─ Duration: 5 consecutive checks      │
│  ├─ Severity: WARNING                   │
│  └─ Action: Alert + Log                 │
│                                         │
│ Rule 2: Combined Threat                 │
│  ├─ Condition: Memory > 70% AND         │
│  │             CPU > 50%                │
│  ├─ Severity: CRITICAL                  │
│  └─ Action: Alert + Log + Terminate     │
│                                         │
│ Rule 3: Extreme Memory                  │
│  ├─ Condition: Memory > 85%             │
│  ├─ Severity: WARNING                   │
│  └─ Action: Alert + Log                 │
├─────────────────────────────────────────┤
│ Features:                               │
│  • 30-second cooldown per PID           │
│  • Consecutive check validation         │
│  • Severity classification              │
│  • Configurable thresholds              │
└─────────────────────────────────────────┘
```

### 5. File Monitor (monitor/file_monitor.py)
```
┌─────────────────────────────────────────┐
│      FileMonitor Class                  │
├─────────────────────────────────────────┤
│ Function:                               │
│  Monitors directory for rapid changes   │
├─────────────────────────────────────────┤
│ Detects:                                │
│  • File creation                        │
│  • File modification                    │
│  • File deletion                        │
│  • File moves                           │
├─────────────────────────────────────────┤
│ Alert Trigger:                          │
│  • 10+ file changes                     │
│  • Within 5 seconds                     │
│  • Indicates ransomware-like behavior   │
├─────────────────────────────────────────┤
│ Uses: watchdog library                  │
└─────────────────────────────────────────┘
```

### 6. Responder (response/responder.py) ⭐ UPGRADED
```
┌─────────────────────────────────────────┐
│        Responder Class                  │
├─────────────────────────────────────────┤
│ Severity-Based Actions:                 │
│                                         │
│ INFO:                                   │
│  └─ Log only                            │
│                                         │
│ WARNING:                                │
│  ├─ Console alert                       │
│  ├─ Text log                            │
│  ├─ JSON log                            │
│  └─ NO termination                      │
│                                         │
│ CRITICAL:                               │
│  ├─ Console alert                       │
│  ├─ Text log                            │
│  ├─ JSON log                            │
│  └─ Terminate process                   │
│     ├─ Try graceful (3s timeout)        │
│     └─ Force kill if needed             │
├─────────────────────────────────────────┤
│ Logging:                                │
│  • Text: logs/edr.log                   │
│  • JSON: logs/edr_structured.json       │
│  • Full process details                 │
│  • Timestamps                           │
│  • Action results                       │
└─────────────────────────────────────────┘
```

### 7. GUI Dashboard (gui/dashboard.py) ⭐ NEW
```
┌─────────────────────────────────────────┐
│      EDRDashboard Class                 │
├─────────────────────────────────────────┤
│ Layout:                                 │
│  ┌─────────────────────────────────┐   │
│  │ Title Bar                       │   │
│  ├─────────────────────────────────┤   │
│  │ Control Panel                   │   │
│  │  [Start] [Stop] ● Status        │   │
│  ├──────────┬──────────┬───────────┤   │
│  │ Top 10   │ Active   │ Log       │   │
│  │ Processes│ Alerts   │ Viewer    │   │
│  │          │          │           │   │
│  │ PID|Name │ Severity │ Timestamp │   │
│  │ CPU|Mem  │ Message  │ Level     │   │
│  │          │          │ Message   │   │
│  └──────────┴──────────┴───────────┘   │
│  │ Status Bar          Time        │   │
│  └─────────────────────────────────┘   │
├─────────────────────────────────────────┤
│ Features:                               │
│  • Tkinter-based                        │
│  • Dark theme (#2b2b2b)                 │
│  • Color-coded alerts                   │
│  • 2-second auto-refresh                │
│  • Threaded execution                   │
│  • Non-blocking                         │
└─────────────────────────────────────────┘
```

---

## Data Flow Diagram

```
┌─────────────┐
│   System    │
│  Processes  │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│ ProcessScanner  │ ──── Scans every 1 second
│                 │
│ Collects:       │
│ - PID           │
│ - Name          │
│ - CPU %         │
│ - Memory %      │
│ - Timestamp     │
└────────┬────────┘
         │
         │ Process Info + History
         │
         ▼
┌─────────────────────────────────────────┐
│      BehaviorAnalyzer                   │
│                                         │
│  1. Check cooldown (30s)                │
│  2. Apply detection rules:              │
│     • Consecutive CPU checks            │
│     • Combined CPU + Memory             │
│     • Extreme memory                    │
│  3. Assign severity:                    │
│     • INFO / WARNING / CRITICAL         │
│  4. Update cooldown timer               │
└────────┬────────────────────────────────┘
         │
         │ Analysis Result
         │ (suspicious, severity, reasons)
         │
         ▼
┌─────────────────────────────────────────┐
│         Responder                       │
│                                         │
│  IF suspicious:                         │
│    1. Log full details                  │
│    2. Console alert                     │
│    3. Write JSON log                    │
│    4. Check severity:                   │
│       • CRITICAL → Terminate process    │
│       • WARNING → Alert only            │
│       • INFO → Log only                 │
└────────┬────────────────────────────────┘
         │
         ├─────────────┬─────────────┐
         │             │             │
         ▼             ▼             ▼
    ┌────────┐   ┌─────────┐   ┌─────────┐
    │Console │   │Text Log │   │JSON Log │
    │ Output │   │edr.log  │   │edr_*.json│
    └────────┘   └─────────┘   └─────────┘
         │
         │ (if GUI enabled)
         │
         ▼
    ┌──────────────┐
    │ GUI Dashboard│
    │ - Add alert  │
    │ - Add log    │
    │ - Update UI  │
    └──────────────┘
```

---

## Threading Model

```
┌─────────────────────────────────────────────────────────┐
│                    MAIN THREAD                          │
│                                                         │
│  ┌──────────────────────────────────────────────┐      │
│  │  LightweightEDR Main Loop                    │      │
│  │                                              │      │
│  │  while running:                              │      │
│  │    1. Scan processes                         │      │
│  │    2. Analyze behavior                       │      │
│  │    3. Handle threats                         │      │
│  │    4. Update GUI (if enabled)                │      │
│  │    5. Sleep (scan_interval)                  │      │
│  └──────────────────────────────────────────────┘      │
│                                                         │
└─────────────────────────────────────────────────────────┘
                         │
                         │ Spawns
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   GUI THREAD (Daemon)                   │
│                                                         │
│  ┌──────────────────────────────────────────────┐      │
│  │  Tkinter Main Loop                           │      │
│  │                                              │      │
│  │  - Handle user input                         │      │
│  │  - Update display every 2s                   │      │
│  │  - Render process list                       │      │
│  │  - Show alerts                               │      │
│  │  - Display logs                              │      │
│  └──────────────────────────────────────────────┘      │
│                                                         │
└─────────────────────────────────────────────────────────┘
                         │
                         │ Spawns
                         ▼
┌─────────────────────────────────────────────────────────┐
│              FILE MONITOR THREAD                        │
│                                                         │
│  ┌──────────────────────────────────────────────┐      │
│  │  Watchdog Observer                           │      │
│  │                                              │      │
│  │  - Monitor file system events                │      │
│  │  - Track changes in time window              │      │
│  │  - Trigger callback if threshold exceeded    │      │
│  └──────────────────────────────────────────────┘      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Configuration Flow

```
┌──────────────┐
│  config.py   │
│  EDRConfig   │
└──────┬───────┘
       │
       │ Import
       │
       ├────────────────┬────────────────┬────────────────┐
       │                │                │                │
       ▼                ▼                ▼                ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Analyzer   │  │  Responder  │  │   Monitor   │  │     GUI     │
│             │  │             │  │             │  │             │
│ Uses:       │  │ Uses:       │  │ Uses:       │  │ Uses:       │
│ - CPU_*     │  │ - AUTO_*    │  │ - FILE_*    │  │ - GUI_*     │
│ - MEMORY_*  │  │ - GRACEFUL_*│  │ - MONITOR_* │  │ - REFRESH_* │
│ - COOLDOWN  │  │ - SEVERITY_*│  │             │  │             │
└─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘
```

---

## Severity Decision Tree

```
                    Process Detected
                          │
                          ▼
                  ┌───────────────┐
                  │ Check Cooldown│
                  └───────┬───────┘
                          │
                  ┌───────┴────────┐
                  │                │
            In Cooldown?      Not in Cooldown
                  │                │
                  ▼                ▼
            Return INFO    Apply Detection Rules
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
            ┌──────────┐   ┌──────────┐   ┌──────────┐
            │ Rule 1:  │   │ Rule 2:  │   │ Rule 3:  │
            │ High CPU │   │ Combined │   │ Extreme  │
            │ 5+ checks│   │ CPU+Mem  │   │ Memory   │
            └────┬─────┘   └────┬─────┘   └────┬─────┘
                 │              │              │
            Triggered?     Triggered?     Triggered?
                 │              │              │
                 ▼              ▼              ▼
            WARNING        CRITICAL        WARNING
                 │              │              │
                 └──────────────┼──────────────┘
                                │
                                ▼
                        ┌───────────────┐
                        │   Responder   │
                        └───────┬───────┘
                                │
                    ┌───────────┼───────────┐
                    │           │           │
                    ▼           ▼           ▼
                  INFO      WARNING     CRITICAL
                    │           │           │
                    ▼           ▼           ▼
                Log Only   Alert+Log   Terminate
```

---

## File Structure Tree

```
Process_Behavior_Monitor/
│
├── 📄 config.py                    # Centralized configuration
├── 📄 main.py                      # Main controller
├── 📄 test_edr.py                  # Test suite
│
├── 📁 scanner/
│   ├── __init__.py
│   └── process_scanner.py          # Process enumeration
│
├── 📁 analyzer/
│   ├── __init__.py
│   └── behavior_analyzer.py        # ⭐ Enhanced detection logic
│
├── 📁 monitor/
│   ├── __init__.py
│   └── file_monitor.py             # File system monitoring
│
├── 📁 response/
│   ├── __init__.py
│   └── responder.py                # ⭐ Enhanced response system
│
├── 📁 gui/                         # ⭐ NEW
│   ├── __init__.py
│   └── dashboard.py                # Tkinter GUI
│
├── 📁 logs/
│   ├── edr.log                     # Text logs
│   └── edr_structured.json         # ⭐ JSON logs
│
├── 📁 monitored/                   # Monitored directory
│
└── 📚 Documentation/
    ├── README.md                   # Original README (updated)
    ├── README_UPGRADED.md          # ⭐ Upgrade documentation
    ├── UPGRADE_SUMMARY.md          # ⭐ Change summary
    ├── QUICK_START.md              # ⭐ Quick start guide
    └── ARCHITECTURE.md             # ⭐ This file
```

---

**Legend:**
- ⭐ = New or significantly upgraded
- 📄 = Python file
- 📁 = Directory
- 📚 = Documentation

---

This architecture provides a modular, extensible, and production-ready EDR system! 🛡️
