# Lightweight EDR — Process Behavior Monitoring System

A lightweight, educational **Endpoint Detection & Response (EDR)** system built in Python. It monitors running processes and the file system in real time, detects suspicious behavior, and responds automatically.

---

## Features

- **Real-time process monitoring** using `psutil`
- **Behavioral threat detection** — 6 rules covering CPU abuse, memory spikes, suspicious names, sensitive file access, and rapid process spawning
- **File system monitoring** using `watchdog` — detects ransomware-like rapid file creation/modification/deletion
- **Automatic response** — alert, suspend, or terminate processes based on severity (INFO / WARNING / CRITICAL)
- **Security logging** — human-readable `logs/edr.log` + structured `logs/edr_structured.json`
- **Live dashboard** — terminal box (always on) or optional Tkinter GUI (`--gui`)

---

## Project Structure

```
Process_Behavior_Monitor/
├── main.py                        # Entry point
├── config.py                      # All thresholds & settings
├── requirements.txt
├── scanner/process_scanner.py     # Process enumeration
├── analyzer/behavior_analyzer.py  # Detection rules engine
├── monitor/file_monitor.py        # Ransomware file-pattern detection
├── response/responder.py          # Alert / terminate / suspend
├── gui/dashboard.py               # Terminal + GUI dashboard
├── logs/                          # edr.log + edr_structured.json
├── attack_simulation/             # Demo attack scripts
│   ├── cpu_stress_test.py
│   ├── ransomware_simulation.py
│   └── fake_malware.py
└── testing_malware/               # Directory watched by file monitor
```

---

## Installation (WSL / Linux)

```bash
pip install -r requirements.txt
mkdir -p logs testing_malware
```

---

## Usage

```bash
# Default — terminal dashboard, auto-terminate on CRITICAL
python main.py

# Alert-only mode (safe for demos — no process killing)
python main.py --no-terminate

# Tkinter GUI dashboard
python main.py --gui

# Verbose debug output
python main.py --debug
```

---

## Attack Simulations

Run the EDR first, then in a separate terminal:

```bash
# Simulates high CPU → triggers WARNING then CRITICAL
python attack_simulation/cpu_stress_test.py

# Simulates rapid file encryption → triggers file-system CRITICAL alert
python attack_simulation/ransomware_simulation.py

# Suspicious-named process with CPU + memory abuse
python attack_simulation/fake_malware.py --mode combined
```

---

## Configuration

All thresholds are in `config.py`:

| Setting | Default | Description |
|---|---|---|
| `CPU_THRESHOLD` | `80.0` | CPU % to flag a process |
| `MEMORY_WARNING_THRESHOLD` | `50.0` | Memory % → WARNING |
| `MEMORY_CRITICAL_THRESHOLD` | `70.0` | Memory % → CRITICAL |
| `FILE_EVENT_THRESHOLD` | `10` | File events in window → CRITICAL |
| `TIME_WINDOW` | `5.0` | Seconds for file event window |
| `AUTO_TERMINATE` | `True` | Kill CRITICAL processes automatically |
| `SCAN_INTERVAL` | `2.0` | Seconds between process scans |
