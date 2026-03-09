"""
Response Module
Handles threat alerts, response actions, and structured logging.

Supported Response Actions:
  ALERT_ONLY       – print alert, write log, do nothing to the process
  TERMINATE_PROCESS – graceful terminate → force kill if needed
  SUSPEND_PROCESS   – send SIGSTOP (Linux/macOS) or pause (Windows)

Log formats:
  logs/edr.log            – human-readable pipe-delimited
  logs/edr_structured.json – JSON-lines (one JSON object per line)
"""

import os
import sys
import signal
import psutil
import logging
import json
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
from config import EDRConfig


# ---------------------------------------------------------------------------
# Severity → ANSI colour map (for terminal output)
# ---------------------------------------------------------------------------
_COLOUR = {
    "INFO":     "\033[94m",   # blue
    "WARNING":  "\033[93m",   # yellow
    "CRITICAL": "\033[91m",   # red
    "RESET":    "\033[0m",
}


def _coloured(severity: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"{_COLOUR.get(severity, '')}{text}{_COLOUR['RESET']}"
    return text


# ---------------------------------------------------------------------------
class Responder:
    """
    Centralized incident response handler.

    Responsibilities:
      1. Print formatted alerts to the terminal (with ANSI colors when supported)
      2. Write pipe-delimited log entries to logs/edr.log
      3. Write structured JSON entries to logs/edr_structured.json
      4. Take configurable action: alert-only, suspend, or terminate
    """

    def __init__(
        self,
        log_file: Optional[str] = None,
        json_log_file: Optional[str] = None,
    ):
        self.log_file = log_file or EDRConfig.LOG_FILE
        self.json_log_file = json_log_file or EDRConfig.JSON_LOG_FILE

        # Make sure the log directory exists
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)
        Path(self.json_log_file).parent.mkdir(parents=True, exist_ok=True)

        # Python logging (plain-text)
        self.logger = logging.getLogger("EDR")
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)
            handler = logging.FileHandler(self.log_file, encoding="utf-8")
            handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s",
                                                   datefmt="%Y-%m-%d %H:%M:%S"))
            self.logger.addHandler(handler)

        # Runtime counters
        self.total_alerts: int = 0
        self.total_terminated: int = 0
        self.total_suspended: int = 0

    # -----------------------------------------------------------------------
    # Public – Process Threats
    # -----------------------------------------------------------------------

    def handle_process_threat(
        self,
        process: Dict,
        reasons: List[str],
        severity: str = "WARNING",
        threat_type: str = "UNKNOWN",
    ):
        """
        Respond to a suspicious process.

        Decision logic:
          CRITICAL + AUTO_TERMINATE  → terminate
          WARNING  + SUSPEND_ON_WARNING (Linux) → suspend
          otherwise                   → alert only
        """
        pid = process.get("pid")
        name = process.get("name", "unknown")
        cpu = process.get("cpu_percent", 0.0)
        memory = process.get("memory_percent", 0.0)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        reason_text = "; ".join(reasons)

        self.total_alerts += 1

        # ---- Determine action -------------------------------------------
        action_type = EDRConfig.ACTION_ALERT_ONLY
        if severity == EDRConfig.SEVERITY_CRITICAL and EDRConfig.AUTO_TERMINATE:
            action_type = EDRConfig.ACTION_TERMINATE
        elif severity == EDRConfig.SEVERITY_WARNING and EDRConfig.SUSPEND_ON_WARNING:
            action_type = EDRConfig.ACTION_SUSPEND

        # ---- Terminal output --------------------------------------------
        border = "=" * 60
        tag = f"[{severity}]"
        print(f"\n{_coloured(severity, border)}")
        print(_coloured(severity, f"{tag} SUSPICIOUS PROCESS DETECTED"))
        print(_coloured(severity, border))
        print(f"  Timestamp  : {ts}")
        print(f"  PID        : {pid}")
        print(f"  Process    : {name}")
        print(f"  CPU        : {cpu:.1f}%")
        print(f"  Memory     : {memory:.1f}%")
        print(f"  Severity   : {_coloured(severity, severity)}")
        print(f"  Threat Type: {threat_type}")
        print(f"  Reason     : {reason_text}")
        print(f"  Action     : {action_type}")
        print(_coloured(severity, border))

        # ---- Perform action ---------------------------------------------
        action_result = self._take_action(action_type, pid, name)

        # ---- Text log ---------------------------------------------------
        log_line = (
            f"{severity} | PROCESS | PID={pid} | NAME={name} | "
            f"CPU={cpu:.1f}% | MEM={memory:.1f}% | "
            f"THREAT={threat_type} | ACTION={action_result} | "
            f"REASON={reason_text}"
        )
        if severity == EDRConfig.SEVERITY_CRITICAL:
            self.logger.critical(log_line)
        elif severity == EDRConfig.SEVERITY_WARNING:
            self.logger.warning(log_line)
        else:
            self.logger.info(log_line)

        # ---- JSON log ---------------------------------------------------
        self._write_json({
            "timestamp": ts,
            "alert_type": "process",
            "severity": severity,
            "threat_type": threat_type,
            "pid": pid,
            "process_name": name,
            "cpu_percent": round(cpu, 2),
            "memory_percent": round(memory, 2),
            "reasons": reasons,
            "action_taken": action_result,
        })

    # -----------------------------------------------------------------------
    # Public – File System Threats
    # -----------------------------------------------------------------------

    def handle_file_threat(
        self,
        changes: List,
        trigger_file: str,
        summary: Optional[Dict] = None,
    ):
        """
        Respond to ransomware-like file activity.

        Args:
            changes:      list of (timestamp, file_path, event_type) tuples
            trigger_file: the file that exceeded the threshold
            summary:      optional dict of event_type → count
        """
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_events = len(changes)
        summary = summary or {}

        self.total_alerts += 1

        border = "=" * 60
        print(f"\n{_coloured('CRITICAL', border)}")
        print(_coloured("CRITICAL", "[CRITICAL] RANSOMWARE-LIKE FILE ACTIVITY DETECTED"))
        print(_coloured("CRITICAL", border))
        print(f"  Timestamp     : {ts}")
        print(f"  Trigger file  : {trigger_file}")
        print(f"  Total events  : {total_events}")
        if summary:
            for etype, count in summary.items():
                print(f"  {etype.capitalize():12s}: {count}")
        print(_coloured("CRITICAL", border))

        log_line = (
            f"CRITICAL | FILE_SYSTEM | Events={total_events} | "
            f"Trigger={trigger_file} | Types={summary}"
        )
        self.logger.critical(log_line)

        self._write_json({
            "timestamp": ts,
            "alert_type": "file_system",
            "severity": "CRITICAL",
            "threat_type": "RANSOMWARE_PATTERN",
            "trigger_file": trigger_file,
            "total_events": total_events,
            "event_summary": summary,
            "event_details": [
                {"time": c[0], "file": c[1], "type": c[2]}
                for c in changes[:15]
            ],
            "action_taken": "Alert logged – manual investigation required",
        })

    # -----------------------------------------------------------------------
    # Public – Read recent alerts from JSON log
    # -----------------------------------------------------------------------

    def get_recent_alerts(self, count: int = 20) -> List[Dict]:
        """Return the most recent *count* alerts from the JSON log."""
        alerts = []
        try:
            if os.path.exists(self.json_log_file):
                with open(self.json_log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                for line in lines[-count:]:
                    try:
                        alerts.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
        except Exception as exc:
            self.logger.error(f"Failed to read JSON log: {exc}")
        return alerts

    def get_stats(self) -> Dict:
        """Return runtime response statistics."""
        return {
            "total_alerts": self.total_alerts,
            "total_terminated": self.total_terminated,
            "total_suspended": self.total_suspended,
        }

    # -----------------------------------------------------------------------
    # Internal – Action dispatch
    # -----------------------------------------------------------------------

    def _take_action(self, action_type: str, pid: int, name: str) -> str:
        if action_type == EDRConfig.ACTION_TERMINATE:
            result = self._terminate_process(pid, name)
            return result
        elif action_type == EDRConfig.ACTION_SUSPEND:
            result = self._suspend_process(pid, name)
            return result
        else:
            return "Alert logged – no process action taken"

    def _terminate_process(self, pid: int, name: str) -> str:
        """Attempt graceful termination then force-kill."""
        if EDRConfig.DEBUG_MODE:
            print(f"[DEBUG] Attempting to terminate PID {pid} ({name})")
        try:
            proc = psutil.Process(pid)
            if not proc.is_running():
                return f"PID {pid} is not running"

            proc.terminate()
            try:
                proc.wait(timeout=EDRConfig.GRACEFUL_TIMEOUT)
                result = f"Process '{name}' (PID {pid}) terminated gracefully"
                self.logger.info(f"ACTION | {result}")
                self.total_terminated += 1
                print(f"  [ACTION] {_coloured('CRITICAL', result)}")
                return result
            except psutil.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=2)
                except psutil.TimeoutExpired:
                    pass
                result = f"Process '{name}' (PID {pid}) force-killed (graceful timeout)"
                self.logger.warning(f"ACTION | {result}")
                self.total_terminated += 1
                print(f"  [ACTION] {_coloured('CRITICAL', result)}")
                return result

        except psutil.NoSuchProcess:
            return f"PID {pid} no longer exists"
        except psutil.AccessDenied:
            msg = f"Access denied terminating PID {pid} – run with sudo/admin rights"
            self.logger.error(f"ACTION FAILED | {msg}")
            print(f"  [ACTION] {msg}")
            return msg
        except Exception as exc:
            msg = f"Failed to terminate PID {pid}: {exc}"
            self.logger.error(f"ACTION FAILED | {msg}")
            return msg

    def _suspend_process(self, pid: int, name: str) -> str:
        """Suspend a process (SIGSTOP on Linux, resume with SIGCONT)."""
        try:
            proc = psutil.Process(pid)
            if sys.platform != "win32":
                os.kill(pid, signal.SIGSTOP)
                result = f"Process '{name}' (PID {pid}) suspended (SIGSTOP)"
            else:
                # Windows: no direct equivalent – freeze via debug API would need ctypes
                result = f"Suspend not supported on Windows for PID {pid}; alert only"
            self.logger.warning(f"ACTION | {result}")
            self.total_suspended += 1
            print(f"  [ACTION] {result}")
            return result
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as exc:
            msg = f"Failed to suspend PID {pid}: {exc}"
            self.logger.error(f"ACTION FAILED | {msg}")
            return msg

    # -----------------------------------------------------------------------
    # Internal – Logging
    # -----------------------------------------------------------------------

    def _write_json(self, data: Dict):
        try:
            with open(self.json_log_file, "a", encoding="utf-8") as f:
                json.dump(data, f, default=str)
                f.write("\n")
        except Exception as exc:
            self.logger.error(f"JSON log write failed: {exc}")
