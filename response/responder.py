"""
Response Module – Lightweight EDR
Handles alerts, process actions, and structured/event logging.

Actions:
  ALERT_ONLY       – print + log, no process change
  TERMINATE_PROCESS – graceful terminate → force kill
  SUSPEND_PROCESS   – SIGSTOP (Linux/macOS)

Issue 3 fix: checks PROTECTED_PROCESSES before terminating.
Issue 7 fix: writes human-friendly edr_events.log in addition to edr.log.
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

# ANSI colours
_C = {
    "INFO":     "\033[94m",
    "WARNING":  "\033[93m",
    "CRITICAL": "\033[91m",
    "RESET":    "\033[0m",
}


def _col(sev: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"{_C.get(sev, '')}{text}{_C['RESET']}"
    return text


class Responder:

    def __init__(self, log_file: Optional[str] = None,
                 json_log_file: Optional[str] = None):
        self.log_file      = log_file      or EDRConfig.LOG_FILE
        self.json_log_file = json_log_file or EDRConfig.JSON_LOG_FILE
        self.events_log    = EDRConfig.EVENTS_LOG

        # Ensure log directory exists
        for p in [self.log_file, self.json_log_file, self.events_log]:
            Path(p).parent.mkdir(parents=True, exist_ok=True)

        # Python logger (pipe-delimited)
        self.logger = logging.getLogger("EDR")
        if not self.logger.handlers:
            self.logger.setLevel(logging.INFO)
            h = logging.FileHandler(self.log_file, encoding="utf-8")
            h.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            ))
            self.logger.addHandler(h)

        # Runtime counters
        self.total_alerts: int     = 0
        self.total_terminated: int = 0
        self.total_suspended: int  = 0

        # Protected process names (lower-cased for fast lookup)
        self._protected = {p.lower() for p in EDRConfig.PROTECTED_PROCESSES}

    # ------------------------------------------------------------------
    # Process threat handler
    # ------------------------------------------------------------------

    def handle_process_threat(
        self,
        process: Dict,
        reasons: List[str],
        severity: str = "WARNING",
        threat_type: str = "UNKNOWN",
    ):
        pid    = process.get("pid")
        name   = process.get("name", "unknown")
        cpu    = process.get("cpu_percent",    0.0)
        memory = process.get("memory_percent", 0.0)
        ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        reason_text = "; ".join(reasons)

        self.total_alerts += 1

        # Decide action
        action_type = EDRConfig.ACTION_ALERT_ONLY
        if severity == EDRConfig.SEVERITY_CRITICAL and EDRConfig.AUTO_TERMINATE:
            action_type = EDRConfig.ACTION_TERMINATE
        elif severity == EDRConfig.SEVERITY_WARNING and EDRConfig.SUSPEND_ON_WARNING:
            action_type = EDRConfig.ACTION_SUSPEND

        # Terminal output
        border = "=" * 60
        print(f"\n{_col(severity, border)}")
        print(_col(severity, f"[{severity}] SUSPICIOUS PROCESS DETECTED"))
        print(_col(severity, border))
        print(f"  Timestamp  : {ts}")
        print(f"  PID        : {pid}")
        print(f"  Process    : {name}")
        print(f"  CPU        : {cpu:.1f}%")
        print(f"  Memory     : {memory:.1f}%")
        print(f"  Severity   : {_col(severity, severity)}")
        print(f"  Threat Type: {threat_type}")
        print(f"  Reason     : {reason_text}")
        print(f"  Action     : {action_type}")
        print(_col(severity, border))

        # Perform action
        action_result = self._take_action(action_type, pid, name)

        # Pipe-delimited log
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

        # Human-friendly event log (Issue 7)
        self._write_event_log(ts, severity, name, pid, cpu, memory)

        # JSON log
        self._write_json({
            "timestamp": ts,
            "alert_type": "process",
            "severity": severity,
            "threat_type": threat_type,
            "pid": pid,
            "process_name": name,
            "cpu_percent":    round(cpu,    2),
            "memory_percent": round(memory, 2),
            "reasons": reasons,
            "action_taken": action_result,
        })

    # ------------------------------------------------------------------
    # File threat handler
    # ------------------------------------------------------------------

    def handle_file_threat(
        self,
        changes: List,
        trigger_file: str,
        summary: Optional[Dict] = None,
    ):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_events = len(changes)
        summary = summary or {}

        self.total_alerts += 1

        border = "=" * 60
        print(f"\n{_col('CRITICAL', border)}")
        print(_col("CRITICAL", "[CRITICAL] RANSOMWARE-LIKE FILE ACTIVITY DETECTED"))
        print(_col("CRITICAL", border))
        print(f"  Timestamp    : {ts}")
        print(f"  Trigger file : {trigger_file}")
        print(f"  Total events : {total_events}")
        for etype, count in summary.items():
            print(f"  {etype.capitalize():12s}: {count}")
        print(_col("CRITICAL", border))

        log_line = (
            f"CRITICAL | FILE | Events={total_events} | "
            f"Trigger={trigger_file} | Types={summary}"
        )
        self.logger.critical(log_line)

        self._write_event_log(ts, "CRITICAL", "FILE_SYSTEM", 0,
                              0, 0, extra=f"Events={total_events} Trigger={trigger_file}")

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

    # ------------------------------------------------------------------
    # Stats / recent alerts
    # ------------------------------------------------------------------

    def get_recent_alerts(self, count: int = 20) -> List[Dict]:
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
        return {
            "total_alerts":     self.total_alerts,
            "total_terminated": self.total_terminated,
            "total_suspended":  self.total_suspended,
        }

    # ------------------------------------------------------------------
    # Action dispatch
    # ------------------------------------------------------------------

    def _take_action(self, action_type: str, pid: int, name: str) -> str:
        if action_type == EDRConfig.ACTION_TERMINATE:
            return self._terminate_process(pid, name)
        elif action_type == EDRConfig.ACTION_SUSPEND:
            return self._suspend_process(pid, name)
        return "Alert logged – no process action taken"

    def _is_protected(self, name: str) -> bool:
        """Return True if process name is in the protected list (Issue 3)."""
        return name.lower() in self._protected

    def _terminate_process(self, pid: int, name: str) -> str:
        """Safe terminate with protected-process guard (Issue 3 fix)."""
        # ---- Protected-process check (Issue 3) ----------------------------
        if self._is_protected(name):
            msg = f"Skipped termination – '{name}' is a protected system process"
            self.logger.warning(f"PROTECTED | PID={pid} | {msg}")
            print(f"  [SKIPPED] {msg}")
            return msg

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
                print(f"  [ACTION] {_col('CRITICAL', result)}")
                return result
            except psutil.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=2)
                except psutil.TimeoutExpired:
                    pass
                result = f"Process '{name}' (PID {pid}) force-killed"
                self.logger.warning(f"ACTION | {result}")
                self.total_terminated += 1
                print(f"  [ACTION] {_col('CRITICAL', result)}")
                return result

        except psutil.NoSuchProcess:
            return f"PID {pid} no longer exists"
        except psutil.AccessDenied:
            msg = f"Access denied terminating PID {pid} – run with sudo"
            self.logger.error(f"ACTION FAILED | {msg}")
            print(f"  [ACTION] {msg}")
            return msg
        except Exception as exc:
            msg = f"Failed to terminate PID {pid}: {exc}"
            self.logger.error(f"ACTION FAILED | {msg}")
            return msg

    def _suspend_process(self, pid: int, name: str) -> str:
        if self._is_protected(name):
            return f"Skipped suspend – '{name}' is protected"
        try:
            if sys.platform != "win32":
                os.kill(pid, signal.SIGSTOP)
                result = f"Process '{name}' (PID {pid}) suspended (SIGSTOP)"
            else:
                result = f"Suspend not supported on Windows for PID {pid}"
            self.logger.warning(f"ACTION | {result}")
            self.total_suspended += 1
            print(f"  [ACTION] {result}")
            return result
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError) as exc:
            return f"Failed to suspend PID {pid}: {exc}"

    # ------------------------------------------------------------------
    # Logging helpers
    # ------------------------------------------------------------------

    def _write_event_log(self, ts: str, severity: str, name: str,
                         pid: int, cpu: float, memory: float,
                         extra: str = ""):
        """Write human-readable alert entry to edr_events.log (Issue 7)."""
        try:
            line = (
                f"[{ts}] ALERT\n"
                f"  Severity : {severity}\n"
                f"  Process  : {name}\n"
                f"  PID      : {pid}\n"
                f"  CPU      : {cpu:.1f}%\n"
                f"  Memory   : {memory:.1f}%\n"
            )
            if extra:
                line += f"  Details  : {extra}\n"
            line += "\n"
            with open(self.events_log, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as exc:
            self.logger.error(f"Event log write failed: {exc}")

    def _write_json(self, data: Dict):
        try:
            with open(self.json_log_file, "a", encoding="utf-8") as f:
                json.dump(data, f, default=str)
                f.write("\n")
        except Exception as exc:
            self.logger.error(f"JSON log write failed: {exc}")
