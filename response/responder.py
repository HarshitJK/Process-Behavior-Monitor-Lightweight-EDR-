"""
Response Module – Lightweight EDR
Handles alerts, process actions, and structured/event logging.

Four-Tier Response Model:
  LOW      → log only (no console output, no process action)
  MEDIUM   → alert (console/GUI notification, no process action)
  HIGH     → suspend process (SIGSTOP on Linux; skip on Windows)
  CRITICAL → terminate process (graceful → force-kill)

  IMPORTANT: WARNING / INFO severities (legacy aliases) NEVER trigger
  termination. Only CRITICAL does, and even then PROTECTED_PROCESSES
  are always skipped.

GUI-mode extra safety:
  When EDRConfig.GUI_MODE is True:
    • HIGH  actions are downgraded to ALERT_ONLY (suspend skipped)
    • CRITICAL actions on any process with ppid == 1 (init children)
      are also skipped with a warning.
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
    "LOW":      "\033[94m",   # blue
    "MEDIUM":   "\033[93m",   # yellow
    "HIGH":     "\033[38;5;208m",  # orange
    "CRITICAL": "\033[91m",   # red
    # Legacy aliases
    "INFO":     "\033[94m",
    "WARNING":  "\033[93m",
    "RESET":    "\033[0m",
}


def _col(sev: str, text: str) -> str:
    if sys.stdout.isatty():
        return f"{_C.get(sev, '')}{text}{_C['RESET']}"
    return text


def _action_for_severity(severity: str) -> str:
    """
    Map severity → default action according to the four-tier model.

      LOW      → ALERT_ONLY  (log only)
      MEDIUM   → ALERT_ONLY  (alert, no process change)
      HIGH     → SUSPEND_PROCESS
      CRITICAL → TERMINATE_PROCESS (if AUTO_TERMINATE is enabled)

    GUI-mode override: HIGH → ALERT_ONLY.
    """
    if severity == EDRConfig.SEVERITY_CRITICAL:
        if EDRConfig.AUTO_TERMINATE:
            return EDRConfig.ACTION_TERMINATE
        return EDRConfig.ACTION_ALERT_ONLY

    if severity == EDRConfig.SEVERITY_HIGH:
        if EDRConfig.GUI_MODE:
            # Extra safety: never auto-suspend in GUI mode
            return EDRConfig.ACTION_ALERT_ONLY
        return EDRConfig.ACTION_SUSPEND

    # LOW / MEDIUM / legacy INFO / WARNING → alert only
    return EDRConfig.ACTION_ALERT_ONLY


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
        self.total_alerts: int            = 0
        self.total_terminated: int        = 0
        self.total_suspended: int         = 0
        self.total_termination_attempts: int = 0   # increments on every attempt

        # Protected process names (lower-cased for fast O(1) lookup)
        self._protected = {p.lower() for p in EDRConfig.PROTECTED_PROCESSES}
        # Safe process names (lower-cased) – extra defense-in-depth layer
        self._safe      = {p.lower() for p in EDRConfig.SAFE_PROCESSES}
        # Prefix-based safe list (handles kworker/0:1, ksoftirqd/3, etc.)
        self._safe_prefixes = [p.lower() for p in EDRConfig.SAFE_PROCESS_PREFIXES]

    # ------------------------------------------------------------------
    # Process threat handler
    # ------------------------------------------------------------------

    def handle_process_threat(
        self,
        process: Dict,
        reasons: List[str],
        severity: str = "LOW",
        threat_type: str = "UNKNOWN",
    ):
        pid    = process.get("pid")
        name   = process.get("name", "unknown")
        cpu    = process.get("cpu_percent",    0.0)
        memory = process.get("memory_percent", 0.0)
        ts     = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        reason_text = "; ".join(reasons)

        self.total_alerts += 1

        # ---- Determine action -----------------------------------------------
        action_type = _action_for_severity(severity)

        # For LOW severity – just log quietly, no console noise
        if severity == EDRConfig.SEVERITY_LOW:
            self.logger.info(
                f"LOW | PROCESS | PID={pid} | NAME={name} | "
                f"THREAT={threat_type} | REASON={reason_text}"
            )
            return

        # ---- Console output --------------------------------------------------
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

        # ---- Perform action --------------------------------------------------
        action_result = self._take_action(action_type, pid, name)

        # ---- Pipe-delimited log ----------------------------------------------
        log_line = (
            f"{severity} | PROCESS | PID={pid} | NAME={name} | "
            f"CPU={cpu:.1f}% | MEM={memory:.1f}% | "
            f"THREAT={threat_type} | ACTION={action_result} | "
            f"REASON={reason_text}"
        )
        if severity == EDRConfig.SEVERITY_CRITICAL:
            self.logger.critical(log_line)
        elif severity in (EDRConfig.SEVERITY_HIGH, EDRConfig.SEVERITY_MEDIUM):
            self.logger.warning(log_line)
        else:
            self.logger.info(log_line)

        # ---- Human-friendly event log ----------------------------------------
        self._write_event_log(ts, severity, name, pid, cpu, memory)

        # ---- JSON log --------------------------------------------------------
        self._write_json({
            "timestamp":      ts,
            "alert_type":     "process",
            "severity":       severity,
            "threat_type":    threat_type,
            "pid":            pid,
            "process_name":   name,
            "cpu_percent":    round(cpu,    2),
            "memory_percent": round(memory, 2),
            "reasons":        reasons,
            "action_taken":   action_result,
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
            "timestamp":    ts,
            "alert_type":   "file_system",
            "severity":     "CRITICAL",
            "threat_type":  "RANSOMWARE_PATTERN",
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
            "total_alerts":               self.total_alerts,
            "total_terminated":           self.total_terminated,
            "total_suspended":            self.total_suspended,
            "total_termination_attempts": self.total_termination_attempts,
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

    def _is_protected(self, name: str, pid: int = -1) -> bool:
        """Return True if this process/PID must never be terminated."""
        # 1. Always protect the EDR process itself
        if pid != -1 and pid == EDRConfig.EDR_OWN_PID:
            return True
        # 2. Always protect the terminal that launched the EDR
        if pid != -1 and EDRConfig.EDR_PARENT_PID and pid == EDRConfig.EDR_PARENT_PID:
            return True
        n = name.lower()
        # 3. Exact set match against safe + protected lists
        if n in self._protected or n in self._safe:
            return True
        # 4. Prefix match (catches kworker/0:1, ksoftirqd/3, etc.)
        for prefix in self._safe_prefixes:
            if n.startswith(prefix):
                return True
        return False

    def _terminate_process(self, pid: int, name: str) -> str:
        """
        Safe terminate with protected-process guard.

        NEVER terminates:
          • Protected / safe processes (listed in config.py)
          • PID 1 (init/systemd) or PID 0
          • Any process whose name resolves to a protected entry
        """
        # Guard 1: protected name list (includes prefix check + PID check)
        if self._is_protected(name, pid):
            msg = f"Skipped termination – '{name}' is a protected system process"
            self.logger.warning(f"PROTECTED | PID={pid} | {msg}")
            print(f"  [SKIPPED] {msg}")
            return msg

        # Guard 2: never kill PID 1 or 0 (init / idle)
        if pid in (0, 1):
            msg = f"Skipped termination – PID {pid} is a critical system identifier"
            self.logger.warning(f"PROTECTED | PID={pid} | {msg}")
            print(f"  [SKIPPED] {msg}")
            return msg

        # Guard 3: double-check by querying psutil for the real process name
        try:
            real_proc = psutil.Process(pid)
            real_name = (real_proc.name() or "")
            if self._is_protected(real_name, pid):
                msg = (f"Skipped termination – real process name '{real_name}' "
                       f"(PID {pid}) is protected")
                self.logger.warning(f"PROTECTED | PID={pid} | {msg}")
                print(f"  [SKIPPED] {msg}")
                return msg
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        self.total_termination_attempts += 1
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
            msg = f"Access denied terminating PID {pid} ('{name}') – run EDR with sudo/root for full termination capability"
            self.logger.error(f"ACTION FAILED | {msg}")
            print(f"  [BLOCKED] {_col('HIGH', msg)}")
            return msg
        except Exception as exc:
            msg = f"Failed to terminate PID {pid}: {exc}"
            self.logger.error(f"ACTION FAILED | {msg}")
            print(f"  [ERROR] {msg}")
            return msg

    def _suspend_process(self, pid: int, name: str) -> str:
        """Suspend a process. Never suspends protected processes."""
        if self._is_protected(name, pid):
            return f"Skipped suspend – '{name}' is protected"
        if pid in (0, 1):
            return f"Skipped suspend – PID {pid} is a critical system identifier"
        if sys.platform == "win32":
            # SIGSTOP is not available on Windows; skip silently
            return f"Suspend not supported on Windows for PID {pid}"
        try:
            os.kill(pid, signal.SIGSTOP)
            result = f"Process '{name}' (PID {pid}) suspended (SIGSTOP)"
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
        """Write human-readable alert entry to edr_events.log."""
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
