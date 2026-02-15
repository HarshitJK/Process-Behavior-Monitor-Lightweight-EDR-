"""
Response Module
Handles alerts, terminates suspicious processes, and logs incidents.
Enhanced with severity levels, detailed logging, and JSON structured logs.
"""

import psutil
import logging
import json
import os
from datetime import datetime
from typing import Dict, List
from pathlib import Path
from config import EDRConfig


class Responder:
    """
    Handles response actions for detected threats with enhanced logging.
    """

    def __init__(self, log_file: str = None, json_log_file: str = None):
        """
        Initialize responder and logging.

        Args:
            log_file: Path to text log file
            json_log_file: Path to JSON structured log file
        """
        self.log_file = log_file or EDRConfig.LOG_FILE
        self.json_log_file = json_log_file or EDRConfig.JSON_LOG_FILE
        
        # Ensure log directory exists
        Path(self.log_file).parent.mkdir(parents=True, exist_ok=True)
        Path(self.json_log_file).parent.mkdir(parents=True, exist_ok=True)
        
        # Setup text logger
        self.logger = logging.getLogger("EDR_Logger")
        self.logger.setLevel(logging.INFO)

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )

        file_handler = logging.FileHandler(self.log_file)
        file_handler.setFormatter(formatter)

        # Avoid duplicate handlers
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)

    def handle_process_threat(self, process: Dict, reasons: List[str], severity: str = "WARNING"):
        """
        Handle suspicious process detection with severity-based actions.

        Args:
            process: Process dictionary
            reasons: List of detection reasons
            severity: Severity level (INFO, WARNING, CRITICAL)
        """
        pid = process.get("pid")
        name = process.get("name")
        cpu = process.get("cpu_percent", 0)
        memory = process.get("memory_percent", 0)
        timestamp = datetime.now().isoformat()
        reason_text = "; ".join(reasons)

        # Log full details
        alert_data = {
            "timestamp": timestamp,
            "alert_type": "process",
            "severity": severity,
            "pid": pid,
            "process_name": name,
            "cpu_percent": cpu,
            "memory_percent": memory,
            "reasons": reasons,
            "action_taken": None
        }

        # Console output with severity color coding
        severity_prefix = {
            "INFO": "[INFO]",
            "WARNING": "[WARNING]",
            "CRITICAL": "[CRITICAL]"
        }
        
        print(f"\n{severity_prefix.get(severity, '[ALERT]')} Suspicious process detected!")
        print(f"Severity: {severity}")
        print(f"PID     : {pid}")
        print(f"Process : {name}")
        print(f"CPU     : {cpu:.2f}%")
        print(f"Memory  : {memory:.2f}%")
        print(f"Reason  : {reason_text}")
        print(f"Time    : {timestamp}")

        # Text log
        self.logger.info(
            f"{severity} | PROCESS ALERT | PID={pid} | NAME={name} | "
            f"CPU={cpu:.2f}% | MEM={memory:.2f}% | REASON={reason_text}"
        )

        # Take action based on severity
        if severity == EDRConfig.SEVERITY_CRITICAL and EDRConfig.AUTO_TERMINATE:
            action_result = self._terminate_process(pid, name)
            alert_data["action_taken"] = action_result
            print(f"[ACTION] {action_result}")
        elif severity == EDRConfig.SEVERITY_WARNING:
            alert_data["action_taken"] = "Alert logged, no termination (WARNING level)"
            print("[ACTION] Alert logged, process not terminated (WARNING level)")
        else:
            alert_data["action_taken"] = "No action (INFO level)"

        # Write to JSON structured log
        self._write_json_log(alert_data)

    def _terminate_process(self, pid: int, name: str) -> str:
        """
        Safely terminate the suspicious process.
        Tries graceful termination first, then force kill if needed.
        
        Returns:
            str: Description of action taken
        """
        try:
            proc = psutil.Process(pid)
            
            # Try graceful termination first
            proc.terminate()
            
            try:
                # Wait for graceful termination
                proc.wait(timeout=EDRConfig.GRACEFUL_TIMEOUT)
                action = f"Process {name} (PID {pid}) terminated gracefully"
                self.logger.info(f"ACTION TAKEN | {action}")
                return action
                
            except psutil.TimeoutExpired:
                # Graceful termination failed, force kill
                proc.kill()
                proc.wait(timeout=2)
                action = f"Process {name} (PID {pid}) force killed (graceful termination failed)"
                self.logger.warning(f"ACTION TAKEN | {action}")
                return action

        except psutil.NoSuchProcess:
            action = f"Process PID {pid} already terminated"
            self.logger.warning(f"PROCESS NOT FOUND | PID={pid}")
            return action

        except psutil.AccessDenied:
            action = f"Access denied while terminating PID {pid} - requires elevated privileges"
            self.logger.error(f"ACCESS DENIED | PID={pid}")
            return action

        except Exception as e:
            action = f"Failed to terminate PID {pid}: {str(e)}"
            self.logger.error(f"TERMINATION FAILED | PID={pid} | ERROR={e}")
            return action

    def handle_file_threat(self, changes: List, trigger_file: str):
        """
        Handle ransomware-like file activity detection.
        """
        timestamp = datetime.now().isoformat()
        
        alert_data = {
            "timestamp": timestamp,
            "alert_type": "file_system",
            "severity": EDRConfig.SEVERITY_CRITICAL,
            "trigger_file": trigger_file,
            "total_events": len(changes),
            "event_details": [
                {
                    "time": change[0],
                    "file": change[1],
                    "event_type": change[2]
                }
                for change in changes[:10]  # Limit to first 10 events
            ],
            "action_taken": "Alert logged, manual investigation required"
        }
        
        print("\n[CRITICAL] Ransomware-like file activity detected!")
        print(f"Trigger file: {trigger_file}")
        print(f"Total file events: {len(changes)}")
        print(f"Time: {timestamp}")

        self.logger.warning(
            f"CRITICAL | FILE ALERT | Trigger={trigger_file} | Events={len(changes)}"
        )
        
        # Write to JSON structured log
        self._write_json_log(alert_data)

    def _write_json_log(self, alert_data: Dict):
        """
        Write alert data to JSON structured log file.
        Each alert is appended as a new JSON object on a new line.
        """
        try:
            with open(self.json_log_file, 'a') as f:
                json.dump(alert_data, f)
                f.write('\n')
        except Exception as e:
            self.logger.error(f"Failed to write JSON log: {e}")
    
    def get_recent_alerts(self, count: int = 20) -> List[Dict]:
        """
        Read recent alerts from JSON log file.
        
        Args:
            count: Number of recent alerts to retrieve
            
        Returns:
            List of alert dictionaries
        """
        alerts = []
        try:
            if os.path.exists(self.json_log_file):
                with open(self.json_log_file, 'r') as f:
                    lines = f.readlines()
                    # Get last N lines
                    for line in lines[-count:]:
                        try:
                            alerts.append(json.loads(line.strip()))
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            self.logger.error(f"Failed to read JSON log: {e}")
        
        return alerts
