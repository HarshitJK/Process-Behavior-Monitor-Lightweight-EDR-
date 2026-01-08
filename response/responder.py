"""
Response Module
Handles alerts, terminates suspicious processes, and logs incidents.
"""

import psutil
import logging
from datetime import datetime
from typing import Dict, List


class Responder:
    """
    Handles response actions for detected threats.
    """

    def __init__(self, log_file: str = "logs/edr.log"):
        """
        Initialize responder and logging.

        Args:
            log_file: Path to log file
        """
        self.logger = logging.getLogger("EDR_Logger")
        self.logger.setLevel(logging.INFO)

        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(message)s"
        )

        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)

        # Avoid duplicate handlers
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)

    def handle_process_threat(self, process: Dict, reasons: List[str]):
        """
        Handle suspicious process detection.

        Args:
            process: Process dictionary
            reasons: List of detection reasons
        """
        pid = process.get("pid")
        name = process.get("name")
        reason_text = "; ".join(reasons)

        print("\n[ALERT] Suspicious process detected!")
        print(f"PID     : {pid}")
        print(f"Process : {name}")
        print(f"Reason  : {reason_text}")

        self.logger.info(
            f"PROCESS ALERT | PID={pid} | NAME={name} | REASON={reason_text}"
        )

        self._terminate_process(pid, name)

    def _terminate_process(self, pid: int, name: str):
        """
        Terminate the suspicious process.
        """
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            proc.wait(timeout=3)

            print(f"[ACTION] Process {name} (PID {pid}) terminated.")
            self.logger.info(
                f"ACTION TAKEN | Process {name} (PID {pid}) terminated"
            )

        except psutil.NoSuchProcess:
            print(f"[INFO] Process PID {pid} already terminated.")
            self.logger.warning(
                f"PROCESS NOT FOUND | PID={pid}"
            )

        except psutil.AccessDenied:
            print(f"[ERROR] Access denied while terminating PID {pid}.")
            self.logger.error(
                f"ACCESS DENIED | PID={pid}"
            )

        except Exception as e:
            print(f"[ERROR] Failed to terminate PID {pid}: {e}")
            self.logger.error(
                f"TERMINATION FAILED | PID={pid} | ERROR={e}"
            )

    def handle_file_threat(self, changes: List, trigger_file: str):
        """
        Handle ransomware-like file activity detection.
        """
        print("\n[ALERT] Ransomware-like file activity detected!")
        print(f"Trigger file: {trigger_file}")
        print(f"Total file events: {len(changes)}")

        self.logger.warning(
            f"FILE ALERT | Trigger={trigger_file} | Events={len(changes)}"
        )
