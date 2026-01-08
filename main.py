"""
Main Controller
Integrates Scanner, Analyzer, File Monitor, and Responder
to form a Lightweight EDR system.
"""

import time
import signal
import sys

from scanner.process_scanner import ProcessScanner
from analyzer.behavior_analyzer import BehaviorAnalyzer
from response.responder import Responder
from monitor.file_monitor import FileMonitor


def ransomware_alert_handler(changes, trigger_file):
    """
    Callback function for file monitor alerts.
    """
    responder.handle_file_threat(changes, trigger_file)


def graceful_exit(sig, frame):
    """
    Handle CTRL+C clean shutdown.
    """
    print("\n[INFO] Shutting down Lightweight EDR...")
    if file_monitor.is_running():
        file_monitor.stop()
    sys.exit(0)


if __name__ == "__main__":
    print("\n=== Lightweight EDR Started ===\n")

    # -------------------------------
    # Initialize modules
    # -------------------------------
    scanner = ProcessScanner(scan_interval=1.0)
    analyzer = BehaviorAnalyzer()
    responder = Responder(log_file="logs/edr.log")

    # -------------------------------
    # File Activity Monitor
    # -------------------------------
    file_monitor = FileMonitor(
        monitor_path="monitored",
        file_change_threshold=10,
        time_window=5.0
    )
    file_monitor.set_alert_callback(ransomware_alert_handler)
    file_monitor.start()

    # Handle CTRL+C safely
    signal.signal(signal.SIGINT, graceful_exit)

    # -------------------------------
    # Main EDR Loop
    # -------------------------------
    try:
        while True:
            processes = scanner.scan_processes()

            for process in processes:
                history = scanner.get_process_history(process["pid"])
                analysis = analyzer.analyze(process, history)

                if analysis["suspicious"]:
                    responder.handle_process_threat(
                        process,
                        analysis["reasons"]
                    )

    except Exception as e:
        print(f"[ERROR] EDR encountered an error: {e}")
        graceful_exit(None, None)
