"""
Main Controller
Integrates Scanner, Analyzer, File Monitor, Responder, and GUI Dashboard
to form an enhanced Lightweight EDR system.
"""

import time
import signal
import sys
import threading
import argparse

from scanner.process_scanner import ProcessScanner
from analyzer.behavior_analyzer import BehaviorAnalyzer
from response.responder import Responder
from monitor.file_monitor import FileMonitor
from gui.dashboard import EDRDashboard
from config import EDRConfig


class LightweightEDR:
    """
    Main EDR controller class.
    """
    
    def __init__(self, use_gui=False):
        """
        Initialize the EDR system.
        
        Args:
            use_gui: Whether to launch the GUI dashboard
        """
        self.use_gui = use_gui
        self.running = False
        self.dashboard = None
        self.gui_thread = None
        
        # Initialize modules
        self.scanner = ProcessScanner(scan_interval=EDRConfig.SCAN_INTERVAL)
        self.analyzer = BehaviorAnalyzer()
        self.responder = Responder(
            log_file=EDRConfig.LOG_FILE,
            json_log_file=EDRConfig.JSON_LOG_FILE
        )
        
        # File Activity Monitor
        self.file_monitor = FileMonitor(
            monitor_path=EDRConfig.MONITOR_DIRECTORY,
            file_change_threshold=EDRConfig.FILE_CHANGE_THRESHOLD,
            time_window=EDRConfig.FILE_TIME_WINDOW
        )
        self.file_monitor.set_alert_callback(self._ransomware_alert_handler)
        
        # Setup signal handler
        signal.signal(signal.SIGINT, self._graceful_exit)
    
    def _ransomware_alert_handler(self, changes, trigger_file):
        """
        Callback function for file monitor alerts.
        """
        self.responder.handle_file_threat(changes, trigger_file)
        
        # Update GUI if running
        if self.dashboard:
            self.dashboard.add_alert(
                "CRITICAL",
                f"Ransomware-like activity: {len(changes)} file changes detected"
            )
    
    def _graceful_exit(self, sig, frame):
        """
        Handle CTRL+C clean shutdown.
        """
        print("\n[INFO] Shutting down Lightweight EDR...")
        self.stop()
        sys.exit(0)
    
    def start(self):
        """
        Start the EDR monitoring system.
        """
        print("\n=== Lightweight EDR Started ===\n")
        print(f"Configuration:")
        print(f"  CPU Threshold: {EDRConfig.CPU_THRESHOLD}%")
        print(f"  Memory Threshold: {EDRConfig.MEMORY_THRESHOLD}%")
        print(f"  Consecutive Checks Required: {EDRConfig.CPU_CONSECUTIVE_CHECKS}")
        print(f"  Alert Cooldown: {EDRConfig.ALERT_COOLDOWN_SECONDS}s")
        print(f"  Auto-Terminate: {EDRConfig.AUTO_TERMINATE}")
        print(f"  Monitoring Directory: {EDRConfig.MONITOR_DIRECTORY}")
        print()
        
        # Start file monitor
        self.file_monitor.start()
        
        # Start GUI if requested
        if self.use_gui:
            self._start_gui()
        
        self.running = True
        
        # Main monitoring loop
        self._monitoring_loop()
    
    def _start_gui(self):
        """
        Start the GUI dashboard in a separate thread.
        """
        self.dashboard = EDRDashboard(responder=self.responder)
        
        def gui_thread_func():
            root = self.dashboard.create_gui()
            self.dashboard.add_log("INFO", "EDR Dashboard initialized")
            self.dashboard.add_log("INFO", "Click 'Start Monitoring' to begin")
            self.dashboard.run()
        
        self.gui_thread = threading.Thread(target=gui_thread_func, daemon=True)
        self.gui_thread.start()
        
        print("[INFO] GUI Dashboard launched in separate thread")
        time.sleep(1)  # Give GUI time to initialize
    
    def _monitoring_loop(self):
        """
        Main EDR monitoring loop.
        """
        try:
            while self.running:
                # Check if GUI is controlling monitoring state
                if self.dashboard and not self.dashboard.monitoring:
                    time.sleep(0.5)
                    continue
                
                processes = self.scanner.scan_processes()

                for process in processes:
                    history = self.scanner.get_process_history(process["pid"])
                    analysis = self.analyzer.analyze(process, history)

                    if analysis["suspicious"]:
                        severity = analysis.get("severity", "WARNING")
                        reasons = analysis["reasons"]
                        
                        # Handle the threat
                        self.responder.handle_process_threat(
                            process,
                            reasons,
                            severity
                        )
                        
                        # Update GUI if running
                        if self.dashboard:
                            alert_msg = (
                                f"PID {process['pid']} ({process['name']}): "
                                f"{', '.join(reasons)}"
                            )
                            self.dashboard.add_alert(severity, alert_msg)
                            self.dashboard.add_log(
                                severity,
                                f"Process alert: {alert_msg}"
                            )

        except Exception as e:
            print(f"[ERROR] EDR encountered an error: {e}")
            if self.dashboard:
                self.dashboard.add_log("ERROR", f"System error: {e}")
            self._graceful_exit(None, None)
    
    def stop(self):
        """
        Stop the EDR system.
        """
        self.running = False
        if self.file_monitor.is_running():
            self.file_monitor.stop()
        print("[INFO] EDR system stopped")


def main():
    """
    Main entry point with command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Lightweight EDR - Process Behavior Monitoring System"
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch with GUI dashboard"
    )
    parser.add_argument(
        "--no-terminate",
        action="store_true",
        help="Disable automatic process termination (alert only)"
    )
    
    args = parser.parse_args()
    
    # Override config if specified
    if args.no_terminate:
        EDRConfig.AUTO_TERMINATE = False
        print("[INFO] Auto-termination disabled - alert-only mode")
    
    # Create and start EDR
    edr = LightweightEDR(use_gui=args.gui)
    edr.start()


if __name__ == "__main__":
    main()
