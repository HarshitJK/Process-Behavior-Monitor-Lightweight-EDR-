"""
Main Controller – Lightweight EDR
Integrates: ProcessScanner → BehaviorAnalyzer → Responder → FileMonitor → Dashboard

Architecture:
  1. ProcessScanner  – enumerate running processes every SCAN_INTERVAL seconds
  2. BehaviorAnalyzer – apply rule-based detection to each process
  3. Responder       – alert / terminate / suspend based on severity
  4. FileMonitor     – watchdog-based ransomware pattern detection
  5. Dashboard       – terminal (always) or Tkinter GUI (--gui flag)

Usage:
  python main.py                 # terminal dashboard, auto-terminate on CRITICAL
  python main.py --gui           # Tkinter GUI dashboard
  python main.py --no-terminate  # alert-only mode (no process killing)
  python main.py --debug         # verbose detection output
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
from gui.dashboard import TerminalDashboard
from config import EDRConfig


class LightweightEDR:
    """
    Main EDR controller.

    Pipeline per scan cycle:
        scan_processes()
            → for each process: analyze()
                → if suspicious: handle_process_threat()  (Responder)
                                 add_alert()              (Dashboard)
        file_monitor runs concurrently in a Watchdog thread
    """

    def __init__(self, use_gui: bool = False, debug: bool = False):
        self.use_gui = use_gui
        self.running = False
        EDRConfig.DEBUG_MODE = debug

        # ---- Core modules ------------------------------------------------
        self.scanner = ProcessScanner(scan_interval=EDRConfig.SCAN_INTERVAL)
        self.analyzer = BehaviorAnalyzer()
        self.responder = Responder(
            log_file=EDRConfig.LOG_FILE,
            json_log_file=EDRConfig.JSON_LOG_FILE,
        )

        # ---- File monitor ------------------------------------------------
        self.file_monitor = FileMonitor(
            monitor_path=EDRConfig.MONITOR_DIRECTORY,
            file_change_threshold=EDRConfig.FILE_EVENT_THRESHOLD,
            time_window=EDRConfig.TIME_WINDOW,
        )
        self.file_monitor.set_alert_callback(self._on_file_alert)

        # ---- Dashboard ---------------------------------------------------
        self.terminal_dash = TerminalDashboard(
            responder=self.responder,
            file_monitor=self.file_monitor,
        )
        self.gui_dash = None       # populated only with --gui
        self.gui_thread = None

        # ---- Statistics --------------------------------------------------
        self._scan_count: int = 0
        self._suspicious_count: int = 0

        # ---- Signal handler for clean CTRL+C ----------------------------
        signal.signal(signal.SIGINT, self._graceful_exit)
        if sys.platform != "win32":
            signal.signal(signal.SIGTERM, self._graceful_exit)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _on_file_alert(self, changes: list, trigger_file: str, summary: dict):
        """Called by FileMonitor when ransomware-like activity is detected."""
        self.responder.handle_file_threat(changes, trigger_file, summary)

        alert_msg = (
            f"Ransomware pattern: {len(changes)} file events "
            f"({', '.join(f'{t}:{c}' for t, c in summary.items())})"
        )
        self.terminal_dash.add_alert("CRITICAL", alert_msg)
        if self.gui_dash:
            self.gui_dash.add_alert("CRITICAL", alert_msg)

    def _graceful_exit(self, sig, frame):
        """Handle CTRL+C / SIGTERM."""
        print("\n\n[INFO] Shutting down Lightweight EDR …")
        self.stop()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Public lifecycle
    # ------------------------------------------------------------------

    def start(self):
        """Print banner, start subsystems, enter monitoring loop."""
        self._print_banner()

        # Start file monitor in its own thread
        self.file_monitor.start()

        # Start optional GUI dashboard
        if self.use_gui:
            self._start_gui()

        # Start terminal dashboard background refresh
        self.terminal_dash.start_background_refresh()

        self.running = True
        self._monitoring_loop()

    def stop(self):
        """Stop all subsystems cleanly."""
        self.running = False
        self.terminal_dash.monitoring = False

        if self.file_monitor.is_running():
            self.file_monitor.stop()

        if self.gui_dash:
            self.gui_dash.monitoring = False

        print("[INFO] EDR system stopped.")
        print(f"[INFO] Total scans: {self._scan_count}")
        print(f"[INFO] Total suspicious events: {self._suspicious_count}")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _print_banner(self):
        print("\n" + "═" * 62)
        print("  🛡  Lightweight EDR  –  Process Behavior Monitor")
        print("═" * 62)
        print(f"  CPU Threshold       : {EDRConfig.CPU_THRESHOLD}%")
        print(f"  Memory Warning      : {EDRConfig.MEMORY_WARNING_THRESHOLD}%")
        print(f"  Memory Critical     : {EDRConfig.MEMORY_CRITICAL_THRESHOLD}%")
        print(f"  Consecutive Checks  : {EDRConfig.CPU_CONSECUTIVE_CHECKS}")
        print(f"  Alert Cooldown      : {EDRConfig.ALERT_COOLDOWN_SECONDS}s")
        print(f"  Auto-Terminate      : {EDRConfig.AUTO_TERMINATE}")
        print(f"  Monitor Directory   : {EDRConfig.MONITOR_DIRECTORY}")
        print(f"  File Alert Threshold: {EDRConfig.FILE_EVENT_THRESHOLD} events / "
              f"{EDRConfig.TIME_WINDOW}s")
        print(f"  Scan Interval       : {EDRConfig.SCAN_INTERVAL}s")
        print(f"  Debug Mode          : {EDRConfig.DEBUG_MODE}")
        print("═" * 62 + "\n")

    def _start_gui(self):
        """Launch the Tkinter dashboard in a dedicated thread."""
        try:
            from gui.dashboard import EDRDashboard
            self.gui_dash = EDRDashboard(
                responder=self.responder,
                file_monitor=self.file_monitor,
            )

            def _gui_main():
                root = self.gui_dash.create_gui()
                if root:
                    self.gui_dash.add_log("INFO", "EDR Dashboard initialized")
                    self.gui_dash.add_log("INFO", "Click 'Start Monitoring' to begin")
                    self.gui_dash.run()

            self.gui_thread = threading.Thread(target=_gui_main, daemon=True)
            self.gui_thread.start()
            print("[INFO] GUI Dashboard launched in background thread\n")
            time.sleep(1)           # Give GUI time to initialize
        except Exception as exc:
            print(f"[WARNING] Could not launch GUI: {exc}")
            print("[INFO] Falling back to terminal dashboard.\n")
            self.gui_dash = None

    def _monitoring_loop(self):
        """
        Main EDR loop:
          scan → analyze → respond → log → update dashboard
        Runs until self.running is False.
        """
        print("[INFO] Monitoring started. Press CTRL+C to stop.\n")

        try:
            while self.running:
                # Respect GUI pause-state if GUI is active
                if self.gui_dash and not self.gui_dash.monitoring:
                    time.sleep(0.5)
                    continue

                # ---- Scan --------------------------------------------------
                processes = self.scanner.scan_processes()
                spawn_count = self.scanner.get_recent_spawn_count(
                    EDRConfig.SPAWN_TIME_WINDOW
                )
                self._scan_count += 1
                suspicious_in_scan = 0

                # ---- Analyze each process ---------------------------------
                for proc in processes:
                    history = self.scanner.get_process_history(proc["pid"])
                    analysis = self.analyzer.analyze(proc, history, spawn_count)

                    if not analysis["suspicious"]:
                        continue

                    suspicious_in_scan += 1
                    self._suspicious_count += 1
                    severity = analysis["severity"]
                    reasons = analysis["reasons"]
                    threat_type = analysis.get("threat_type", "UNKNOWN")

                    # ---- Respond ------------------------------------------
                    self.responder.handle_process_threat(
                        proc, reasons, severity, threat_type
                    )

                    # ---- Update dashboards --------------------------------
                    alert_msg = (
                        f"[{threat_type}] PID {proc['pid']} "
                        f"({proc['name']}): {', '.join(reasons)}"
                    )
                    self.terminal_dash.add_alert(severity, alert_msg)

                    if self.gui_dash:
                        self.gui_dash.add_alert(severity, alert_msg)
                        self.gui_dash.add_log(severity, alert_msg)

                # ---- Update dashboard stats --------------------------------
                total = self.scanner.get_total_process_count()
                self.terminal_dash.increment_scanned(len(processes))
                self.terminal_dash.increment_suspicious(suspicious_in_scan)

                if self.gui_dash:
                    self.gui_dash.update_counts(total, self._suspicious_count)

        except KeyboardInterrupt:
            pass
        except Exception as exc:
            print(f"\n[ERROR] EDR encountered an unexpected error: {exc}")
            if EDRConfig.DEBUG_MODE:
                import traceback
                traceback.print_exc()
            self._graceful_exit(None, None)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Lightweight EDR – Process Behavior Monitoring System"
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch with Tkinter GUI dashboard",
    )
    parser.add_argument(
        "--no-terminate",
        action="store_true",
        help="Disable automatic process termination (alert-only mode)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug output",
    )
    args = parser.parse_args()

    if args.no_terminate:
        EDRConfig.AUTO_TERMINATE = False
        print("[INFO] Auto-termination DISABLED – running in alert-only mode")

    edr = LightweightEDR(use_gui=args.gui, debug=args.debug)
    edr.start()


if __name__ == "__main__":
    main()
