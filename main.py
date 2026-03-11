"""
Main Controller – Lightweight EDR

Architecture (Issue 2 fix):
  CLI mode:  monitoring loop runs in the MAIN thread.
  GUI mode:  monitoring loop runs in a BACKGROUND thread;
             Tkinter mainloop() runs in the MAIN thread.

Pipeline per scan cycle:
  ProcessScanner → BehaviorAnalyzer → Responder → Dashboard update
  FileMonitor runs concurrently in a Watchdog observer thread.

Usage:
  python main.py                 # terminal dashboard
  python main.py --gui           # Tkinter GUI (mainloop in main thread)
  python main.py --no-terminate  # alert-only (safe demo)
  python main.py --debug         # verbose per-rule output
"""

import os
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

    def __init__(self, use_gui: bool = False, debug: bool = False):
        self.use_gui = use_gui
        self.running = False
        EDRConfig.DEBUG_MODE = debug
        # Tell config (and responder) we are in GUI mode so extra safety
        # guards are applied (no auto-suspend in GUI mode).
        EDRConfig.GUI_MODE = use_gui
        # Record this process's PID so scanner/analyzer can self-exclude.
        EDRConfig.EDR_OWN_PID = os.getpid()

        # Core modules
        self.scanner  = ProcessScanner(scan_interval=EDRConfig.SCAN_INTERVAL)
        self.analyzer = BehaviorAnalyzer()
        self.responder = Responder(
            log_file=EDRConfig.LOG_FILE,
            json_log_file=EDRConfig.JSON_LOG_FILE,
        )

        # File monitor
        self.file_monitor = FileMonitor(
            monitor_path=EDRConfig.MONITOR_DIRECTORY,
            file_change_threshold=EDRConfig.FILE_EVENT_THRESHOLD,
            time_window=EDRConfig.TIME_WINDOW,
        )
        self.file_monitor.set_alert_callback(self._on_file_alert)

        # Dashboard – only one is ever active:
        #   CLI mode → TerminalDashboard (prints to stdout)
        #   GUI mode → EDRDashboard (Tkinter, main thread)
        # NEVER create TerminalDashboard in GUI mode – it causes the freeze.
        self.terminal_dash = None   # set below only in CLI mode
        self.gui_dash = None        # set below only in GUI mode

        if not use_gui:
            self.terminal_dash = TerminalDashboard(
                responder=self.responder,
                file_monitor=self.file_monitor,
            )

        # Counters
        self._scan_count:      int = 0
        self._suspicious_count: int = 0

        # Signal handlers
        signal.signal(signal.SIGINT, self._graceful_exit)
        if sys.platform != "win32":
            signal.signal(signal.SIGTERM, self._graceful_exit)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _on_file_alert(self, changes: list, trigger_file: str, summary: dict):
        """Called from Watchdog thread – forward to responder and dashboards."""
        try:
            self.responder.handle_file_threat(changes, trigger_file, summary)
            alert_msg = (
                f"Ransomware pattern: {len(changes)} file events "
                f"({', '.join(f'{t}:{c}' for t, c in summary.items())})"
            )
            # Only forward to the active dashboard
            if self.terminal_dash:
                self.terminal_dash.add_alert("CRITICAL", alert_msg)
            if self.gui_dash:
                self.gui_dash.add_alert("CRITICAL", alert_msg)
                self.gui_dash.add_log("CRITICAL", alert_msg)
        except Exception as exc:
            print(f"[ERROR] File alert handler: {exc}")

    def _graceful_exit(self, sig, frame):
        print("\n\n[INFO] Shutting down Lightweight EDR …")
        self.stop()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self):
        self._print_banner()

        # Start file monitor (Watchdog observer thread)
        try:
            self.file_monitor.start()
        except Exception as exc:
            print(f"[WARNING] File monitor failed to start: {exc}")

        self.running = True

        if self.use_gui:
            # GUI mode:
            #   • terminal dashboard is NOT started (avoids the freeze)
            #   • monitoring runs in a background daemon thread
            #   • Tkinter mainloop() runs in the main thread
            monitor_thread = threading.Thread(
                target=self._monitoring_loop, daemon=True, name="EDR-Monitor"
            )
            monitor_thread.start()
            self._run_gui()   # blocks until window is closed
        else:
            # CLI mode:
            #   • terminal dashboard prints every TERMINAL_DASHBOARD_INTERVAL s
            #   • monitoring runs in the main thread
            self.terminal_dash.start_background_refresh()
            self._monitoring_loop()

    def stop(self):
        self.running = False
        if self.terminal_dash:
            self.terminal_dash.monitoring = False

        try:
            if self.file_monitor.is_running():
                self.file_monitor.stop()
        except Exception:
            pass

        if self.gui_dash:
            self.gui_dash.monitoring = False

        print(f"\n[INFO] EDR stopped. Scans: {self._scan_count} | "
              f"Suspicious: {self._suspicious_count}")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _print_banner(self):
        print("\n" + "═" * 62)
        print("  🛡  Lightweight EDR  –  Process Behavior Monitor")
        print("═" * 62)
        print(f"  CPU Warning         : {EDRConfig.CPU_THRESHOLD}%")
        print(f"  CPU Critical        : {EDRConfig.CPU_CRITICAL_THRESHOLD}%")
        print(f"  Memory Warning      : {EDRConfig.MEMORY_WARNING_THRESHOLD}%")
        print(f"  Memory Critical     : {EDRConfig.MEMORY_CRITICAL_THRESHOLD}%")
        print(f"  Consecutive Checks  : {EDRConfig.CPU_CONSECUTIVE_CHECKS}")
        print(f"  Alert Cooldown      : {EDRConfig.ALERT_COOLDOWN_SECONDS}s")
        print(f"  Auto-Terminate      : {EDRConfig.AUTO_TERMINATE}")
        print(f"  Monitor Directory   : {EDRConfig.MONITOR_DIRECTORY}")
        print(f"  File Alert Threshold: {EDRConfig.FILE_EVENT_THRESHOLD} events/{EDRConfig.TIME_WINDOW}s")
        print(f"  Scan Interval       : {EDRConfig.SCAN_INTERVAL}s")
        print("═" * 62 + "\n")

    def _run_gui(self):
        """Create and run the Tkinter GUI in the main thread (Issue 2 fix)."""
        try:
            from gui.dashboard import EDRDashboard
            self.gui_dash = EDRDashboard(
                responder=self.responder,
                file_monitor=self.file_monitor,
            )
            root = self.gui_dash.create_gui()
            if root is None:
                print("[WARNING] GUI creation failed – falling back to CLI.\n")
                self._monitoring_loop()
                return
            self.gui_dash.add_log("INFO", "EDR Dashboard initialized")
            self.gui_dash.add_log("INFO", "Click 'Start Monitoring' to begin")
            self.gui_dash.run()   # ← blocks in main thread (Tk mainloop)
        except Exception as exc:
            print(f"[WARNING] GUI error: {exc} – falling back to CLI.\n")
            self._monitoring_loop()

    def _monitoring_loop(self):
        """
        Core scan loop.
        Issue 4 fix: actually counts and prints processes.
        Issue 9 fix: wrapped in try/except per iteration.
        """
        print("[INFO] Monitoring started. Press Ctrl+C to stop.\n")

        try:
            while self.running:
                # Respect GUI pause toggle
                if self.gui_dash and not self.gui_dash.monitoring:
                    time.sleep(0.5)
                    continue

                try:
                    # ---- Scan ------------------------------------------
                    processes          = self.scanner.scan_processes()
                    # Per-parent spawn counts (fix for false-positive spawning alerts)
                    parent_spawn_counts = self.scanner.get_parent_spawn_counts(
                        EDRConfig.SPAWN_TIME_WINDOW
                    )
                    self._scan_count    += 1
                    suspicious_in_scan   = 0

                    # ---- Analyze ----------------------------------------
                    for proc in processes:
                        try:
                            history  = self.scanner.get_process_history(proc["pid"])
                            analysis = self.analyzer.analyze(
                                proc, history,
                                parent_spawn_counts=parent_spawn_counts
                            )

                            if not analysis["suspicious"]:
                                continue

                            suspicious_in_scan  += 1
                            self._suspicious_count += 1
                            severity    = analysis["severity"]
                            reasons     = analysis["reasons"]
                            threat_type = analysis.get("threat_type", "UNKNOWN")

                            # ---- Respond --------------------------------
                            self.responder.handle_process_threat(
                                proc, reasons, severity, threat_type
                            )

                            # ---- Dashboard update -----------------------
                            alert_msg = (
                                f"[{threat_type}] PID {proc['pid']} "
                                f"({proc['name']}): {reasons[0]}"
                            )
                            if self.terminal_dash:
                                self.terminal_dash.add_alert(severity, alert_msg)

                            if self.gui_dash:
                                self.gui_dash.add_alert(severity, alert_msg)
                                self.gui_dash.add_log(severity, alert_msg)

                        except Exception as exc:
                            if EDRConfig.DEBUG_MODE:
                                print(f"[DEBUG] Process analysis error: {exc}")

                    # ---- Dashboard stats --------------------------------
                    total = self.scanner.get_total_process_count()
                    # Set (not accumulate) the current process count
                    if self.terminal_dash:
                        self.terminal_dash.set_scanned(len(processes))
                        self.terminal_dash.increment_suspicious(suspicious_in_scan)

                    if self.gui_dash:
                        self.gui_dash.update_counts(total, self._suspicious_count)

                    time.sleep(EDRConfig.SCAN_INTERVAL)

                except Exception as exc:
                    print(f"[ERROR] Scan iteration error: {exc}")
                    if EDRConfig.DEBUG_MODE:
                        import traceback
                        traceback.print_exc()
                    time.sleep(EDRConfig.SCAN_INTERVAL)

        except KeyboardInterrupt:
            pass
        finally:
            self.stop()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Lightweight EDR – Process Behavior Monitoring System"
    )
    parser.add_argument("--gui",          action="store_true",
                        help="Launch Tkinter GUI (runs in main thread)")
    parser.add_argument("--no-terminate", action="store_true",
                        help="Alert-only mode – no process termination")
    parser.add_argument("--debug",        action="store_true",
                        help="Verbose per-rule detection output")
    args = parser.parse_args()

    if args.no_terminate:
        EDRConfig.AUTO_TERMINATE = False
        print("[INFO] Auto-termination DISABLED")

    edr = LightweightEDR(use_gui=args.gui, debug=args.debug)
    edr.start()


if __name__ == "__main__":
    main()
