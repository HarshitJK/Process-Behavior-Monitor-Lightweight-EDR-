"""
Dashboard Module
Two modes:
  1. Tkinter GUI  (python main.py --gui)
  2. Terminal dashboard printed to stdout (default)

The terminal dashboard renders a live summary box every
EDRConfig.TERMINAL_DASHBOARD_INTERVAL seconds without requiring Tkinter.
"""

import os
import sys
import time
import threading
import psutil
from datetime import datetime
from typing import List, Dict, Optional
from config import EDRConfig


# ============================================================
# Terminal Dashboard (no Tkinter dependency)
# ============================================================

class TerminalDashboard:
    """
    Lightweight terminal-based dashboard.
    Prints a formatted status box at a configurable interval.
    Does NOT require Tkinter.
    """

    def __init__(self, responder=None, file_monitor=None):
        self.responder = responder
        self.file_monitor = file_monitor
        self.monitoring = True

        self._alert_history: List[Dict] = []
        self._lock = threading.Lock()
        self._total_processes_scanned: int = 0
        self._total_suspicious: int = 0
        self._start_time: float = time.time()

    # ------------------------------------------------------------------
    def start_background_refresh(self):
        """Spawn a daemon thread that redraws the dashboard periodically."""
        t = threading.Thread(target=self._refresh_loop, daemon=True)
        t.start()

    def _refresh_loop(self):
        while self.monitoring:
            self._render()
            time.sleep(EDRConfig.TERMINAL_DASHBOARD_INTERVAL)

    def _render(self):
        """Print the dashboard box to stdout."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        uptime_s = int(time.time() - self._start_time)
        hours, rem = divmod(uptime_s, 3600)
        mins, secs = divmod(rem, 60)

        responder_stats = self.responder.get_stats() if self.responder else {}
        file_stats = self.file_monitor.get_stats() if self.file_monitor else {}

        total_alerts = responder_stats.get("total_alerts", 0)
        terminated = responder_stats.get("total_terminated", 0)
        file_alerts = file_stats.get("total_alerts", 0)

        # System CPU / RAM
        sys_cpu = psutil.cpu_percent(interval=None)
        sys_mem = psutil.virtual_memory().percent

        status = "\033[92mACTIVE\033[0m" if self.monitoring else "\033[91mSTOPPED\033[0m"

        width = 58
        border = "═" * width

        lines = [
            f"\033[96m╔{border}╗\033[0m",
            f"\033[96m║\033[0m {'Lightweight EDR  –  Live Dashboard':^{width}s} \033[96m║\033[0m",
            f"\033[96m╠{border}╣\033[0m",
            f"\033[96m║\033[0m  {'Timestamp:':<22} {now:<33} \033[96m║\033[0m",
            f"\033[96m║\033[0m  {'Uptime:':<22} {hours:02d}h {mins:02d}m {secs:02d}s{'':<22} \033[96m║\033[0m",
            f"\033[96m║\033[0m  {'System Status:':<22} {status:<33} \033[96m║\033[0m",
            f"\033[96m╠{border}╣\033[0m",
            f"\033[96m║\033[0m  {'System CPU:':<22} {sys_cpu:>5.1f}%{'':<29} \033[96m║\033[0m",
            f"\033[96m║\033[0m  {'System Memory:':<22} {sys_mem:>5.1f}%{'':<29} \033[96m║\033[0m",
            f"\033[96m╠{border}╣\033[0m",
            f"\033[96m║\033[0m  {'Processes Monitored:':<30} {self._total_processes_scanned:>5}{'':<19} \033[96m║\033[0m",
            f"\033[96m║\033[0m  {'Suspicious Processes:':<30} {self._total_suspicious:>5}{'':<19} \033[96m║\033[0m",
            f"\033[96m║\033[0m  {'Total Alerts Raised:':<30} {total_alerts:>5}{'':<19} \033[96m║\033[0m",
            f"\033[96m║\033[0m  {'Processes Terminated:':<30} {terminated:>5}{'':<19} \033[96m║\033[0m",
            f"\033[96m║\033[0m  {'File System Alerts:':<30} {file_alerts:>5}{'':<19} \033[96m║\033[0m",
            f"\033[96m╠{border}╣\033[0m",
        ]

        # Recent alerts
        with self._lock:
            recent = list(self._alert_history[-5:])

        if recent:
            lines.append(f"\033[96m║\033[0m  {'Recent Alerts':<{width}} \033[96m║\033[0m")
            for a in recent:
                sev = a.get("severity", "INFO")
                colour = "\033[91m" if sev == "CRITICAL" else "\033[93m" if sev == "WARNING" else "\033[94m"
                msg = a.get("message", "")[:45]
                lines.append(
                    f"\033[96m║\033[0m  {colour}[{sev:<8}]\033[0m {msg:<{width - 13}} \033[96m║\033[0m"
                )
        else:
            lines.append(f"\033[96m║\033[0m  {'No alerts yet':<{width}} \033[96m║\033[0m")

        lines.append(f"\033[96m╚{border}╝\033[0m")

        # Clear the last N lines and reprint (simple approach)
        output = "\n".join(lines)
        print(f"\n{output}")

    # ------------------------------------------------------------------
    def add_alert(self, severity: str, message: str):
        with self._lock:
            self._alert_history.append({
                "severity": severity,
                "message": message,
                "time": datetime.now().strftime("%H:%M:%S"),
            })
            if len(self._alert_history) > 100:
                self._alert_history.pop(0)

    def increment_scanned(self, count: int):
        self._total_processes_scanned += count

    def increment_suspicious(self, count: int = 1):
        self._total_suspicious += count


# ============================================================
# Tkinter GUI Dashboard (optional)
# ============================================================

class EDRDashboard:
    """
    Tkinter-based GUI dashboard.
    Launched only when --gui flag is passed.
    Falls back gracefully if Tkinter is not available.
    """

    def __init__(self, responder=None, file_monitor=None):
        self.responder = responder
        self.file_monitor = file_monitor
        self.monitoring = False
        self.root = None

        self.alerts: List[str] = []
        self.max_alerts = EDRConfig.GUI_MAX_ALERTS

        self._total_processes = 0
        self._total_suspicious = 0

    # ------------------------------------------------------------------

    def create_gui(self):
        """Build and return the Tk root window."""
        try:
            import tkinter as tk
            from tkinter import ttk, scrolledtext
        except ImportError:
            print("[ERROR] Tkinter is not available. Run without --gui flag.")
            return None

        self.root = tk.Tk()
        self.root.title("Lightweight EDR – Security Dashboard")
        self.root.geometry("1280x820")
        self.root.configure(bg="#1a1a2e")

        # -------- Fonts & styles ------------------------------------------
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                        background="#16213e", foreground="#e0e0e0",
                        fieldbackground="#16213e", rowheight=22)
        style.configure("Treeview.Heading",
                        background="#0f3460", foreground="#00d4ff",
                        font=("Consolas", 10, "bold"))
        style.map("Treeview", background=[("selected", "#533483")])

        # -------- Title bar -----------------------------------------------
        title_bar = tk.Frame(self.root, bg="#0f3460", pady=8)
        title_bar.pack(fill=tk.X)

        tk.Label(
            title_bar,
            text="🛡  Lightweight EDR  –  Process Behavior Monitor",
            font=("Consolas", 16, "bold"),
            bg="#0f3460", fg="#00d4ff",
        ).pack(side=tk.LEFT, padx=20)

        self.clock_label = tk.Label(
            title_bar, text="", font=("Consolas", 11),
            bg="#0f3460", fg="#a0c4ff"
        )
        self.clock_label.pack(side=tk.RIGHT, padx=20)

        # -------- Stats bar -----------------------------------------------
        stats_bar = tk.Frame(self.root, bg="#16213e", pady=6)
        stats_bar.pack(fill=tk.X, padx=10)

        self.stat_labels: Dict[str, tk.Label] = {}
        stat_defs = [
            ("Processes", "0", "#00d4ff"),
            ("Suspicious", "0", "#ff6b6b"),
            ("File Alerts", "0", "#ffd166"),
            ("Terminated", "0", "#ef476f"),
        ]
        for label, val, colour in stat_defs:
            frame = tk.Frame(stats_bar, bg="#0f3460", padx=15, pady=5)
            frame.pack(side=tk.LEFT, padx=6, pady=4, ipadx=8)
            tk.Label(frame, text=label, bg="#0f3460", fg="#a0c4ff",
                     font=("Consolas", 9)).pack()
            lbl = tk.Label(frame, text=val, bg="#0f3460", fg=colour,
                           font=("Consolas", 18, "bold"))
            lbl.pack()
            self.stat_labels[label] = lbl

        # -------- Control Row ---------------------------------------------
        ctrl = tk.Frame(self.root, bg="#1a1a2e")
        ctrl.pack(fill=tk.X, padx=10, pady=4)

        def btn(parent, text, cmd, bg, fg="#ffffff"):
            return tk.Button(parent, text=text, command=cmd,
                             bg=bg, fg=fg, font=("Consolas", 10, "bold"),
                             padx=14, pady=6, relief=tk.FLAT,
                             activebackground=bg, cursor="hand2")

        self.start_btn = btn(ctrl, "▶  Start Monitoring", self.start_monitoring,
                             "#06d6a0")
        self.start_btn.pack(side=tk.LEFT, padx=4)

        self.stop_btn = btn(ctrl, "⏹  Stop Monitoring", self.stop_monitoring,
                            "#ef476f", state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=4)

        btn(ctrl, "🗑  Clear Alerts", self._clear_alerts, "#533483").pack(
            side=tk.LEFT, padx=4)

        self.status_lbl = tk.Label(ctrl, text="● STOPPED",
                                   font=("Consolas", 11, "bold"),
                                   bg="#1a1a2e", fg="#ef476f")
        self.status_lbl.pack(side=tk.LEFT, padx=20)

        # -------- Main content area (3 columns) ---------------------------
        content = tk.Frame(self.root, bg="#1a1a2e")
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        self._create_process_panel(content)
        self._create_alerts_panel(content)
        self._create_log_panel(content)

        # -------- Start refresh loop ------------------------------------
        self._schedule_refresh()
        return self.root

    def _panel(self, parent, title, fg):
        import tkinter as tk
        frame = tk.LabelFrame(parent, text=f" {title} ", bg="#16213e",
                              fg=fg, font=("Consolas", 10, "bold"),
                              relief=tk.RIDGE, borderwidth=2)
        frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=4)
        return frame

    def _create_process_panel(self, parent):
        import tkinter as tk
        from tkinter import ttk
        frame = self._panel(parent, "Top CPU Processes", "#00d4ff")
        cols = ("PID", "Process", "CPU %", "Mem %", "Status")
        self.process_tree = ttk.Treeview(frame, columns=cols, show="headings", height=22)
        for col, w in zip(cols, (70, 200, 80, 80, 90)):
            self.process_tree.heading(col, text=col)
            self.process_tree.column(col, width=w, anchor=tk.CENTER)
        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL,
                           command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=sb.set)
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    def _create_alerts_panel(self, parent):
        import tkinter as tk
        from tkinter import scrolledtext
        frame = self._panel(parent, "Active Alerts", "#ff6b6b")
        self.alerts_text = scrolledtext.ScrolledText(
            frame, bg="#16213e", fg="#ffd166",
            font=("Consolas", 9), wrap=tk.WORD, height=22,
            insertbackground="#ffffff"
        )
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.alerts_text.config(state="disabled")
        # Tag colours for severity levels
        self.alerts_text.tag_configure("CRITICAL", foreground="#ef476f")
        self.alerts_text.tag_configure("WARNING", foreground="#ffd166")
        self.alerts_text.tag_configure("INFO", foreground="#06d6a0")

    def _create_log_panel(self, parent):
        import tkinter as tk
        from tkinter import scrolledtext
        frame = self._panel(parent, "Event Log", "#a0c4ff")
        self.log_text = scrolledtext.ScrolledText(
            frame, bg="#16213e", fg="#a0c4ff",
            font=("Consolas", 9), wrap=tk.WORD, height=22,
            insertbackground="#ffffff"
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.log_text.config(state="disabled")
        self.log_text.tag_configure("ERROR", foreground="#ef476f")
        self.log_text.tag_configure("WARNING", foreground="#ffd166")
        self.log_text.tag_configure("INFO", foreground="#06d6a0")

    # ------------------------------------------------------------------
    # Monitoring control
    # ------------------------------------------------------------------

    def start_monitoring(self):
        import tkinter as tk
        self.monitoring = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_lbl.config(text="● ACTIVE", fg="#06d6a0")
        self.add_log("INFO", "Monitoring started")

    def stop_monitoring(self):
        import tkinter as tk
        self.monitoring = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_lbl.config(text="● STOPPED", fg="#ef476f")
        self.add_log("INFO", "Monitoring paused")

    def _clear_alerts(self):
        self.alerts.clear()
        self.alerts_text.config(state="normal")
        self.alerts_text.delete(1.0, "end")
        self.alerts_text.config(state="disabled")

    # ------------------------------------------------------------------
    # Periodic refresh
    # ------------------------------------------------------------------

    def _schedule_refresh(self):
        self._update_display()
        if self.root:
            self.root.after(EDRConfig.GUI_REFRESH_INTERVAL, self._schedule_refresh)

    def _update_display(self):
        try:
            import tkinter as tk
        except ImportError:
            return

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.clock_label.config(text=now)
        self._update_processes()
        self._update_stat_counts()

    def _update_processes(self):
        try:
            import tkinter as tk
            procs = []
            for p in psutil.process_iter(["pid", "name", "cpu_percent",
                                          "memory_percent", "status"]):
                try:
                    info = p.info
                    procs.append({
                        "pid": info["pid"],
                        "name": info["name"] or "?",
                        "cpu": info["cpu_percent"] or 0.0,
                        "mem": info["memory_percent"] or 0.0,
                        "status": info["status"] or "",
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            procs.sort(key=lambda x: x["cpu"], reverse=True)

            for item in self.process_tree.get_children():
                self.process_tree.delete(item)

            for p in procs[:EDRConfig.GUI_TOP_PROCESSES]:
                self.process_tree.insert(
                    "", tk.END,
                    values=(
                        p["pid"],
                        p["name"][:28],
                        f"{p['cpu']:.1f}",
                        f"{p['mem']:.1f}",
                        p["status"],
                    ),
                    tags=(
                        "CRITICAL" if p["cpu"] > EDRConfig.CPU_THRESHOLD else
                        "WARNING" if p["cpu"] > EDRConfig.CPU_THRESHOLD * 0.6 else ""
                    ),
                )
            # Row coloring
            self.process_tree.tag_configure("CRITICAL", foreground="#ef476f")
            self.process_tree.tag_configure("WARNING", foreground="#ffd166")
        except Exception:
            pass

    def _update_stat_counts(self):
        try:
            self.stat_labels["Processes"].config(text=str(self._total_processes))
            self.stat_labels["Suspicious"].config(text=str(self._total_suspicious))
            if self.responder:
                stats = self.responder.get_stats()
                self.stat_labels["Terminated"].config(
                    text=str(stats.get("total_terminated", 0)))
                self.stat_labels["File Alerts"].config(
                    text=str(stats.get("total_alerts", 0)))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # External API (called from main monitoring loop)
    # ------------------------------------------------------------------

    def add_alert(self, severity: str, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] [{severity}] {message}\n"
        self.alerts.append(entry)
        if len(self.alerts) > self.max_alerts:
            self.alerts.pop(0)
        try:
            self.alerts_text.config(state="normal")
            self.alerts_text.insert("end", entry, severity)
            self.alerts_text.see("end")
            self.alerts_text.config(state="disabled")
        except Exception:
            pass

    def add_log(self, level: str, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] [{level}] {message}\n"
        try:
            self.log_text.config(state="normal")
            self.log_text.insert("end", entry, level)
            lines = int(self.log_text.index("end-1c").split(".")[0])
            if lines > EDRConfig.GUI_MAX_LOGS:
                self.log_text.delete("1.0", "2.0")
            self.log_text.see("end")
            self.log_text.config(state="disabled")
        except Exception:
            pass

    def update_counts(self, total_processes: int, suspicious: int):
        self._total_processes = total_processes
        self._total_suspicious = suspicious

    def run(self):
        if self.root:
            self.root.mainloop()
