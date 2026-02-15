"""
GUI Dashboard Module
Provides a Tkinter-based dashboard for the EDR system.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import psutil
from datetime import datetime
from typing import List, Dict
from config import EDRConfig


class EDRDashboard:
    """
    Lightweight EDR Dashboard using Tkinter.
    Displays live process information, alerts, and logs.
    """

    def __init__(self, responder=None):
        """
        Initialize the dashboard.
        
        Args:
            responder: Responder instance for accessing alerts
        """
        self.responder = responder
        self.monitoring = False
        self.root = None
        self.update_thread = None
        
        # Storage for alerts
        self.alerts = []
        self.max_alerts = EDRConfig.GUI_MAX_ALERTS

    def create_gui(self):
        """Create the GUI window and all components."""
        self.root = tk.Tk()
        self.root.title("Lightweight EDR Dashboard")
        self.root.geometry("1200x800")
        self.root.configure(bg="#2b2b2b")
        
        # Create main container
        main_frame = tk.Frame(self.root, bg="#2b2b2b")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = tk.Label(
            main_frame,
            text="Lightweight EDR Dashboard",
            font=("Arial", 20, "bold"),
            bg="#2b2b2b",
            fg="#00ff00"
        )
        title_label.pack(pady=(0, 10))
        
        # Control buttons
        self._create_control_panel(main_frame)
        
        # Create three-column layout
        content_frame = tk.Frame(main_frame, bg="#2b2b2b")
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left column: Top Processes
        self._create_process_panel(content_frame)
        
        # Middle column: Active Alerts
        self._create_alerts_panel(content_frame)
        
        # Right column: Log Viewer
        self._create_log_panel(content_frame)
        
        # Status bar
        self._create_status_bar(main_frame)
        
        # Start auto-refresh
        self._schedule_refresh()
        
        return self.root

    def _create_control_panel(self, parent):
        """Create control buttons panel."""
        control_frame = tk.Frame(parent, bg="#2b2b2b")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Start button
        self.start_btn = tk.Button(
            control_frame,
            text="▶ Start Monitoring",
            command=self.start_monitoring,
            bg="#00aa00",
            fg="white",
            font=("Arial", 12, "bold"),
            padx=20,
            pady=10,
            relief=tk.RAISED,
            cursor="hand2"
        )
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        # Stop button
        self.stop_btn = tk.Button(
            control_frame,
            text="⏸ Stop Monitoring",
            command=self.stop_monitoring,
            bg="#aa0000",
            fg="white",
            font=("Arial", 12, "bold"),
            padx=20,
            pady=10,
            relief=tk.RAISED,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Status indicator
        self.status_indicator = tk.Label(
            control_frame,
            text="● Stopped",
            font=("Arial", 12, "bold"),
            bg="#2b2b2b",
            fg="#ff0000"
        )
        self.status_indicator.pack(side=tk.LEFT, padx=20)

    def _create_process_panel(self, parent):
        """Create top processes display panel."""
        process_frame = tk.LabelFrame(
            parent,
            text="Top 10 Processes (CPU Usage)",
            bg="#3b3b3b",
            fg="#00ff00",
            font=("Arial", 11, "bold"),
            relief=tk.RIDGE,
            borderwidth=2
        )
        process_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Create treeview for processes
        columns = ("PID", "Name", "CPU%", "Memory%")
        self.process_tree = ttk.Treeview(
            process_frame,
            columns=columns,
            show="headings",
            height=25
        )
        
        # Configure columns
        self.process_tree.heading("PID", text="PID")
        self.process_tree.heading("Name", text="Process Name")
        self.process_tree.heading("CPU%", text="CPU %")
        self.process_tree.heading("Memory%", text="Memory %")
        
        self.process_tree.column("PID", width=80, anchor=tk.CENTER)
        self.process_tree.column("Name", width=200, anchor=tk.W)
        self.process_tree.column("CPU%", width=80, anchor=tk.CENTER)
        self.process_tree.column("Memory%", width=80, anchor=tk.CENTER)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(process_frame, orient=tk.VERTICAL, command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        
        self.process_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Style for treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b")
        style.configure("Treeview.Heading", background="#1b1b1b", foreground="#00ff00", font=("Arial", 10, "bold"))

    def _create_alerts_panel(self, parent):
        """Create active alerts panel."""
        alerts_frame = tk.LabelFrame(
            parent,
            text="Active Alerts",
            bg="#3b3b3b",
            fg="#ffaa00",
            font=("Arial", 11, "bold"),
            relief=tk.RIDGE,
            borderwidth=2
        )
        alerts_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Scrolled text for alerts
        self.alerts_text = scrolledtext.ScrolledText(
            alerts_frame,
            bg="#2b2b2b",
            fg="#ffaa00",
            font=("Courier", 9),
            wrap=tk.WORD,
            height=25
        )
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.alerts_text.config(state=tk.DISABLED)

    def _create_log_panel(self, parent):
        """Create log viewer panel."""
        log_frame = tk.LabelFrame(
            parent,
            text="Log Viewer",
            bg="#3b3b3b",
            fg="#00aaff",
            font=("Arial", 11, "bold"),
            relief=tk.RIDGE,
            borderwidth=2
        )
        log_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0))
        
        # Scrolled text for logs
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            bg="#2b2b2b",
            fg="#00aaff",
            font=("Courier", 9),
            wrap=tk.WORD,
            height=25
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.log_text.config(state=tk.DISABLED)

    def _create_status_bar(self, parent):
        """Create status bar at bottom."""
        status_frame = tk.Frame(parent, bg="#1b1b1b", relief=tk.SUNKEN, borderwidth=1)
        status_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            bg="#1b1b1b",
            fg="#00ff00",
            font=("Arial", 9),
            anchor=tk.W
        )
        self.status_label.pack(side=tk.LEFT, padx=10, pady=2)
        
        # Time label
        self.time_label = tk.Label(
            status_frame,
            text="",
            bg="#1b1b1b",
            fg="#00ff00",
            font=("Arial", 9),
            anchor=tk.E
        )
        self.time_label.pack(side=tk.RIGHT, padx=10, pady=2)

    def start_monitoring(self):
        """Start the monitoring system."""
        self.monitoring = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_indicator.config(text="● Running", fg="#00ff00")
        self.add_log("INFO", "Monitoring started")

    def stop_monitoring(self):
        """Stop the monitoring system."""
        self.monitoring = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_indicator.config(text="● Stopped", fg="#ff0000")
        self.add_log("INFO", "Monitoring stopped")

    def _schedule_refresh(self):
        """Schedule periodic GUI refresh."""
        self._update_display()
        if self.root:
            self.root.after(EDRConfig.GUI_REFRESH_INTERVAL, self._schedule_refresh)

    def _update_display(self):
        """Update all display components."""
        # Update time
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=current_time)
        
        # Update processes
        self._update_processes()
        
        # Update status
        if self.monitoring:
            self.status_label.config(text=f"Monitoring active | Last update: {current_time}")

    def _update_processes(self):
        """Update the process list with top CPU consumers."""
        try:
            # Get all processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    info = proc.info
                    processes.append({
                        'pid': info['pid'],
                        'name': info['name'],
                        'cpu': info['cpu_percent'] or 0,
                        'memory': info['memory_percent'] or 0
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage
            processes.sort(key=lambda x: x['cpu'], reverse=True)
            top_processes = processes[:EDRConfig.GUI_TOP_PROCESSES]
            
            # Clear existing items
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)
            
            # Add top processes
            for proc in top_processes:
                self.process_tree.insert(
                    "",
                    tk.END,
                    values=(
                        proc['pid'],
                        proc['name'][:30],  # Truncate long names
                        f"{proc['cpu']:.1f}",
                        f"{proc['memory']:.1f}"
                    )
                )
        except Exception as e:
            self.add_log("ERROR", f"Failed to update processes: {e}")

    def add_alert(self, severity: str, message: str):
        """
        Add an alert to the alerts panel.
        
        Args:
            severity: Alert severity (INFO, WARNING, CRITICAL)
            message: Alert message
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        alert_entry = f"[{timestamp}] [{severity}] {message}\n"
        
        self.alerts.append(alert_entry)
        
        # Keep only recent alerts
        if len(self.alerts) > self.max_alerts:
            self.alerts.pop(0)
        
        # Update display
        self.alerts_text.config(state=tk.NORMAL)
        self.alerts_text.delete(1.0, tk.END)
        self.alerts_text.insert(tk.END, "".join(self.alerts))
        self.alerts_text.see(tk.END)
        self.alerts_text.config(state=tk.DISABLED)

    def add_log(self, level: str, message: str):
        """
        Add a log entry to the log panel.
        
        Args:
            level: Log level (INFO, WARNING, ERROR, etc.)
            message: Log message
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, log_entry)
        
        # Keep only recent logs
        lines = int(self.log_text.index('end-1c').split('.')[0])
        if lines > EDRConfig.GUI_MAX_LOGS:
            self.log_text.delete(1.0, 2.0)
        
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def run(self):
        """Start the GUI main loop."""
        if self.root:
            self.root.mainloop()
