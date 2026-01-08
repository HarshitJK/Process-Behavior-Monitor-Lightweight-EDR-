"""
File System Monitor Module
Monitors directory for rapid file changes to detect ransomware-like behavior.
"""

import os
import time
from pathlib import Path
from typing import Callable, List, Tuple
from collections import deque

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


class RansomwareDetector(FileSystemEventHandler):
    """
    File system event handler that detects rapid file modifications,
    creations, deletions, and renames (ransomware-like behavior).
    """

    def __init__(
        self,
        alert_callback: Callable,
        file_change_threshold: int = 10,
        time_window: float = 5.0
    ):
        """
        Initialize the ransomware detector.

        Args:
            alert_callback: Function to call when suspicious activity is detected
            file_change_threshold: Number of file changes to trigger alert
            time_window: Time window in seconds
        """
        super().__init__()
        self.alert_callback = alert_callback
        self.file_change_threshold = file_change_threshold
        self.time_window = time_window

        # Stores (timestamp, file_path, event_type)
        self.file_changes = deque()

    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self._record_change(event.src_path, "created")

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self._record_change(event.src_path, "modified")

    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory:
            self._record_change(event.src_path, "deleted")

    def on_moved(self, event: FileSystemEvent):
        if not event.is_directory:
            self._record_change(event.dest_path, "moved")

    def _record_change(self, file_path: str, event_type: str):
        """
        Record a file system change and check for suspicious patterns.
        """
        current_time = time.time()
        self.file_changes.append((current_time, file_path, event_type))

        # Remove old events outside the time window
        while self.file_changes and (current_time - self.file_changes[0][0] > self.time_window):
            self.file_changes.popleft()

        # Check threshold
        if len(self.file_changes) >= self.file_change_threshold:
            recent_changes = list(self.file_changes)
            self.alert_callback(recent_changes, file_path)

            # Reset to prevent repeated alerts for same burst
            self.file_changes.clear()


class FileMonitor:
    """
    Monitors a directory for ransomware-like file system activity.
    """

    def __init__(
        self,
        monitor_path: str = None,
        file_change_threshold: int = 10,
        time_window: float = 5.0
    ):
        """
        Initialize the file monitor.

        Args:
            monitor_path: Directory path to monitor
            file_change_threshold: Number of changes to trigger alert
            time_window: Time window in seconds
        """
        if monitor_path is None:
            monitor_path = os.getcwd()

        self.monitor_path = Path(monitor_path).resolve()

        if not self.monitor_path.exists():
            self.monitor_path.mkdir(parents=True, exist_ok=True)

        if not self.monitor_path.is_dir():
            raise ValueError(f"Monitor path must be a directory: {self.monitor_path}")

        self.file_change_threshold = file_change_threshold
        self.time_window = time_window

        self.observer: Observer | None = None
        self.detector: RansomwareDetector | None = None
        self.alert_callback: Callable | None = None

    def set_alert_callback(self, callback: Callable):
        """
        Set the callback function for alerts.

        Args:
            callback: Function that takes (changes_list, trigger_file)
        """
        self.alert_callback = callback

    def start(self):
        """Start monitoring the directory."""
        if self.alert_callback is None:
            raise ValueError("Alert callback must be set before starting monitor")

        self.detector = RansomwareDetector(
            self.alert_callback,
            self.file_change_threshold,
            self.time_window
        )

        self.observer = Observer()
        self.observer.schedule(
            self.detector,
            str(self.monitor_path),
            recursive=True
        )
        self.observer.start()

        print(f"[FILE MONITOR] Monitoring directory: {self.monitor_path}")
        print(
            f"[FILE MONITOR] Alert if ≥ {self.file_change_threshold} events "
            f"within {self.time_window} seconds"
        )

    def stop(self):
        """Stop monitoring the directory."""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            print("[FILE MONITOR] Monitoring stopped")

    def is_running(self) -> bool:
        """Check if the monitor is currently running."""
        return self.observer is not None and self.observer.is_alive()

    def get_monitored_path(self) -> str:
        """Return monitored directory path."""
        return str(self.monitor_path)
