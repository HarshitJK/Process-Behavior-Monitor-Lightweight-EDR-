"""
File System Monitor Module
Monitors a directory for ransomware-like behavior patterns.

Detects:
  • Rapid file creation
  • Rapid file modification
  • Rapid file deletion / rename

Alert is triggered when total events exceed FILE_EVENT_THRESHOLD
within TIME_WINDOW seconds.
"""

import os
import time
from pathlib import Path
from typing import Callable, List, Dict, Optional
from collections import deque, Counter

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


class RansomwareDetector(FileSystemEventHandler):
    """
    Watchdog event handler that counts rapid file operations and fires
    an alert callback when the rate exceeds the configured threshold.
    """

    def __init__(
        self,
        alert_callback: Callable,
        file_change_threshold: int = 10,
        time_window: float = 5.0,
    ):
        super().__init__()
        self.alert_callback = alert_callback
        self.file_change_threshold = file_change_threshold
        self.time_window = time_window

        # Each entry: (timestamp, file_path, event_type)
        self.file_changes: deque = deque()

        # Per-type counters to support detailed reporting
        self.event_type_counts: Counter = Counter()

        # Last alert timestamp to avoid flooding
        self._last_alert_time: float = 0.0
        self._alert_cooldown: float = time_window  # don't re-alert until window expires

    # ---- Watchdog callbacks -----------------------------------------------

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
            self._record_change(event.dest_path, "moved/renamed")

    # ---- Internal ----------------------------------------------------------

    def _record_change(self, file_path: str, event_type: str):
        current_time = time.time()

        self.file_changes.append((current_time, file_path, event_type))
        self.event_type_counts[event_type] += 1

        # Evict events outside the time window
        while self.file_changes and (current_time - self.file_changes[0][0] > self.time_window):
            _, _, old_type = self.file_changes.popleft()
            self.event_type_counts[old_type] = max(0, self.event_type_counts[old_type] - 1)

        # Alert if threshold exceeded and we're past the cooldown
        if (
            len(self.file_changes) >= self.file_change_threshold
            and (current_time - self._last_alert_time) >= self._alert_cooldown
        ):
            self._last_alert_time = current_time
            summary = dict(self.event_type_counts)
            recent = list(self.file_changes)
            self.file_changes.clear()
            self.event_type_counts.clear()

            self.alert_callback(recent, file_path, summary)

    def get_current_stats(self) -> Dict:
        """Return a snapshot of current activity inside the time window."""
        return {
            "events_in_window": len(self.file_changes),
            "threshold": self.file_change_threshold,
            "time_window_seconds": self.time_window,
            "event_types": dict(self.event_type_counts),
        }


class FileMonitor:
    """
    Manages a Watchdog Observer and exposes high-level methods for the EDR.
    """

    def __init__(
        self,
        monitor_path: Optional[str] = None,
        file_change_threshold: Optional[int] = None,
        time_window: Optional[float] = None,
    ):
        from config import EDRConfig

        if monitor_path is None:
            monitor_path = EDRConfig.MONITOR_DIRECTORY

        file_change_threshold = file_change_threshold or EDRConfig.FILE_EVENT_THRESHOLD
        time_window = time_window or EDRConfig.TIME_WINDOW

        self.monitor_path = Path(monitor_path).resolve()
        self.monitor_path.mkdir(parents=True, exist_ok=True)

        if not self.monitor_path.is_dir():
            raise ValueError(f"Monitor path must be a directory: {self.monitor_path}")

        self.file_change_threshold = file_change_threshold
        self.time_window = time_window

        self._observer: Optional[Observer] = None
        self._detector: Optional[RansomwareDetector] = None
        self._alert_callback: Optional[Callable] = None

        # Cumulative stats
        self.total_file_alerts: int = 0
        self.total_file_events: int = 0

    # ---- Public API -------------------------------------------------------

    def set_alert_callback(self, callback: Callable):
        """
        Set handler called when suspicious file activity is detected.
        Signature: callback(changes: list, trigger_file: str, summary: dict)
        """
        self._alert_callback = callback

    def start(self):
        """Begin watching the configured directory."""
        if self._alert_callback is None:
            raise ValueError("An alert callback must be set before starting the file monitor.")

        # Wrap callback to update stats before passing to user handler
        def _wrapped_callback(changes: list, trigger_file: str, summary: dict):
            self.total_file_alerts += 1
            self.total_file_events += len(changes)
            self._alert_callback(changes, trigger_file, summary)

        self._detector = RansomwareDetector(
            alert_callback=_wrapped_callback,
            file_change_threshold=self.file_change_threshold,
            time_window=self.time_window,
        )

        self._observer = Observer()
        self._observer.schedule(self._detector, str(self.monitor_path), recursive=True)
        self._observer.start()

        print(f"[FILE MONITOR] Watching: {self.monitor_path}")
        print(
            f"[FILE MONITOR] Alert threshold: "
            f"{self.file_change_threshold} events within {self.time_window}s"
        )

    def stop(self):
        """Stop the watchdog observer."""
        if self._observer:
            self._observer.stop()
            self._observer.join()
            print("[FILE MONITOR] Stopped.")

    def is_running(self) -> bool:
        return self._observer is not None and self._observer.is_alive()

    def get_monitored_path(self) -> str:
        return str(self.monitor_path)

    def get_stats(self) -> Dict:
        """Return cumulative file-monitor statistics."""
        current = self._detector.get_current_stats() if self._detector else {}
        return {
            "total_alerts": self.total_file_alerts,
            "total_events": self.total_file_events,
            "current_window": current,
        }
