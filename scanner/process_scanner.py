"""
Process Scanner Module
Scans running processes and maintains historical data for behavior analysis.
Enhanced: captures exe path, open-file handles, and spawn-rate tracking.
"""

import psutil
import time
from typing import List, Dict, Optional
from collections import deque


class ProcessScanner:
    """
    Scans system processes and maintains per-process history.
    Tracks new-process birth timestamps for rapid-spawn detection.
    """

    # How many history entries to keep per PID
    HISTORY_DEPTH = 15

    def __init__(self, scan_interval: float = 2.0):
        self.scan_interval = scan_interval

        # pid → list of {timestamp, cpu, memory} dicts
        self.process_cache: Dict[int, List[Dict]] = {}

        # Timestamps of newly-observed PIDs (for spawn-rate detection)
        self.new_process_times: deque = deque()

        # PIDs seen in previous scan (to detect brand-new processes)
        self._prev_pids: set = set()

        # Prime the CPU percent counters (first call always returns 0)
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # Wait one interval so the next cpu_percent call is meaningful
        time.sleep(self.scan_interval)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_processes(self) -> List[Dict]:
        """
        Iterate all running processes and return enriched process dicts.
        Updates internal history cache and spawn-rate tracker.
        """
        processes: List[Dict] = []
        current_time = time.time()
        current_pids: set = set()

        for proc in psutil.process_iter(
            ['pid', 'name', 'status', 'memory_percent', 'username']
        ):
            try:
                pid = proc.pid
                current_pids.add(pid)
                cpu = proc.cpu_percent(None)
                mem = proc.memory_percent()

                # Try to get executable path and open files (may fail on some OSes/privs)
                exe = self._safe_exe(proc)
                open_files = self._safe_open_files(proc)
                connections = self._safe_connections(proc)

                process_info: Dict = {
                    "pid": pid,
                    "name": proc.info.get("name") or "unknown",
                    "cpu_percent": cpu,
                    "memory_percent": mem,
                    "status": proc.info.get("status", "unknown"),
                    "username": proc.info.get("username", ""),
                    "exe": exe,
                    "open_files": open_files,
                    "connections": connections,
                    "timestamp": current_time,
                    "is_new": pid not in self._prev_pids,
                }

                processes.append(process_info)
                self._update_cache(process_info)

                # Track new process births for spawn-rate detection
                if process_info["is_new"]:
                    self.new_process_times.append(current_time)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Prune spawn-rate window
        cutoff = current_time - 30.0   # keep last 30 s of birth events
        while self.new_process_times and self.new_process_times[0] < cutoff:
            self.new_process_times.popleft()

        self._prev_pids = current_pids
        self._cleanup_cache(current_pids)
        return processes

    def get_process_history(self, pid: int) -> List[Dict]:
        """Return stored CPU/memory history for a given PID."""
        return self.process_cache.get(pid, [])

    def get_recent_spawn_count(self, window_seconds: float) -> int:
        """
        Return how many new processes appeared within the last
        *window_seconds* seconds (used for spawn-rate detection).
        """
        cutoff = time.time() - window_seconds
        return sum(1 for t in self.new_process_times if t >= cutoff)

    def get_total_process_count(self) -> int:
        """Return total number of processes in the cache."""
        return len(self.process_cache)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _update_cache(self, proc_info: Dict):
        pid = proc_info["pid"]
        if pid not in self.process_cache:
            self.process_cache[pid] = []

        self.process_cache[pid].append({
            "timestamp": proc_info["timestamp"],
            "cpu": proc_info["cpu_percent"],
            "memory": proc_info["memory_percent"],
        })

        # Keep rolling window
        if len(self.process_cache[pid]) > self.HISTORY_DEPTH:
            self.process_cache[pid].pop(0)

    def _cleanup_cache(self, active_pids: Optional[set] = None):
        if active_pids is None:
            active_pids = {p.pid for p in psutil.process_iter()}
        for pid in list(self.process_cache.keys()):
            if pid not in active_pids:
                del self.process_cache[pid]

    @staticmethod
    def _safe_exe(proc: psutil.Process) -> str:
        try:
            return proc.exe() or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            return ""

    @staticmethod
    def _safe_open_files(proc: psutil.Process) -> List[str]:
        try:
            return [f.path for f in proc.open_files()]
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            return []

    @staticmethod
    def _safe_connections(proc: psutil.Process) -> int:
        try:
            return len(proc.connections())
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            return 0
