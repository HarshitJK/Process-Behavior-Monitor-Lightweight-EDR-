"""
Process Scanner Module
Scans running processes and maintains historical data for behavior analysis.

Enhanced:
  - Captures exe path, open-file handles.
  - Per-PARENT-PID spawn tracking (not system-wide).
    Rationale: system-wide new-process count produces massive false positives
    because normal boot / session startup spawns dozens of processes. Tracking
    per parent lets us detect a single misbehaving process forking rapidly.
"""

import psutil
import time
from typing import List, Dict, Optional
from collections import defaultdict, deque
from config import EDRConfig


class ProcessScanner:
    """
    Scans system processes and maintains per-process history.

    Spawn detection (fix for Issue #2):
      - Tracks (parent_pid → deque of child-birth timestamps).
      - get_parent_spawn_counts() returns {parent_pid: count_in_window}.
      - Old system-wide get_recent_spawn_count() kept for backward compat
        but is now derived from per-parent data.
    """

    # How many history entries to keep per PID
    HISTORY_DEPTH = 15

    def __init__(self, scan_interval: float = 2.0):
        self.scan_interval = scan_interval

        # pid → list of {timestamp, cpu, memory} dicts
        self.process_cache: Dict[int, List[Dict]] = {}

        # parent_pid → deque of child-birth timestamps
        self._parent_spawn_times: Dict[int, deque] = defaultdict(deque)

        # PIDs seen in previous scan (to detect brand-new processes)
        self._prev_pids: set = set()

        # Prime the CPU percent counters (first call always returns 0.0)
        # and simultaneously build the initial PID baseline so that the
        # very first real scan does NOT treat every existing process as
        # 'new' (which would create thousands of phantom spawn events).
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(None)
                self._prev_pids.add(proc.pid)   # baseline for spawn detection
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
        Updates internal history cache and per-parent spawn-rate tracker.
        """
        processes: List[Dict] = []
        current_time = time.time()
        current_pids: set = set()

        for proc in psutil.process_iter(
            ['pid', 'name', 'status', 'memory_percent', 'username']
        ):
            try:
                pid = proc.pid

                # Always skip the EDR monitoring process itself
                if pid == EDRConfig.EDR_OWN_PID:
                    current_pids.add(pid)   # still track it to avoid 'new' on next scan
                    continue
                cpu = proc.cpu_percent(None)
                mem = proc.memory_percent()

                # Parent PID (safe – returns 0 if unavailable)
                try:
                    ppid = proc.ppid()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    ppid = 0

                exe = self._safe_exe(proc)
                open_files = self._safe_open_files(proc)
                connections = self._safe_connections(proc)

                is_new = pid not in self._prev_pids

                process_info: Dict = {
                    "pid":            pid,
                    "ppid":           ppid,
                    "name":           proc.info.get("name") or "unknown",
                    "cpu_percent":    cpu,
                    "memory_percent": mem,
                    "status":         proc.info.get("status", "unknown"),
                    "username":       proc.info.get("username", ""),
                    "exe":            exe,
                    "open_files":     open_files,
                    "connections":    connections,
                    "timestamp":      current_time,
                    "is_new":         is_new,
                }

                processes.append(process_info)
                self._update_cache(process_info)

                # Track new process births per parent PID
                if is_new and ppid:
                    self._parent_spawn_times[ppid].append(current_time)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Prune old birth events from per-parent queues (keep last 60 s)
        cutoff = current_time - 60.0
        for ppid, dq in list(self._parent_spawn_times.items()):
            while dq and dq[0] < cutoff:
                dq.popleft()
            if not dq:
                del self._parent_spawn_times[ppid]

        self._prev_pids = current_pids
        self._cleanup_cache(current_pids)
        return processes

    def get_parent_spawn_counts(self, window_seconds: float) -> Dict[int, int]:
        """
        Return {parent_pid: child_count} for parents that spawned at least
        one child within the last *window_seconds* seconds.

        This is the primary spawn-rate API used by BehaviorAnalyzer.
        """
        cutoff = time.time() - window_seconds
        result: Dict[int, int] = {}
        for ppid, dq in self._parent_spawn_times.items():
            count = sum(1 for t in dq if t >= cutoff)
            if count:
                result[ppid] = count
        return result

    def get_recent_spawn_count(self, window_seconds: float) -> int:
        """
        Backward-compat: total new processes across all parents in window.
        Prefer get_parent_spawn_counts() for accurate per-parent analysis.
        """
        return sum(self.get_parent_spawn_counts(window_seconds).values())

    def get_process_history(self, pid: int) -> List[Dict]:
        """Return stored CPU/memory history for a given PID."""
        return self.process_cache.get(pid, [])

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
            "cpu":       proc_info["cpu_percent"],
            "memory":    proc_info["memory_percent"],
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
