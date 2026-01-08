import psutil
import time
from typing import List, Dict


class ProcessScanner:

    def __init__(self, scan_interval: float = 1.0):
        self.scan_interval = scan_interval
        self.process_cache = {}

        # Initialize CPU percent for all processes
        for proc in psutil.process_iter():
            try:
                proc.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def scan_processes(self) -> List[Dict]:
    
        processes = []
        current_time = time.time()

        for proc in psutil.process_iter(
            ['pid', 'name', 'memory_percent', 'status']
        ):
            try:
                cpu = proc.cpu_percent(None)
                mem = proc.memory_percent()

                process_info = {
                    "pid": proc.pid,
                    "name": proc.info['name'],
                    "cpu_percent": cpu,
                    "memory_percent": mem,
                    "status": proc.info['status'],
                    "timestamp": current_time
                }

                processes.append(process_info)
                self._update_cache(process_info)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        self._cleanup_cache()
        time.sleep(self.scan_interval)
        return processes

    def _update_cache(self, proc_info: Dict):
        pid = proc_info['pid']

        if pid not in self.process_cache:
            self.process_cache[pid] = []

        self.process_cache[pid].append({
            "timestamp": proc_info['timestamp'],
            "cpu": proc_info['cpu_percent'],
            "memory": proc_info['memory_percent']
        })

        # Keep last 10 entries
        if len(self.process_cache[pid]) > 10:
            self.process_cache[pid].pop(0)

    def get_process_history(self, pid: int) -> List[Dict]:
        return self.process_cache.get(pid, [])

    def _cleanup_cache(self):
        active_pids = {p.pid for p in psutil.process_iter()}
        for pid in list(self.process_cache.keys()):
            if pid not in active_pids:
                del self.process_cache[pid]
