"""
Behavior Analyzer Module
Rule-based behavioral detection engine for the Lightweight EDR.

Detection Rules:
  A. High CPU usage              → WARNING
  B. High memory usage           → WARNING / CRITICAL
  C. Long-running resource abuse → CRITICAL
  D. Suspicious process names    → WARNING
  E. Rapid process spawning      → WARNING / CRITICAL
  F. Access to sensitive files   → CRITICAL

Each analysis returns a structured result dict with:
  suspicious  (bool)
  severity    (str)  – INFO | WARNING | CRITICAL
  reasons     (List[str]) – human-readable descriptions
  threat_type (str)  – primary threat category label
"""

import time
from typing import Dict, List, Optional
from config import EDRConfig


# ---------------------------------------------------------------------------
# Helper: severity ordering
# ---------------------------------------------------------------------------
_SEV_ORDER = {
    EDRConfig.SEVERITY_INFO: 0,
    EDRConfig.SEVERITY_WARNING: 1,
    EDRConfig.SEVERITY_CRITICAL: 2,
}


def _max_severity(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b


# ---------------------------------------------------------------------------
class BehaviorAnalyzer:
    """
    Analyzes process data + history using configurable rule-based detection.

    Rules:
        A  High instantaneous CPU
        B  High / critical memory
        C  Sustained (long-running) high CPU
        D  Suspicious keywords in process name or path
        E  Sensitive file access detected via open-files list
        F  Rapid process spawning (requires ProcessScanner.get_recent_spawn_count)
    """

    def __init__(
        self,
        cpu_threshold: Optional[float] = None,
        memory_warning_threshold: Optional[float] = None,
        memory_critical_threshold: Optional[float] = None,
        cpu_consecutive_checks: Optional[int] = None,
        cooldown_seconds: Optional[int] = None,
    ):
        self.cpu_threshold = cpu_threshold or EDRConfig.CPU_THRESHOLD
        self.mem_warn = memory_warning_threshold or EDRConfig.MEMORY_WARNING_THRESHOLD
        self.mem_crit = memory_critical_threshold or EDRConfig.MEMORY_CRITICAL_THRESHOLD
        self.cpu_consecutive = cpu_consecutive_checks or EDRConfig.CPU_CONSECUTIVE_CHECKS
        self.cooldown_seconds = cooldown_seconds or EDRConfig.ALERT_COOLDOWN_SECONDS

        # pid → last alert epoch timestamp
        self.last_alert_time: Dict[int, float] = {}

        # Suspicious keyword list (lower-cased for fast matching)
        self._keywords = [kw.lower() for kw in EDRConfig.SUSPICIOUS_KEYWORDS]

        # Sensitive path prefixes (lower-cased)
        self._sensitive = [p.lower() for p in EDRConfig.SENSITIVE_PATHS]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        process: Dict,
        history: List[Dict],
        recent_spawn_count: int = 0,
    ) -> Dict:
        """
        Analyze a process snapshot and its history.

        Args:
            process:            dict from ProcessScanner.scan_processes()
            history:            list of {timestamp, cpu, memory} from get_process_history()
            recent_spawn_count: processes born in SPAWN_TIME_WINDOW (from scanner)

        Returns:
            {
                suspicious: bool,
                severity:   str,
                reasons:    List[str],
                threat_type: str,
            }
        """
        pid = process.get("pid", -1)
        name = (process.get("name") or "unknown").lower()
        exe = (process.get("exe") or "").lower()
        cpu = process.get("cpu_percent", 0.0)
        mem = process.get("memory_percent", 0.0)
        open_files: List[str] = [f.lower() for f in process.get("open_files", [])]
        current_time = time.time()

        # ---- Cooldown gate --------------------------------------------------
        if pid in self.last_alert_time:
            elapsed = current_time - self.last_alert_time[pid]
            if elapsed < self.cooldown_seconds:
                if EDRConfig.DEBUG_MODE:
                    print(f"[DEBUG] PID {pid} in cooldown ({elapsed:.1f}s/{self.cooldown_seconds}s)")
                return self._result(False, EDRConfig.SEVERITY_INFO, ["In cooldown period"], "NONE")

        reasons: List[str] = []
        severity: str = EDRConfig.SEVERITY_INFO
        threat_type: str = "NONE"

        # ---- Rule A: High CPU (instantaneous) ------------------------------
        if cpu >= self.cpu_threshold:
            reasons.append(
                f"High CPU usage: {cpu:.1f}% (threshold: {self.cpu_threshold}%)"
            )
            severity = _max_severity(severity, EDRConfig.SEVERITY_WARNING)
            threat_type = "HIGH_CPU"
            if EDRConfig.DEBUG_MODE:
                print(f"[DEBUG] PID {pid} Rule A TRIGGERED: CPU={cpu:.1f}%")

        # ---- Rule B: Memory (independent) -----------------------------------
        if mem >= self.mem_crit:
            reasons.append(
                f"Critical memory usage: {mem:.1f}% (critical threshold: {self.mem_crit}%)"
            )
            severity = _max_severity(severity, EDRConfig.SEVERITY_CRITICAL)
            threat_type = "HIGH_MEMORY"
            if EDRConfig.DEBUG_MODE:
                print(f"[DEBUG] PID {pid} Rule B-CRIT TRIGGERED: MEM={mem:.1f}%")

        elif mem >= self.mem_warn:
            reasons.append(
                f"High memory usage: {mem:.1f}% (warning threshold: {self.mem_warn}%)"
            )
            severity = _max_severity(severity, EDRConfig.SEVERITY_WARNING)
            if threat_type == "NONE":
                threat_type = "HIGH_MEMORY"
            if EDRConfig.DEBUG_MODE:
                print(f"[DEBUG] PID {pid} Rule B-WARN TRIGGERED: MEM={mem:.1f}%")

        # ---- Rule C: Sustained high CPU ------------------------------------
        if len(history) >= self.cpu_consecutive:
            recent = history[-self.cpu_consecutive:]
            sustained = sum(1 for h in recent if h["cpu"] >= self.cpu_threshold)
            if sustained >= self.cpu_consecutive:
                reasons.append(
                    f"Sustained high CPU: {cpu:.1f}% for "
                    f"{self.cpu_consecutive} consecutive scans"
                )
                severity = _max_severity(severity, EDRConfig.SEVERITY_CRITICAL)
                threat_type = "RESOURCE_ABUSE"
                if EDRConfig.DEBUG_MODE:
                    print(f"[DEBUG] PID {pid} Rule C TRIGGERED: sustained CPU")

        # ---- Rule D: Suspicious keyword in name / path ---------------------
        matched_keyword = self._check_keywords(name, exe)
        if matched_keyword:
            reasons.append(
                f"Suspicious keyword in process name/path: '{matched_keyword}'"
            )
            severity = _max_severity(severity, EDRConfig.SEVERITY_WARNING)
            if threat_type == "NONE":
                threat_type = "SUSPICIOUS_NAME"
            if EDRConfig.DEBUG_MODE:
                print(f"[DEBUG] PID {pid} Rule D TRIGGERED: keyword='{matched_keyword}'")

        # ---- Rule E: Sensitive file access ---------------------------------
        sensitive_hit = self._check_sensitive_files(open_files)
        if sensitive_hit:
            reasons.append(
                f"Access to sensitive path detected: {sensitive_hit}"
            )
            severity = _max_severity(severity, EDRConfig.SEVERITY_CRITICAL)
            threat_type = "SENSITIVE_FILE_ACCESS"
            if EDRConfig.DEBUG_MODE:
                print(f"[DEBUG] PID {pid} Rule E TRIGGERED: path='{sensitive_hit}'")

        # ---- Rule F: Rapid process spawning --------------------------------
        spawn_thresh = EDRConfig.SPAWN_RATE_THRESHOLD
        if recent_spawn_count >= spawn_thresh:
            reasons.append(
                f"Rapid process spawning: {recent_spawn_count} new processes "
                f"in {EDRConfig.SPAWN_TIME_WINDOW}s window"
            )
            # CRITICAL if very fast, WARNING if moderate
            if recent_spawn_count >= spawn_thresh * 2:
                severity = _max_severity(severity, EDRConfig.SEVERITY_CRITICAL)
            else:
                severity = _max_severity(severity, EDRConfig.SEVERITY_WARNING)
            if threat_type == "NONE":
                threat_type = "PROCESS_INJECTION"
            if EDRConfig.DEBUG_MODE:
                print(f"[DEBUG] Rule F TRIGGERED: spawns={recent_spawn_count}")

        # ---- Combine CPU + Memory → escalate to CRITICAL -------------------
        if cpu >= EDRConfig.COMBINED_CPU_THRESHOLD and mem >= EDRConfig.MEMORY_THRESHOLD:
            if len(reasons) >= 2:          # only if multiple flags already raised
                severity = _max_severity(severity, EDRConfig.SEVERITY_CRITICAL)

        # ---- Final decision -------------------------------------------------
        suspicious = len(reasons) > 0

        if EDRConfig.DEBUG_MODE:
            status = "SUSPICIOUS" if suspicious else "NORMAL"
            print(f"[DEBUG] PID {pid} ({name}) → {status} | {severity} | {reasons}")

        if suspicious:
            self.last_alert_time[pid] = current_time

        return self._result(suspicious, severity, reasons, threat_type)

    def reset_cooldown(self, pid: int):
        """Manually clear the cooldown for a given PID (useful for testing)."""
        self.last_alert_time.pop(pid, None)

    def get_cooldown_status(self, pid: int) -> Dict:
        """Return how long the cooldown has remaining for a PID."""
        if pid not in self.last_alert_time:
            return {"in_cooldown": False, "remaining_seconds": 0.0}
        elapsed = time.time() - self.last_alert_time[pid]
        remaining = max(0.0, self.cooldown_seconds - elapsed)
        return {"in_cooldown": remaining > 0, "remaining_seconds": remaining}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _check_keywords(self, name: str, exe: str) -> str:
        """Return the first matching keyword found, or empty string."""
        combined = f"{name} {exe}"
        for kw in self._keywords:
            if kw in combined:
                return kw
        return ""

    def _check_sensitive_files(self, open_files: List[str]) -> str:
        """Return the first sensitive path matched, or empty string."""
        for f in open_files:
            for sensitive in self._sensitive:
                if f.startswith(sensitive):
                    return f
        return ""

    @staticmethod
    def _result(suspicious: bool, severity: str, reasons: List[str], threat_type: str) -> Dict:
        return {
            "suspicious": suspicious,
            "severity": severity,
            "reasons": reasons if reasons else ["Normal behavior"],
            "threat_type": threat_type,
        }
