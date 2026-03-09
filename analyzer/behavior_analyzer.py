"""
Behavior Analyzer – rule-based detection engine.

Rules:
  A  High instantaneous CPU  → WARNING
  A+ CPU ≥ CPU_CRITICAL_THRESHOLD → CRITICAL (immediate, no consecutive wait)
  B  High memory             → WARNING / CRITICAL
  C  Sustained high CPU (N consecutive scans) → CRITICAL
  D  Suspicious keyword in name/exe → WARNING
  E  Sensitive file access   → CRITICAL
  F  Rapid process spawning  → WARNING / CRITICAL
"""

import time
from typing import Dict, List, Optional
from config import EDRConfig

_SEV_ORDER = {
    EDRConfig.SEVERITY_INFO:     0,
    EDRConfig.SEVERITY_WARNING:  1,
    EDRConfig.SEVERITY_CRITICAL: 2,
}


def _max_sev(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 0) >= _SEV_ORDER.get(b, 0) else b


class BehaviorAnalyzer:

    def __init__(
        self,
        cpu_threshold: Optional[float] = None,
        memory_warning_threshold: Optional[float] = None,
        memory_critical_threshold: Optional[float] = None,
        cpu_consecutive_checks: Optional[int] = None,
        cooldown_seconds: Optional[int] = None,
    ):
        self.cpu_threshold  = cpu_threshold or EDRConfig.CPU_THRESHOLD
        self.cpu_crit       = EDRConfig.CPU_CRITICAL_THRESHOLD
        self.mem_warn       = memory_warning_threshold or EDRConfig.MEMORY_WARNING_THRESHOLD
        self.mem_crit       = memory_critical_threshold or EDRConfig.MEMORY_CRITICAL_THRESHOLD
        self.cpu_consecutive = cpu_consecutive_checks or EDRConfig.CPU_CONSECUTIVE_CHECKS
        self.cooldown_seconds = cooldown_seconds or EDRConfig.ALERT_COOLDOWN_SECONDS

        self.last_alert_time: Dict[int, float] = {}
        self._keywords  = [kw.lower() for kw in EDRConfig.SUSPICIOUS_KEYWORDS]
        self._sensitive = [p.lower() for p in EDRConfig.SENSITIVE_PATHS]

    # ------------------------------------------------------------------

    def analyze(
        self,
        process: Dict,
        history: List[Dict],
        recent_spawn_count: int = 0,
    ) -> Dict:
        pid  = process.get("pid", -1)
        name = (process.get("name") or "unknown").lower()
        exe  = (process.get("exe")  or "").lower()
        cpu  = process.get("cpu_percent",    0.0)
        mem  = process.get("memory_percent", 0.0)
        open_files: List[str] = [f.lower() for f in process.get("open_files", [])]
        now  = time.time()

        # Cooldown gate
        if pid in self.last_alert_time:
            if now - self.last_alert_time[pid] < self.cooldown_seconds:
                return self._result(False, EDRConfig.SEVERITY_INFO,
                                    ["In cooldown period"], "NONE")

        reasons: List[str] = []
        severity: str = EDRConfig.SEVERITY_INFO
        threat_type: str = "NONE"

        # ---- Rule A+: Instant CRITICAL CPU --------------------------------
        if cpu >= self.cpu_crit:
            reasons.append(
                f"Critical CPU usage: {cpu:.1f}% (critical threshold: {self.cpu_crit}%)"
            )
            severity = _max_sev(severity, EDRConfig.SEVERITY_CRITICAL)
            threat_type = "HIGH_CPU"

        # ---- Rule A: High CPU (WARNING) -----------------------------------
        elif cpu >= self.cpu_threshold:
            reasons.append(
                f"High CPU usage: {cpu:.1f}% (threshold: {self.cpu_threshold}%)"
            )
            severity = _max_sev(severity, EDRConfig.SEVERITY_WARNING)
            threat_type = "HIGH_CPU"

        # ---- Rule B: Memory -----------------------------------------------
        if mem >= self.mem_crit:
            reasons.append(
                f"Critical memory usage: {mem:.1f}% (critical: {self.mem_crit}%)"
            )
            severity = _max_sev(severity, EDRConfig.SEVERITY_CRITICAL)
            if threat_type == "NONE":
                threat_type = "HIGH_MEMORY"

        elif mem >= self.mem_warn:
            reasons.append(
                f"High memory usage: {mem:.1f}% (warning: {self.mem_warn}%)"
            )
            severity = _max_sev(severity, EDRConfig.SEVERITY_WARNING)
            if threat_type == "NONE":
                threat_type = "HIGH_MEMORY"

        # ---- Rule C: Sustained CPU ----------------------------------------
        if len(history) >= self.cpu_consecutive:
            recent = history[-self.cpu_consecutive:]
            sustained = sum(1 for h in recent if h["cpu"] >= self.cpu_threshold)
            if sustained >= self.cpu_consecutive:
                reasons.append(
                    f"Sustained high CPU: {cpu:.1f}% for "
                    f"{self.cpu_consecutive} consecutive scans"
                )
                severity = _max_sev(severity, EDRConfig.SEVERITY_CRITICAL)
                threat_type = "RESOURCE_ABUSE"

        # ---- Rule D: Suspicious keyword -----------------------------------
        kw = self._check_keywords(name, exe)
        if kw:
            reasons.append(f"Suspicious keyword in process name/path: '{kw}'")
            severity = _max_sev(severity, EDRConfig.SEVERITY_WARNING)
            if threat_type == "NONE":
                threat_type = "SUSPICIOUS_NAME"

        # ---- Rule E: Sensitive file access --------------------------------
        sf = self._check_sensitive_files(open_files)
        if sf:
            reasons.append(f"Access to sensitive path: {sf}")
            severity = _max_sev(severity, EDRConfig.SEVERITY_CRITICAL)
            threat_type = "SENSITIVE_FILE_ACCESS"

        # ---- Rule F: Rapid spawn ------------------------------------------
        spawn_thresh = EDRConfig.SPAWN_RATE_THRESHOLD
        if recent_spawn_count >= spawn_thresh:
            reasons.append(
                f"Rapid process spawning: {recent_spawn_count} new processes "
                f"in {EDRConfig.SPAWN_TIME_WINDOW}s"
            )
            sev_f = (EDRConfig.SEVERITY_CRITICAL if recent_spawn_count >= spawn_thresh * 2
                     else EDRConfig.SEVERITY_WARNING)
            severity = _max_sev(severity, sev_f)
            if threat_type == "NONE":
                threat_type = "PROCESS_INJECTION"

        suspicious = len(reasons) > 0

        if EDRConfig.DEBUG_MODE and suspicious:
            print(f"[DEBUG] PID {pid} ({name}) → {severity} | {reasons}")

        if suspicious:
            self.last_alert_time[pid] = now

        return self._result(suspicious, severity, reasons, threat_type)

    def reset_cooldown(self, pid: int):
        self.last_alert_time.pop(pid, None)

    # ------------------------------------------------------------------

    def _check_keywords(self, name: str, exe: str) -> str:
        combined = f"{name} {exe}"
        for kw in self._keywords:
            if kw in combined:
                return kw
        return ""

    def _check_sensitive_files(self, open_files: List[str]) -> str:
        for f in open_files:
            for s in self._sensitive:
                if f.startswith(s):
                    return f
        return ""

    @staticmethod
    def _result(suspicious: bool, severity: str, reasons: List[str],
                threat_type: str) -> Dict:
        return {
            "suspicious": suspicious,
            "severity":   severity,
            "reasons":    reasons if reasons else ["Normal behavior"],
            "threat_type": threat_type,
        }
