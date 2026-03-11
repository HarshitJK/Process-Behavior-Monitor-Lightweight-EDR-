"""
Behavior Analyzer – rule-based detection engine.

Four-Tier Severity Model:
  LOW      → log only
  MEDIUM   → alert (notification, no process action)
  HIGH     → suspend process
  CRITICAL → terminate process

Rules:
  A   High instantaneous CPU  → MEDIUM
  A+  CPU ≥ CPU_CRITICAL_THRESHOLD → HIGH (immediate, no consecutive wait)
  B   High memory             → MEDIUM / HIGH
  C   Sustained high CPU (N consecutive scans) → CRITICAL
  D   Suspicious keyword in name/exe → MEDIUM
  E   Sensitive file access   → HIGH
  F   Rapid spawning from same PARENT PID → MEDIUM / CRITICAL
      (uses per-parent spawn counts from ProcessScanner)

Protected / safe processes skip all analysis and are NEVER returned as
suspicious (defense-in-depth: BehaviorAnalyzer + Responder both check).
"""

import time
from typing import Dict, List, Optional
from config import EDRConfig

# Ordered severity levels for comparison
_SEV_ORDER = {
    EDRConfig.SEVERITY_LOW:      0,
    EDRConfig.SEVERITY_MEDIUM:   1,
    EDRConfig.SEVERITY_HIGH:     2,
    EDRConfig.SEVERITY_CRITICAL: 3,
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
        self.cpu_threshold   = cpu_threshold           if cpu_threshold           is not None else EDRConfig.CPU_THRESHOLD
        self.cpu_crit        = EDRConfig.CPU_CRITICAL_THRESHOLD
        self.mem_warn        = memory_warning_threshold  if memory_warning_threshold  is not None else EDRConfig.MEMORY_WARNING_THRESHOLD
        self.mem_crit        = memory_critical_threshold if memory_critical_threshold is not None else EDRConfig.MEMORY_CRITICAL_THRESHOLD
        self.cpu_consecutive = cpu_consecutive_checks    if cpu_consecutive_checks    is not None else EDRConfig.CPU_CONSECUTIVE_CHECKS
        self.cooldown_seconds = cooldown_seconds         if cooldown_seconds          is not None else EDRConfig.ALERT_COOLDOWN_SECONDS

        self.last_alert_time: Dict[int, float] = {}
        self._keywords   = [kw.lower() for kw in EDRConfig.SUSPICIOUS_KEYWORDS]
        self._sensitive  = [p.lower()  for p in EDRConfig.SENSITIVE_PATHS]
        # Safe / protected – skip analysis entirely (defense-in-depth)
        self._safe_procs = {p.lower() for p in EDRConfig.SAFE_PROCESSES}
        self._protected  = {p.lower() for p in EDRConfig.PROTECTED_PROCESSES}
        # Prefix-based safe list (handles kworker/0:1, ksoftirqd/3, etc.)
        self._safe_prefixes = [p.lower() for p in EDRConfig.SAFE_PROCESS_PREFIXES]

    # ------------------------------------------------------------------

    def analyze(
        self,
        process: Dict,
        history: List[Dict],
        parent_spawn_counts: Optional[Dict[int, int]] = None,
        # Legacy param kept for backward compat – ignored if parent_spawn_counts given
        recent_spawn_count: int = 0,
    ) -> Dict:
        """
        Analyze a single process and return a result dict.

        Args:
            process:             Process info dict from ProcessScanner.
            history:             Per-PID CPU/memory history list.
            parent_spawn_counts: {parent_pid: child_count_in_window} from
                                 ProcessScanner.get_parent_spawn_counts().
                                 Preferred over legacy recent_spawn_count.
            recent_spawn_count:  Legacy system-wide count (ignored when
                                 parent_spawn_counts is provided).
        """
        pid  = process.get("pid", -1)
        ppid = process.get("ppid", 0)
        name = (process.get("name") or "unknown").lower()
        exe  = (process.get("exe")  or "").lower()
        cpu  = process.get("cpu_percent",    0.0)
        mem  = process.get("memory_percent", 0.0)
        open_files: List[str] = [f.lower() for f in process.get("open_files", [])]
        now  = time.time()

        # Defense-in-depth: skip safe and protected processes entirely.
        # Checks:
        #  1. EDR's own PID – always skip (prevents self-flagging).
        #  2. Exact name match in safe / protected sets.
        #  3. Prefix match (catches kworker/0:1, ksoftirqd/3, etc.).
        if pid == EDRConfig.EDR_OWN_PID:
            return self._result(False, EDRConfig.SEVERITY_LOW,
                                ["EDR self-exclusion – own process skipped"], "NONE")
        if self._is_safe(name):
            return self._result(False, EDRConfig.SEVERITY_LOW,
                                ["Trusted/protected process – skipped"], "NONE")

        # Cooldown gate
        if pid in self.last_alert_time:
            if now - self.last_alert_time[pid] < self.cooldown_seconds:
                return self._result(False, EDRConfig.SEVERITY_LOW,
                                    ["In cooldown period"], "NONE")

        reasons: List[str] = []
        severity: str = EDRConfig.SEVERITY_LOW
        threat_type: str = "NONE"

        # ---- Rule A+: Instant HIGH CPU ----------------------------------------
        if cpu >= self.cpu_crit:
            reasons.append(
                f"Critical CPU usage: {cpu:.1f}% (critical threshold: {self.cpu_crit}%)"
            )
            severity = _max_sev(severity, EDRConfig.SEVERITY_HIGH)
            threat_type = "HIGH_CPU"

        # ---- Rule A: High CPU (MEDIUM) ----------------------------------------
        elif cpu >= self.cpu_threshold:
            reasons.append(
                f"High CPU usage: {cpu:.1f}% (threshold: {self.cpu_threshold}%)"
            )
            severity = _max_sev(severity, EDRConfig.SEVERITY_MEDIUM)
            threat_type = "HIGH_CPU"

        # ---- Rule B: Memory ---------------------------------------------------
        if mem >= self.mem_crit:
            reasons.append(
                f"Critical memory usage: {mem:.1f}% (critical: {self.mem_crit}%)"
            )
            severity = _max_sev(severity, EDRConfig.SEVERITY_HIGH)
            if threat_type == "NONE":
                threat_type = "HIGH_MEMORY"

        elif mem >= self.mem_warn:
            reasons.append(
                f"High memory usage: {mem:.1f}% (warning: {self.mem_warn}%)"
            )
            severity = _max_sev(severity, EDRConfig.SEVERITY_MEDIUM)
            if threat_type == "NONE":
                threat_type = "HIGH_MEMORY"

        # ---- Rule C: Sustained CPU → CRITICAL (only non-protected) -----------
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

        # ---- Rule D: Suspicious keyword → MEDIUM ------------------------------
        kw = self._check_keywords(name, exe)
        if kw:
            reasons.append(f"Suspicious keyword in process name/path: '{kw}'")
            severity = _max_sev(severity, EDRConfig.SEVERITY_MEDIUM)
            if threat_type == "NONE":
                threat_type = "SUSPICIOUS_NAME"

        # ---- Rule E: Sensitive file access → HIGH -----------------------------
        sf = self._check_sensitive_files(open_files)
        if sf:
            reasons.append(f"Access to sensitive path: {sf}")
            severity = _max_sev(severity, EDRConfig.SEVERITY_HIGH)
            threat_type = "SENSITIVE_FILE_ACCESS"

        # ---- Rule F: Rapid spawn detection (PER-PARENT-PID) ------------------
        # Use per-parent counts when available (new API), else fall back to
        # legacy system-wide count for backward compatibility.
        ppid_spawn_count = 0
        if parent_spawn_counts is not None:
            # Check how many children THIS process's parent has spawned
            ppid_spawn_count = parent_spawn_counts.get(ppid, 0)
            # Also check if this process itself is a heavy spawner (as a parent)
            ppid_spawn_count = max(ppid_spawn_count,
                                   parent_spawn_counts.get(pid, 0))
        else:
            ppid_spawn_count = recent_spawn_count

        spawn_thresh = EDRConfig.SPAWN_RATE_THRESHOLD
        if ppid_spawn_count >= spawn_thresh:
            sev_f = (EDRConfig.SEVERITY_CRITICAL
                     if ppid_spawn_count >= spawn_thresh * 2
                     else EDRConfig.SEVERITY_MEDIUM)
            reasons.append(
                f"Rapid process spawning from parent PID {ppid}: "
                f"{ppid_spawn_count} children in {EDRConfig.SPAWN_TIME_WINDOW}s"
            )
            severity = _max_sev(severity, sev_f)
            if threat_type == "NONE":
                threat_type = "PROCESS_SPAWN_ANOMALY"

        suspicious = len(reasons) > 0

        if EDRConfig.DEBUG_MODE and suspicious:
            print(f"[DEBUG] PID {pid} ({name}) → {severity} | {reasons}")

        if suspicious:
            self.last_alert_time[pid] = now

        return self._result(suspicious, severity, reasons, threat_type)

    def reset_cooldown(self, pid: int):
        self.last_alert_time.pop(pid, None)

    # ------------------------------------------------------------------

    def _is_safe(self, name: str) -> bool:
        """
        Return True if *name* should be considered a trusted process.

        Two-tier check:
          1. Exact match  – O(1) set lookup against safe_procs + protected.
          2. Prefix match – linear scan of SAFE_PROCESS_PREFIXES.
             Needed for kernel threads whose names end with CPU/core numbers
             (e.g. "kworker/0:1", "ksoftirqd/3", "migration/0").
        """
        if name in self._safe_procs or name in self._protected:
            return True
        for prefix in self._safe_prefixes:
            if name.startswith(prefix):
                return True
        return False

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
            "suspicious":  suspicious,
            "severity":    severity,
            "reasons":     reasons if reasons else ["Normal behavior"],
            "threat_type": threat_type,
        }
