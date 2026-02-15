"""
Behavior Analyzer Module
Applies rule-based behavioral detection to processes with improved accuracy.
FIXED: Independent memory detection, debug mode, proper severity escalation.
"""

import time
from typing import Dict, List
from config import EDRConfig


class BehaviorAnalyzer:
    """
    Analyzes process behavior using enhanced time-based rules.
    Includes consecutive checks, combined indicators, and cooldown mechanism.
    
    FIXES APPLIED:
    - Memory detection now works independently of CPU
    - Added configurable memory thresholds (60% WARNING, 80% CRITICAL)
    - Added debug mode for troubleshooting
    - Fixed severity escalation logic
    """

    def __init__(
        self,
        cpu_threshold: float = None,
        memory_warning_threshold: float = None,
        memory_critical_threshold: float = None,
        cpu_consecutive_checks: int = None,
        combined_cpu_threshold: float = None,
        cooldown_seconds: int = None
    ):
        # Use config defaults if not specified
        self.cpu_threshold = cpu_threshold or EDRConfig.CPU_THRESHOLD
        self.memory_warning_threshold = memory_warning_threshold or EDRConfig.MEMORY_WARNING_THRESHOLD
        self.memory_critical_threshold = memory_critical_threshold or EDRConfig.MEMORY_CRITICAL_THRESHOLD
        self.cpu_consecutive_checks = cpu_consecutive_checks or EDRConfig.CPU_CONSECUTIVE_CHECKS
        self.combined_cpu_threshold = combined_cpu_threshold or EDRConfig.COMBINED_CPU_THRESHOLD
        self.cooldown_seconds = cooldown_seconds or EDRConfig.ALERT_COOLDOWN_SECONDS
        
        # Track last alert time for each PID (cooldown mechanism)
        self.last_alert_time = {}

    def analyze(
        self,
        process: Dict,
        history: List[Dict]
    ) -> Dict:
        """
        Analyze a process and its behavior history with improved detection.

        Returns:
            Dict:
            - suspicious (bool)
            - severity (str): INFO, WARNING, or CRITICAL
            - reasons (List[str])
        """
        pid = process['pid']
        name = process.get('name', 'unknown')
        cpu_percent = process['cpu_percent']
        memory_percent = process['memory_percent']
        current_time = time.time()
        
        # DEBUG MODE: Print process info
        if EDRConfig.DEBUG_MODE:
            print(f"\n[DEBUG] Analyzing PID {pid} ({name})")
            print(f"[DEBUG]   CPU: {cpu_percent:.2f}%")
            print(f"[DEBUG]   Memory: {memory_percent:.2f}%")
        
        # Check cooldown - prevent repeated alerts for same PID
        if pid in self.last_alert_time:
            time_since_last_alert = current_time - self.last_alert_time[pid]
            if time_since_last_alert < self.cooldown_seconds:
                # Still in cooldown period
                if EDRConfig.DEBUG_MODE:
                    print(f"[DEBUG]   Status: In cooldown ({time_since_last_alert:.1f}s / {self.cooldown_seconds}s)")
                return {
                    "suspicious": False,
                    "severity": EDRConfig.SEVERITY_INFO,
                    "reasons": ["In cooldown period"]
                }
        
        reasons = []
        severity = EDRConfig.SEVERITY_INFO
        
        # ========================================
        # RULE 1: Sustained High CPU Usage
        # ========================================
        consecutive_high_cpu = 0
        if len(history) >= self.cpu_consecutive_checks:
            # Check last N entries for consecutive high CPU
            recent_history = history[-self.cpu_consecutive_checks:]
            consecutive_high_cpu = sum(
                1 for entry in recent_history
                if entry['cpu'] >= self.cpu_threshold
            )
            
            if consecutive_high_cpu >= self.cpu_consecutive_checks:
                reasons.append(
                    f"Sustained high CPU usage: {cpu_percent:.2f}% "
                    f"for {self.cpu_consecutive_checks} consecutive checks"
                )
                severity = EDRConfig.SEVERITY_WARNING
                
                if EDRConfig.DEBUG_MODE:
                    print(f"[DEBUG]   Rule 1 TRIGGERED: Sustained CPU")
        
        # ========================================
        # RULE 2: INDEPENDENT Memory Detection (FIXED)
        # ========================================
        # Memory detection now works WITHOUT requiring high CPU
        
        # CRITICAL: Memory >= 80% (independent of CPU)
        if memory_percent >= self.memory_critical_threshold:
            reasons.append(
                f"CRITICAL memory usage: {memory_percent:.2f}% "
                f"(threshold: {self.memory_critical_threshold}%)"
            )
            severity = EDRConfig.SEVERITY_CRITICAL  # Escalate to CRITICAL
            
            if EDRConfig.DEBUG_MODE:
                print(f"[DEBUG]   Rule 2a TRIGGERED: CRITICAL Memory (>={self.memory_critical_threshold}%)")
        
        # WARNING: Memory >= 60% but < 80% (independent of CPU)
        elif memory_percent >= self.memory_warning_threshold:
            reasons.append(
                f"High memory usage: {memory_percent:.2f}% "
                f"(threshold: {self.memory_warning_threshold}%)"
            )
            # Only set to WARNING if not already CRITICAL from CPU
            if severity != EDRConfig.SEVERITY_CRITICAL:
                severity = EDRConfig.SEVERITY_WARNING
            
            if EDRConfig.DEBUG_MODE:
                print(f"[DEBUG]   Rule 2b TRIGGERED: WARNING Memory (>={self.memory_warning_threshold}%)")
        
        # ========================================
        # RULE 3: Combined High Memory + Moderate CPU
        # ========================================
        # This is an ADDITIONAL check for combined threats
        # FIXED: Use configurable threshold instead of hardcoded value
        if (memory_percent >= EDRConfig.MEMORY_THRESHOLD and 
            cpu_percent >= self.combined_cpu_threshold):
            # Only add if not already detected by Rule 2
            combined_reason = (
                f"Combined threat: Memory {memory_percent:.2f}% "
                f"AND CPU {cpu_percent:.2f}%"
            )
            if combined_reason not in reasons:
                reasons.append(combined_reason)
            
            # Escalate to CRITICAL for combined threat
            severity = EDRConfig.SEVERITY_CRITICAL
            
            if EDRConfig.DEBUG_MODE:
                print(f"[DEBUG]   Rule 3 TRIGGERED: Combined Memory+CPU")
        
        # Determine if suspicious based on reasons found
        suspicious = len(reasons) > 0
        
        # DEBUG MODE: Print decision
        if EDRConfig.DEBUG_MODE:
            print(f"[DEBUG]   Decision: {'SUSPICIOUS' if suspicious else 'NORMAL'}")
            print(f"[DEBUG]   Severity: {severity}")
            print(f"[DEBUG]   Reasons: {reasons}")
        
        # Update last alert time if suspicious
        if suspicious:
            self.last_alert_time[pid] = current_time
        
        return {
            "suspicious": suspicious,
            "severity": severity,
            "reasons": reasons if reasons else ["Normal behavior"]
        }
    
    def reset_cooldown(self, pid: int):
        """
        Manually reset cooldown for a specific PID.
        Useful for testing or manual intervention.
        """
        if pid in self.last_alert_time:
            del self.last_alert_time[pid]
    
    def get_cooldown_status(self, pid: int) -> Dict:
        """
        Get cooldown status for a PID.
        
        Returns:
            Dict with 'in_cooldown' (bool) and 'remaining_seconds' (float)
        """
        if pid not in self.last_alert_time:
            return {"in_cooldown": False, "remaining_seconds": 0}
        
        current_time = time.time()
        time_since_alert = current_time - self.last_alert_time[pid]
        remaining = max(0, self.cooldown_seconds - time_since_alert)
        
        return {
            "in_cooldown": remaining > 0,
            "remaining_seconds": remaining
        }
