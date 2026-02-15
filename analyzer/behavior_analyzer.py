"""
Behavior Analyzer Module
Applies rule-based behavioral detection to processes with improved accuracy.
"""

import time
from typing import Dict, List
from config import EDRConfig


class BehaviorAnalyzer:
    """
    Analyzes process behavior using enhanced time-based rules.
    Includes consecutive checks, combined indicators, and cooldown mechanism.
    """

    def __init__(
        self,
        cpu_threshold: float = None,
        memory_threshold: float = None,
        cpu_consecutive_checks: int = None,
        combined_cpu_threshold: float = None,
        cooldown_seconds: int = None
    ):
        # Use config defaults if not specified
        self.cpu_threshold = cpu_threshold or EDRConfig.CPU_THRESHOLD
        self.memory_threshold = memory_threshold or EDRConfig.MEMORY_THRESHOLD
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
        current_time = time.time()
        
        # Check cooldown - prevent repeated alerts for same PID
        if pid in self.last_alert_time:
            time_since_last_alert = current_time - self.last_alert_time[pid]
            if time_since_last_alert < self.cooldown_seconds:
                # Still in cooldown period
                return {
                    "suspicious": False,
                    "severity": EDRConfig.SEVERITY_INFO,
                    "reasons": ["In cooldown period"]
                }
        
        reasons = []
        severity = EDRConfig.SEVERITY_INFO
        
        # Rule 1: Sustained high CPU usage (consecutive checks)
        # Only trigger if CPU stays above threshold for consecutive checks
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
                    f"Sustained high CPU usage: {process['cpu_percent']:.2f}% "
                    f"for {self.cpu_consecutive_checks} consecutive checks"
                )
                severity = EDRConfig.SEVERITY_WARNING
        
        # Rule 2: Combined high memory AND moderate CPU
        # More accurate detection - both must be elevated
        if (process['memory_percent'] >= self.memory_threshold and 
            process['cpu_percent'] >= self.combined_cpu_threshold):
            reasons.append(
                f"Combined threat: Memory {process['memory_percent']:.2f}% "
                f"AND CPU {process['cpu_percent']:.2f}%"
            )
            # Upgrade to CRITICAL if both are high
            severity = EDRConfig.SEVERITY_CRITICAL
        
        # Rule 3: Extreme memory usage alone (new rule)
        if process['memory_percent'] >= 85.0:
            reasons.append(
                f"Extreme memory usage: {process['memory_percent']:.2f}%"
            )
            severity = EDRConfig.SEVERITY_WARNING
        
        # Determine if suspicious based on reasons found
        suspicious = len(reasons) > 0
        
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
