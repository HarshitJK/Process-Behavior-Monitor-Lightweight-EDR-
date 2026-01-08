"""
Behavior Analyzer Module
Applies rule-based behavioral detection to processes.
"""

from typing import Dict, List


class BehaviorAnalyzer:
    """
    Analyzes process behavior using time-based rules.
    """

    def __init__(
        self,
        cpu_threshold: float = 80.0,
        memory_threshold: float = 70.0,
        cpu_samples_required: int = 5
    ):
        self.cpu_threshold = cpu_threshold
        self.memory_threshold = memory_threshold
        self.cpu_samples_required = cpu_samples_required

    def analyze(
        self,
        process: Dict,
        history: List[Dict]
    ) -> Dict:
        """
        Analyze a process and its behavior history.

        Returns:
            Dict:
            - suspicious (bool)
            - reasons (List[str])
        """

        reasons = []

        # Rule 1: High memory usage
        if process['memory_percent'] >= self.memory_threshold:
            reasons.append(
                f"High memory usage: {process['memory_percent']:.2f}%"
            )

        # Rule 2: Sustained high CPU usage
        high_cpu_count = sum(
            1 for entry in history
            if entry['cpu'] >= self.cpu_threshold
        )

        if high_cpu_count >= self.cpu_samples_required:
            reasons.append(
                f"Sustained high CPU usage (> {self.cpu_threshold}%)"
            )

        return {
            "suspicious": len(reasons) > 0,
            "reasons": reasons if reasons else ["Normal behavior"]
        }
