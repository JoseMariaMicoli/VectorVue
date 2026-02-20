"""
Copyright (c) 2026 NyxeraLabs
Author: José María Micoli
Licensed under BSL 1.1
Change Date: 2033-02-17 → Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
"""

"""
vv_tempo: Operator Action Rate Analysis

Track operator pace and tempo:
- actions_per_hour
- actions_per_day
- action_intensity (burst vs sustained)

Detect activity spikes and recommend operational modes.
"""

from typing import List, Dict
from datetime import datetime, timedelta
from vv_cognition import TempoAnalysis


class TempoEngine:
    """
    Analyze operator action tempo.
    
    Modes:
    - slow_mode: 1-2 actions/hour (careful, stealth)
    - normal_mode: 3-5 actions/hour (balanced)
    - fast_mode: 6+ actions/hour (aggressive, risky)
    """
    
    def __init__(self):
        self.action_history = []  # [(timestamp, action_type), ...]
    
    def analyze_tempo(self,
                     recent_actions: List[Dict],
                     window_hours: int = 24) -> TempoAnalysis:
        """
        Analyze operator tempo from recent actions.
        
        Args:
        - recent_actions: List of {"timestamp": datetime, ...}
        - window_hours: Hours to analyze (default 24)
        
        Returns:
        - TempoAnalysis with intensity, spike detection, recommendations
        """
        
        if not recent_actions:
            return TempoAnalysis(
                campaign_id="unknown",
                actions_per_hour=0.0,
                actions_per_day=0.0,
                action_intensity="idle",
                activity_spike_detected=False,
                spike_severity=0.0,
                recommended_mode="normal_mode",
                explanation="No recent actions.",
                confidence=1.0
            )
        
        now = datetime.now()
        window_start = now - timedelta(hours=window_hours)
        
        # Filter actions in window
        in_window = [
            a for a in recent_actions
            if a.get("timestamp") and a.get("timestamp") > window_start
        ]
        
        if not in_window:
            return TempoAnalysis(
                campaign_id="unknown",
                actions_per_hour=0.0,
                actions_per_day=0.0,
                action_intensity="idle",
                activity_spike_detected=False,
                spike_severity=0.0,
                recommended_mode="normal_mode",
                explanation="No actions in window.",
                confidence=1.0
            )
        
        # Calculate rates
        actual_window = (now - in_window[0]["timestamp"]).total_seconds() / 3600
        actions_per_hour = len(in_window) / max(1, actual_window)
        actions_per_day = actions_per_hour * 24
        
        # Determine intensity
        if actions_per_hour < 1.5:
            intensity = "slow"
        elif actions_per_hour < 4:
            intensity = "normal"
        elif actions_per_hour < 8:
            intensity = "fast"
        else:
            intensity = "aggressive"
        
        # Detect spikes (rapid bursts)
        spike_detected, spike_severity = self._detect_spike(in_window)
        
        # Recommend mode based on intensity
        recommended_mode = self._recommend_mode(intensity, spike_detected)
        
        # Generate explanation
        explanation = self._generate_explanation(
            actions_per_hour, intensity, spike_detected, spike_severity
        )
        
        # Confidence
        confidence = min(0.95, 0.7 + (len(in_window) / 50.0))
        
        return TempoAnalysis(
            campaign_id="unknown",
            actions_per_hour=round(actions_per_hour, 2),
            actions_per_day=round(actions_per_day, 2),
            action_intensity=intensity,
            activity_spike_detected=spike_detected,
            spike_severity=round(spike_severity, 2),
            recommended_mode=recommended_mode,
            explanation=explanation,
            confidence=confidence
        )
    
    def _detect_spike(self, actions: List[Dict]) -> tuple:
        """
        Detect activity spikes (rapid action bursts).
        
        Returns (spike_detected, severity)
        """
        if len(actions) < 3:
            return False, 0.0
        
        # Calculate inter-action intervals (minutes)
        timestamps = sorted([
            a.get("timestamp") for a in actions
            if a.get("timestamp")
        ])
        
        if len(timestamps) < 3:
            return False, 0.0
        
        intervals = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i-1]).total_seconds() / 60
            intervals.append(delta)
        
        # Spike = very short intervals (< 5 min between actions)
        short_intervals = [i for i in intervals if i < 5]
        
        if len(short_intervals) >= 3:
            # Multiple rapid actions = spike
            severity = len(short_intervals) / len(intervals)
            return True, severity
        
        return False, 0.0
    
    def _recommend_mode(self, intensity: str, spike_detected: bool) -> str:
        """
        Recommend operational mode.
        """
        if spike_detected:
            return "slow_mode"  # Always slow on spike
        
        if intensity == "slow":
            return "normal_mode"  # Can sustain normal
        elif intensity in ["normal", "fast"]:
            return "fast_mode"  # Can maintain current pace
        else:  # aggressive
            return "slow_mode"  # Need to dial back
    
    def _generate_explanation(self, actions_per_hour: float,
                             intensity: str,
                             spike_detected: bool,
                             severity: float) -> str:
        """
        Generate human-readable tempo explanation.
        """
        explanation = f"Operating at {actions_per_hour:.1f} actions/hour ({intensity} pace). "
        
        if spike_detected:
            explanation += f"Activity spike detected (severity: {severity:.0%}). "
            explanation += "Recommend reverting to slow_mode to avoid detection."
        else:
            explanation += f"Tempo is sustainable."
        
        if intensity == "aggressive":
            explanation += " WARNING: Very aggressive pace increases detection risk."
        
        return explanation
    
    def assess_detection_risk_from_tempo(self, actions_per_hour: float,
                                        detection_pressure: int) -> Dict:
        """
        Assess how tempo contributes to detection risk.
        """
        # Fast action rate + high detection pressure = very risky
        combined_risk = (actions_per_hour / 10.0) + (detection_pressure / 100.0)
        combined_risk = min(1.0, combined_risk)
        
        if combined_risk > 0.7:
            risk_level = "critical"
            advice = "Immediately reduce pace"
        elif combined_risk > 0.5:
            risk_level = "high"
            advice = "Consider slowing down"
        else:
            risk_level = "acceptable"
            advice = "Current tempo acceptable"
        
        return {
            "combined_risk": round(combined_risk, 2),
            "risk_level": risk_level,
            "advice": advice,
            "actions_per_hour": actions_per_hour,
            "detection_pressure": detection_pressure,
        }


__all__ = [
    'TempoEngine',
]
