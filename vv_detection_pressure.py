"""
Copyright (c) 2026 José María Micoli
Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
"""

"""
vv_detection_pressure: Detection Pressure Tracking

Track defensive detection state:
pressure = recent_alerts + failed_actions + repetition_penalty (0-100)

State machine: QUIET → CAUTION → WATCHED → HUNTING → COMPROMISED
"""

from typing import List, Dict
from enum import Enum
from datetime import datetime, timedelta
from vv_cognition import DetectionPressure, DetectionEvent, DetectionState


class PressureTrend(Enum):
    """Detection pressure trend."""
    DECREASING = "decreasing"
    STABLE = "stable"
    INCREASING = "increasing"


class DetectionPressureEngine:
    """
    Track and calculate detection pressure.
    
    pressure = recent_alerts + failed_actions + repetition_penalty
    
    States:
    - QUIET (0-20): Minimal defensive activity
    - CAUTION (21-40): Increased alertness
    - WATCHED (41-60): Active monitoring
    - HUNTING (61-80): Active hunt
    - COMPROMISED (81-100): Assumed compromised
    """
    
    def __init__(self):
        self.pressure_history = []  # Track recent pressure calculations
    
    def calculate_pressure(self,
                          detections: List[DetectionEvent],
                          failed_actions: List[Dict],
                          recent_actions_window: int = 24) -> DetectionPressure:
        """
        Calculate detection pressure from defensive detections and failed actions.
        
        Args:
        - detections: List of DetectionEvent objects
        - failed_actions: List of failed operator actions
        - recent_actions_window: Hours to look back for recent activity
        
        Returns:
        - DetectionPressure object with state and trend
        """
        
        now = datetime.now()
        window_start = now - timedelta(hours=recent_actions_window)
        
        # Count recent alerts
        recent_alerts = len([
            d for d in detections
            if hasattr(d, 'detected_at') and d.detected_at > window_start
        ])
        
        # Failed actions penalty
        failed_count = len(failed_actions)
        failed_penalty = failed_count * 5  # 5 points per failure
        
        # Repetition penalty (same technique repeated)
        technique_counts = {}
        for action in failed_actions:
            tech = action.get("technique", "unknown")
            technique_counts[tech] = technique_counts.get(tech, 0) + 1
        
        repetition_penalty = sum(
            count - 1 if count > 1 else 0
            for count in technique_counts.values()
        ) * 3  # 3 points per repeat
        
        # Base pressure from alerts
        alert_pressure = min(80, recent_alerts * 2)  # Each alert = 2 points, max 80
        
        # Total pressure (0-100 scale)
        total_pressure = min(100, alert_pressure + failed_penalty + repetition_penalty)
        
        # Determine state
        state = self._pressure_to_state(total_pressure)
        
        # Calculate trend
        self.pressure_history.append((now, total_pressure))
        # Keep last 100 measurements
        self.pressure_history = self.pressure_history[-100:]
        
        trend = self._calculate_trend()
        
        # Health (inverse of pressure)
        health = 100 - total_pressure
        
        # Build confidence
        confidence = min(
            0.95,
            0.6 + (len(detections) / 100.0)  # More detections = more confidence
        )
        
        return DetectionPressure(
            campaign_id="unknown",  # Set by caller
            recent_alerts=recent_alerts,
            failed_actions=failed_count,
            repetition_penalty=repetition_penalty,
            total_pressure=total_pressure,
            health=health,
            state=state,
            confidence=confidence,
            pressure_trend=trend
        )
    
    def _pressure_to_state(self, pressure: int) -> DetectionState:
        """
        Convert pressure (0-100) to detection state.
        """
        if pressure <= 20:
            return DetectionState.QUIET
        elif pressure <= 40:
            return DetectionState.CAUTION
        elif pressure <= 60:
            return DetectionState.WATCHED
        elif pressure <= 80:
            return DetectionState.HUNTING
        else:
            return DetectionState.COMPROMISED
    
    def _calculate_trend(self) -> str:
        """
        Calculate trend from pressure history.
        
        Returns: "decreasing", "stable", or "increasing"
        """
        if len(self.pressure_history) < 3:
            return "stable"
        
        # Get last 3 measurements
        recent = [p for _, p in self.pressure_history[-3:]]
        
        # Simple linear trend
        if recent[-1] > recent[-2] > recent[-3]:
            return "increasing"
        elif recent[-1] < recent[-2] < recent[-3]:
            return "decreasing"
        else:
            return "stable"
    
    def evaluate_risk_threshold(self, pressure: int) -> Dict[str, any]:
        """
        Evaluate if current pressure exceeds safe thresholds.
        
        Returns dict with warnings and recommendations.
        """
        state = self._pressure_to_state(pressure)
        
        warnings = []
        recommendations = []
        
        if state == DetectionState.WATCHED:
            warnings.append("Elevated detection activity detected")
            recommendations.append("Reduce action frequency")
            recommendations.append("Avoid noisy techniques (T1110, T1548)")
        
        elif state == DetectionState.HUNTING:
            warnings.append("Active hunt detected - defensive team is mobilized")
            recommendations.append("Consider switching to passive intelligence gathering")
            recommendations.append("Use only established access (credentials, sessions)")
            recommendations.append("Avoid any new exploitation")
        
        elif state == DetectionState.COMPROMISED:
            warnings.append("CRITICAL: Likely detected and isolated")
            recommendations.append("Do not execute further actions")
            recommendations.append("Execute exfiltration if planned")
            recommendations.append("Prepare for remediation by defender")
        
        return {
            "state": state.value,
            "pressure": pressure,
            "warnings": warnings,
            "recommendations": recommendations,
            "safe_to_continue": state in [DetectionState.QUIET, DetectionState.CAUTION]
        }


__all__ = [
    'DetectionPressureEngine',
    'PressureTrend',
]
