"""
Copyright (c) 2026 José María Micoli
Licensed under {'license_type': 'Apache-2.0'}

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
"""

"""
detection_engine.py - Defensive Detection Tracking

Track defensive detections and assess impact.
Correlate detections with operator actions.
Calculate detection pressure.
"""

from typing import List, Dict
from engines.data_contracts import DetectionEvent


class DetectionEngine:
    """Track and analyze defensive detections"""
    
    def __init__(self):
        self.detections: List[DetectionEvent] = []
    
    def record_detection(self,
                        timestamp,
                        asset: str,
                        detection_type: str,
                        severity: int,
                        related_technique: str,
                        description: str,
                        confidence: float = 0.8) -> DetectionEvent:
        """Record a defensive detection event"""
        
        event = DetectionEvent(
            timestamp=timestamp,
            asset=asset,
            detection_type=detection_type,
            severity=severity,
            related_technique=related_technique,
            description=description,
            confidence=confidence,
        )
        
        self.detections.append(event)
        return event
    
    def get_detections_for_technique(self, technique: str) -> List[DetectionEvent]:
        """Get all detections related to a technique"""
        return [d for d in self.detections if d.related_technique == technique]
    
    def get_detections_for_asset(self, asset: str) -> List[DetectionEvent]:
        """Get all detections on a specific asset"""
        return [d for d in self.detections if d.asset == asset]
    
    def get_recent_detections(self, hours: int = 24) -> List[DetectionEvent]:
        """Get recent detections within time window"""
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(hours=hours)
        return [d for d in self.detections if d.timestamp > cutoff]
    
    def calculate_detection_pressure(self) -> float:
        """
        Calculate detection pressure (0-100).
        
        Higher = more detections, more severe
        
        pressure = (count * 5) + (max_severity * 10)
        """
        
        if not self.detections:
            return 0.0
        
        count = len(self.detections)
        max_severity = max((d.severity for d in self.detections), default=1)
        
        pressure = (count * 5) + (max_severity * 10)
        return max(0, min(100, pressure))
    
    def calculate_detection_trend(self, hours: int = 24) -> str:
        """
        Determine if detections are increasing/decreasing.
        
        Returns: "increasing", "stable", or "decreasing"
        """
        
        recent = self.get_recent_detections(hours)
        
        if not recent:
            return "stable"
        
        # Check if detections are accelerating
        if len(recent) > 3:
            rate = len(recent) / hours
            if rate > 0.5:  # More than 1 detection per 2 hours
                return "increasing"
            elif rate < 0.1:  # Less than 1 detection per 10 hours
                return "decreasing"
        
        return "stable"


__all__ = ['DetectionEngine']
