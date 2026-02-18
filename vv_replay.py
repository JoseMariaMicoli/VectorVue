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
vv_replay: Append-Only Event Log

Immutable event history for campaign narrative and replay.

Events structure:
- What: action_description
- When: timestamp
- Who: actor (operator ID)
- Result: success/failure with evidence

Generate narrative from events for debrief and analysis.
"""

from typing import List, Dict, Optional
from datetime import datetime
from vv_cognition import ReplayEvent


class ReplayEngine:
    """
    Append-only event log for campaign narrative.
    
    Every action, detection, credential discovery is logged.
    Enables:
    - Campaign narrative generation
    - Timeline analysis
    - Operator behavior patterns
    - What-if scenario replay
    """
    
    def __init__(self, campaign_id: str):
        self.campaign_id = campaign_id
        self.events: List[ReplayEvent] = []
        self.event_counter = 0
    
    def record_event(self,
                    event_type: str,
                    actor: str,
                    action_description: str,
                    target_asset: int = None,
                    technique: str = None,
                    success: bool = True,
                    evidence: Dict = None) -> ReplayEvent:
        """
        Record an event (append-only).
        
        Args:
        - event_type: "action" / "detection" / "discovery" / "analysis"
        - actor: operator ID or "system"
        - action_description: what happened
        - target_asset: asset ID (optional)
        - technique: MITRE technique (optional)
        - success: action succeeded/failed
        - evidence: supporting data
        
        Returns:
        - ReplayEvent object
        """
        
        self.event_counter += 1
        
        event = ReplayEvent(
            event_id=f"{self.campaign_id}_{self.event_counter:04d}",
            campaign_id=self.campaign_id,
            timestamp=datetime.now(),
            event_type=event_type,
            actor=actor,
            action_description=action_description,
            target_asset=target_asset,
            mitre_technique=technique,
            related_findings=[],
            success=success,
            evidence=evidence or {}
        )
        
        self.events.append(event)
        return event
    
    def record_operator_action(self,
                              operator_id: str,
                              action_type: str,
                              target_asset: int,
                              technique: str,
                              description: str,
                              success: bool,
                              notes: str = None) -> ReplayEvent:
        """
        Record operator action specifically.
        """
        return self.record_event(
            event_type="action",
            actor=operator_id,
            action_description=f"{action_type}: {description}",
            target_asset=target_asset,
            technique=technique,
            success=success,
            evidence={"notes": notes} if notes else {}
        )
    
    def record_detection(self,
                        detection_id: str,
                        detector: str,
                        severity: str,
                        description: str,
                        related_technique: str = None) -> ReplayEvent:
        """
        Record defensive detection event.
        """
        return self.record_event(
            event_type="detection",
            actor="defender",
            action_description=f"[{severity.upper()}] {detector}: {description}",
            technique=related_technique,
            success=True,
            evidence={"detector": detector, "severity": severity}
        )
    
    def record_credential_discovery(self,
                                   credential_id: str,
                                   username: str,
                                   credential_type: str,
                                   source_asset: int,
                                   operator_id: str) -> ReplayEvent:
        """
        Record credential discovery.
        """
        return self.record_event(
            event_type="discovery",
            actor=operator_id,
            action_description=f"Discovered {credential_type} credential: {username}",
            target_asset=source_asset,
            success=True,
            evidence={"credential_id": credential_id, "type": credential_type}
        )
    
    def generate_narrative(self, from_time: datetime = None,
                          to_time: datetime = None) -> str:
        """
        Generate campaign narrative from events.
        
        Args:
        - from_time: Start of time window (optional)
        - to_time: End of time window (optional)
        
        Returns:
        - Markdown narrative
        """
        
        # Filter by time window
        filtered = self.events
        if from_time:
            filtered = [e for e in filtered if e.timestamp >= from_time]
        if to_time:
            filtered = [e for e in filtered if e.timestamp <= to_time]
        
        if not filtered:
            return f"# {self.campaign_id} Campaign Narrative\n\nNo events in time window."
        
        # Group by day
        by_day = {}
        for event in filtered:
            day = event.timestamp.strftime("%Y-%m-%d")
            if day not in by_day:
                by_day[day] = []
            by_day[day].append(event)
        
        # Build narrative
        narrative = f"# {self.campaign_id} Campaign Narrative\n\n"
        narrative += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        for day in sorted(by_day.keys()):
            narrative += f"## {day}\n\n"
            
            for event in by_day[day]:
                time_str = event.timestamp.strftime("%H:%M:%S")
                
                # Status indicator
                status = "✅" if event.success else "❌"
                
                # Type icon
                type_icon = {
                    "action": "▶",
                    "detection": "🚨",
                    "discovery": "🔓",
                    "analysis": "📊",
                }.get(event.event_type, "•")
                
                # Build line
                line = f"{time_icon} [{time_str}] {status} "
                line += f"**{event.actor}**: {event.action_description}"
                
                if event.mitre_technique:
                    line += f" ({event.mitre_technique})"
                
                narrative += f"{line}\n\n"
        
        return narrative
    
    def get_event_timeline(self) -> List[Dict]:
        """
        Get events as structured timeline.
        """
        timeline = []
        for event in self.events:
            timeline.append({
                "timestamp": event.timestamp.isoformat(),
                "type": event.event_type,
                "actor": event.actor,
                "action": event.action_description,
                "target": event.target_asset,
                "technique": event.mitre_technique,
                "success": event.success,
            })
        
        return timeline
    
    def get_operator_actions(self, operator_id: str = None) -> List[ReplayEvent]:
        """
        Get all operator actions (optionally filtered by operator).
        """
        actions = [e for e in self.events if e.event_type == "action"]
        
        if operator_id:
            actions = [a for a in actions if a.actor == operator_id]
        
        return actions
    
    def get_detections(self) -> List[ReplayEvent]:
        """
        Get all defensive detections.
        """
        return [e for e in self.events if e.event_type == "detection"]
    
    def get_discoveries(self) -> List[ReplayEvent]:
        """
        Get all credential/asset discoveries.
        """
        return [e for e in self.events if e.event_type == "discovery"]
    
    def analyze_operator_behavior(self, operator_id: str) -> Dict:
        """
        Analyze operator's action patterns.
        """
        actions = self.get_operator_actions(operator_id)
        
        if not actions:
            return {"operator": operator_id, "total_actions": 0}
        
        # Count by technique
        by_technique = {}
        for action in actions:
            tech = action.mitre_technique or "unknown"
            by_technique[tech] = by_technique.get(tech, 0) + 1
        
        # Success rate
        successes = sum(1 for a in actions if a.success)
        success_rate = successes / len(actions) if actions else 0
        
        return {
            "operator": operator_id,
            "total_actions": len(actions),
            "success_rate": success_rate,
            "techniques_used": by_technique,
            "first_action": actions[0].timestamp if actions else None,
            "last_action": actions[-1].timestamp if actions else None,
        }


__all__ = [
    'ReplayEngine',
]
