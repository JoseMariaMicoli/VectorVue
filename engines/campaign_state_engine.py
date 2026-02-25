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
campaign_state_engine.py - Campaign State & Strategy

Tracks campaign phase and recommends strategy.

Phases:
1. RECON - Intelligence gathering
2. ACCESS - Initial compromise
3. ESCALATION - Privilege escalation
4. OBJECTIVE - Mission completion
5. EXFIL - Data exfiltration

Recommends next move based on current state.
"""

from typing import Dict, List
from datetime import datetime
from engines.data_contracts import CampaignState


class CampaignStateEngine:
    """Manage campaign state and recommend strategy"""
    
    PHASES = ["recon", "access", "escalation", "objective", "exfil"]
    
    def __init__(self):
        pass
    
    def assess_campaign_state(self,
                            campaign_id: str,
                            assets_owned: int,
                            credentials_obtained: int,
                            detections: int,
                            detection_severity: int,
                            recent_activity_timestamp: datetime) -> CampaignState:
        """
        Assess overall campaign state and recommend strategy.
        
        Args:
        - campaign_id: Campaign context
        - assets_owned: Number of compromised assets
        - credentials_obtained: Number of harvested credentials
        - detections: Number of defensive detections
        - detection_severity: Max severity (1-10)
        - recent_activity_timestamp: Last operator activity
        
        Returns: CampaignState with phase and recommendations
        """
        
        # Determine phase
        phase = self._determine_phase(
            assets_owned,
            credentials_obtained,
            detections
        )
        
        # Calculate stealth budget remaining
        stealth_budget = self._calculate_stealth_budget(detections, detection_severity)
        
        # Overall confidence (decreases with detections)
        confidence = max(0.1, 1.0 - (detections * 0.1))
        
        # Recommend strategy
        strategy = self._recommend_strategy(phase, stealth_budget, detections)
        
        return CampaignState(
            phase=phase,
            stealth_budget_remaining=stealth_budget,
            detections=detections,
            detection_severity=detection_severity,
            confidence=confidence,
            recommended_strategy=strategy,
            assets_owned=assets_owned,
            credentials_obtained=credentials_obtained,
            last_activity=recent_activity_timestamp,
        )
    
    def _determine_phase(self,
                        assets_owned: int,
                        credentials_obtained: int,
                        detections: int) -> str:
        """
        Determine campaign phase based on progress.
        
        Simplified heuristic:
        - RECON: 0 assets owned
        - ACCESS: 1-2 assets, some credentials
        - ESCALATION: 3+ assets, elevated credentials
        - OBJECTIVE: 5+ assets, admin credentials
        - EXFIL: Any phase, if detections > 5
        """
        
        if detections > 5:
            return "exfil"  # Escalate to exfiltration if burned
        
        if assets_owned == 0:
            return "recon"
        elif assets_owned <= 2:
            return "access"
        elif assets_owned <= 4:
            return "escalation"
        else:
            return "objective"
    
    def _calculate_stealth_budget(self, detections: int, severity: int) -> float:
        """
        Calculate remaining stealth budget (0-100).
        
        Formula:
        budget = 100 - (detections * 10) - (severity * 5)
        Clamped to 0-100
        """
        
        budget = 100.0
        budget -= (detections * 10)      # Each detection costs 10 points
        budget -= (severity * 5)          # Severity adds to cost
        
        return max(0, min(100, budget))
    
    def _recommend_strategy(self, phase: str, stealth_budget: float, detections: int) -> str:
        """
        Recommend next strategic move.
        """
        
        if phase == "recon":
            return "Focus on passive intelligence gathering. Establish C2 channels."
        
        elif phase == "access":
            if stealth_budget > 70:
                return "Execute initial compromise. Prioritize credential harvesting."
            else:
                return "Initial compromise successful. Move to escalation carefully."
        
        elif phase == "escalation":
            if detections > 5:
                return "Detections increasing. Execute fast escalation or prepare exfil."
            else:
                return "Escalate privileges and expand asset ownership."
        
        elif phase == "objective":
            if stealth_budget < 30:
                return "Stealth budget low. Execute objective immediately and exfil."
            else:
                return "Execute objective. Ensure data integrity and preparation for exfil."
        
        elif phase == "exfil":
            return "URGENT: Prepare exfiltration. Activate contingency channels. Expect defensive response."
        
        return "Assess situation and plan next move."
    
    def is_campaign_compromised(self, state: CampaignState) -> bool:
        """Check if campaign is likely compromised"""
        return state.detection_severity >= 8 or state.detections > 10
    
    def should_accelerate(self, state: CampaignState) -> bool:
        """Check if operator should accelerate timeline"""
        return state.stealth_budget_remaining < 30 or state.detection_severity >= 7


__all__ = ['CampaignStateEngine']
