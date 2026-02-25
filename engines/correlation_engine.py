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
correlation_engine.py - Evidence Correlation

Link evidence to opportunities.
Correlate detections with actions.
Build evidence chains for impact analysis.
"""

from typing import List, Dict, Tuple
from engines.data_contracts import Opportunity, DetectionEvent


class CorrelationEngine:
    """Correlate evidence with opportunities and detections"""
    
    def __init__(self):
        self.correlations: Dict[str, List[str]] = {}  # entity_id -> [related_ids]
    
    def correlate_detection_to_action(self,
                                     detection: DetectionEvent,
                                     action_technique: str,
                                     time_window: int = 5) -> float:
        """
        Calculate probability that detection is from action.
        
        Args:
        - detection: DetectionEvent to analyze
        - action_technique: MITRE technique executed
        - time_window: Time window in minutes
        
        Returns: 0.0-1.0 confidence that detection is from action
        """
        
        # Simple heuristic: if related_technique matches or is in same family
        if detection.related_technique == action_technique:
            return 0.9  # High confidence match
        
        # Check if in same technique family
        if self._same_technique_family(detection.related_technique, action_technique):
            return 0.6  # Moderate confidence
        
        # Time-based correlation (if recent)
        # Would need timestamp context - for now assume correlated if same session
        return 0.3  # Low confidence
    
    def correlate_evidence_to_opportunity(self,
                                        opportunity: Opportunity,
                                        evidence_ids: List[str]) -> float:
        """
        Calculate how well evidence supports opportunity.
        
        Args:
        - opportunity: Opportunity to evaluate
        - evidence_ids: Evidence that might support this
        
        Returns: 0.0-1.0 confidence that evidence supports opportunity
        """
        
        if not evidence_ids:
            return 0.5  # No evidence = moderate confidence
        
        # More evidence = higher confidence
        confidence = min(0.95, 0.5 + (len(evidence_ids) * 0.1))
        
        return confidence
    
    def _same_technique_family(self, tech1: str, tech2: str) -> bool:
        """Check if two techniques are in same family"""
        
        # Simplified - just check first part
        t1_family = tech1.split(":")[0] if tech1 else ""
        t2_family = tech2.split(":")[0] if tech2 else ""
        
        return t1_family == t2_family
    
    def link_evidence(self, from_id: str, to_id: str) -> None:
        """Create correlation link between evidence"""
        
        if from_id not in self.correlations:
            self.correlations[from_id] = []
        
        if to_id not in self.correlations[from_id]:
            self.correlations[from_id].append(to_id)
    
    def get_related_evidence(self, entity_id: str) -> List[str]:
        """Get all related evidence for entity"""
        return self.correlations.get(entity_id, [])
    
    def calculate_chain_of_custody(self,
                                   opportunity_id: str,
                                   evidence_chain: List[str]) -> Dict:
        """
        Verify chain of custody for evidence.
        
        Returns: {valid: bool, gaps: [str]}
        """
        
        # Check if evidence chain is complete and logically connected
        gaps = []
        
        if not evidence_chain:
            gaps.append("No evidence provided")
            return {"valid": False, "gaps": gaps}
        
        # Check each link
        for i in range(len(evidence_chain) - 1):
            current = evidence_chain[i]
            next_evidence = evidence_chain[i + 1]
            
            # Check if correlated
            if next_evidence not in self.get_related_evidence(current):
                gaps.append(f"Gap between {current} and {next_evidence}")
        
        valid = len(gaps) == 0
        return {"valid": valid, "gaps": gaps}


__all__ = ['CorrelationEngine']
