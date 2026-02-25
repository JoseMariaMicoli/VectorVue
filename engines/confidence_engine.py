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
confidence_engine.py - Decision Confidence

Calculate confidence in recommendations.
Identify data gaps and uncertainties.
Warn when confidence is too low.
"""

from typing import Dict, List
from engines.knowledge_engine import KnowledgeEngine
from engines.detection_engine import DetectionEngine


class ConfidenceEngine:
    """Assess confidence in decisions"""
    
    MIN_RECOMMENDATION_CONFIDENCE = 0.3
    
    def __init__(self):
        pass
    
    def assess_recommendation_confidence(self,
                                        opportunity_score: float,
                                        knowledge_completeness: float,
                                        detection_count: int,
                                        evidence_count: int) -> float:
        """
        Calculate confidence in an opportunity recommendation.
        
        Args:
        - opportunity_score: 0-100 from scoring_engine
        - knowledge_completeness: 0.0-1.0 from knowledge_engine
        - detection_count: Number of detections so far
        - evidence_count: Amount of collected evidence
        
        Returns: 0.0-1.0 confidence
        """
        
        # Normalize opportunity score
        opp_factor = opportunity_score / 100.0
        
        # Knowledge completeness factor
        knowledge_factor = knowledge_completeness
        
        # Evidence factor (more evidence = more confidence)
        evidence_factor = min(1.0, evidence_count / 10.0)  # 10 pieces = complete
        
        # Detection penalty (detections reduce confidence)
        detection_penalty = max(0, 1.0 - (detection_count * 0.1))
        
        # Combined confidence
        confidence = (opp_factor * 0.4 + knowledge_factor * 0.3 + evidence_factor * 0.3) * detection_penalty
        
        return max(0.0, min(1.0, confidence))
    
    def assess_path_confidence(self,
                              path_success_probability: float,
                              num_steps: int,
                              knowledge_completeness: float) -> float:
        """
        Calculate confidence in attack path.
        
        Args:
        - path_success_probability: 0.0-1.0 from path_engine
        - num_steps: Number of steps in path
        - knowledge_completeness: 0.0-1.0
        
        Returns: 0.0-1.0 confidence
        """
        
        # Longer paths = lower confidence
        length_penalty = max(0.3, 1.0 - (num_steps * 0.1))
        
        # Combine factors
        confidence = path_success_probability * length_penalty * (0.5 + knowledge_completeness)
        
        return max(0.0, min(1.0, confidence))
    
    def get_confidence_factors(self,
                              knowledge_engine: KnowledgeEngine,
                              detection_engine: DetectionEngine) -> Dict:
        """
        Get detailed confidence factors for analysis.
        
        Returns: {factor_name: value}
        """
        
        return {
            "knowledge_completeness": knowledge_engine.calculate_knowledge_completeness(),
            "detection_pressure": detection_engine.calculate_detection_pressure() / 100.0,
            "detection_trend": detection_engine.calculate_detection_trend(),
            "technique_confidence": len(knowledge_engine.learned_techniques) / 10.0,
        }
    
    def is_confidence_sufficient(self, confidence: float) -> bool:
        """Check if confidence is sufficient for recommendation"""
        return confidence >= self.MIN_RECOMMENDATION_CONFIDENCE
    
    def identify_confidence_gaps(self,
                                knowledge_engine: KnowledgeEngine,
                                detection_engine: DetectionEngine) -> List[str]:
        """
        Identify what would improve confidence.
        
        Returns: List of suggested actions
        """
        
        gaps = []
        
        completeness = knowledge_engine.calculate_knowledge_completeness()
        if completeness < 0.5:
            gaps.append("Expand recon to improve knowledge completeness")
        
        evidence_count = len(knowledge_engine.evidence)
        if evidence_count < 5:
            gaps.append("Collect more evidence before committing to attack")
        
        pressure = detection_engine.calculate_detection_pressure()
        if pressure > 50:
            gaps.append("High detection pressure - confidence in stealth is low")
        
        return gaps


__all__ = ['ConfidenceEngine']
