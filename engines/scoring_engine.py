
/*
Copyright (c) 2026 José María Micoli
Licensed under Apache-2.0

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Remove copyright notices
*/

"""
scoring_engine.py - Phase 5.5 Core Scoring Engine

Implements the 3 base scores: STEALTH, VALUE, RISK
Then derives OPPORTUNITY_SCORE from these.

All formulas are deterministic and reproducible.
No randomness. Math only.

STEALTH = 100 - (log_events * 6) - (alerts * 15) - (edr_visibility * 20) - (privilege_noise * 5)
VALUE = (criticality * 25) + (credential_access * 20) + (lateral * 15) + (domain_impact * 25) + (data_access * 15)
RISK = (detection_prob * 35) + (blast_radius * 25) + (irreversibility * 20) + (complexity * 20)
OPPORTUNITY = (value * 0.5) + (stealth * 0.3) - (risk * 0.2), clamped 0-100
"""

from typing import Dict, Tuple
from engines.data_contracts import ScoringResult


class ScoringEngine:
    """Deterministic scoring system for red team operations"""
    
    def __init__(self):
        """Initialize with no state - pure functions only"""
        pass
    
    def calculate_stealth(self,
                         log_events: int = 0,
                         alerts: int = 0,
                         edr_visibility: float = 0.0,
                         privilege_noise: float = 0.0) -> float:
        """
        Calculate STEALTH score (0-100).
        
        Higher = less visible to defenders
        
        Formula:
        stealth = 100 - (log_events * 6) - (alerts * 15) - (edr_visibility * 20) - (privilege_noise * 5)
        
        Args:
        - log_events: Estimated event logs generated (0-20)
        - alerts: Defensive alerts expected (0-10)
        - edr_visibility: 0.0-1.0, how visible to EDR
        - privilege_noise: 0.0-1.0, privilege escalation visibility
        
        Returns: 0-100 score
        """
        
        stealth = 100.0
        stealth -= (log_events * 6)           # Each log event costs 6 points
        stealth -= (alerts * 15)               # Each alert costs 15 points
        stealth -= (edr_visibility * 20)       # EDR visibility costs up to 20 points
        stealth -= (privilege_noise * 5)       # Privilege escalation noise costs up to 5 points
        
        return max(0, min(100, stealth))
    
    def calculate_value(self,
                       asset_criticality: float = 0.0,
                       credential_access: float = 0.0,
                       lateral_movement: float = 0.0,
                       domain_impact: float = 0.0,
                       data_access: float = 0.0) -> float:
        """
        Calculate VALUE score (0-100).
        
        Higher = more mission progress
        
        Formula:
        value = (criticality * 25) + (credential_access * 20) + (lateral * 15) + (domain_impact * 25) + (data_access * 15)
        
        Args (all 0.0-1.0 weights):
        - asset_criticality: How important is this asset? (weights 25%)
        - credential_access: Do we get credentials? (weights 20%)
        - lateral_movement: Does this enable lateral movement? (weights 15%)
        - domain_impact: Domain-wide significance? (weights 25%)
        - data_access: Access to sensitive data? (weights 15%)
        
        Returns: 0-100 score
        """
        
        value = 0.0
        value += (asset_criticality * 25)     # Asset importance
        value += (credential_access * 20)     # Credential value
        value += (lateral_movement * 15)      # Lateral potential
        value += (domain_impact * 25)         # Domain-wide impact
        value += (data_access * 15)           # Data access value
        
        return max(0, min(100, value))
    
    def calculate_risk(self,
                      detection_probability: float = 0.0,
                      blast_radius: float = 0.0,
                      irreversibility: float = 0.0,
                      operator_complexity: float = 0.0) -> float:
        """
        Calculate RISK score (0-100).
        
        Higher = more dangerous (worse for us)
        
        Formula:
        risk = (detection_prob * 35) + (blast_radius * 25) + (irreversibility * 20) + (complexity * 20)
        
        Args (all 0.0-1.0 weights):
        - detection_probability: Likelihood of detection (weights 35%)
        - blast_radius: Scope of damage if detected (weights 25%)
        - irreversibility: Can this be undone? (weights 20%)
        - operator_complexity: How complex to execute? (weights 20%)
        
        Returns: 0-100 score
        """
        
        risk = 0.0
        risk += (detection_probability * 35)  # Detection likelihood
        risk += (blast_radius * 25)           # Impact radius
        risk += (irreversibility * 20)        # Reversibility
        risk += (operator_complexity * 20)    # Execution complexity
        
        return max(0, min(100, risk))
    
    def calculate_opportunity_score(self,
                                   value: float,
                                   stealth: float,
                                   risk: float) -> float:
        """
        Calculate final OPPORTUNITY score (0-100).
        
        Balances value and stealth against risk.
        
        Formula:
        opportunity = (value * 0.5) + (stealth * 0.3) - (risk * 0.2)
        Clamped to 0-100
        
        Args:
        - value: 0-100, from calculate_value()
        - stealth: 0-100, from calculate_stealth()
        - risk: 0-100, from calculate_risk()
        
        Returns: 0-100 score
        """
        
        opportunity = (value * 0.5) + (stealth * 0.3) - (risk * 0.2)
        return max(0, min(100, opportunity))
    
    def score_opportunity(self,
                         asset_criticality: float,
                         credential_access: float,
                         lateral_movement: float,
                         domain_impact: float,
                         data_access: float,
                         log_events: int,
                         alerts: int,
                         edr_visibility: float,
                         privilege_noise: float,
                         detection_probability: float,
                         blast_radius: float,
                         irreversibility: float,
                         operator_complexity: float,
                         confidence: float = 0.8) -> ScoringResult:
        """
        Complete scoring pipeline - single call for all three dimensions.
        
        Returns ScoringResult with STEALTH, VALUE, RISK, and final OPPORTUNITY_SCORE.
        """
        
        # Calculate each dimension
        stealth = self.calculate_stealth(
            log_events=log_events,
            alerts=alerts,
            edr_visibility=edr_visibility,
            privilege_noise=privilege_noise
        )
        
        value = self.calculate_value(
            asset_criticality=asset_criticality,
            credential_access=credential_access,
            lateral_movement=lateral_movement,
            domain_impact=domain_impact,
            data_access=data_access
        )
        
        risk = self.calculate_risk(
            detection_probability=detection_probability,
            blast_radius=blast_radius,
            irreversibility=irreversibility,
            operator_complexity=operator_complexity
        )
        
        opportunity_score = self.calculate_opportunity_score(value, stealth, risk)
        
        # Build calculation details for explainability
        calculation_details = {
            "log_events": log_events,
            "alerts": alerts,
            "edr_visibility": edr_visibility,
            "privilege_noise": privilege_noise,
            "detection_probability": detection_probability,
            "blast_radius": blast_radius,
            "irreversibility": irreversibility,
            "operator_complexity": operator_complexity,
        }
        
        return ScoringResult(
            stealth=stealth,
            value=value,
            risk=risk,
            opportunity_score=opportunity_score,
            confidence=confidence,
            calculation_details=calculation_details
        )
    
    def score_many(self, opportunities: list) -> list:
        """
        Score multiple opportunities at once.
        
        Each item in opportunities dict should have all parameters.
        Returns list of ScoringResult objects.
        """
        results = []
        for opp in opportunities:
            result = self.score_opportunity(
                asset_criticality=opp.get("asset_criticality", 0.5),
                credential_access=opp.get("credential_access", 0.5),
                lateral_movement=opp.get("lateral_movement", 0.5),
                domain_impact=opp.get("domain_impact", 0.5),
                data_access=opp.get("data_access", 0.5),
                log_events=opp.get("log_events", 0),
                alerts=opp.get("alerts", 0),
                edr_visibility=opp.get("edr_visibility", 0.0),
                privilege_noise=opp.get("privilege_noise", 0.0),
                detection_probability=opp.get("detection_probability", 0.5),
                blast_radius=opp.get("blast_radius", 0.5),
                irreversibility=opp.get("irreversibility", 0.5),
                operator_complexity=opp.get("operator_complexity", 0.5),
                confidence=opp.get("confidence", 0.8)
            )
            results.append(result)
        
        return results


__all__ = ['ScoringEngine']
