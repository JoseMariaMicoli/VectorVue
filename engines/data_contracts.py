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
Data Contracts for Phase 5.5 Operational Cognition Layer

Strict typed interfaces between engines.
Never invent new fields - extend carefully with justification.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from enum import Enum


class ScoringDimension(Enum):
    """Core scoring dimensions (0-100 each)"""
    STEALTH = "stealth"      # How exposed is this action?
    VALUE = "value"          # How much progress does it make?
    RISK = "risk"            # What's the cost if detected?


@dataclass
class ScoringResult:
    """
    Deterministic scoring output.
    
    stealth = 100 - (log_events * 6) - (alerts * 15) - (edr_visibility * 20) - (privilege_noise * 5)
    value = (criticality * 25) + (credential_access * 20) + (lateral * 15) + (domain_impact * 25) + (data_access * 15)
    risk = (detection_prob * 35) + (blast_radius * 25) + (irreversibility * 20) + (complexity * 20)
    opportunity_score = (value * 0.5) + (stealth * 0.3) - (risk * 0.2), clamped 0-100
    """
    stealth: float                # 0-100, higher is better
    value: float                  # 0-100, higher is better
    risk: float                   # 0-100, higher is worse
    opportunity_score: float      # 0-100, final ranking score
    confidence: float             # 0.0-1.0, how sure are we?
    calculation_details: Dict[str, float] = field(default_factory=dict)
    
    def __post_init__(self):
        """Clamp values to valid ranges"""
        self.stealth = max(0, min(100, self.stealth))
        self.value = max(0, min(100, self.value))
        self.risk = max(0, min(100, self.risk))
        self.opportunity_score = max(0, min(100, self.opportunity_score))
        self.confidence = max(0.0, min(1.0, self.confidence))


@dataclass
class Opportunity:
    """Single exploitation opportunity with justification"""
    id: str                           # Unique ID (campaign_timestamp_sequence)
    source_evidence: List[str]        # Evidence IDs that generated this
    technique: str                    # MITRE technique (T-number)
    target_asset: str                 # Asset ID or hostname
    stealth: float                    # 0-100, from ScoringResult
    value: float                      # 0-100, from ScoringResult
    risk: float                       # 0-100, from ScoringResult
    score: float                      # 0-100, opportunity_score from ScoringResult
    confidence: float                 # 0.0-1.0, how certain?
    explanation: str                  # Why this opportunity was generated
    expected_logs: List[str]         # What logs might be generated?
    edr_risks: List[str]             # EDR detection risks
    dependencies: List[str]          # Other opportunities that must precede this
    alternatives: List[str]          # Alternative approaches to same objective
    timestamp_generated: datetime = field(default_factory=datetime.now)
    
    def is_valid(self) -> bool:
        """Sanity check before presenting to operator"""
        return (
            0 <= self.stealth <= 100 and
            0 <= self.value <= 100 and
            0 <= self.risk <= 100 and
            0 <= self.score <= 100 and
            0.0 <= self.confidence <= 1.0 and
            len(self.explanation) > 0
        )


@dataclass
class AttackPath:
    """Complete path to objective with risk analysis"""
    id: str                               # Path ID
    objective: str                        # Campaign objective
    steps: List[str]                      # Ordered list of steps (opportunity IDs)
    cumulative_risk: float                # Total risk if entire path executed
    cumulative_stealth: float             # Overall stealth profile
    cumulative_value: float               # Total value delivered
    success_probability: float            # 0.0-1.0, estimated success chance
    explanation: str                      # Why this path was chosen
    alternatives: List['AttackPath'] = field(default_factory=list)
    estimated_detection_time: int = 0     # Hours until likely detection
    
    def risk_per_step(self) -> float:
        """Average risk per step"""
        return self.cumulative_risk / max(1, len(self.steps))


@dataclass
class DetectionEvent:
    """Defensive detection or alert"""
    timestamp: datetime
    asset: str                    # Asset where detection occurred
    detection_type: str           # alert, edr, log, behavior, etc.
    severity: int                 # 1-10, criticality
    related_technique: str        # MITRE technique if known
    description: str              # Full description
    confidence: float             # 0.0-1.0, detection confidence


@dataclass
class CampaignState:
    """Overall campaign state and strategy"""
    phase: str                    # recon, access, escalation, objective, exfil
    stealth_budget_remaining: float  # 0-100, how much "noise" can we afford?
    detections: int               # Number of defensive detections so far
    detection_severity: int       # Max severity (1-10) so far
    confidence: float             # 0.0-1.0, overall campaign confidence
    recommended_strategy: str     # Next recommended strategic move
    assets_owned: int             # Number of compromised assets
    credentials_obtained: int     # Number of credentials harvested
    last_activity: datetime = field(default_factory=datetime.now)


@dataclass
class ValidationResult:
    """Result of action validation"""
    approved: bool
    reason: str
    required_approvals: List[str] = field(default_factory=list)  # Approvals needed
    safety_checks: Dict[str, bool] = field(default_factory=dict)  # What passed/failed


__all__ = [
    'ScoringDimension',
    'ScoringResult',
    'Opportunity',
    'AttackPath',
    'DetectionEvent',
    'CampaignState',
    'ValidationResult',
]
