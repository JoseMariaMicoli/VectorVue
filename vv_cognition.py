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
VectorVue Phase 5.5: Cognition Platform
=========================================

Core data contract for all modules.

Never access raw database tables across modules.
All communication via standardized data structures.

Deterministic logic only - no ML/autonomy.
All outputs explainable and confidence-scored.

Author: VectorVue AI Cognition
Version: 1.0
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum
from datetime import datetime
import json


# ============================================================================
# DATA CONTRACT STRUCTURES (Communication Standard)
# ============================================================================

class ConfidenceLevel(Enum):
    """Confidence in decision: how much data supports this?"""
    MINIMAL = 0.2      # Guessing, incomplete data
    LOW = 0.4          # Some data, major gaps
    MEDIUM = 0.6       # Good data, minor gaps
    HIGH = 0.8         # Strong data, minor uncertainty
    VERY_HIGH = 1.0    # Complete data, no uncertainty


class DetectionState(Enum):
    """Overall detection pressure state"""
    QUIET = "quiet"              # No detections, safe to operate
    CAUTION = "caution"          # Minor detections, elevated awareness
    WATCHED = "watched"          # Active monitoring suspected
    HUNTING = "hunting"          # Active threat hunt in progress
    COMPROMISED = "compromised"  # Operator identity/tool exposed


@dataclass
class Asset:
    """Compromise target"""
    asset_id: int
    name: str                      # IP, hostname, or account
    asset_type: str                # host, network, service, account, database
    os: Optional[str] = None
    criticality: str = "medium"    # low, medium, high, critical
    sensitivity_tags: List[str] = field(default_factory=list)  # [prod, finance]
    is_compromised: bool = False
    lateral_movement_cost: int = 1 # Hops from here to objective
    owner: Optional[str] = None


@dataclass
class Credential:
    """Harvested or known credential"""
    credential_id: int
    username: str
    credential_type: str           # password, hash, token, ssh_key, mfa_bypass
    access_level: str              # guest, user, admin, system
    assets_with_access: List[int] = field(default_factory=list)  # Asset IDs
    source: Optional[str] = None   # Where obtained (T-number, phishing)
    freshness_days: int = 0        # How old is this credential?
    is_active: bool = True


@dataclass
class Session:
    """Active operational session (reverse shell, C2, etc.)"""
    session_id: int
    session_type: str              # meterpreter, reverse_shell, ssh, winrm
    target_asset: int
    executing_user: str
    callback_ip: str
    opened_at: datetime
    is_active: bool = True
    commands_executed: int = 0


@dataclass
class DetectionEvent:
    """Defensive action detected"""
    event_id: int
    event_type: str                # antivirus, ids, edr, siem, behavioral
    detector_product: str          # Defender, Splunk, CrowdStrike, etc.
    detected_at: datetime
    triggered_by: str              # What action triggered this?
    mitre_technique: Optional[str] = None  # T-number if known
    severity: str = "medium"       # low, medium, high, critical
    confidence: float = 0.8        # How confident is detection attribution?


@dataclass
class OperatorAction:
    """Action operator is about to take"""
    action_id: int
    campaign_id: int
    action_type: str               # lateral_move, credential_harvest, command_exec
    target_asset: Optional[int]
    technique: Optional[str]       # T-number
    description: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    operator_id: int = 0
    confidence_in_success: float = 0.7


@dataclass
class Recommendation:
    """Scored recommendation for next action"""
    rec_id: int
    action: str                    # Natural language description
    action_type: str               # lateral_move, credential_harvest, etc.
    target_asset: Optional[int]
    technique: Optional[str]
    
    # Scoring
    value_score: float             # How much does this advance objective?
    noise_score: float             # How much detection risk?
    risk_score: float              # Combined risk after detection pressure
    stealth_score: float           # How hidden is this action?
    novelty_score: float           # How novel (vs. repeated patterns)?
    final_score: float             # Weighted combination
    confidence: float              # How confident are we in this rec?
    
    # Explanation
    explanation: str               # Why this recommendation?
    expected_logs: List[str] = field(default_factory=list)  # What will be logged?
    edr_risks: List[str] = field(default_factory=list)      # EDR detection risks
    safer_alternatives: List[str] = field(default_factory=list)  # Other options
    
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ObjectiveDistance:
    """How far from objective? What does it take to get there?"""
    objective_id: int
    objective_text: str
    
    # Distance calculation
    privilege_steps: int           # Privilege escalation steps needed
    lateral_moves: int             # Assets to compromise
    unknown_penalty: int           # For unknowns/assumptions
    pressure_penalty: int          # Penalty for high detection pressure
    
    total_distance: int            # Sum of above
    steps_remaining: int
    confidence: float              # How confident in this path?
    
    # Narrative
    critical_path: List[str] = field(default_factory=list)  # Key steps
    alternatives: List[List[str]] = field(default_factory=list)  # Other paths
    blockers: List[str] = field(default_factory=list)  # What's preventing progress?


@dataclass
class DetectionPressure:
    """Overall detection risk level"""
    campaign_id: int
    
    # Pressure components
    recent_alerts: int             # Detections in last 24h
    failed_actions: int            # Failed exploitation attempts
    repetition_penalty: int        # Using same technique repeatedly
    
    total_pressure: int            # 0-100 scale
    health: int                    # 100 - pressure
    state: DetectionState          # QUIET, CAUTION, WATCHED, HUNTING, COMPROMISED
    confidence: float
    
    # Trending
    pressure_trend: str            # "stable", "increasing", "decreasing"
    time_to_critical: Optional[int] = None  # Days until hunting starts?


@dataclass
class OpSecSimulation:
    """Safety analysis of an action"""
    action: str
    
    # Predictions
    predicted_logs: List[str]      # Event log entries expected
    predicted_edr_rules: List[str] # EDR rules likely triggered
    behavioral_flags: List[str]    # Behavioral detection risks
    
    # Probability
    probability_logged: float      # 0.0-1.0
    probability_detected_edr: float
    probability_behavioral: float
    
    # Recommendation
    is_safe: bool                  # Should operator proceed?
    risk_level: str                # low, medium, high, critical
    safer_alternative: Optional[str] = None
    confidence: float = 0.8


@dataclass
class TempoAnalysis:
    """Operator action rate and detection risk"""
    campaign_id: int
    
    # Activity tracking
    actions_per_hour: float
    actions_per_day: float
    action_intensity: str          # "slow", "normal", "fast", "aggressive"
    
    # Detection correlation
    activity_spike_detected: bool
    spike_severity: str            # minor, moderate, severe
    
    # Recommendation
    recommended_mode: str          # "slow_mode", "normal", "fast_mode"
    explanation: str
    confidence: float


@dataclass
class InfraBurnAnalysis:
    """C2 infrastructure exposure tracking"""
    campaign_id: int
    
    # Burn factors
    detections_correlated_with_c2: int
    unique_c2_ips_exposed: int
    tools_attributed: List[str]    # Identified tools/malware
    
    # Burn probability
    burn_probability: float        # 0.0-1.0
    burn_level: str                # "fresh", "warm", "hot", "burned"
    days_until_critical: Optional[int] = None
    
    # Warning
    should_rotate: bool
    warning_message: Optional[str] = None
    confidence: float


@dataclass
class ConfidenceAnalysis:
    """Confidence in all our decisions"""
    campaign_id: int
    
    # Confidence factors
    data_completeness: float       # 0.0-1.0 how much of the network do we know?
    observation_count: int         # How many data points?
    path_stability: float          # 0.0-1.0 are paths still valid?
    
    # Overall
    overall_confidence: float      # Weighted combination
    confidence_trend: str          # "stable", "improving", "degrading"
    
    # Caveats
    major_unknowns: List[str] = field(default_factory=list)
    data_gaps: List[str] = field(default_factory=list)


@dataclass
class ReplayEvent:
    """Single append-only event in campaign timeline"""
    event_id: int
    campaign_id: int
    timestamp: datetime
    
    # Event details
    event_type: str                # action_executed, detection_observed, etc.
    actor: str                     # Operator or system
    action_description: str        # Natural language
    
    # Context
    target_asset: Optional[int]
    mitre_technique: Optional[str]
    related_findings: List[int] = field(default_factory=list)
    
    # Outcome
    success: bool
    evidence: Optional[str]        # Link to evidence item


@dataclass
class CognitionState:
    """Complete snapshot of cognition state at point in time"""
    campaign_id: int
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Core state
    assets: Dict[int, Asset] = field(default_factory=dict)
    credentials: Dict[int, Credential] = field(default_factory=dict)
    sessions: Dict[int, Session] = field(default_factory=dict)
    detections: List[DetectionEvent] = field(default_factory=list)
    
    # Analyses
    detection_pressure: Optional[DetectionPressure] = None
    objective_distances: Dict[int, ObjectiveDistance] = field(default_factory=dict)
    tempo_analysis: Optional[TempoAnalysis] = None
    infra_burn: Optional[InfraBurnAnalysis] = None
    confidence_analysis: Optional[ConfidenceAnalysis] = None
    
    # Recommendations
    recommendations: List[Recommendation] = field(default_factory=list)
    
    # Recent events
    recent_actions: List[OperatorAction] = field(default_factory=list)
    recent_events: List[ReplayEvent] = field(default_factory=list)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def to_dict(obj) -> Dict[str, Any]:
    """Convert dataclass to JSON-serializable dict"""
    if hasattr(obj, '__dataclass_fields__'):
        result = {}
        for field_name, field_obj in obj.__dataclass_fields__.items():
            value = getattr(obj, field_name)
            if isinstance(value, (list, dict)):
                result[field_name] = value
            elif isinstance(value, Enum):
                result[field_name] = value.value
            elif isinstance(value, datetime):
                result[field_name] = value.isoformat()
            elif hasattr(value, '__dataclass_fields__'):
                result[field_name] = to_dict(value)
            else:
                result[field_name] = value
        return result
    return obj


def confidence_to_text(conf: float) -> str:
    """Convert confidence float to human text"""
    if conf >= 1.0:
        return "Very High"
    elif conf >= 0.8:
        return "High"
    elif conf >= 0.6:
        return "Medium"
    elif conf >= 0.4:
        return "Low"
    else:
        return "Minimal"


def detection_state_icon(state: DetectionState) -> str:
    """Icon for detection state"""
    icons = {
        DetectionState.QUIET: "🟢",
        DetectionState.CAUTION: "🟡",
        DetectionState.WATCHED: "🟠",
        DetectionState.HUNTING: "🔴",
        DetectionState.COMPROMISED: "⛔",
    }
    return icons.get(state, "❓")


# ============================================================================
# VALIDATION
# ============================================================================

def validate_recommendation(rec: Recommendation) -> Tuple[bool, Optional[str]]:
    """Validate recommendation before presenting to operator"""
    
    # Must have confidence
    if rec.confidence < 0.2:
        return False, "Confidence too low (< 0.2)"
    
    # Must have explanation
    if not rec.explanation or len(rec.explanation) < 10:
        return False, "Missing explanation"
    
    # Must have action
    if not rec.action or len(rec.action) < 5:
        return False, "Missing action description"
    
    # Scores must be valid
    if not (0.0 <= rec.value_score <= 1.0):
        return False, "Invalid value_score"
    if not (0.0 <= rec.noise_score <= 1.0):
        return False, "Invalid noise_score"
    if not (0.0 <= rec.risk_score <= 1.0):
        return False, "Invalid risk_score"
    
    return True, None


# ============================================================================
# EXPORTS
# ============================================================================

__all__ = [
    'ConfidenceLevel',
    'DetectionState',
    'Asset',
    'Credential',
    'Session',
    'DetectionEvent',
    'OperatorAction',
    'Recommendation',
    'ObjectiveDistance',
    'DetectionPressure',
    'OpSecSimulation',
    'TempoAnalysis',
    'InfraBurnAnalysis',
    'ConfidenceAnalysis',
    'ReplayEvent',
    'CognitionState',
    'to_dict',
    'confidence_to_text',
    'detection_state_icon',
    'validate_recommendation',
]
