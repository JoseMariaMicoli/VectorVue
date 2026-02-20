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
VectorVue Phase 5.5 - Operational Cognition Layer

10 deterministic decision-support engines for red team operations.

Engines (no randomness, fully reproducible):
1. scoring_engine - STEALTH, VALUE, RISK formulas
2. opportunity_engine - Opportunity generation and ranking
3. path_engine - Attack path planning and analysis
4. detection_engine - Defensive detection tracking
5. knowledge_engine - Evidence correlation and learning
6. campaign_state_engine - Campaign phase and strategy
7. correlation_engine - Evidence-to-opportunity linking
8. confidence_engine - Decision confidence calculation
9. explainability_engine - Human-readable reasoning
10. validation_engine - Safety guardrails and approval

All communication via typed data contracts.
No randomness. No ML. Deterministic and reproducible.
"""

from engines.data_contracts import (
    Opportunity,
    AttackPath,
    DetectionEvent,
    CampaignState,
    ScoringResult,
    ValidationResult,
)
from engines.scoring_engine import ScoringEngine
from engines.opportunity_engine import OpportunityEngine
from engines.path_engine import PathEngine
from engines.detection_engine import DetectionEngine
from engines.knowledge_engine import KnowledgeEngine
from engines.campaign_state_engine import CampaignStateEngine
from engines.correlation_engine import CorrelationEngine
from engines.confidence_engine import ConfidenceEngine
from engines.explainability_engine import ExplainabilityEngine
from engines.validation_engine import ValidationEngine

__all__ = [
    # Data contracts
    'Opportunity',
    'AttackPath',
    'DetectionEvent',
    'CampaignState',
    'ScoringResult',
    'ValidationResult',
    # Engines
    'ScoringEngine',
    'OpportunityEngine',
    'PathEngine',
    'DetectionEngine',
    'KnowledgeEngine',
    'CampaignStateEngine',
    'CorrelationEngine',
    'ConfidenceEngine',
    'ExplainabilityEngine',
    'ValidationEngine',
]
