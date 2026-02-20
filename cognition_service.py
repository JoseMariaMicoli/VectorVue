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
cognition_service.py - Service Layer for Phase 5.5 Cognition Platform

Gateway between UI (vv.py) and Engines.

RULE: UI NEVER calls engines directly. Always goes through this service.
RULE: UI NEVER queries DB directly. Always goes through this service.
RULE: All state changes go through this service (transactional).

This layer:
1. Orchestrates engine calls
2. Handles database persistence
3. Manages campaign state consistency
4. Provides high-level operations (opportunity, plan, validate, execute)
"""

from typing import List, Dict, Optional, Tuple
from datetime import datetime
import logging

from engines import (
    ScoringEngine,
    OpportunityEngine,
    PathEngine,
    DetectionEngine,
    KnowledgeEngine,
    CampaignStateEngine,
    CorrelationEngine,
    ConfidenceEngine,
    ExplainabilityEngine,
    ValidationEngine,
    Opportunity,
    AttackPath,
)

logger = logging.getLogger(__name__)


class CognitionService:
    """
    Service layer for cognition platform.
    
    All UI → Engine communication flows through here.
    All state changes are managed here.
    """
    
    def __init__(self, db=None):
        """
        Initialize service with optional database connection.
        
        Args:
        - db: Database connection (vv_core.Database instance)
        """
        self.db = db
        
        # Initialize all engines
        self.scoring = ScoringEngine()
        self.opportunity = OpportunityEngine()
        self.path = PathEngine()
        self.detection = DetectionEngine()
        self.knowledge = KnowledgeEngine()
        self.campaign_state = CampaignStateEngine()
        self.correlation = CorrelationEngine()
        self.confidence = ConfidenceEngine()
        self.explainability = ExplainabilityEngine()
        self.validation = ValidationEngine()
    
    # ========================================================================
    # HIGH-LEVEL OPERATIONS (What UI Calls)
    # ========================================================================
    
    def generate_opportunities(self,
                              campaign_id: str) -> Tuple[List[Opportunity], str]:
        """
        Generate ranked opportunities for campaign.
        
        Returns:
        - opportunities: Ranked list
        - status_message: What happened
        """
        
        logger.info(f"Generating opportunities for campaign: {campaign_id}")
        
        try:
            # Load campaign context
            campaign = self.db.get_campaign(campaign_id) if self.db else {}
            assets = self.db.list_assets(campaign_id) if self.db else []
            credentials = self.db.list_credentials(campaign_id) if self.db else []
            
            # Generate opportunities
            evidence = {
                "assets": assets,
                "credentials": credentials,
            }
            
            opportunities = self.opportunity.generate_opportunities(
                campaign_id=campaign_id,
                evidence=evidence,
                known_assets=assets,
                known_credentials=credentials
            )
            
            # Persist opportunities
            if self.db:
                for opp in opportunities:
                    self.db.save_opportunity(campaign_id, opp)
            
            return opportunities, f"Generated {len(opportunities)} opportunities"
        
        except Exception as e:
            logger.error(f"Error generating opportunities: {e}")
            return [], f"Error: {str(e)}"
    
    def plan_attack_path(self,
                        campaign_id: str,
                        objective: str,
                        opportunities: List[Opportunity]) -> Tuple[List[AttackPath], str]:
        """
        Plan attack paths to objective.
        
        Returns:
        - paths: Ranked list of paths
        - status_message
        """
        
        logger.info(f"Planning paths to: {objective}")
        
        try:
            # Plan paths
            paths = self.path.plan_paths(
                objective=objective,
                opportunities=opportunities,
                current_position="external"
            )
            
            # Persist paths
            if self.db:
                for p in paths:
                    self.db.save_attack_path(campaign_id, p)
            
            return paths, f"Planned {len(paths)} potential attack paths"
        
        except Exception as e:
            logger.error(f"Error planning paths: {e}")
            return [], f"Error: {str(e)}"
    
    def validate_opportunity(self,
                            campaign_id: str,
                            opportunity: Opportunity) -> Tuple[bool, str]:
        """
        Validate if opportunity can be executed.
        
        Returns:
        - approved: Boolean
        - explanation: Why approved/rejected
        """
        
        logger.info(f"Validating opportunity: {opportunity.id}")
        
        try:
            # Get campaign state
            campaign = self.db.get_campaign(campaign_id) if self.db else {}
            
            # Validate
            result = self.validation.validate_action(
                opportunity=opportunity,
                campaign_state=campaign,
                operator_role="operator"
            )
            
            # Generate explanation
            explanation = self.explainability.explain_validation_decision(
                {
                    "approved": result.approved,
                    "reason": result.reason,
                    "required_approvals": result.required_approvals,
                    "safety_checks": result.safety_checks,
                }
            )
            
            return result.approved, explanation
        
        except Exception as e:
            logger.error(f"Error validating opportunity: {e}")
            return False, f"Error: {str(e)}"
    
    def record_action_outcome(self,
                             campaign_id: str,
                             opportunity_id: str,
                             succeeded: bool,
                             evidence_collected: Dict = None) -> Tuple[bool, str]:
        """
        Record outcome of executed action.
        
        Updates campaign knowledge and learning.
        """
        
        logger.info(f"Recording action outcome: {opportunity_id} -> {succeeded}")
        
        try:
            # Get opportunity details
            opp = self.db.get_opportunity(campaign_id, opportunity_id) if self.db else {}
            technique = opp.get("technique", "T1000")
            
            # Learn from outcome
            self.knowledge.learn_technique_outcome(technique, succeeded)
            
            # Record evidence
            if evidence_collected and self.db:
                for evidence in evidence_collected:
                    self.knowledge.record_evidence(
                        evidence_id=f"{campaign_id}_{opportunity_id}_{len(self.knowledge.evidence)}",
                        evidence_type=evidence.get("type"),
                        content=evidence
                    )
            
            # Persist learning
            if self.db:
                self.db.save_learning(campaign_id, {
                    "technique": technique,
                    "succeeded": succeeded,
                    "timestamp": datetime.now(),
                })
            
            return True, f"Action recorded and learning updated"
        
        except Exception as e:
            logger.error(f"Error recording outcome: {e}")
            return False, f"Error: {str(e)}"
    
    def record_detection(self,
                        campaign_id: str,
                        asset: str,
                        detection_type: str,
                        severity: int,
                        description: str) -> Tuple[bool, str]:
        """
        Record a defensive detection event.
        
        Updates detection pressure and confidence.
        """
        
        logger.info(f"Recording detection: {asset} -> {detection_type}")
        
        try:
            # Record detection
            self.detection.record_detection(
                timestamp=datetime.now(),
                asset=asset,
                detection_type=detection_type,
                severity=severity,
                related_technique="",
                description=description,
                confidence=0.8
            )
            
            # Update pressure
            pressure = self.detection.calculate_detection_pressure()
            
            # Persist detection
            if self.db:
                self.db.save_detection(campaign_id, {
                    "asset": asset,
                    "type": detection_type,
                    "severity": severity,
                    "description": description,
                    "timestamp": datetime.now(),
                })
            
            return True, f"Detection recorded (pressure now: {pressure:.0f}/100)"
        
        except Exception as e:
            logger.error(f"Error recording detection: {e}")
            return False, f"Error: {str(e)}"
    
    def assess_campaign_state(self, campaign_id: str) -> Dict:
        """
        Get current campaign state and strategy recommendation.
        """
        
        logger.info(f"Assessing campaign state: {campaign_id}")
        
        try:
            # Load campaign metrics
            campaign = self.db.get_campaign(campaign_id) if self.db else {}
            assets_owned = campaign.get("assets_owned", 0)
            credentials = campaign.get("credentials_obtained", 0)
            detections = len(self.detection.detections)
            
            # Assess state
            state = self.campaign_state.assess_campaign_state(
                campaign_id=campaign_id,
                assets_owned=assets_owned,
                credentials_obtained=credentials,
                detections=detections,
                detection_severity=5,  # Would calculate from detections
                recent_activity_timestamp=datetime.now()
            )
            
            return {
                "phase": state.phase,
                "stealth_budget": state.stealth_budget_remaining,
                "detections": state.detections,
                "confidence": state.confidence,
                "strategy": state.recommended_strategy,
                "is_compromised": self.campaign_state.is_campaign_compromised(state),
                "should_accelerate": self.campaign_state.should_accelerate(state),
            }
        
        except Exception as e:
            logger.error(f"Error assessing state: {e}")
            return {"error": str(e)}
    
    # ========================================================================
    # EXPLANATION GENERATION (For UI Display)
    # ========================================================================
    
    def explain_opportunity(self, opportunity: Opportunity) -> str:
        """Get detailed explanation for opportunity"""
        return self.explainability.explain_opportunity(opportunity)
    
    def explain_path(self, path: AttackPath) -> str:
        """Get detailed explanation for attack path"""
        return self.explainability.explain_path(path)
    
    def summarize_recommendation(self,
                                opportunity: Opportunity) -> str:
        """Get one-line summary for UI display"""
        return self.explainability.summarize_decision(
            opportunity.score,
            opportunity.stealth,
            opportunity.value,
            opportunity.risk,
            opportunity.confidence
        )


# ============================================================================
# MODULE-LEVEL FUNCTIONS (For easy service initialization from UI)
# ============================================================================

_cognition_service_instance: Optional[CognitionService] = None


def initialize_cognition_service(db=None) -> CognitionService:
    """
    Initialize the global cognition service instance.
    
    Called once at startup in vv.py _post_login_setup()
    
    Args:
    - db: Database connection from vv_core.Database
    
    Returns:
    - CognitionService instance
    """
    global _cognition_service_instance
    _cognition_service_instance = CognitionService(db=db)
    logger.info("Cognition service initialized")
    return _cognition_service_instance


def get_cognition_service() -> Optional[CognitionService]:
    """
    Get the global cognition service instance.
    
    Returns:
    - CognitionService instance or None if not initialized
    """
    return _cognition_service_instance


__all__ = ['CognitionService', 'initialize_cognition_service', 'get_cognition_service']
