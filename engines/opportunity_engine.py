
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
opportunity_engine.py - Opportunity Generation

Generates ranked opportunities from evidence.
Uses scoring_engine to rank candidates.

Flow:
1. Receive evidence (detections, credentials, assets)
2. Generate candidate opportunities (possible actions)
3. Score each opportunity
4. Rank by opportunity_score
5. Return ranked list with explanations
"""

from typing import List, Dict, Optional
from datetime import datetime
from engines.data_contracts import Opportunity, ScoringResult
from engines.scoring_engine import ScoringEngine


class OpportunityEngine:
    """Generate and rank exploitation opportunities"""
    
    def __init__(self):
        self.scoring_engine = ScoringEngine()
        self.opportunity_counter = 0
    
    def generate_opportunities(self,
                              campaign_id: str,
                              evidence: Dict,
                              known_assets: List[Dict],
                              known_credentials: List[Dict]) -> List[Opportunity]:
        """
        Generate opportunity list from evidence.
        
        Args:
        - campaign_id: Campaign context
        - evidence: {"assets": [...], "credentials": [...], "detections": [...]}
        - known_assets: List of discovered assets
        - known_credentials: List of known credentials
        
        Returns: Ranked list of Opportunity objects
        """
        
        opportunities = []
        
        # Generate candidates from evidence
        candidates = self._generate_candidates(evidence, known_assets, known_credentials)
        
        # Score each candidate
        for candidate in candidates:
            opportunity = self._score_and_create_opportunity(
                campaign_id=campaign_id,
                candidate=candidate,
                evidence=evidence
            )
            
            if opportunity.is_valid():
                opportunities.append(opportunity)
        
        # Sort by score (descending)
        opportunities.sort(key=lambda o: o.score, reverse=True)
        
        return opportunities
    
    def _generate_candidates(self,
                            evidence: Dict,
                            known_assets: List[Dict],
                            known_credentials: List[Dict]) -> List[Dict]:
        """
        Generate candidate opportunities from evidence.
        
        Heuristics:
        - For each asset: can we exploit it?
        - For each credential: can we use it?
        - For each detection: can we correlate?
        """
        
        candidates = []
        
        # Credential-based opportunities
        for cred in known_credentials:
            for asset in known_assets:
                # Can this credential access this asset?
                if self._credential_can_access(cred, asset):
                    candidates.append({
                        "type": "credential_use",
                        "technique": "T1021",  # Remote Services
                        "target_asset": asset.get("id", asset.get("name")),
                        "source": f"credential_{cred.get('id')}",
                        "description": f"Use {cred.get('username')} on {asset.get('name')}",
                    })
        
        # Exploitation opportunities
        for asset in known_assets:
            # Common exploitation techniques
            exploitable_techniques = [
                {"technique": "T1110", "description": "Brute force authentication"},
                {"technique": "T1021", "description": "Remote services exploitation"},
                {"technique": "T1548", "description": "Privilege escalation"},
                {"technique": "T1555", "description": "Credential dumping"},
            ]
            
            for tech in exploitable_techniques:
                candidates.append({
                    "type": "exploitation",
                    "technique": tech["technique"],
                    "target_asset": asset.get("id", asset.get("name")),
                    "source": f"asset_{asset.get('id')}",
                    "description": f"{tech['description']} on {asset.get('name')}",
                })
        
        return candidates
    
    def _credential_can_access(self, credential: Dict, asset: Dict) -> bool:
        """Heuristic: does credential have access to asset?"""
        
        # Simple heuristic: credential access level + asset type
        access_level = credential.get("access_level", "user")
        asset_type = asset.get("type", "host")
        
        # Credentials with higher access can access more
        if access_level == "admin":
            return True
        elif access_level == "system":
            return True
        elif asset_type == "workstation" and access_level in ["user", "admin"]:
            return True
        
        return False
    
    def _score_and_create_opportunity(self,
                                     campaign_id: str,
                                     candidate: Dict,
                                     evidence: Dict) -> Opportunity:
        """
        Score a candidate and create Opportunity object.
        
        Uses scoring_engine to calculate STEALTH, VALUE, RISK, OPPORTUNITY_SCORE.
        """
        
        self.opportunity_counter += 1
        opp_id = f"{campaign_id}_{self.opportunity_counter:04d}"
        
        # Extract candidate properties
        technique = candidate.get("technique", "T1000")
        target = candidate.get("target_asset", "unknown")
        
        # Calculate score (use heuristics based on technique)
        scoring_params = self._get_technique_parameters(technique)
        
        score_result = self.scoring_engine.score_opportunity(**scoring_params)
        
        # Generate explanation
        explanation = self._generate_explanation(candidate, score_result)
        
        # Predict logs and risks
        expected_logs = self._get_expected_logs(technique)
        edr_risks = self._get_edr_risks(technique)
        
        opportunity = Opportunity(
            id=opp_id,
            source_evidence=[candidate.get("source", "unknown")],
            technique=technique,
            target_asset=target,
            stealth=score_result.stealth,
            value=score_result.value,
            risk=score_result.risk,
            score=score_result.opportunity_score,
            confidence=score_result.confidence,
            explanation=explanation,
            expected_logs=expected_logs,
            edr_risks=edr_risks,
            dependencies=[],
            alternatives=[],
        )
        
        return opportunity
    
    def _get_technique_parameters(self, technique: str) -> Dict:
        """Get scoring parameters based on MITRE technique"""
        
        # Default parameters
        params = {
            "asset_criticality": 0.5,
            "credential_access": 0.5,
            "lateral_movement": 0.5,
            "domain_impact": 0.5,
            "data_access": 0.5,
            "log_events": 3,
            "alerts": 1,
            "edr_visibility": 0.3,
            "privilege_noise": 0.2,
            "detection_probability": 0.5,
            "blast_radius": 0.5,
            "irreversibility": 0.3,
            "operator_complexity": 0.5,
            "confidence": 0.7,
        }
        
        # Technique-specific overrides
        if technique == "T1021":  # Remote Services
            params.update({
                "log_events": 2,
                "edr_visibility": 0.4,
                "lateral_movement": 0.8,
                "detection_probability": 0.5,
            })
        elif technique == "T1110":  # Brute Force
            params.update({
                "log_events": 5,
                "alerts": 3,
                "edr_visibility": 0.8,
                "detection_probability": 0.8,
                "irreversibility": 0.7,
            })
        elif technique == "T1548":  # Privilege Escalation
            params.update({
                "log_events": 3,
                "edr_visibility": 0.6,
                "privilege_noise": 0.7,
                "domain_impact": 0.8,
                "detection_probability": 0.6,
            })
        elif technique == "T1555":  # Credential Dumping
            params.update({
                "log_events": 2,
                "edr_visibility": 0.7,
                "credential_access": 0.9,
                "detection_probability": 0.7,
            })
        
        return params
    
    def _generate_explanation(self, candidate: Dict, score: ScoringResult) -> str:
        """Generate human-readable explanation"""
        
        description = candidate.get("description", "Unknown action")
        
        # Narrative based on scores
        if score.opportunity_score >= 70:
            quality = "high-value, stealthy"
        elif score.opportunity_score >= 50:
            quality = "moderate value"
        else:
            quality = "low confidence"
        
        return (
            f"{description}. "
            f"This is a {quality} opportunity. "
            f"Stealth: {score.stealth:.0f}/100, "
            f"Value: {score.value:.0f}/100, "
            f"Risk: {score.risk:.0f}/100."
        )
    
    def _get_expected_logs(self, technique: str) -> List[str]:
        """Predict what logs will be generated"""
        
        logs = {
            "T1021": ["Network logon events", "RDP/SSH logs"],
            "T1110": ["Failed logon attempts", "Account lockout logs"],
            "T1548": ["Privilege escalation events", "UAC logs"],
            "T1555": ["LSASS access events", "Process memory access"],
        }
        
        return logs.get(technique, ["Generic event logs"])
    
    def _get_edr_risks(self, technique: str) -> List[str]:
        """Predict EDR detection risks"""
        
        risks = {
            "T1021": ["Suspicious logon from new host", "Lateral movement detection"],
            "T1110": ["Logon failure spike", "Account enumeration"],
            "T1548": ["Privilege escalation attempt", "UAC bypass signature"],
            "T1555": ["LSASS access attempt", "Credential dumping signature"],
        }
        
        return risks.get(technique, ["Generic EDR signature"])


__all__ = ['OpportunityEngine']
