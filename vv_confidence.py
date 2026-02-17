
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
vv_confidence: Confidence Analysis Engine

Calculate overall decision confidence:
confidence = data_completeness × observation_count × path_stability

Warn about major unknowns and data gaps.

Core principle: NEVER advise without confidence value.
"""

from typing import List, Dict, Set
from vv_cognition import ConfidenceAnalysis, Asset, Credential, DetectionEvent


class ConfidenceEngine:
    """
    Analyze and calculate confidence in recommendations.
    
    confidence = data_completeness × observation_count × path_stability
    
    Factors:
    - Data completeness: How much of the environment do we understand?
    - Observation count: How many data points support this?
    - Path stability: How reliably can we replicate the path?
    """
    
    def __init__(self):
        self.min_confidence_for_advice = 0.3  # Never advise below this
    
    def calculate_confidence(self,
                            assets: Dict[int, Asset],
                            credentials: Dict[str, Credential],
                            detections: List[DetectionEvent],
                            objectives: List[Dict] = None) -> ConfidenceAnalysis:
        """
        Calculate overall confidence in current intelligence.
        
        Args:
        - assets: Known assets (completeness measure)
        - credentials: Harvested credentials (observation count)
        - detections: Defensive detections (path stability)
        - objectives: Campaign objectives (context)
        
        Returns:
        - ConfidenceAnalysis with confidence score and warnings
        """
        
        if objectives is None:
            objectives = []
        
        # Data completeness (0.0-1.0)
        # Assume 100 assets typical environment
        expected_assets = 100
        known_assets = len(assets)
        data_completeness = min(1.0, known_assets / expected_assets)
        
        # Observation count
        # Each credential and detection is an observation
        total_observations = len(credentials) + len(detections)
        observation_factor = min(1.0, total_observations / 50.0)  # Scale to 50 obs
        
        # Path stability
        # Detections reduce stability, but expected
        successful_techniques = self._count_successful_techniques(credentials)
        detection_rate = len(detections) / max(1, total_observations)
        path_stability = (successful_techniques / max(1, len(credentials))) \
                        * (1.0 - min(0.3, detection_rate))  # Cap impact at 30%
        
        # Overall confidence
        overall_confidence = data_completeness * observation_factor * path_stability
        overall_confidence = max(0.2, min(0.95, overall_confidence))
        
        # Confidence trend (would track over time)
        trend = "stable"  # Default
        
        # Identify unknowns
        major_unknowns = self._identify_unknowns(
            assets, credentials, objectives
        )
        
        # Identify gaps
        data_gaps = self._identify_gaps(
            assets, credentials, detections
        )
        
        return ConfidenceAnalysis(
            campaign_id="unknown",
            data_completeness=round(data_completeness, 2),
            observation_count=total_observations,
            path_stability=round(path_stability, 2),
            overall_confidence=round(overall_confidence, 2),
            confidence_trend=trend,
            major_unknowns=major_unknowns,
            data_gaps=data_gaps
        )
    
    def _count_successful_techniques(self, credentials: Dict) -> int:
        """
        Count distinct techniques that successfully yielded credentials.
        """
        # Simplified: assume each credential represents success
        return len(credentials)
    
    def _identify_unknowns(self,
                          assets: Dict[int, Asset],
                          credentials: Dict[str, Credential],
                          objectives: List[Dict]) -> List[str]:
        """
        Identify major unknowns that reduce confidence.
        """
        unknowns = []
        
        if len(assets) < 50:
            unknowns.append("Asset inventory incomplete (< 50 assets mapped)")
        
        if len(credentials) == 0:
            unknowns.append("No credentials harvested yet - limited visibility")
        
        if len(credentials) < 5:
            unknowns.append("Small credential set - limited access paths")
        
        # Check for specific gaps
        has_admin = any(c.access_level == "admin" for c in credentials.values())
        if not has_admin:
            unknowns.append("No admin-level credentials - elevated access unknown")
        
        has_domain = any(c.assets_with_access for c in credentials.values())
        if not has_domain:
            unknowns.append("Cross-asset access patterns unknown")
        
        if objectives:
            has_mapped_objective = any(
                obj.get("target_asset") for obj in objectives
            )
            if not has_mapped_objective:
                unknowns.append("Objective targets not yet mapped")
        
        return unknowns
    
    def _identify_gaps(self,
                      assets: Dict[int, Asset],
                      credentials: Dict[str, Credential],
                      detections: List[DetectionEvent]) -> List[str]:
        """
        Identify specific data gaps.
        """
        gaps = []
        
        # Credential freshness
        stale_creds = [c for c in credentials.values()
                      if c.freshness_days and c.freshness_days > 30]
        if stale_creds:
            gaps.append(
                f"Credential freshness risk: {len(stale_creds)} credentials > 30 days old"
            )
        
        # Network coverage
        unique_networks = set()
        for asset in assets.values():
            if hasattr(asset, 'network_segment'):
                unique_networks.add(asset.network_segment)
        
        if len(unique_networks) < 3:
            gaps.append(f"Limited network coverage: only {len(unique_networks)} segments")
        
        # Detection types
        detection_types = set(d.event_type for d in detections)
        if len(detection_types) < 3:
            gaps.append(
                f"Detection diversity low: {len(detection_types)} types. "
                "May be missing entire defensive layer."
            )
        
        # Asset coverage by sensitivity
        critical_assets = [a for a in assets.values()
                          if a.criticality == "critical"]
        if critical_assets:
            known_creds = sum(
                1 for c in credentials.values()
                if c.assets_with_access and critical_assets[0].asset_id in c.assets_with_access
            )
            if known_creds == 0:
                gaps.append(f"Critical assets not yet compromised: {len(critical_assets)} total")
        
        return gaps
    
    def validate_recommendation(self, confidence: float) -> bool:
        """
        Check if recommendation should be presented to operator.
        
        True if confidence >= minimum threshold.
        """
        return confidence >= self.min_confidence_for_advice
    
    def assess_information_need(self) -> List[str]:
        """
        Suggest highest-priority intelligence gathering activities.
        """
        return [
            "Enumerate all domain users and groups",
            "Map network segments and subnets",
            "Identify privileged accounts (admin, service accounts)",
            "Discover sensitive data locations",
            "Profile defensive tools (AV, EDR, SIEM)",
        ]


__all__ = [
    'ConfidenceEngine',
]
