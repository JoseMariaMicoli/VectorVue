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
vv_recommend: Recommendation Scoring Engine

Score operator actions by:
- value_score: privilege gain + intel gain + objective progress
- noise_score: logs, EDR signatures, behavioral flags
- risk_score: noise_score × detection_pressure × asset_criticality
- stealth_score: (1 - risk_score) × familiarity_bonus
- novelty_score: inverse of usage frequency
- final_score: value_score × stealth_score × novelty_score

Include confidence and safer alternatives.
"""

from typing import List, Dict, Tuple
from dataclasses import dataclass, field
from vv_cognition import Recommendation, Asset, Credential
from vv_graph import AttackGraph


class RecommendationEngine:
    """
    Score and rank operator recommendations.
    
    Scoring formula:
    value = privilege_gain + intel_gain + objective_proximity
    noise = expected_logs + tool_signature + behavioral_flags
    risk = noise × detection_pressure × asset_criticality
    stealth = (1 - risk) × familiarity_bonus
    novelty = inverse_usage_frequency
    final = value × stealth × novelty
    """
    
    # Technique noise profiles (logs, EDR, behavioral cost)
    TECHNIQUE_PROFILES = {
        "T1598": {"noise": 1, "logs": 3, "edr": 2, "behavioral": 1, "name": "Phishing"},
        "T1110": {"noise": 3, "logs": 5, "edr": 4, "behavioral": 2, "name": "Brute Force"},
        "T1021": {"noise": 2, "logs": 4, "edr": 3, "behavioral": 2, "name": "Remote Services"},
        "T1547": {"noise": 2, "logs": 3, "edr": 5, "behavioral": 4, "name": "Boot or Logon"},
        "T1543": {"noise": 3, "logs": 4, "edr": 5, "behavioral": 3, "name": "Create/Modify System"},
        "T1548": {"noise": 2, "logs": 4, "edr": 4, "behavioral": 3, "name": "Abuse Elevation"},
        "T1555": {"noise": 1, "logs": 2, "edr": 1, "behavioral": 1, "name": "Credentials from Storage"},
        "T1123": {"noise": 2, "logs": 3, "edr": 4, "behavioral": 3, "name": "Audio Capture"},
        "T1119": {"noise": 2, "logs": 3, "edr": 4, "behavioral": 2, "name": "Automated Exfiltration"},
        "T1048": {"noise": 2, "logs": 2, "edr": 3, "behavioral": 2, "name": "Exfiltration Over C2"},
    }
    
    def __init__(self, graph: AttackGraph):
        self.graph = graph
        self.usage_frequency = {}  # Track how often each technique is used
    
    def score_recommendations(self,
                            candidate_actions: List[Dict],
                            target_asset: Asset,
                            detection_pressure: int,
                            recent_actions: List[Dict] = None) -> List[Recommendation]:
        """
        Score a list of candidate actions.
        
        Args:
        - candidate_actions: [{"technique": "T1021", "method": "SSH", "target": 5}, ...]
        - target_asset: Asset to compromise
        - detection_pressure: 0-100 detection risk
        - recent_actions: List of recently executed actions for novelty calculation
        
        Returns:
        - List of Recommendation objects, sorted by final_score desc
        """
        
        if recent_actions is None:
            recent_actions = []
        
        recommendations = []
        
        for i, action in enumerate(candidate_actions):
            technique = action.get("technique", "T1000")
            method = action.get("method", "unknown")
            
            # Get technique profile
            profile = self.TECHNIQUE_PROFILES.get(technique, {
                "noise": 2, "logs": 3, "edr": 3, "behavioral": 2, "name": "Technique"
            })
            
            # Calculate value score
            value_score = self._calculate_value_score(
                technique, method, target_asset, action
            )
            
            # Calculate noise score
            noise_score = self._calculate_noise_score(
                profile, target_asset, technique, recent_actions
            )
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(
                noise_score, detection_pressure, target_asset
            )
            
            # Calculate stealth score
            stealth_score = self._calculate_stealth_score(
                risk_score, technique, recent_actions
            )
            
            # Calculate novelty score
            novelty_score = self._calculate_novelty_score(technique, recent_actions)
            
            # Final score
            final_score = max(0.0, min(1.0,
                value_score * stealth_score * novelty_score
            ))
            
            # Calculate confidence
            confidence = self._calculate_confidence(
                value_score, stealth_score, detection_pressure
            )
            
            # Generate explanation
            explanation = self._generate_explanation(
                action, technique, value_score, stealth_score, confidence
            )
            
            # List expected logs
            expected_logs = self._predict_logs(technique, target_asset)
            
            # List EDR risks
            edr_risks = self._predict_edr_risks(technique, profile)
            
            # Suggest safer alternative
            safer_alt = self._suggest_safer_alternative(technique, target_asset, recent_actions)
            
            rec = Recommendation(
                rec_id=f"rec_{i}",
                action=f"{profile.get('name', 'Action')} via {method}",
                action_type=technique,
                target_asset=target_asset.asset_id,
                technique=technique,
                value_score=value_score,
                noise_score=noise_score,
                risk_score=risk_score,
                stealth_score=stealth_score,
                novelty_score=novelty_score,
                final_score=final_score,
                confidence=confidence,
                explanation=explanation,
                expected_logs=expected_logs,
                edr_risks=edr_risks,
                safer_alternatives=[safer_alt] if safer_alt else []
            )
            
            recommendations.append(rec)
        
        # Sort by final_score descending
        recommendations.sort(key=lambda r: r.final_score, reverse=True)
        
        return recommendations
    
    def _calculate_value_score(self, technique: str, method: str, 
                               asset: Asset, action: Dict) -> float:
        """
        Calculate value of action.
        
        value = privilege_gain + intel_gain + objective_proximity
        Range: 0.0-1.0
        """
        value = 0.5
        
        # Privilege gain
        if asset.criticality == "critical":
            value += 0.3
        elif asset.criticality == "high":
            value += 0.2
        
        # Intel gain (if credentials expected)
        if technique in ["T1555", "T1110", "T1021"]:
            value += 0.2
        
        return min(1.0, value)
    
    def _calculate_noise_score(self, profile: Dict, asset: Asset, 
                               technique: str, recent_actions: List) -> float:
        """
        Calculate logs/noise generated by action.
        
        Range: 0.0-10.0 (normalized to 0.0-1.0)
        """
        noise = float(profile.get("logs", 3))
        
        # Sensitive assets amplify noise
        if "prod" in asset.sensitivity_tags:
            noise *= 1.5
        if "medical" in asset.sensitivity_tags or "pii" in asset.sensitivity_tags:
            noise *= 1.3
        
        # Normalize to 0.0-1.0
        return min(1.0, noise / 10.0)
    
    def _calculate_risk_score(self, noise_score: float, 
                             detection_pressure: int, asset: Asset) -> float:
        """
        Calculate risk = noise × detection_pressure × asset_criticality
        
        Range: 0.0-1.0
        """
        # Normalize detection_pressure (0-100 → 0.0-1.0)
        pressure_factor = detection_pressure / 100.0
        
        # Asset criticality factor
        crit_factor = 0.3 if asset.criticality == "critical" else 0.2
        
        risk = noise_score * pressure_factor * (0.5 + crit_factor)
        
        return min(1.0, risk)
    
    def _calculate_stealth_score(self, risk_score: float, 
                                technique: str, recent_actions: List) -> float:
        """
        Calculate stealth = (1 - risk) × familiarity_bonus
        
        Range: 0.0-1.0
        """
        stealth = 1.0 - risk_score
        
        # Familiar techniques (already used) are stealthier
        # (attacker knows what to expect)
        recent_techs = [a.get("technique") for a in recent_actions]
        if technique in recent_techs:
            stealth *= 1.2  # Bonus for familiarity
        
        return min(1.0, stealth)
    
    def _calculate_novelty_score(self, technique: str, recent_actions: List) -> float:
        """
        Calculate novelty = inverse of usage frequency.
        
        Novel techniques are better (less detected/expected).
        Range: 0.0-1.0
        """
        recent_techs = [a.get("technique") for a in recent_actions]
        freq = recent_techs.count(technique)
        
        # Decay: 1st use = 1.0, 2nd = 0.7, 3rd+ = 0.4
        if freq == 0:
            return 1.0
        elif freq == 1:
            return 0.7
        else:
            return 0.4
    
    def _calculate_confidence(self, value_score: float, stealth_score: float,
                             detection_pressure: int) -> float:
        """
        Calculate confidence in success.
        
        confidence = (value_score × stealth_score) - pressure_uncertainty
        """
        conf = value_score * stealth_score
        
        # Detection pressure reduces confidence
        pressure_uncertainty = (detection_pressure / 100.0) * 0.3
        
        return max(0.2, min(1.0, conf - pressure_uncertainty))
    
    def _generate_explanation(self, action: Dict, technique: str,
                             value_score: float, stealth_score: float,
                             confidence: float) -> str:
        """
        Generate human-readable explanation.
        """
        profile = self.TECHNIQUE_PROFILES.get(technique, {})
        name = profile.get("name", "Technique")
        
        if stealth_score > 0.7:
            stealth_text = "high stealth"
        elif stealth_score > 0.4:
            stealth_text = "moderate stealth"
        else:
            stealth_text = "low stealth (high noise)"
        
        if value_score > 0.7:
            value_text = "high value"
        elif value_score > 0.4:
            value_text = "moderate value"
        else:
            value_text = "low value"
        
        conf_pct = int(confidence * 100)
        
        return (
            f"{name} attack with {value_text} and {stealth_text}. "
            f"Confidence in success: {conf_pct}%. "
            f"Expect significant logs and EDR activity."
        )
    
    def _predict_logs(self, technique: str, asset: Asset) -> List[str]:
        """
        Predict what logs will be generated.
        """
        logs = []
        
        profile = self.TECHNIQUE_PROFILES.get(technique, {})
        
        if profile.get("logs", 0) >= 4:
            logs.append("Windows Security Event Log (Auth failures/successes)")
        if profile.get("logs", 0) >= 3:
            logs.append("Application event logs")
        if profile.get("edr", 0) >= 4:
            logs.append("EDR telemetry (process creation, network)")
        
        if "prod" in asset.sensitivity_tags:
            logs.append("Centralized SIEM correlation")
        
        return logs
    
    def _predict_edr_risks(self, technique: str, profile: Dict) -> List[str]:
        """
        List EDR detection risks.
        """
        risks = []
        
        if profile.get("edr", 0) >= 5:
            risks.append("High-fidelity EDR rule (process behavior)")
        if profile.get("edr", 0) >= 3:
            risks.append("Generic EDR heuristic match")
        if profile.get("behavioral", 0) >= 4:
            risks.append("Behavioral analysis (anomalous execution)")
        
        return risks
    
    def _suggest_safer_alternative(self, technique: str, asset: Asset,
                                   recent_actions: List) -> str:
        """
        Suggest a safer alternative technique.
        """
        # Simple heuristic: if current is noisy, suggest credential-based instead
        profile = self.TECHNIQUE_PROFILES.get(technique, {})
        
        if profile.get("noise", 2) > 2:
            return "Use harvested credentials instead of active exploitation"
        
        if asset.criticality == "critical":
            return "Stage on lower-criticality asset first, then lateral move"
        
        return "Gather more intelligence before direct engagement"


__all__ = [
    'RecommendationEngine',
]
