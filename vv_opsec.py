"""
vv_opsec: OPSEC Simulation

Predict logs, EDR rules, behavioral flags for actions.

Return:
- probability_logged
- probability_detected_edr  
- probability_behavioral
- is_safe
- risk_level
- safer_alternative
"""

from typing import List, Dict
from vv_cognition import OpSecSimulation, Asset


class OpSecSimulator:
    """
    Simulate OPSEC risk for a proposed action.
    
    Predict what logs, EDR signatures, and behavioral flags will trigger.
    """
    
    # Technique OPSEC profiles
    TECHNIQUE_OPSEC = {
        "T1598": {  # Phishing
            "logs": ["Email gateway logs", "Email client logs"],
            "edr": ["Email filter heuristics"],
            "behavioral": ["Unusual email patterns"],
            "noise": 1,
        },
        "T1110": {  # Brute Force
            "logs": ["Auth failure logs (4625/4771)", "Account lockout logs"],
            "edr": ["Logon failure spike detection"],
            "behavioral": ["Rapid auth failures", "Multiple user enumeration"],
            "noise": 5,
        },
        "T1021": {  # Remote Services
            "logs": ["Network logon logs (4624-3)", "RDP/SSH logs"],
            "edr": ["Lateral movement detection", "Unusual service logon"],
            "behavioral": ["Admin account logon from unexpected system"],
            "noise": 3,
        },
        "T1547": {  # Boot or Logon
            "logs": ["Registry modification logs", "Logon events"],
            "edr": ["Persistence mechanism detection", "Autostart modification"],
            "behavioral": ["Suspicious registry changes"],
            "noise": 4,
        },
        "T1543": {  # Create or Modify System Process
            "logs": ["Service creation logs", "Process creation (Sysmon)"],
            "edr": ["Service creation anomaly", "Driver loading detection"],
            "behavioral": ["Suspicious service/driver parameters"],
            "noise": 5,
        },
        "T1548": {  # Abuse Elevation Control
            "logs": ["Privilege escalation logs", "UAC bypass logs"],
            "edr": ["Privilege escalation attempt", "UAC bypass signature"],
            "behavioral": ["Suspicious process elevation", "Token manipulation"],
            "noise": 4,
        },
        "T1555": {  # Credentials from Storage
            "logs": ["Process memory access logs", "Registry credential access"],
            "edr": ["LSASS access attempt", "Credential dumping signature"],
            "behavioral": ["Unusual credential access pattern"],
            "noise": 2,
        },
        "T1123": {  # Audio Capture
            "logs": ["Device audio logs", "Microphone access logs"],
            "edr": ["Audio device access anomaly"],
            "behavioral": ["Unusual audio device access"],
            "noise": 3,
        },
        "T1119": {  # Automated Exfiltration
            "logs": ["Network transfer logs", "DLP logs"],
            "edr": ["Data exfiltration detection", "Volume anomaly"],
            "behavioral": ["Unusual data volume transfer"],
            "noise": 4,
        },
        "T1048": {  # Exfiltration Over C2
            "logs": ["Network flow logs", "DLP logs"],
            "edr": ["C2 beacon detection", "Suspicious outbound connection"],
            "behavioral": ["Unusual outbound traffic pattern"],
            "noise": 3,
        },
    }
    
    # Asset-specific considerations
    ASSET_OPSEC_MODIFIERS = {
        "critical": 1.5,      # Critical assets have more monitoring
        "high": 1.3,
        "medium": 1.0,
        "low": 0.8,
    }
    
    # Environment modifiers
    ENV_MODIFIERS = {
        "production": 1.5,
        "staging": 1.0,
        "development": 0.6,
    }
    
    def simulate(self,
                action: str,
                target_asset: Asset,
                technique: str,
                additional_context: Dict = None) -> OpSecSimulation:
        """
        Simulate OPSEC impact of proposed action.
        
        Args:
        - action: Description of action
        - target_asset: Asset being targeted
        - technique: MITRE technique (e.g., "T1021")
        - additional_context: {"environment": "production", ...}
        
        Returns:
        - OpSecSimulation with detailed predictions
        """
        
        if additional_context is None:
            additional_context = {}
        
        # Get technique profile
        profile = self.TECHNIQUE_OPSEC.get(
            technique,
            {
                "logs": ["Generic action logs"],
                "edr": ["Generic EDR signature"],
                "behavioral": ["Anomalous behavior"],
                "noise": 3,
            }
        )
        
        # Get base probabilities from technique noise
        noise = profile.get("noise", 3)
        
        # Modifier based on asset criticality
        crit_mod = self.ASSET_OPSEC_MODIFIERS.get(
            target_asset.criticality, 1.0
        )
        
        # Modifier based on environment
        env = additional_context.get("environment", "production")
        env_mod = self.ENV_MODIFIERS.get(env, 1.0)
        
        # Calculate probabilities (0.0-1.0)
        # Base: noise level / 5, then apply modifiers
        prob_logged = min(0.95, (noise / 5.0) * crit_mod * env_mod)
        prob_edr = min(0.85, (noise / 6.0) * crit_mod * env_mod)
        prob_behavioral = min(0.75, (noise / 7.0) * crit_mod * env_mod)
        
        # Overall detection probability
        # If ANY detection method catches it, it's detected
        overall_prob = 1.0 - (
            (1.0 - prob_logged) *
            (1.0 - prob_edr) *
            (1.0 - prob_behavioral)
        )
        
        # Determine if safe
        is_safe = overall_prob < 0.4
        
        # Risk level
        if overall_prob < 0.2:
            risk_level = "low"
        elif overall_prob < 0.5:
            risk_level = "medium"
        elif overall_prob < 0.8:
            risk_level = "high"
        else:
            risk_level = "critical"
        
        # Suggest safer alternative
        safer_alt = self._suggest_safer_alternative(technique, target_asset)
        
        # Confidence in simulation
        confidence = min(0.9, 0.5 + len(profile.get("logs", [])) * 0.1)
        
        return OpSecSimulation(
            action=action,
            predicted_logs=profile.get("logs", []),
            predicted_edr_rules=profile.get("edr", []),
            behavioral_flags=profile.get("behavioral", []),
            probability_logged=prob_logged,
            probability_detected_edr=prob_edr,
            probability_behavioral=prob_behavioral,
            is_safe=is_safe,
            risk_level=risk_level,
            safer_alternative=safer_alt,
            confidence=confidence
        )
    
    def _suggest_safer_alternative(self, technique: str, asset: Asset) -> str:
        """
        Suggest a safer way to achieve the same objective.
        """
        # Build context-specific suggestion
        if asset.criticality == "critical":
            return "Avoid direct engagement. Gain access via lower-criticality asset, then lateral move."
        
        if technique in ["T1110", "T1543", "T1548"]:
            # Noisy techniques
            return "Use harvested credentials instead of active exploitation."
        
        if technique in ["T1119", "T1048"]:
            # Exfiltration is always risky
            return "Exfiltrate during maintenance window or after rotating C2 infrastructure."
        
        return "Gather more intelligence before committing to action."
    
    def batch_simulate(self,
                      actions: List[Dict],
                      target_asset: Asset) -> List[OpSecSimulation]:
        """
        Simulate OPSEC for multiple candidate actions.
        
        Returns list of simulations, sorted by risk.
        """
        results = []
        
        for action in actions:
            sim = self.simulate(
                action.get("description", "Unknown"),
                target_asset,
                action.get("technique", "T1000"),
                action.get("context", {})
            )
            results.append(sim)
        
        # Sort by risk (safest first)
        results.sort(key=lambda s: (
            1.0 if s.is_safe else 0.0,  # Safe first
            -s.confidence,  # Then high confidence
            s.probability_detected_edr + s.probability_logged  # Then lower noise
        ), reverse=True)
        
        return results


__all__ = [
    'OpSecSimulator',
]
