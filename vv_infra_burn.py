"""
vv_infra_burn: Infrastructure Burn Tracking

Track C2 and infrastructure exposure:
- detections_correlated_with_c2
- unique_c2_ips_exposed
- tools_attributed

Calculate burn probability and recommend rotation.
"""

from typing import List, Dict, Set
from vv_cognition import InfraBurnAnalysis, DetectionEvent


class InfraBurnEngine:
    """
    Track infrastructure burn (exposure/attribution).
    
    Burn states:
    - fresh: No known exposure
    - warm: Some detections, not yet attributed
    - hot: Clear attribution or multiple detections
    - burned: Definitely detected and blocked
    """
    
    def __init__(self):
        self.detection_history = {}  # {c2_ip: [detections]}
        self.tool_detections = {}    # {tool_name: count}
    
    def update_burn(self,
                   detections: List[DetectionEvent],
                   sessions: List[Dict],
                   c2_servers: List[str] = None) -> InfraBurnAnalysis:
        """
        Calculate infrastructure burn from detections and sessions.
        
        Args:
        - detections: List of DetectionEvent objects
        - sessions: List of active sessions with C2 callbacks
        - c2_servers: List of known C2 IPs (optional)
        
        Returns:
        - InfraBurnAnalysis with burn probability and rotation recommendations
        """
        
        if c2_servers is None:
            c2_servers = []
        
        # Extract C2 IPs from sessions
        used_ips = set()
        for session in sessions:
            ip = session.get("callback_ip")
            if ip:
                used_ips.add(ip)
        
        # Correlate detections with C2
        detections_correlated = self._correlate_detections(
            detections, used_ips
        )
        
        # Identify tools attributed
        tools_attributed = self._identify_attributed_tools(detections)
        
        # Calculate burn probability
        burn_probability = self._calculate_burn_probability(
            detections_correlated, len(detections), tools_attributed
        )
        
        # Determine burn level
        burn_level = self._burn_level_from_probability(burn_probability)
        
        # Estimate days until critical
        days_until_critical = self._estimate_days_to_critical(
            burn_probability, detections_correlated
        )
        
        # Rotation recommendation
        should_rotate = burn_level in ["hot", "burned"]
        
        # Warning message
        warning_message = self._generate_warning(
            burn_level, burn_probability, days_until_critical
        )
        
        # Confidence
        confidence = min(0.9, 0.6 + (len(detections) / 100.0))
        
        return InfraBurnAnalysis(
            campaign_id="unknown",
            detections_correlated_with_c2=detections_correlated,
            unique_c2_ips_exposed=len(used_ips),
            tools_attributed=tools_attributed,
            burn_probability=round(burn_probability, 2),
            burn_level=burn_level,
            days_until_critical=days_until_critical,
            should_rotate=should_rotate,
            warning_message=warning_message,
            confidence=confidence
        )
    
    def _correlate_detections(self, detections: List[DetectionEvent],
                             c2_ips: Set[str]) -> int:
        """
        Count detections that mention C2 IPs.
        """
        correlated = 0
        
        for detection in detections:
            if not hasattr(detection, 'description'):
                continue
            
            desc = detection.description.lower()
            
            # Check for C2 patterns
            if any(ip in desc for ip in c2_ips):
                correlated += 1
            
            # Check for C2 indicators
            if any(pattern in desc for pattern in [
                'c2', 'beacon', 'callback', 'command and control',
                'remote server', 'suspicious outbound'
            ]):
                correlated += 1
        
        return correlated
    
    def _identify_attributed_tools(self,
                                   detections: List[DetectionEvent]) -> List[str]:
        """
        Identify which attack tools have been attributed by defenders.
        """
        attributed = set()
        
        tool_signatures = {
            "metasploit": ["meterpreter", "msf"],
            "empire": ["empire", "powershell-empire"],
            "cobalt-strike": ["beacon", "cobalt"],
            "mimikatz": ["mimikatz", "lsass"],
            "psexec": ["psexec", "lateral"],
            "bloodhound": ["sharphound", "bloodhound"],
        }
        
        for detection in detections:
            if not hasattr(detection, 'description'):
                continue
            
            desc = detection.description.lower()
            
            for tool, signatures in tool_signatures.items():
                if any(sig in desc for sig in signatures):
                    attributed.add(tool)
        
        return list(attributed)
    
    def _calculate_burn_probability(self, correlated: int,
                                    total_detections: int,
                                    attributed_tools: List[str]) -> float:
        """
        Calculate probability infrastructure is burned/attributed.
        
        Range: 0.0-1.0
        """
        if total_detections == 0:
            return 0.0
        
        # Base probability from correlated detections
        correlation_factor = min(1.0, correlated / max(1, total_detections))
        
        # Tool attribution increases burn probability
        tool_factor = min(1.0, len(attributed_tools) / 5.0)
        
        # Combined
        probability = (correlation_factor * 0.6) + (tool_factor * 0.4)
        
        return min(1.0, probability)
    
    def _burn_level_from_probability(self, probability: float) -> str:
        """
        Convert probability to burn level.
        """
        if probability < 0.1:
            return "fresh"
        elif probability < 0.3:
            return "warm"
        elif probability < 0.7:
            return "hot"
        else:
            return "burned"
    
    def _estimate_days_to_critical(self, burn_probability: float,
                                   correlated_detections: int) -> int:
        """
        Estimate days until infrastructure becomes critical/burned.
        """
        # If already hot/burned, estimate 1-3 days
        if burn_probability > 0.6:
            return 1
        
        # If showing correlation, estimate 3-7 days
        if correlated_detections > 3:
            return 3
        
        # Otherwise, estimate 7-30 days
        if burn_probability > 0.2:
            return 7
        
        # Fresh infrastructure
        return 30
    
    def _generate_warning(self, burn_level: str,
                         probability: float,
                         days_until_critical: int) -> str:
        """
        Generate warning message for operator.
        """
        if burn_level == "burned":
            return (
                f"CRITICAL: Infrastructure attributed (burn probability: {probability:.0%}). "
                f"Expect immediate blocking. Activate contingency C2 within 24 hours."
            )
        elif burn_level == "hot":
            return (
                f"WARNING: Infrastructure showing strong correlation with campaign "
                f"(burn probability: {probability:.0%}). "
                f"Recommend rotating C2 within {days_until_critical} days."
            )
        elif burn_level == "warm":
            return (
                f"CAUTION: Some detections may correlate with infrastructure "
                f"(probability: {probability:.0%}). "
                f"Monitor detection trends. Consider rotation in {days_until_critical} days."
            )
        else:
            return "Infrastructure status: FRESH. No known exposure."
    
    def recommend_rotation_strategy(self, current_burn: InfraBurnAnalysis) -> Dict:
        """
        Recommend infrastructure rotation strategy.
        """
        if not current_burn.should_rotate:
            return {
                "rotate_now": False,
                "strategy": "Continue monitoring. No immediate action needed.",
            }
        
        # Rotation strategy
        strategy = {
            "rotate_now": True,
            "recommended_actions": [
                "Prepare new C2 infrastructure (different providers, regions)",
                "Stage new implants/agents on existing access",
                "Test new C2 channel before cutover",
                "Execute graceful migration over 12-24 hours",
                "Monitor for new detections post-rotation",
            ],
            "timeline": {
                "preparation": "Immediate",
                "staging": "Within 12 hours",
                "cutover": "Within 24 hours",
                "monitoring": "72 hours post-cutover",
            },
        }
        
        return strategy


__all__ = [
    'InfraBurnEngine',
]
