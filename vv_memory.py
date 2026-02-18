"""
Copyright (c) 2026 José María Micoli
Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}

You may:
✔ Study
✔ Modify
✔ Use for internal security testing

You may NOT:
✘ Offer as a commercial service
✘ Sell derived competing products
"""

"""
vv_memory: Context and Pattern Memory

Maintain long-term campaign context:
- Successful techniques per asset/network
- Failed approaches and why
- Asset evolution over time
- Operator behavior patterns

Enable pattern-based suggestions.
"""

from typing import List, Dict, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, field


@dataclass
class TechniquePattern:
    """Historical success/failure pattern for technique."""
    technique: str
    asset_type: str  # host, network, account, etc.
    success_count: int = 0
    failure_count: int = 0
    last_used: datetime = None
    avg_time_to_compromise: float = 0.0  # minutes
    confidence: float = 0.5


@dataclass
class AssetPattern:
    """Evolution pattern for asset type."""
    asset_type: str
    avg_discovery_time: float = 0.0  # minutes from initial compromise
    avg_compromise_time: float = 0.0
    common_techniques: List[str] = field(default_factory=list)
    defensive_measures: List[str] = field(default_factory=list)
    is_honeypot_risk: bool = False


class MemoryEngine:
    """
    Long-term context and pattern memory.
    
    Maintains:
    - Technique success rates
    - Asset evolution patterns
    - Network topology learning
    - Operator behavior
    """
    
    def __init__(self, campaign_id: str):
        self.campaign_id = campaign_id
        self.technique_patterns: Dict[str, TechniquePattern] = {}
        self.asset_patterns: Dict[str, AssetPattern] = {}
        self.operator_preferences: Dict[str, List[str]] = {}  # {operator: [techniques]}
        self.failed_approaches: List[Dict] = []
        self.network_map: Dict[str, Set[str]] = {}  # {segment: {assets}}
    
    def learn_technique_outcome(self,
                               technique: str,
                               asset_type: str,
                               success: bool,
                               time_to_compromise: float = None) -> None:
        """
        Record technique success/failure for learning.
        
        Args:
        - technique: MITRE technique (T-number)
        - asset_type: Type of asset targeted
        - success: Whether technique succeeded
        - time_to_compromise: Minutes taken (optional)
        """
        
        pattern_key = f"{technique}_{asset_type}"
        
        if pattern_key not in self.technique_patterns:
            self.technique_patterns[pattern_key] = TechniquePattern(
                technique=technique,
                asset_type=asset_type
            )
        
        pattern = self.technique_patterns[pattern_key]
        
        if success:
            pattern.success_count += 1
            if time_to_compromise:
                # Update moving average
                total = pattern.success_count + pattern.failure_count
                pattern.avg_time_to_compromise = (
                    (pattern.avg_time_to_compromise * (total - 1) + time_to_compromise)
                    / total
                )
        else:
            pattern.failure_count += 1
        
        pattern.last_used = datetime.now()
        
        # Update confidence (simple: success_rate)
        total = pattern.success_count + pattern.failure_count
        pattern.confidence = pattern.success_count / max(1, total)
    
    def record_failed_approach(self,
                              technique: str,
                              target: str,
                              failure_reason: str) -> None:
        """
        Record failed approach for learning.
        """
        
        self.failed_approaches.append({
            "timestamp": datetime.now(),
            "technique": technique,
            "target": target,
            "reason": failure_reason,
        })
    
    def record_operator_technique(self,
                                  operator_id: str,
                                  technique: str) -> None:
        """
        Record operator's technique preference.
        """
        
        if operator_id not in self.operator_preferences:
            self.operator_preferences[operator_id] = []
        
        if technique not in self.operator_preferences[operator_id]:
            self.operator_preferences[operator_id].append(technique)
    
    def suggest_techniques(self,
                         asset_type: str,
                         operator_id: str = None) -> List[Dict]:
        """
        Suggest effective techniques based on history.
        
        Args:
        - asset_type: Type of asset being targeted
        - operator_id: Operator's preference (optional)
        
        Returns:
        - List of suggestions with confidence
        """
        
        suggestions = []
        
        # Get all patterns for this asset type
        applicable = {
            k: v for k, v in self.technique_patterns.items()
            if v.asset_type == asset_type
        }
        
        # Sort by confidence (success rate)
        sorted_patterns = sorted(
            applicable.values(),
            key=lambda p: p.confidence,
            reverse=True
        )
        
        for pattern in sorted_patterns[:5]:  # Top 5
            suggestion = {
                "technique": pattern.technique,
                "confidence": pattern.confidence,
                "success_count": pattern.success_count,
                "avg_time_minutes": round(pattern.avg_time_to_compromise, 1),
                "is_operator_preference": (
                    operator_id and
                    pattern.technique in self.operator_preferences.get(operator_id, [])
                ),
            }
            suggestions.append(suggestion)
        
        return suggestions
    
    def get_operator_profile(self, operator_id: str) -> Dict:
        """
        Build operator behavior profile.
        """
        
        preferences = self.operator_preferences.get(operator_id, [])
        
        # Count uses and success rate
        technique_stats = {}
        for tech in preferences:
            pattern_keys = [
                k for k in self.technique_patterns.keys()
                if self.technique_patterns[k].technique == tech
            ]
            
            for key in pattern_keys:
                pattern = self.technique_patterns[key]
                if tech not in technique_stats:
                    technique_stats[tech] = {
                        "uses": 0,
                        "success_rate": 0.0,
                    }
                
                total = pattern.success_count + pattern.failure_count
                technique_stats[tech]["uses"] += total
                technique_stats[tech]["success_rate"] = (
                    pattern.confidence  # Use pattern confidence
                )
        
        return {
            "operator_id": operator_id,
            "preferred_techniques": preferences,
            "technique_stats": technique_stats,
            "favorite_technique": (
                preferences[0] if preferences else "unknown"
            ),
        }
    
    def get_lessons_learned(self) -> str:
        """
        Generate lessons learned narrative.
        """
        
        narrative = f"# {self.campaign_id} Lessons Learned\n\n"
        
        # Most successful techniques
        narrative += "## Effective Techniques\n\n"
        best_techniques = sorted(
            self.technique_patterns.values(),
            key=lambda p: p.confidence,
            reverse=True
        )[:5]
        
        for pattern in best_techniques:
            if pattern.confidence > 0.5:
                narrative += (
                    f"- **{pattern.technique}** (vs {pattern.asset_type}): "
                    f"{pattern.success_count}S/{pattern.failure_count}F, "
                    f"{pattern.confidence:.0%} success rate\n"
                )
        
        # Failed approaches
        narrative += "\n## Failed Approaches\n\n"
        recent_failures = [
            f for f in self.failed_approaches
            if f.get("timestamp") > datetime.now() - timedelta(days=7)
        ]
        
        for failure in recent_failures[:5]:
            narrative += (
                f"- {failure.get('technique')} on {failure.get('target')}: "
                f"{failure.get('reason')}\n"
            )
        
        # Operator patterns
        if self.operator_preferences:
            narrative += "\n## Operator Preferences\n\n"
            for op, techs in self.operator_preferences.items():
                narrative += f"- **{op}**: Prefers {', '.join(techs[:3])}\n"
        
        return narrative
    
    def recommend_avoidance(self) -> List[str]:
        """
        Recommend techniques/approaches to avoid.
        """
        
        recommendations = []
        
        # Identify consistently failed techniques
        failed = {
            k: v for k, v in self.technique_patterns.items()
            if v.confidence < 0.3 and (v.success_count + v.failure_count) > 3
        }
        
        for key, pattern in failed.items():
            recommendations.append(
                f"Avoid {pattern.technique} on {pattern.asset_type} "
                f"({pattern.confidence:.0%} success rate)"
            )
        
        return recommendations


__all__ = [
    'MemoryEngine',
    'TechniquePattern',
    'AssetPattern',
]
