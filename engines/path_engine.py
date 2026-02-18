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
path_engine.py - Attack Path Planning

Plans multi-step attack paths to objectives.
Chains opportunities into coherent sequences.
Calculates cumulative risk, stealth, value.
"""

from typing import List, Dict
from engines.data_contracts import AttackPath, Opportunity


class PathEngine:
    """Plan attack paths to objectives"""
    
    def __init__(self):
        self.path_counter = 0
    
    def plan_paths(self,
                  objective: str,
                  opportunities: List[Opportunity],
                  current_position: str = "external") -> List[AttackPath]:
        """
        Plan attack paths to objective.
        
        Args:
        - objective: Campaign objective (e.g., "Access database")
        - opportunities: Available opportunities
        - current_position: Where we are now ("external", asset_id, etc.)
        
        Returns: Ranked list of AttackPath objects
        """
        
        paths = []
        
        # Generate path candidates (simplified - linear chains)
        candidates = self._generate_path_candidates(
            objective, opportunities, current_position
        )
        
        # Score each path
        for candidate in candidates:
            path = self._create_attack_path(objective, candidate)
            if path:
                paths.append(path)
        
        # Sort by success probability (descending)
        paths.sort(key=lambda p: p.success_probability, reverse=True)
        
        return paths
    
    def _generate_path_candidates(self,
                                 objective: str,
                                 opportunities: List[Opportunity],
                                 current_position: str) -> List[List[Opportunity]]:
        """
        Generate candidate paths (chains of opportunities).
        
        Simplified version: linear paths only.
        Real version would use graph search (A*, BFS).
        """
        
        candidates = []
        
        # Single-step paths
        for opp in opportunities:
            candidates.append([opp])
        
        # Two-step paths
        for i, opp1 in enumerate(opportunities):
            for j, opp2 in enumerate(opportunities):
                if i != j:  # Different opportunities
                    # Check if opp1 enables opp2 (simplified)
                    if self._can_follow(opp1, opp2):
                        candidates.append([opp1, opp2])
        
        return candidates
    
    def _can_follow(self, opp1: Opportunity, opp2: Opportunity) -> bool:
        """Check if opp2 can follow opp1 (dependency check)"""
        
        # Simple heuristic: if opp2 depends on output of opp1
        # For now, assume all can follow all (no hard dependencies)
        return True
    
    def _create_attack_path(self, objective: str, opportunities: List[Opportunity]) -> AttackPath:
        """Create AttackPath object from opportunity chain"""
        
        self.path_counter += 1
        path_id = f"path_{self.path_counter:04d}"
        
        # Extract step IDs
        steps = [opp.id for opp in opportunities]
        
        # Calculate cumulative metrics
        cumulative_risk = sum(opp.risk for opp in opportunities) / len(opportunities)
        cumulative_stealth = sum(opp.stealth for opp in opportunities) / len(opportunities)
        cumulative_value = sum(opp.value for opp in opportunities) / len(opportunities)
        
        # Calculate success probability (simplified)
        # Each step success chance * length penalty
        success_prob = 0.9  # Base 90%
        success_prob *= (0.95 ** len(opportunities))  # Penalty per step (0.95)^n
        
        # Explanation
        explanation = self._generate_path_explanation(objective, opportunities)
        
        # Estimated detection time (hours)
        estimated_detection = max(1, int(100 / (cumulative_risk / 10)))
        
        path = AttackPath(
            id=path_id,
            objective=objective,
            steps=steps,
            cumulative_risk=cumulative_risk,
            cumulative_stealth=cumulative_stealth,
            cumulative_value=cumulative_value,
            success_probability=success_prob,
            explanation=explanation,
            alternatives=[],
            estimated_detection_time=estimated_detection,
        )
        
        return path
    
    def _generate_path_explanation(self, objective: str, opportunities: List[Opportunity]) -> str:
        """Generate human-readable path explanation"""
        
        if len(opportunities) == 1:
            return f"Single-step path to {objective}: {opportunities[0].explanation}"
        else:
            steps_desc = " → ".join([f"{opp.technique}" for opp in opportunities])
            return f"Multi-step path to {objective}: {steps_desc}"


__all__ = ['PathEngine']
