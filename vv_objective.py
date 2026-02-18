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
vv_objective: Objective Distance Calculation

Calculate distance to objectives:
distance = privilege_steps + lateral_moves + unknown_penalty + pressure_penalty

Return steps_remaining and confidence for each objective.
"""

from typing import List, Dict, Tuple
from dataclasses import dataclass
from vv_cognition import ObjectiveDistance, Asset
from vv_graph import AttackGraph


class ObjectiveEngine:
    """
    Calculate distance to campaign objectives.
    
    Distance = privilege_escalation_steps + lateral_movement_steps + uncertainty
    """
    
    def __init__(self, graph: AttackGraph):
        self.graph = graph
    
    def calculate_distances(self, 
                          objectives: List[Dict],
                          assets: Dict[int, Asset],
                          detection_pressure: int) -> List[ObjectiveDistance]:
        """
        Calculate distance to each objective.
        
        Args:
        - objectives: [{"id": 1, "text": "Access database", "target_asset": 5}, ...]
        - assets: {asset_id: Asset}
        - detection_pressure: 0-100 penalty for detection risk
        
        Returns:
        - List of ObjectiveDistance objects
        """
        
        results = []
        
        for obj in objectives:
            obj_id = obj.get("id", 0)
            obj_text = obj.get("text", "Unknown objective")
            target_asset = obj.get("target_asset")
            
            if not target_asset:
                # Can't calculate distance without target
                dist = ObjectiveDistance(
                    objective_id=obj_id,
                    objective_text=obj_text,
                    privilege_steps=0,
                    lateral_moves=0,
                    unknown_penalty=10,
                    pressure_penalty=0,
                    total_distance=10,
                    steps_remaining=10,
                    confidence=0.0,
                    critical_path=[],
                    alternatives=[],
                    blockers=["No target asset specified"]
                )
                results.append(dist)
                continue
            
            # Find path to target
            path, path_desc, path_conf = self.graph.shortest_path(target_asset)
            
            if not path:
                # No path found
                dist = ObjectiveDistance(
                    objective_id=obj_id,
                    objective_text=obj_text,
                    privilege_steps=0,
                    lateral_moves=999,
                    unknown_penalty=20,
                    pressure_penalty=max(0, detection_pressure - 50),
                    total_distance=999,
                    steps_remaining=999,
                    confidence=0.1,
                    critical_path=[],
                    alternatives=[],
                    blockers=["No path to objective found", "Need more intelligence"]
                )
                results.append(dist)
                continue
            
            # Calculate distance components
            lateral_moves = len(path) - 1  # Hops
            
            # Privilege steps (simplified)
            privilege_steps = self._estimate_privesc_steps(path, assets)
            
            # Unknown penalty (length of path = more unknowns)
            unknown_penalty = max(0, len(path) - 3)  # 0 penalty for short paths
            
            # Pressure penalty (adjusts for detection risk)
            pressure_penalty = max(0, (detection_pressure - 30) // 20)
            
            total_distance = lateral_moves + privilege_steps + unknown_penalty + pressure_penalty
            
            # Confidence: higher for shorter paths
            confidence = max(0.3, 1.0 - (len(path) * 0.15))
            
            # Build critical path narrative
            critical_path = [
                f"Step 1: Compromise {assets.get(path[0], 'initial').name if path else 'initial'}",
            ]
            for i in range(1, len(path)):
                from_asset = assets.get(path[i-1], Asset(path[i-1], f"Asset {path[i-1]}", "unknown"))
                to_asset = assets.get(path[i], Asset(path[i], f"Asset {path[i]}", "unknown"))
                critical_path.append(f"Step {i+1}: Lateral move to {to_asset.name}")
            
            if privilege_steps > 0:
                critical_path.append(f"Step {len(path)+1}: Escalate privileges (×{privilege_steps})")
            
            dist = ObjectiveDistance(
                objective_id=obj_id,
                objective_text=obj_text,
                privilege_steps=privilege_steps,
                lateral_moves=lateral_moves,
                unknown_penalty=unknown_penalty,
                pressure_penalty=pressure_penalty,
                total_distance=total_distance,
                steps_remaining=total_distance,
                confidence=confidence,
                critical_path=critical_path,
                alternatives=self._find_alternative_paths(target_asset, assets),
                blockers=self._identify_blockers(path, assets)
            )
            
            results.append(dist)
        
        return results
    
    def _estimate_privesc_steps(self, path: List[int], assets: Dict[int, Asset]) -> int:
        """
        Estimate privilege escalation steps needed along path.
        
        More complex targets = more privesc needed
        """
        steps = 0
        
        for asset_id in path:
            if asset_id in assets:
                asset = assets[asset_id]
                # Critical assets require more privesc
                if asset.criticality == "critical":
                    steps += 2
                elif asset.criticality == "high":
                    steps += 1
        
        return steps
    
    def _find_alternative_paths(self, target_asset: int, assets: Dict[int, Asset]) -> List[List[str]]:
        """
        Find alternative paths (simplified - just return main path alternatives).
        
        In production, would use k-shortest-paths algorithm.
        """
        # Simplified: return 1-2 alternative descriptions
        alternatives = [
            ["Via admin account", "Lateral move", "Privilege escalation"],
            ["Via software supply chain", "Initial compromise", "Lateral movement"],
        ]
        
        return alternatives[:2]
    
    def _identify_blockers(self, path: List[int], assets: Dict[int, Asset]) -> List[str]:
        """
        Identify obstacles to reaching objective.
        """
        blockers = []
        
        for asset_id in path:
            if asset_id in assets:
                asset = assets[asset_id]
                if "prod" in asset.sensitivity_tags:
                    blockers.append(f"{asset.name} is production - high detection risk")
                if asset.criticality == "critical":
                    blockers.append(f"{asset.name} is critical - enhanced monitoring likely")
        
        if len(path) > 5:
            blockers.append("Long path increases detection risk (> 5 hops)")
        
        return blockers


__all__ = [
    'ObjectiveEngine',
]
