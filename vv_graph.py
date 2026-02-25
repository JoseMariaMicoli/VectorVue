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
vv_graph: Attack Graph Maintenance

Maintain a directed graph of asset compromise relationships.

Functions:
- update_graph(event): Add detection/session/credential to graph
- shortest_path(objective_asset): Path to reach target
- reachable_assets(identity): Assets accessible from this user
- privesc_paths(host): Privilege escalation chains on host

All logic deterministic and explainable.
"""

from typing import List, Dict, Set, Tuple, Optional
from dataclasses import dataclass, field
import heapq
from collections import defaultdict

from vv_cognition import Asset, Credential, Session, DetectionEvent, OperatorAction


@dataclass
class Edge:
    """Connection from one asset to another"""
    from_asset: int
    to_asset: int
    cost: int = 1                  # Hops/difficulty
    technique: Optional[str] = None  # T-number
    credential_id: Optional[int] = None
    method: str = "unknown"        # lateral_move, privesc, etc.
    confidence: float = 1.0        # How confident in this path?


@dataclass
class CompromiseGraph:
    """Directed graph of asset compromise relationships"""
    
    # Nodes: asset_id -> Asset
    nodes: Dict[int, Asset] = field(default_factory=dict)
    
    # Edges: source_asset -> [Edge]
    edges: Dict[int, List[Edge]] = field(default_factory=lambda: defaultdict(list))
    
    # Credentials that unlock edges
    credentials: Dict[int, Credential] = field(default_factory=dict)
    
    # Sessions (active compromise)
    sessions: Dict[int, Session] = field(default_factory=dict)
    
    # Nodes we control (compromised)
    controlled_assets: Set[int] = field(default_factory=set)
    
    def add_asset(self, asset: Asset):
        """Add node to graph"""
        self.nodes[asset.asset_id] = asset
    
    def add_credential(self, cred: Credential):
        """Add credential that enables edges"""
        self.credentials[cred.credential_id] = cred
        
        # Create edges to assets this credential accesses
        for asset_id in cred.assets_with_access:
            if asset_id in self.nodes:
                edge = Edge(
                    from_asset=None,  # Can access from anywhere
                    to_asset=asset_id,
                    technique="T1110" if "password" in cred.credential_type else "T1040",
                    credential_id=cred.credential_id,
                    method="credential_use",
                    confidence=0.9 if cred.is_active else 0.5,
                )
                # Add as direct edge from all controlled assets
                for controlled in self.controlled_assets:
                    if controlled != asset_id:
                        self.edges[controlled].append(edge)
    
    def add_session(self, session: Session):
        """Record active session (compromise)"""
        self.sessions[session.session_id] = session
        if session.is_active:
            self.controlled_assets.add(session.target_asset)
    
    def compromise_asset(self, asset_id: int):
        """Mark asset as compromised (we own it)"""
        self.controlled_assets.add(asset_id)
        
        # Add edges from this asset to others we have creds for
        if asset_id in self.nodes:
            for cred in self.credentials.values():
                if cred.is_active and asset_id in cred.assets_with_access:
                    for target in cred.assets_with_access:
                        if target != asset_id and target in self.nodes:
                            edge = Edge(
                                from_asset=asset_id,
                                to_asset=target,
                                credential_id=cred.credential_id,
                                method="credential_use",
                                confidence=0.95,
                            )
                            self.edges[asset_id].append(edge)
    
    def shortest_path(self, from_asset: Optional[int], to_asset: int) -> Optional[List[int]]:
        """
        Dijkstra's algorithm: shortest path from controlled assets to target.
        
        If from_asset is None, find shortest from ANY controlled asset.
        """
        
        if to_asset not in self.nodes:
            return None
        
        # Start from all controlled assets if from_asset not specified
        if from_asset is None:
            if not self.controlled_assets:
                return None
            starts = list(self.controlled_assets)
        else:
            starts = [from_asset]
        
        best_path = None
        best_cost = float('inf')
        
        # Run Dijkstra from each start
        for start in starts:
            path = self._dijkstra(start, to_asset)
            if path and len(path) < best_cost:
                best_path = path
                best_cost = len(path)
        
        return best_path
    
    def _dijkstra(self, start: int, goal: int) -> Optional[List[int]]:
        """Internal Dijkstra implementation"""
        if start not in self.nodes or goal not in self.nodes:
            return None
        
        # (cost, node, path)
        heap = [(0, start, [start])]
        visited = set()
        
        while heap:
            cost, node, path = heapq.heappop(heap)
            
            if node == goal:
                return path
            
            if node in visited:
                continue
            visited.add(node)
            
            # Explore edges
            for edge in self.edges.get(node, []):
                next_node = edge.to_asset
                if next_node not in visited:
                    new_cost = cost + edge.cost
                    new_path = path + [next_node]
                    heapq.heappush(heap, (new_cost, next_node, new_path))
        
        return None
    
    def reachable_assets(self, from_asset: Optional[int]) -> Set[int]:
        """
        BFS: Find all assets reachable from asset (or controlled assets if None).
        
        Returns set of asset IDs we can reach.
        """
        if from_asset is None:
            starts = list(self.controlled_assets)
        else:
            starts = [from_asset]
        
        reachable = set()
        visited = set()
        queue = starts.copy()
        
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            reachable.add(node)
            
            # Add neighbors
            for edge in self.edges.get(node, []):
                next_node = edge.to_asset
                if next_node not in visited:
                    queue.append(next_node)
        
        return reachable
    
    def privesc_paths(self, host_id: int) -> List[Tuple[str, str, float]]:
        """
        Find privilege escalation paths on a specific host.
        
        Returns: [(current_level, target_level, confidence), ...]
        """
        paths = []
        
        # Simulate common privesc techniques
        # (This would come from a privesc knowledge base in production)
        
        # For now, return hardcoded common patterns
        common_privesc = [
            ("guest", "user", 0.3, "T1548"),
            ("user", "admin", 0.4, "T1548"),
            ("admin", "system", 0.5, "T1548"),
        ]
        
        # Filter to this host if applicable
        for current, target, conf, technique in common_privesc:
            paths.append((current, target, conf))
        
        return paths
    
    def explain_path(self, path: List[int]) -> str:
        """Generate natural language explanation of a path"""
        if not path or len(path) < 2:
            return ""
        
        steps = []
        for i in range(len(path) - 1):
            from_id = path[i]
            to_id = path[i + 1]
            
            from_name = self.nodes[from_id].name if from_id in self.nodes else f"Asset {from_id}"
            to_name = self.nodes[to_id].name if to_id in self.nodes else f"Asset {to_id}"
            
            # Find edge for technique
            edges = [e for e in self.edges.get(from_id, []) if e.to_asset == to_id]
            technique = edges[0].technique if edges else "unknown"
            
            step = f"{from_name} → {to_name} ({technique})"
            steps.append(step)
        
        return " → ".join(steps)


# ============================================================================
# MODULE INTERFACE
# ============================================================================

class AttackGraph:
    """
    Attack graph maintenance and queries.
    
    Maintains compromise relationships and finds paths to objectives.
    """
    
    def __init__(self):
        self.graph = CompromiseGraph()
    
    def update_graph(self, assets: List[Asset], credentials: List[Credential], 
                    sessions: List[Session], detections: List[DetectionEvent]) -> None:
        """
        Update graph with latest intelligence.
        
        Called after every action to refresh state.
        """
        # Add/update nodes
        for asset in assets:
            self.graph.add_asset(asset)
        
        # Add credentials
        for cred in credentials:
            self.graph.add_credential(cred)
        
        # Add sessions (mark as compromised)
        for session in sessions:
            if session.is_active:
                self.graph.add_session(session)
                self.graph.compromise_asset(session.target_asset)
    
    def shortest_path(self, objective_asset: int) -> Tuple[Optional[List[int]], str, float]:
        """
        Find shortest path to objective asset.
        
        Returns:
        - path: List of asset IDs [start, ..., objective]
        - explanation: Natural language description
        - confidence: 0.0-1.0 how confident in this path?
        """
        path = self.graph.shortest_path(None, objective_asset)
        
        if not path:
            return None, "No path found to objective", 0.0
        
        explanation = self.graph.explain_path(path)
        
        # Confidence based on path certainty
        # Longer paths = lower confidence
        confidence = 1.0 / (1.0 + len(path) * 0.1)
        
        return path, explanation, confidence
    
    def reachable_assets(self, from_identity: Optional[str] = None) -> Tuple[Set[int], str, float]:
        """
        Find assets reachable from current position.
        
        Returns:
        - reachable: Set of asset IDs
        - explanation: What we can access
        - confidence: How confident we are
        """
        reachable = self.graph.reachable_assets(None)
        
        asset_names = [
            self.graph.nodes[aid].name for aid in reachable 
            if aid in self.graph.nodes
        ]
        
        explanation = f"Can reach {len(reachable)} assets: {', '.join(asset_names)}"
        confidence = 0.9 if len(reachable) > 0 else 0.0
        
        return reachable, explanation, confidence
    
    def privesc_paths(self, host_id: int) -> Tuple[List[Tuple[str, str, float]], str, float]:
        """
        Find privilege escalation paths on host.
        
        Returns:
        - paths: [(from_level, to_level, confidence), ...]
        - explanation: Summary
        - confidence: Overall confidence
        """
        paths = self.graph.privesc_paths(host_id)
        
        if not paths:
            return [], "No known privilege escalation paths", 0.5
        
        explanation = f"Found {len(paths)} potential privesc paths on host {host_id}"
        confidence = 0.7  # Privesc paths often unreliable
        
        return paths, explanation, confidence


__all__ = [
    'Edge',
    'CompromiseGraph',
    'AttackGraph',
]
