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
knowledge_engine.py - Evidence and Learning

Track collected evidence.
Build knowledge base from observations.
Learn patterns from successful/failed actions.
"""

from typing import List, Dict, Set
from datetime import datetime


class KnowledgeEngine:
    """Build and manage campaign knowledge"""
    
    def __init__(self):
        self.evidence: Dict[str, Dict] = {}  # evidence_id -> evidence
        self.learned_techniques: Dict[str, float] = {}  # technique -> success_rate
        self.asset_knowledge: Dict[str, Dict] = {}  # asset_id -> knowledge
    
    def record_evidence(self,
                       evidence_id: str,
                       evidence_type: str,
                       content: Dict,
                       timestamp: datetime = None) -> None:
        """
        Record collected evidence.
        
        Args:
        - evidence_id: Unique ID
        - evidence_type: credential, config, network_map, etc.
        - content: Evidence content
        - timestamp: When was evidence collected
        """
        
        self.evidence[evidence_id] = {
            "type": evidence_type,
            "content": content,
            "timestamp": timestamp or datetime.now(),
            "confidence": content.get("confidence", 0.8),
        }
    
    def learn_technique_outcome(self,
                               technique: str,
                               succeeded: bool) -> None:
        """Record technique success/failure for learning"""
        
        if technique not in self.learned_techniques:
            self.learned_techniques[technique] = 0.5  # Start at 50%
        
        # Update success rate (exponential smoothing)
        current = self.learned_techniques[technique]
        if succeeded:
            self.learned_techniques[technique] = current * 0.9 + 0.1  # Increase
        else:
            self.learned_techniques[technique] = current * 0.9 - 0.1  # Decrease
        
        # Clamp to 0-1
        self.learned_techniques[technique] = max(0, min(1, self.learned_techniques[technique]))
    
    def get_technique_success_rate(self, technique: str) -> float:
        """Get learned success rate for technique"""
        return self.learned_techniques.get(technique, 0.5)
    
    def record_asset_knowledge(self,
                              asset_id: str,
                              knowledge_type: str,
                              content: Dict) -> None:
        """Record knowledge about an asset"""
        
        if asset_id not in self.asset_knowledge:
            self.asset_knowledge[asset_id] = {}
        
        self.asset_knowledge[asset_id][knowledge_type] = content
    
    def get_asset_knowledge(self, asset_id: str) -> Dict:
        """Get all knowledge about an asset"""
        return self.asset_knowledge.get(asset_id, {})
    
    def get_evidence_for_opportunity(self, opportunity_id: str) -> List[Dict]:
        """Get all evidence related to an opportunity"""
        # Simplified - in reality would link opportunities to evidence
        return list(self.evidence.values())
    
    def calculate_knowledge_completeness(self) -> float:
        """
        Calculate how much we know about the environment (0-1).
        
        Based on: evidence collected, techniques learned, assets mapped
        """
        
        evidence_score = min(1.0, len(self.evidence) / 20)  # 20 pieces = complete
        technique_score = min(1.0, len(self.learned_techniques) / 10)  # 10 techniques
        asset_score = min(1.0, len(self.asset_knowledge) / 50)  # 50 assets
        
        completeness = (evidence_score + technique_score + asset_score) / 3
        return completeness


__all__ = ['KnowledgeEngine']
