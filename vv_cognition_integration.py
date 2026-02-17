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
vv_cognition_integration: Phase 5.5 Cognition Platform Integration

Orchestrates all 10 cognition modules to implement the mandatory UX flow:

Observe → Simulate → Execute → Evaluate → Adapt

After every operator action:
1. Record event (replay)
2. Update graph (reachability)
3. Calculate distances (objective)
4. Update pressure (detection)
5. Recalculate recommendations (score)
6. Update confidence (analysis)
7. Update tempo (rate)
8. Update infra burn (exposure)
9. Learn patterns (memory)
10. Refresh UI

Core principle: Operator always decides, system always advises with confidence.
"""

from typing import List, Dict, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass

# Import all cognition modules
from vv_cognition import (
    CognitionState, Asset, Credential, Session, DetectionEvent,
    OperatorAction, Recommendation, ObjectiveDistance,
    DetectionPressure, OpSecSimulation, TempoAnalysis,
    InfraBurnAnalysis, ConfidenceAnalysis, ReplayEvent
)
from vv_graph import AttackGraph
from vv_objective import ObjectiveEngine
from vv_recommend import RecommendationEngine
from vv_detection_pressure import DetectionPressureEngine
from vv_opsec import OpSecSimulator
from vv_replay import ReplayEngine
from vv_tempo import TempoEngine
from vv_infra_burn import InfraBurnEngine
from vv_confidence import ConfidenceEngine
from vv_memory import MemoryEngine


class CognitionOrchestrator:
    """
    Orchestrates Phase 5.5 Cognition Platform.
    
    Single entry point for operator actions with automatic state refresh.
    """
    
    def __init__(self, campaign_id: str):
        self.campaign_id = campaign_id
        
        # Initialize all sub-engines
        self.graph = AttackGraph()
        self.objectives = ObjectiveEngine(self.graph)
        self.recommendations = RecommendationEngine(self.graph)
        self.pressure = DetectionPressureEngine()
        self.opsec = OpSecSimulator()
        self.replay = ReplayEngine(campaign_id)
        self.tempo = TempoEngine()
        self.infra = InfraBurnEngine()
        self.confidence = ConfidenceEngine()
        self.memory = MemoryEngine(campaign_id)
        
        # Current state
        self.state: Optional[CognitionState] = None
        self.assets: Dict[int, Asset] = {}
        self.credentials: Dict[str, Credential] = {}
        self.sessions: Dict[str, Session] = {}
        self.detections: List[DetectionEvent] = []
        self.objectives_list: List[Dict] = []
        self.recent_actions: List[Dict] = []
    
    def initialize_state(self,
                        assets: Dict[int, Asset],
                        credentials: Dict[str, Credential],
                        sessions: Dict[str, Session],
                        detections: List[DetectionEvent],
                        objectives: List[Dict]) -> CognitionState:
        """
        Initialize cognition state from database.
        """
        
        self.assets = assets
        self.credentials = credentials
        self.sessions = sessions
        self.detections = detections
        self.objectives_list = objectives
        
        # Build initial state
        return self._update_state_complete()
    
    def execute_operator_action(self,
                               operator_id: str,
                               action_type: str,
                               target_asset: int,
                               technique: str,
                               description: str) -> Tuple[bool, str, CognitionState]:
        """
        Execute operator action with mandatory state refresh.
        
        Mandatory flow:
        1. Operator decides action
        2. System simulates OPSEC impact
        3. Operator executes (on their decision)
        4. System records event
        5. System evaluates outcome
        6. System adapts recommendations
        
        Returns:
        - (success: bool, message: str, updated_state: CognitionState)
        """
        
        # Get target asset
        target = self.assets.get(target_asset)
        if not target:
            return False, f"Asset {target_asset} not found", self.state
        
        # SIMULATE: OPSEC impact (system advises, operator decides)
        opsec_sim = self.opsec.simulate(
            description, target, technique
        )
        
        simulation_msg = (
            f"OPSEC Simulation: {opsec_sim.risk_level.upper()} risk, "
            f"{opsec_sim.probability_logged:.0%} likelihood of logging, "
            f"Confidence: {opsec_sim.confidence:.0%}"
        )
        
        # In real implementation, operator confirms here
        # For now, assume operator approves
        
        # EXECUTE: Record action (assume success for demo)
        success = True
        
        # RECORD: Event log
        event = self.replay.record_operator_action(
            operator_id=operator_id,
            action_type=action_type,
            target_asset=target_asset,
            technique=technique,
            description=description,
            success=success,
            notes=simulation_msg
        )
        
        # EVALUATE: Update internal state
        if success:
            # Mark asset compromised
            if target_asset not in [s.target_asset for s in self.sessions.values()]:
                session = Session(
                    session_id=f"session_{len(self.sessions)}",
                    session_type="shell",
                    target_asset=target_asset,
                    executing_user="unknown",
                    callback_ip="unknown",
                    opened_at=datetime.now(),
                    is_active=True,
                    commands_executed=0
                )
                self.sessions[session.session_id] = session
            
            # Record in memory
            self.memory.learn_technique_outcome(
                technique=technique,
                asset_type=target.asset_type,
                success=True,
                time_to_compromise=5.0
            )
            self.memory.record_operator_technique(operator_id, technique)
            
            # Track action
            self.recent_actions.append({
                "timestamp": datetime.now(),
                "operator": operator_id,
                "technique": technique,
                "asset": target_asset,
                "success": True
            })
        else:
            # Record failure
            self.memory.record_failed_approach(
                technique=technique,
                target=f"Asset {target_asset}",
                failure_reason="Technique blocked or ineffective"
            )
        
        # ADAPT: Refresh all cognition
        updated_state = self._update_state_complete()
        
        result_msg = (
            f"Action recorded. {simulation_msg}\n"
            f"State refreshed. {len(updated_state.recommendations)} recommendations available."
        )
        
        return success, result_msg, updated_state
    
    def observe(self) -> Dict:
        """
        Observe phase: Gather intelligence.
        
        Returns: Current observable state
        """
        
        return {
            "assets": len(self.assets),
            "credentials": len(self.credentials),
            "sessions": len(self.sessions),
            "detections": len(self.detections),
            "objectives": len(self.objectives_list),
        }
    
    def simulate(self) -> Dict:
        """
        Simulate phase: Predict outcomes.
        
        Returns: Risk analysis
        """
        
        if not self.state:
            return {"error": "No state available"}
        
        return {
            "detection_pressure": self.state.detection_pressure.total_pressure,
            "pressure_state": self.state.detection_pressure.state.value,
            "confidence": self.state.confidence_analysis.overall_confidence,
            "infra_burn": self.state.infra_burn.burn_level,
            "recommendations_available": len(self.state.recommendations),
        }
    
    def get_next_recommendation(self) -> Optional[Recommendation]:
        """
        Get highest-confidence next recommendation.
        """
        
        if not self.state or not self.state.recommendations:
            return None
        
        # Return top recommendation
        return self.state.recommendations[0]
    
    def get_dashboard(self) -> Dict:
        """
        Get operator dashboard snapshot.
        """
        
        if not self.state:
            return {"error": "State not initialized"}
        
        return {
            "campaign": self.campaign_id,
            "timestamp": self.state.timestamp.isoformat(),
            "observe": {
                "assets": len(self.assets),
                "credentials": len(self.credentials),
                "sessions": len(self.sessions),
            },
            "simulate": {
                "detection_pressure": self.state.detection_pressure.total_pressure,
                "pressure_state": self.state.detection_pressure.state.value,
                "infra_burn": self.state.infra_burn.burn_level,
                "should_rotate_c2": self.state.infra_burn.should_rotate,
            },
            "recommend": {
                "top_action": (
                    self.state.recommendations[0].action
                    if self.state.recommendations
                    else "No recommendations available"
                ),
                "confidence": (
                    self.state.recommendations[0].confidence
                    if self.state.recommendations
                    else 0.0
                ),
                "count": len(self.state.recommendations),
            },
            "confidence": {
                "overall": self.state.confidence_analysis.overall_confidence,
                "data_completeness": self.state.confidence_analysis.data_completeness,
                "major_unknowns": self.state.confidence_analysis.major_unknowns,
            },
            "tempo": {
                "actions_per_hour": self.state.tempo_analysis.actions_per_hour,
                "intensity": self.state.tempo_analysis.action_intensity,
                "spike_detected": self.state.tempo_analysis.activity_spike_detected,
            },
        }
    
    def _update_state_complete(self) -> CognitionState:
        """
        MANDATORY: Update all 10 modules - the full cognition refresh.
        
        Called after every action to maintain state consistency.
        """
        
        # 1. Update graph
        self.graph.update_graph(
            list(self.assets.values()),
            list(self.credentials.values()),
            list(self.sessions.values()),
            self.detections
        )
        
        # 2. Calculate objective distances
        obj_distances = self.objectives.calculate_distances(
            self.objectives_list,
            self.assets,
            0  # detection_pressure (calculate separately)
        )
        
        # 3. Update detection pressure
        detection_pressure = self.pressure.calculate_pressure(
            self.detections,
            []  # failed_actions (would come from replay)
        )
        
        # 4. Recalculate recommendations
        candidate_actions = [
            {"technique": "T1021", "method": "SSH"},
            {"technique": "T1110", "method": "BruteForce"},
            {"technique": "T1555", "method": "CredentialDump"},
            {"technique": "T1548", "method": "UAC Bypass"},
        ]
        
        if self.assets:
            first_asset = list(self.assets.values())[0]
            recommendations = self.recommendations.score_recommendations(
                candidate_actions,
                first_asset,
                detection_pressure.total_pressure,
                self.recent_actions
            )
        else:
            recommendations = []
        
        # 5. Update confidence
        confidence_analysis = self.confidence.calculate_confidence(
            self.assets,
            self.credentials,
            self.detections,
            self.objectives_list
        )
        
        # 6. Update tempo
        tempo_analysis = self.tempo.analyze_tempo(
            self.recent_actions,
            window_hours=24
        )
        
        # 7. Update infra burn
        infra_burn = self.infra.update_burn(
            self.detections,
            [s.__dict__ for s in self.sessions.values()]
        )
        
        # 8. Build state
        state = CognitionState(
            campaign_id=self.campaign_id,
            timestamp=datetime.now(),
            assets={a.asset_id: a for a in self.assets.values()},
            credentials={c.credential_id: c for c in self.credentials.values()},
            sessions={s.session_id: s for s in self.sessions.values()},
            detections=self.detections,
            detection_pressure=detection_pressure,
            objective_distances={o.objective_id: o for o in obj_distances},
            tempo_analysis=tempo_analysis,
            infra_burn=infra_burn,
            confidence_analysis=confidence_analysis,
            recommendations=recommendations,
            recent_actions=self.recent_actions[-10:],  # Last 10
            recent_events=self.replay.get_event_timeline()[-10:]  # Last 10
        )
        
        self.state = state
        return state


__all__ = [
    'CognitionOrchestrator',
]
