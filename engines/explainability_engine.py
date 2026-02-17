
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
explainability_engine.py - Human-Readable Reasoning

Generate human-readable explanations for every recommendation.
Reference evidence, scoring, and tradeoffs.
No "black box" - every decision is justified.
"""

from typing import Dict, List
from engines.data_contracts import Opportunity, AttackPath, ScoringResult


class ExplainabilityEngine:
    """Generate human-readable explanations for all decisions"""
    
    def explain_opportunity(self, opportunity: Opportunity) -> str:
        """
        Generate detailed explanation for why opportunity was recommended.
        
        Returns: Multi-paragraph explanation
        """
        
        explanation = f"""
OPPORTUNITY: {opportunity.technique} on {opportunity.target_asset}

RATIONALE:
This opportunity was identified because {opportunity.explanation}

SCORING BREAKDOWN:
- Stealth: {opportunity.stealth:.0f}/100 - How exposed is this action?
- Value: {opportunity.value:.0f}/100 - How much mission progress?
- Risk: {opportunity.risk:.0f}/100 - What's the cost if detected?
- Overall Score: {opportunity.score:.0f}/100
- Confidence: {opportunity.confidence:.0%}

EXPECTED CONSEQUENCES:
- Generated logs: {', '.join(opportunity.expected_logs)}
- EDR risks: {', '.join(opportunity.edr_risks)}

ALTERNATIVES CONSIDERED:
{chr(10).join(f'- {alt}' for alt in opportunity.alternatives) if opportunity.alternatives else '- No alternatives identified'}

RECOMMENDATION:
{"APPROVED FOR EXECUTION" if opportunity.score > 70 else "REVIEW BEFORE EXECUTION" if opportunity.score > 50 else "NOT RECOMMENDED"}
"""
        
        return explanation
    
    def explain_path(self, path: AttackPath) -> str:
        """
        Generate explanation for why attack path was chosen.
        """
        
        explanation = f"""
ATTACK PATH: {path.objective}

STRATEGY:
{path.explanation}

PATH COMPOSITION:
- Number of steps: {len(path.steps)}
- Steps: {' → '.join(path.steps)}

RISK ANALYSIS:
- Cumulative risk: {path.cumulative_risk:.0f}/100
- Cumulative stealth: {path.cumulative_stealth:.0f}/100
- Cumulative value: {path.cumulative_value:.0f}/100
- Success probability: {path.success_probability:.0%}
- Estimated time to detection: {path.estimated_detection_time} hours

TRADEOFFS:
- Higher value paths tend to be noisier
- Stealthier paths may be longer
- Shorter paths may be riskier

NEXT STEPS:
Execute first step: {path.steps[0] if path.steps else 'N/A'}
"""
        
        return explanation
    
    def explain_scoring(self, score_result: ScoringResult, technique: str) -> str:
        """
        Explain the math behind a score.
        """
        
        explanation = f"""
SCORING ANALYSIS: {technique}

STEALTH CALCULATION:
stealth = 100 - (log_events * 6) - (alerts * 15) - (edr_visibility * 20) - (privilege_noise * 5)
Result: {score_result.stealth:.1f}/100

VALUE CALCULATION:
value = (criticality * 25) + (credential_access * 20) + (lateral * 15) + (domain_impact * 25) + (data_access * 15)
Result: {score_result.value:.1f}/100

RISK CALCULATION:
risk = (detection_prob * 35) + (blast_radius * 25) + (irreversibility * 20) + (complexity * 20)
Result: {score_result.risk:.1f}/100

OPPORTUNITY SCORE:
opportunity = (value * 0.5) + (stealth * 0.3) - (risk * 0.2)
           = ({score_result.value:.1f} * 0.5) + ({score_result.stealth:.1f} * 0.3) - ({score_result.risk:.1f} * 0.2)
           = {score_result.opportunity_score:.1f}/100

CONFIDENCE: {score_result.confidence:.0%}

INTERPRETATION:
This action has moderate value, good stealth, and acceptable risk.
Execute with caution.
"""
        
        return explanation
    
    def explain_validation_decision(self, validation_result: Dict) -> str:
        """
        Explain why action was approved/rejected.
        """
        
        explanation = f"""
VALIDATION DECISION: {"APPROVED" if validation_result['approved'] else "REJECTED"}

Reason: {validation_result['reason']}

{"Required approvals: " + ", ".join(validation_result['required_approvals']) if validation_result['required_approvals'] else "No approvals required."}

Safety checks:
"""
        
        for check, passed in validation_result.get('safety_checks', {}).items():
            status = "✓ PASS" if passed else "✗ FAIL"
            explanation += f"\n- {check}: {status}"
        
        return explanation
    
    def summarize_decision(self,
                          opportunity_score: float,
                          stealth: float,
                          value: float,
                          risk: float,
                          confidence: float) -> str:
        """
        One-line summary for quick decision.
        """
        
        if confidence < 0.3:
            return f"LOW CONFIDENCE ({confidence:.0%}) - insufficient data"
        elif opportunity_score > 70:
            if risk > 70:
                return f"HIGH VALUE but HIGH RISK - lead approval recommended"
            else:
                return f"HIGH VALUE, LOW RISK - execute"
        elif opportunity_score > 50:
            return f"MODERATE OPPORTUNITY - proceed with caution"
        else:
            return f"LOW SCORE ({opportunity_score:.0f}/100) - not recommended"


__all__ = ['ExplainabilityEngine']
