
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
validation_engine.py - Safety Guardrails

Enforces safety constraints before operator actions.

Rules:
1. Campaign must be approved
2. Opportunity must be validated
3. Risk must be below threshold
4. Action must be within Rules of Engagement
5. Escalation approval required for high-risk actions
"""

from typing import Dict, List
from engines.data_contracts import ValidationResult, Opportunity


class ValidationEngine:
    """Validate actions before execution"""
    
    def __init__(self, riskthreshold: float = 60.0):
        """
        Initialize with risk threshold.
        
        Args:
        - riskthreshold: Max risk allowed without escalation (0-100)
        """
        self.riskthreshold = riskthreshold
    
    def validate_action(self,
                       opportunity: Opportunity,
                       campaign_state: Dict,
                       operator_role: str = "operator") -> ValidationResult:
        """
        Validate if opportunity can be executed.
        
        Args:
        - opportunity: Opportunity to validate
        - campaign_state: Campaign context
        - operator_role: "operator", "lead", "admin"
        
        Returns: ValidationResult with approval status
        """
        
        checks = {}
        required_approvals = []
        
        # Check 1: Campaign approved
        campaign_approved = campaign_state.get("approved", False)
        checks["campaign_approved"] = campaign_approved
        if not campaign_approved:
            return ValidationResult(
                approved=False,
                reason="Campaign not approved for operations",
                required_approvals=["lead"]
            )
        
        # Check 2: Opportunity is valid
        opp_valid = opportunity.is_valid()
        checks["opportunity_valid"] = opp_valid
        if not opp_valid:
            return ValidationResult(
                approved=False,
                reason="Opportunity data is invalid or incomplete",
                required_approvals=[]
            )
        
        # Check 3: Risk below threshold
        high_risk = opportunity.risk > self.riskthreshold
        checks["risk_acceptable"] = not high_risk
        if high_risk:
            required_approvals.append("lead")
        
        # Check 4: Within Rules of Engagement
        roe_violation = self._check_roe_violation(opportunity, campaign_state)
        checks["within_roe"] = not roe_violation
        if roe_violation:
            return ValidationResult(
                approved=False,
                reason="Action violates Rules of Engagement",
                required_approvals=["lead", "admin"],
                safety_checks=checks
            )
        
        # Check 5: Irreversibility warning
        irreversible = opportunity.risk > 70  # High risk actions
        if irreversible:
            checks["irreversibility"] = True
            if operator_role == "operator":
                required_approvals.append("lead")
        else:
            checks["irreversibility"] = False
        
        # Determine final approval
        approved = len(required_approvals) == 0
        
        if approved:
            reason = "Approved for execution"
        else:
            reason = f"Requires approval from: {', '.join(required_approvals)}"
        
        return ValidationResult(
            approved=approved,
            reason=reason,
            required_approvals=required_approvals,
            safety_checks=checks
        )
    
    def _check_roe_violation(self, opportunity: Opportunity, campaign_state: Dict) -> bool:
        """Check if action violates Rules of Engagement"""
        
        roe = campaign_state.get("rules_of_engagement", {})
        
        # Prohibited techniques
        prohibited = roe.get("prohibited_techniques", [])
        if opportunity.technique in prohibited:
            return True
        
        # Out-of-scope assets
        scope = roe.get("scope", {})
        in_scope = scope.get("in_scope_assets", [])
        if in_scope and opportunity.target_asset not in in_scope:
            return True
        
        # Destructive actions forbidden
        if roe.get("prohibit_destructive", True):
            if opportunity.risk > 80:
                return True
        
        return False
    
    def validate_multiple(self,
                         opportunities: List[Opportunity],
                         campaign_state: Dict) -> Dict[str, ValidationResult]:
        """
        Validate multiple opportunities.
        
        Returns: {opportunity.id: ValidationResult}
        """
        results = {}
        for opp in opportunities:
            results[opp.id] = self.validate_action(opp, campaign_state)
        
        return results


__all__ = ['ValidationEngine']
