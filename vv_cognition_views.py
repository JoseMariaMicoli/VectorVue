
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
VectorVue Phase 5.5 - 10 Operational Cognition Views
UI components for decision-support engines.

The 10 tabs are:
1. Opportunities - Ranked exploitation opportunities
2. Attack Paths - Multi-step attack planning
3. Campaign State - Phase assessment & strategy
4. Detection Pressure - Defensive event tracking
5. Confidence Analysis - Decision confidence & gaps
6. Knowledge Completeness - Evidence & learning
7. Technique Effectiveness - Learned technique outcomes
8. Validation Queue - Safety checks & approvals
9. Explainability - Decision reasoning breakdown
10. Cognition Dashboard - Unified overview
"""

from textual.containers import Container, Vertical, Horizontal, ScrollableContainer
from textual.widgets import (
    Label, Static, Button,
    DataTable, TextArea, TabbedContent, TabPane, Input, ListView, ListItem
)
from textual.reactive import reactive
from textual import on

from vv_theme import CyberColors


# =============================================================================
# 1. OPPORTUNITIES VIEW
# =============================================================================

class OpportunitiesView(Container):
    """Ranked exploitation opportunities ranked by opportunity_score."""
    
    CSS = """
    OpportunitiesView {
        layout: vertical;
        background: $bg-void;
        height: 100%;
    }
    #opp-header {
        height: auto;
        background: #000;
        border-bottom: solid $p-green;
        padding: 1;
    }
    #opp-table { height: 1fr; }
    #opp-detail { height: 15; border-top: solid $steel; padding: 1; }
    .opp-score-high { color: $p-green; }
    .opp-score-med { color: $a-amber; }
    .opp-score-low { color: $r-alert; }
    """
    
    def compose(self):
        with Container(id="opp-header"):
            yield Label("[bold green]OPPORTUNITIES[/] - Ranked by Score")
        yield DataTable(id="opp-table", cursor_type="row")
        with Container(id="opp-detail"):
            yield Label("Select opportunity for details", id="opp-detail-label")
    
    def on_mount(self):
        table = self.query_one("#opp-table", DataTable)
        table.add_columns("Score", "Technique", "Target", "Stealth", "Value", "Risk", "Confidence")
    
    def refresh_opportunities(self, opportunities):
        """Load opportunities into table."""
        table = self.query_one("#opp-table", DataTable)
        table.clear()
        for opp in opportunities:
            table.add_row(
                f"{opp['score']:.0f}",
                opp['technique'],
                opp['target_asset'][:15],
                f"{opp['stealth']:.0f}",
                f"{opp['value']:.0f}",
                f"{opp['risk']:.0f}",
                f"{opp['confidence']:.2f}",
                key=opp['id']
            )
    
    def display_opportunity(self, opp):
        """Show detailed explanation for selected opportunity."""
        label = self.query_one("#opp-detail-label", Label)
        detail_text = (
            f"[bold]ID:[/] {opp['id']}\n"
            f"[bold]Technique:[/] {opp['technique']}\n"
            f"[bold]Target:[/] {opp['target_asset']}\n"
            f"[bold]Score:[/] {opp['score']:.0f} | "
            f"[bold]Confidence:[/] {opp['confidence']:.2f}\n"
            f"[bold]Explanation:[/] {opp['explanation'][:100]}..."
        )
        label.update(detail_text)


# =============================================================================
# 2. ATTACK PATHS VIEW
# =============================================================================

class AttackPathsView(Container):
    """Multi-step attack paths with success probability."""
    
    CSS = """
    AttackPathsView { layout: vertical; height: 100%; }
    #path-header { height: auto; background: #000; border-bottom: solid $p-purple; padding: 1; }
    #path-list { height: 1fr; }
    #path-detail { height: 15; border-top: solid $steel; padding: 1; overflow-y: auto; }
    """
    
    def compose(self):
        with Container(id="path-header"):
            yield Label("[bold magenta]ATTACK PATHS[/] - Multi-Step Planning")
        with ScrollableContainer(id="path-list"):
            yield ListView()
        with Container(id="path-detail"):
            yield Label("Select path for analysis", id="path-detail-label")
    
    def refresh_paths(self, paths):
        """Load paths into view."""
        view = self.query_one(ListView)
        view.clear()
        for path in paths:
            item_label = (
                f"Path {path['id']}: {len(path['steps'])} steps | "
                f"Success: {path['success_probability']:.0%} | "
                f"Risk: {path['cumulative_risk']:.0f}"
            )
            view.append(ListItem(Label(item_label), key=path['id']))
    
    def display_path(self, path):
        """Show detailed path analysis."""
        label = self.query_one("#path-detail-label", Label)
        steps_str = "\n".join([
            f"  → {step['technique']} on {step['target']}"
            for step in path['steps']
        ])
        detail_text = (
            f"[bold]Path ID:[/] {path['id']}\n"
            f"[bold]Objective:[/] {path['objective']}\n"
            f"[bold]Success Probability:[/] {path['success_probability']:.0%}\n"
            f"[bold]Steps ({len(path['steps'])}):[/]\n{steps_str}\n"
            f"[bold]Cumulative Risk:[/] {path['cumulative_risk']:.0f}"
        )
        label.update(detail_text)


# =============================================================================
# 3. CAMPAIGN STATE VIEW
# =============================================================================

class CampaignStateView(Container):
    """Campaign phase, stealth budget, and strategy recommendations."""
    
    CSS = """
    CampaignStateView { layout: vertical; height: 100%; padding: 1; }
    #state-grid { layout: horizontal; height: auto; margin-bottom: 2; }
    .state-box { width: 1fr; border: solid $steel; padding: 1; margin-right: 1; }
    #strategy-box { height: 1fr; border: solid $p-purple; padding: 1; overflow-y: auto; }
    """
    
    def compose(self):
        yield Label("[bold purple]CAMPAIGN STATE[/]")
        with Container(id="state-grid"):
            yield Static("", id="phase-box", classes="state-box")
            yield Static("", id="budget-box", classes="state-box")
            yield Static("", id="pressure-box", classes="state-box")
        with ScrollableContainer(id="strategy-box"):
            yield Label("", id="strategy-label")
    
    def refresh_state(self, state):
        """Update campaign state display."""
        self.query_one("#phase-box").update(
            f"[bold cyan]PHASE[/]\n{state['phase']}"
        )
        self.query_one("#budget-box").update(
            f"[bold amber]STEALTH BUDGET[/]\n{state['stealth_budget_remaining']:.0f}%"
        )
        self.query_one("#pressure-box").update(
            f"[bold red]SEVERITY[/]\n{state['detection_severity']}/10"
        )
        self.query_one("#strategy-label").update(
            f"[bold]Strategy:[/]\n{state['strategy']}\n\n"
            f"[bold]Assets:[/] {state['assets_owned']} owned\n"
            f"[bold]Credentials:[/] {state['credentials_obtained']} captured\n"
            f"[bold]Status:[/] {'[red]COMPROMISED' if state['is_compromised'] else '[green]OPERATIONAL'}[/]"
        )


# =============================================================================
# 4. DETECTION PRESSURE VIEW
# =============================================================================

class DetectionPressureView(Container):
    """Detection pressure, trend, and defensive event timeline."""
    
    CSS = """
    DetectionPressureView { layout: vertical; height: 100%; }
    #detect-header { height: auto; background: #000; border-bottom: solid $r-alert; padding: 1; }
    #detect-gauge { height: 3; border: solid $steel; padding: 1; }
    #detect-table { height: 1fr; }
    """
    
    def compose(self):
        with Container(id="detect-header"):
            yield Label("[bold red]DETECTION PRESSURE[/]")
        with Container(id="detect-gauge"):
            yield Static("", id="pressure-gauge")
        yield DataTable(id="detect-table", cursor_type="row")
    
    def on_mount(self):
        table = self.query_one("#detect-table", DataTable)
        table.add_columns("Time", "Type", "Asset", "Severity", "Technique", "Confidence")
    
    def refresh_pressure(self, pressure_data, detections):
        """Update pressure display and detection timeline."""
        # Update pressure gauge
        pressure = pressure_data['pressure']
        gauge = self.query_one("#pressure-gauge")
        bar = "█" * int(pressure / 10) + "░" * (10 - int(pressure / 10))
        gauge.update(
            f"[bold]{pressure:.0f}%[/] {bar} [dim]{pressure_data['trend'].upper()}[/]"
        )
        
        # Update detection table
        table = self.query_one("#detect-table", DataTable)
        table.clear()
        for det in detections[-10:]:  # Last 10
            table.add_row(
                det.timestamp[:16],
                det.detection_type,
                det.asset,
                str(det.severity),
                det.related_technique,
                f"{det.confidence:.0%}",
            )


# =============================================================================
# 5. CONFIDENCE ANALYSIS VIEW
# =============================================================================

class ConfidenceAnalysisView(Container):
    """Decision confidence assessment and confidence gaps."""
    
    CSS = """
    ConfidenceAnalysisView { layout: vertical; height: 100%; padding: 1; }
    #conf-score { height: 5; border: solid $steel; padding: 1; margin-bottom: 1; }
    #conf-gaps { height: 1fr; border: solid $a-amber; padding: 1; overflow-y: auto; }
    """
    
    def compose(self):
        yield Label("[bold amber]CONFIDENCE ANALYSIS[/]")
        with Container(id="conf-score"):
            yield Static("", id="conf-meter")
        with ScrollableContainer(id="conf-gaps"):
            yield Label("", id="gaps-label")
    
    def refresh_confidence(self, conf_data):
        """Update confidence assessment."""
        meter = self.query_one("#conf-meter")
        conf = conf_data['confidence']
        bar = "█" * int(conf * 20) + "░" * (20 - int(conf * 20))
        threshold = conf_data['min_threshold']
        status = "[green]SUFFICIENT[/]" if conf >= threshold else "[red]INSUFFICIENT[/]"
        meter.update(
            f"[bold]Confidence:[/] {conf:.2f} {bar}\n"
            f"[bold]Threshold:[/] {threshold:.2f} | {status}\n"
            f"[bold]Will Recommend:[/] {'YES' if conf_data['will_recommend'] else 'NO'}"
        )
        
        # Update gaps
        gaps_label = self.query_one("#gaps-label")
        gaps_text = "[bold]Confidence Gaps:[/]\n" + "\n".join([
            f"  • {gap}" for gap in conf_data['gaps']
        ]) + "\n\n[bold]Recommended Evidence:[/]\n" + "\n".join([
            f"  • {rec}" for rec in conf_data['recommended_evidence']
        ])
        gaps_label.update(gaps_text)


# =============================================================================
# 6. KNOWLEDGE COMPLETENESS VIEW
# =============================================================================

class KnowledgeCompletenessView(Container):
    """Evidence tracking and knowledge completeness."""
    
    CSS = """
    KnowledgeCompletenessView { layout: vertical; height: 100%; padding: 1; }
    #knowledge-meter { height: 4; border: solid $steel; padding: 1; margin-bottom: 1; }
    #knowledge-items { height: 1fr; border: solid $e-cyan; padding: 1; overflow-y: auto; }
    """
    
    def compose(self):
        yield Label("[bold cyan]KNOWLEDGE COMPLETENESS[/]")
        with Container(id="knowledge-meter"):
            yield Static("", id="knowledge-bar")
        with ScrollableContainer(id="knowledge-items"):
            yield Label("", id="knowledge-items-label")
    
    def refresh_knowledge(self, completeness, evidence_list):
        """Update knowledge metrics."""
        bar_widget = self.query_one("#knowledge-bar")
        bar = "█" * int(completeness * 20) + "░" * (20 - int(completeness * 20))
        bar_widget.update(
            f"[bold]Campaign Knowledge:[/] {completeness:.0%} {bar}\n"
            f"[bold]Evidence Items:[/] {len(evidence_list)}"
        )
        
        items_label = self.query_one("#knowledge-items-label")
        items_text = "[bold]Collected Evidence:[/]\n" + "\n".join([
            f"  • {ev['type']}: {ev['source']} (confidence: {ev['confidence']:.0%})"
            for ev in evidence_list[:10]
        ])
        items_label.update(items_text)


# =============================================================================
# 7. TECHNIQUE EFFECTIVENESS VIEW
# =============================================================================

class TechniqueEffectivenessView(Container):
    """Learned technique outcomes and success rates."""
    
    CSS = """
    TechniqueEffectivenessView { layout: vertical; height: 100%; }
    #tech-header { height: auto; border-bottom: solid $e-cyan; padding: 1; }
    #tech-table { height: 1fr; }
    """
    
    def compose(self):
        with Container(id="tech-header"):
            yield Label("[bold cyan]TECHNIQUE EFFECTIVENESS[/] - Learning from Execution")
        yield DataTable(id="tech-table", cursor_type="row")
    
    def on_mount(self):
        table = self.query_one("#tech-table", DataTable)
        table.add_columns("Technique", "Executions", "Success Rate", "Avg Stealth", "Last Tried")
    
    def refresh_techniques(self, techniques):
        """Load technique effectiveness data."""
        table = self.query_one("#tech-table", DataTable)
        table.clear()
        for tech in techniques:
            table.add_row(
                tech['technique'],
                str(tech['execution_count']),
                f"{tech['success_rate']:.0%}",
                f"{tech['avg_stealth']:.0f}",
                tech['last_executed'][:10],
            )


# =============================================================================
# 8. VALIDATION QUEUE VIEW
# =============================================================================

class ValidationQueueView(Container):
    """Pending approvals and safety validation results."""
    
    CSS = """
    ValidationQueueView { layout: vertical; height: 100%; }
    #val-header { height: auto; border-bottom: solid $m-audit; padding: 1; }
    #val-table { height: 1fr; }
    #val-actions { height: 3; padding: 1; }
    """
    
    def compose(self):
        with Container(id="val-header"):
            yield Label("[bold magenta]VALIDATION QUEUE[/] - Pending Approvals")
        yield DataTable(id="val-table", cursor_type="row")
        with Horizontal(id="val-actions"):
            yield Button("APPROVE", id="btn-approve", variant="success")
            yield Button("REJECT", id="btn-reject", variant="warning")
            yield Button("DETAILS", id="btn-val-details", variant="primary")
    
    def on_mount(self):
        table = self.query_one("#val-table", DataTable)
        table.add_columns("ID", "Opportunity", "Risk", "Status", "Reason")
    
    def refresh_validations(self, validations):
        """Load pending validations."""
        table = self.query_one("#val-table", DataTable)
        table.clear()
        for val in validations:
            table.add_row(
                val['id'][:8],
                val['opportunity'][:20],
                f"{val['risk']:.0f}",
                "PENDING" if not val['approved'] else "APPROVED",
                val['reason'][:30],
                key=val['id']
            )


# =============================================================================
# 9. EXPLAINABILITY VIEW
# =============================================================================

class ExplainabilityView(Container):
    """Detailed decision reasoning and scoring breakdown."""
    
    CSS = """
    ExplainabilityView { layout: vertical; height: 100%; padding: 1; }
    #explain-text { height: 1fr; border: solid $p-green; padding: 1; overflow-y: auto; }
    """
    
    def compose(self):
        yield Label("[bold green]EXPLAINABILITY[/] - Decision Reasoning")
        with ScrollableContainer(id="explain-text"):
            yield Label("", id="explain-content")
    
    def show_explanation(self, explanation_data):
        """Display decision explanation."""
        content = self.query_one("#explain-content")
        text = (
            f"[bold yellow]Summary:[/]\n{explanation_data['summary']}\n\n"
            f"[bold yellow]Rationale:[/]\n{explanation_data['rationale']}\n\n"
            f"[bold yellow]Scoring Breakdown:[/]\n{explanation_data['scoring_breakdown']}"
        )
        content.update(text)


# =============================================================================
# 10. COGNITION DASHBOARD VIEW
# =============================================================================

class CognitionDashboardView(Container):
    """Unified overview of all 10 cognition engines."""
    
    CSS = """
    CognitionDashboardView { layout: vertical; height: 100%; }
    #dash-grid { layout: horizontal; height: 1fr; }
    .dash-panel { width: 1fr; height: 1fr; border: solid $steel; padding: 1; margin-right: 1; overflow-y: auto; }
    """
    
    def compose(self):
        yield Label("[bold cyan]COGNITION DASHBOARD[/] - 10 Engine Overview")
        with Container(id="dash-grid"):
            with Vertical(classes="dash-panel"):
                yield Label("[bold]Top Opportunity[/]", classes="cyber-label")
                yield Static("", id="dash-opp")
            with Vertical(classes="dash-panel"):
                yield Label("[bold]Campaign Phase[/]", classes="cyber-label")
                yield Static("", id="dash-phase")
            with Vertical(classes="dash-panel"):
                yield Label("[bold]Detection Pressure[/]", classes="cyber-label")
                yield Static("", id="dash-pressure")
            with Vertical(classes="dash-panel"):
                yield Label("[bold]Recommendation[/]", classes="cyber-label")
                yield Static("", id="dash-recommendation")
    
    def refresh_dashboard(self, dashboard_data):
        """Update unified dashboard."""
        self.query_one("#dash-opp").update(
            f"[bold]{dashboard_data['top_opportunity']['technique']}[/]\n"
            f"Score: {dashboard_data['top_opportunity']['score']:.0f}\n"
            f"Confidence: {dashboard_data['top_opportunity']['confidence']:.2f}"
        )
        self.query_one("#dash-phase").update(
            f"[bold]{dashboard_data['campaign_state']['phase']}[/]\n"
            f"Budget: {dashboard_data['campaign_state']['stealth_budget_remaining']:.0f}%\n"
            f"Strategy: {dashboard_data['campaign_state']['strategy'][:30]}"
        )
        self.query_one("#dash-pressure").update(
            f"Pressure: {dashboard_data['detection_pressure']['pressure']:.0f}%\n"
            f"Trend: {dashboard_data['detection_pressure']['trend'].upper()}\n"
            f"Events: {dashboard_data['detection_pressure']['detection_count']}"
        )
        self.query_one("#dash-recommendation").update(
            f"[bold]{dashboard_data['recommendation']}[/]"
        )
