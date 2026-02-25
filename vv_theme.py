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
VectorVue v3.0 - Phosphor Cyberpunk Design System
Centralized Theme & Layout Configuration for Red Team Platform

Color Philosophy:
- High-contrast neon palette for low-light SOC/NOC environments
- Semantic coloring for OPSEC decisions (approval, audit, risk)
- MITRE ATT&CK coverage heatmap integration
- Evidence immutability and approval state visualization
"""

class CyberColors:
    # VectorVue official design system
    PHOSPHOR_GREEN = "#8A2BE2"  # Primary accent purple
    ELECTRIC_CYAN  = "#D9E1F2"  # Metallic light
    AMBER_WARNING  = "#FFB020"  # Warning
    RED_ALERT      = "#FF4D4F"  # Error
    PURPLE_HAZE    = "#AAB2D5"  # Muted text
    CRIMSON_BLOOD  = "#FF4D4F"  # Sensitive-impact accent
    
    # v3.0 OPSEC Colors (New)
    ORANGE_CAUTION  = "#FFB020"
    LIME_EVIDENCE   = "#00C896"
    MAGENTA_AUDIT   = "#9D4DFF"
    TEAL_APPROVAL   = "#00C896"
    GRAY_DISABLED   = "#5C6370"
    
    # Phase 5 Threat Intelligence Colors
    NEON_PINK       = "#9D4DFF"
    
    # Phase 5.5 Cognition Engine Colors (10 Engines)
    COG_OPPORTUNITY = "#00C896"
    COG_PATH        = "#9D4DFF"
    COG_STATE       = "#D9E1F2"
    COG_DETECTION   = "#FF4D4F"
    COG_CONFIDENCE  = "#FFB020"
    COG_KNOWLEDGE   = "#00C896"
    COG_TECHNIQUE   = "#8A2BE2"
    COG_VALIDATION  = "#9D4DFF"
    COG_EXPLAINABILITY = "#C7CEDB"
    COG_DASHBOARD   = "#8A2BE2"
    
    # Industrial Dark Mode Neutrals
    VOID_DARK      = "#0A0F2D"
    PANEL_GREY     = "#121735"
    STEEL_BORDER   = "#2A335A"
    TEXT_MAIN      = "#E6E9F2"
    TEXT_DIM       = "#AAB2D5"
    TEXT_MUTED     = "#7C88B8"
    
    # MITRE Coverage Heatmap (technique distribution)
    COVERAGE_NONE   = "#1a1d24"
    COVERAGE_LOW    = "#5c3a38"
    COVERAGE_MED    = "#a56c45"
    COVERAGE_HIGH   = "#d39a5c"
    COVERAGE_FULL   = "#ffb86b"

# Global CSS Injection
CYBER_CSS = f"""
/* --- VARIABLES --- */
$p-green: {CyberColors.PHOSPHOR_GREEN};
$e-cyan: {CyberColors.ELECTRIC_CYAN};
$a-amber: {CyberColors.AMBER_WARNING};
$r-alert: {CyberColors.RED_ALERT};
$p-purple: {CyberColors.PURPLE_HAZE};
$c-blood: {CyberColors.CRIMSON_BLOOD};
$o-caution: {CyberColors.ORANGE_CAUTION};
$l-evidence: {CyberColors.LIME_EVIDENCE};
$m-audit: {CyberColors.MAGENTA_AUDIT};
$t-approval: {CyberColors.TEAL_APPROVAL};
$g-disabled: {CyberColors.GRAY_DISABLED};
$n-pink: {CyberColors.NEON_PINK};
$cog-opp: {CyberColors.COG_OPPORTUNITY};
$cog-path: {CyberColors.COG_PATH};
$cog-state: {CyberColors.COG_STATE};
$cog-detect: {CyberColors.COG_DETECTION};
$cog-conf: {CyberColors.COG_CONFIDENCE};
$cog-know: {CyberColors.COG_KNOWLEDGE};
$cog-tech: {CyberColors.COG_TECHNIQUE};
$cog-val: {CyberColors.COG_VALIDATION};
$cog-explain: {CyberColors.COG_EXPLAINABILITY};
$cog-dash: {CyberColors.COG_DASHBOARD};
$bg-void: {CyberColors.VOID_DARK};
$bg-panel: {CyberColors.PANEL_GREY};
$steel: {CyberColors.STEEL_BORDER};
$text-main: {CyberColors.TEXT_MAIN};
$text-dim: {CyberColors.TEXT_DIM};
$text-muted: {CyberColors.TEXT_MUTED};
$coverage-none: {CyberColors.COVERAGE_NONE};
$coverage-low: {CyberColors.COVERAGE_LOW};
$coverage-med: {CyberColors.COVERAGE_MED};
$coverage-high: {CyberColors.COVERAGE_HIGH};
$coverage-full: {CyberColors.COVERAGE_FULL};

/* --- GLOBAL LAYOUT --- */
Screen {{
    background: $bg-void;
    color: $text-main;
    layout: grid;
    grid-size: 2 4;
    grid-columns: 1fr 34;
    grid-rows: 2 5 1fr 1;
}}

/* --- LOGIN SCREEN --- */
LoginView {{
    align: center middle;
    background: $bg-void;
    height: 100%;
}}

#login-container {{
    width: 54;
    height: auto;
    border: heavy $steel;
    background: $bg-panel;
    padding: 1;
    align: center middle;
}}

.login-title {{
    color: $p-green;
    text-style: bold;
    margin-bottom: 2;
    width: 100%;
    content-align: center middle;
}}

#login-username {{
    width: 100%;
    margin-bottom: 1;
    border: solid $steel;
    background: #131720;
    color: $text-main;
}}

#login-input {{
    width: 100%;
    margin-bottom: 2;
    border: solid $steel;
    background: #131720;
    color: $text-main;
}}

#login-btn {{
    width: 1fr;
    border: solid $p-green;
    color: $p-green;
}}

#login-register-btn {{
    width: 1fr;
    border: solid $steel;
    color: $text-main;
}}

#login-register-hint {{
    color: $text-dim;
    margin-top: 1;
}}

#login-status {{
    color: $r-alert;
    margin-top: 1;
    text-align: center;
}}

/* --- REGISTER SCREEN --- */
RegisterView {{
    align: center middle;
    background: $bg-void;
    height: 100%;
}}

#register-container {{
    width: 54;
    height: auto;
    border: heavy $steel;
    background: $bg-panel;
    padding: 1;
    align: center middle;
}}

.reg-title {{
    color: $p-green;
    text-style: bold;
    margin-bottom: 1;
    width: 100%;
    content-align: center middle;
}}

#reg-btn {{
    width: 1fr;
    border: solid $p-green;
    color: $p-green;
    margin-top: 1;
}}

#reg-back-btn {{
    width: 1fr;
    border: solid $steel;
    color: $text-main;
    margin-top: 1;
}}

#reg-status {{
    color: $r-alert;
    margin-top: 1;
    text-align: center;
}}

/* --- HEADER HUD --- */
#hud-header {{
    column-span: 2;
    background: #151922;
    border-bottom: solid $steel;
    height: 2;
    layout: horizontal;
    align: center middle;
    padding: 0 1;
}}

.hud-title {{
    color: $p-green;
    text-style: bold;
    width: 1fr;
    content-align: left middle;
}}

.hud-file {{
    color: $e-cyan;
    text-style: bold;
    width: 1fr;
    content-align: right middle;
}}

/* --- VIEWPORT SWITCHER --- */
#view-switcher {{
    row-span: 1;
    background: $bg-panel;
    border-right: solid $steel;
    height: 100%;
}}

/* --- LATERAL TOOLS --- */
#lateral-tools {{
    row-span: 1;
    background: #151922;
    border-left: solid $steel;
    padding: 0 1;
    overflow-y: auto;
    scrollbar-gutter: stable;
}}

/* --- STATUS BAR --- */
#status-bar {{
    column-span: 2;
    background: #151922;
    color: $text-main;
    border-top: solid $steel;
    content-align: left middle;
    padding-left: 1;
}}

/* --- WIDGET STYLING --- */

TextArea {{
    background: #12161e;
    border: solid $steel;
    padding: 0 1;
    overflow-y: auto;
    scrollbar-gutter: stable;
}}
TextArea:focus {{
    border: heavy $p-green;
}}

Input {{
    background: #12161e;
    border: solid $steel;
    color: $text-main;
    padding: 0 1;
    height: auto;
    margin-bottom: 1;
}}
Input:focus {{
    border: heavy $p-green;
    color: $p-green;
}}

.input-row {{
    height: 3;
    width: 100%;
    margin-bottom: 1;
    layout: horizontal;
}}
.half-input {{
    width: 1fr;
}}

Button {{
    width: 100%;
    height: 3;
    margin-bottom: 0;
    background: $bg-panel;
    border: solid $steel;
    color: $text-main;
    text-style: bold;
}}
Button:hover {{
    background: #202734;
    border: heavy $e-cyan;
    color: $e-cyan;
}}
.btn-save {{ border: solid $p-green; color: $p-green; }}
.btn-save:hover {{ background: $p-green; color: black; }}
.btn-delete {{ border: solid $r-alert; color: $r-alert; }}
.btn-delete:hover {{ background: $r-alert; color: black; }}
.btn-purple {{ border: solid $p-purple; color: $p-purple; }}
.btn-purple:hover {{ background: $p-purple; color: white; }}
.btn-threat-intel {{ border: solid $n-pink; color: $n-pink; }}
.btn-threat-intel:hover {{ background: $n-pink; color: white; }}

.info-box {{
    background: $bg-panel;
    border: solid $steel;
    padding: 0;
    margin-bottom: 0;
    text-align: center;
    color: $steel;
}}
.risk-crit {{ color: $r-alert; border: heavy $r-alert; }}
.risk-high {{ color: $a-amber; border: heavy $a-amber; }}
.risk-med {{ color: $e-cyan; border: heavy $e-cyan; }}
.risk-low {{ color: $p-green; border: heavy $p-green; }}

ListView {{
    border: solid $steel;
    background: $bg-panel;
    height: 10;
    margin-bottom: 1;
}}
ListItem {{ padding-left: 1; color: {CyberColors.TEXT_DIM}; }}
ListItem:hover {{ background: #202734; color: $e-cyan; }}

.cyber-label {{
    color: $a-amber;
    text-style: bold;
    margin-top: 0;
    margin-bottom: 0;
}}

#lateral-tools Button {{
    margin-bottom: 0;
    margin-top: 0;
}}

#lateral-tools Input {{
    margin-bottom: 0;
}}

#lateral-tools .info-box {{
    height: 3;
}}

/* --- CAMPAIGN VIEW --- */
CampaignView {{
    layout: vertical;
    background: $bg-void;
    height: 100%;
    border-right: heavy $p-purple;
}}

#camp-header {{
    height: auto;
    background: #151922;
    border-bottom: solid $p-purple;
    padding: 1;
}}

#camp-stats {{
    layout: horizontal;
    height: 3;
    margin-bottom: 1;
}}
.stat-box {{ width: 1fr; content-align: center middle; border: solid $steel; color: $e-cyan; }}

#camp-tabs {{
    height: 3;
    layout: horizontal;
    border-bottom: solid $steel;
}}

.tab-btn {{
    width: 1fr; border: none; background: #202734; color: $text-dim;
}}
.tab-btn:hover {{ color: white; }}
.tab-active {{ color: $p-purple; text-style: bold; border-bottom: solid $p-purple; }}

#camp-content {{
    height: 1fr;
    background: $bg-panel;
}}

.camp-table {{
    height: 1fr;
    width: 100%;
}}

#camp-form-container {{
    height: auto;
    border-top: solid $steel;
    padding: 1;
    background: #151922;
}}

/* --- v3.0 APPROVAL & AUDIT WORKFLOW --- */

.approval-pending {{
    background: $bg-panel;
    border: heavy $a-amber;
    color: $a-amber;
}}

.approval-approved {{
    background: $bg-panel;
    border: heavy $t-approval;
    color: $t-approval;
}}

.approval-rejected {{
    background: $bg-panel;
    border: heavy $r-alert;
    color: $r-alert;
}}

.evidence-immutable {{
    background: $bg-panel;
    border: solid $l-evidence;
    color: $l-evidence;
}}

.audit-logged {{
    color: $m-audit;
    text-style: italic;
}}

.finding-approved {{
    background: $bg-panel;
    border: solid $t-approval;
    color: $t-approval;
}}

.finding-review-required {{
    background: $bg-panel;
    border: heavy $m-audit;
    color: $m-audit;
    text-style: bold;
}}

/* --- OPSEC SAFEGUARDS --- */

.sensitive-host {{
    background: $bg-panel;
    border: heavy $o-caution;
    color: $o-caution;
}}

.prohibited-hours {{
    background: $bg-panel;
    border: heavy $c-blood;
    color: $c-blood;
}}

.destructive-action {{
    border: double $r-alert;
    color: $r-alert;
    background: #330000;
}}
.destructive-action:hover {{
    background: $r-alert;
    color: #000;
}}

.client-safe-mode {{
    background: $bg-panel;
    border: solid $o-caution;
    color: $o-caution;
}}

/* --- ROLE-BASED STYLING --- */

.role-viewer {{
    color: $steel;
    text-style: dim;
}}

.role-operator {{
    color: $e-cyan;
}}

.role-lead {{
    color: $p-purple;
}}

.role-admin {{
    color: $p-green;
    text-style: bold;
}}

.permission-denied {{
    color: $r-alert;
    text-style: italic;
}}

/* --- EVIDENCE CHAIN OF CUSTODY --- */

.evidence-item {{
    border: solid $l-evidence;
    background: $bg-panel;
    padding: 1;
    margin-bottom: 1;
}}

.evidence-hash {{
    color: $e-cyan;
}}

.evidence-metadata {{
    color: $steel;
    text-style: dim;
    padding: 1;
}}

.chain-of-custody {{
    border-left: heavy $l-evidence;
    padding-left: 1;
    color: $l-evidence;
}}

/* --- MITRE COVERAGE HEATMAP --- */

.coverage-none {{
    background: $coverage-none;
    color: $steel;
}}

.coverage-low {{
    background: $coverage-low;
    color: $r-alert;
}}

.coverage-med {{
    background: $coverage-med;
    color: white;
}}

.coverage-high {{
    background: $coverage-high;
    color: black;
}}

.coverage-full {{
    background: $coverage-full;
    color: black;
    text-style: bold;
}}

/* --- ACTIVITY TIMELINE --- */

.timeline-entry {{
    border-left: solid $p-purple;
    padding-left: 1;
    margin-bottom: 1;
}}

.timeline-timestamp {{
    color: $e-cyan;
}}

.timeline-operator {{
    color: $p-purple;
    text-style: bold;
}}

.timeline-technique {{
    color: $p-green;
}}

.timeline-detection {{
    color: $a-amber;
}}

/* --- CAMPAIGN TEAM COLORS --- */

.team-operator-1 {{ color: #00FF9F; }}
.team-operator-2 {{ color: #00CCFF; }}
.team-operator-3 {{ color: #FF00FF; }}
.team-operator-4 {{ color: #FFFF00; }}

/* --- SHUTDOWN SCREEN --- */
ShutdownScreen {{
    align: center middle;
    background: $bg-void;
    layout: vertical;
}}

#shutdown-container {{
    width: 60;
    height: 20;
    border: heavy $p-green;
    background: #000;
    padding: 2;
}}

.shutdown-header {{
    width: 100%;
    content-align: center middle;
    margin-bottom: 2;
    color: white;
}}

.shutdown-row {{
    height: 3;
    width: 100%;
    layout: horizontal;
    margin-bottom: 1;
}}

.shutdown-label {{
    color: $e-cyan;
    width: 80%;
}}

.shutdown-status {{
    width: 20%;
    text-align: right;
    text-style: bold;
}}

#final-msg {{
    width: 100%;
    content-align: center middle;
    margin-top: 2;
}}

.status-pending {{ color: $steel; }}
.status-done {{ color: $p-green; }}

/* --- v3.0 UTILITY CLASSES --- */

/* Badges & Tags */
.badge {{
    border: solid $steel;
    padding: 0 1;
    margin-right: 1;
}}

.badge-success {{
    border: solid $p-green;
    color: $p-green;
}}

.badge-warning {{
    border: solid $a-amber;
    color: $a-amber;
}}

.badge-critical {{
    border: solid $r-alert;
    color: $r-alert;
}}

.badge-info {{
    border: solid $e-cyan;
    color: $e-cyan;
}}

.badge-audit {{
    border: solid $m-audit;
    color: $m-audit;
    text-style: italic;
}}

/* Status Indicators */
.status-icon {{
    text-style: bold;
    margin-right: 1;
}}

.status-ok {{ color: $p-green; }}
.status-warn {{ color: $a-amber; }}
.status-fail {{ color: $r-alert; }}
.status-info {{ color: $e-cyan; }}
.status-audit {{ color: $m-audit; }}

/* Data Table Enhancements */
DataTable {{
    border: solid $steel;
    height: 100%;
}}

DataTable > .datatable--header {{
    background: #0a0a0a;
    border-bottom: solid $p-green;
}}

/* Finding State Indicators */
.finding-open {{
    color: $e-cyan;
}}

.finding-in-progress {{
    color: $p-purple;
}}

.finding-closed {{
    color: $p-green;
}}

.finding-blocked {{
    color: $r-alert;
}}

/* Campaign States */
.campaign-planning {{
    color: $a-amber;
}}

.campaign-active {{
    color: $p-purple;
    text-style: bold;
}}

.campaign-finished {{
    color: $p-green;
}}

.campaign-archived {{
    color: $g-disabled;
    text-style: dim;
}}

/* Credential Security States */
.credential-plain {{
    color: $r-alert;
    text-style: bold;
}}

.credential-hashed {{
    color: $a-amber;
}}

.credential-encrypted {{
    color: $p-green;
}}

.credential-captured {{
    color: $m-audit;
}}

/* Detection States */
.detection-unknown {{
    color: $steel;
}}

.detection-missed {{
    color: $p-green;
}}

.detection-alerted {{
    color: $a-amber;
}}

.detection-blocked {{
    color: $r-alert;
}}

/* Technique Coverage */
.technique-new {{
    color: $e-cyan;
    text-style: bold;
}}

.technique-repeated {{
    color: $a-amber;
}}

.technique-saturated {{
    color: $r-alert;
}}

/* Input Validation */
Input.error {{
    border: heavy $r-alert;
    color: $r-alert;
}}

Input.warning {{
    border: heavy $a-amber;
    color: $a-amber;
}}

Input.success {{
    border: heavy $p-green;
    color: $p-green;
}}

/* --- PHASE 5.5 COGNITION ENGINE VIEWS --- */

/* Opportunity View */
OpportunitiesView {{
    border-left: heavy $cog-opp;
}}
.opp-score-high {{ color: $p-green; }}
.opp-score-med {{ color: $a-amber; }}
.opp-score-low {{ color: $r-alert; }}

/* Attack Paths View */
AttackPathsView {{
    border-left: heavy $cog-path;
}}

/* Campaign State View */
CampaignStateView {{
    border-left: heavy $cog-state;
}}

/* Detection Pressure View */
DetectionPressureView {{
    border-left: heavy $cog-detect;
}}
#pressure-gauge {{
    background: $bg-panel;
    border: solid $cog-detect;
    padding: 1;
}}

/* Confidence Analysis View */
ConfidenceAnalysisView {{
    border-left: heavy $cog-conf;
}}
#conf-meter {{
    background: $bg-panel;
    border: solid $cog-conf;
    padding: 1;
}}

/* Knowledge Completeness View */
KnowledgeCompletenessView {{
    border-left: heavy $cog-know;
}}
#knowledge-bar {{
    background: $bg-panel;
    border: solid $cog-know;
    padding: 1;
}}

/* Technique Effectiveness View */
TechniqueEffectivenessView {{
    border-left: heavy $cog-tech;
}}

/* Validation Queue View */
ValidationQueueView {{
    border-left: heavy $cog-val;
}}
.val-pending {{ color: $a-amber; }}
.val-approved {{ color: $p-green; }}
.val-rejected {{ color: $r-alert; }}

/* Explainability View */
ExplainabilityView {{
    border-left: heavy $cog-explain;
}}
#explain-text {{
    background: $bg-panel;
    border: solid $cog-explain;
    padding: 1;
}}

/* Cognition Dashboard View */
CognitionDashboardView {{
    border-left: heavy $cog-dash;
}}
.dash-panel {{
    background: $bg-panel;
    border: solid $steel;
    padding: 1;
}}

/* Cognition Tab Styling */
.cog-tab {{
    border-bottom: solid $steel;
    color: $steel;
}}
.cog-tab:hover {{
    color: $e-cyan;
}}
.cog-tab-active {{
    color: $cog-dash;
    text-style: bold;
    border-bottom: heavy $cog-dash;
}}

/* Scoring Indicators */
.score-excellent {{ color: $p-green; text-style: bold; }}
.score-good {{ color: $e-cyan; }}
.score-fair {{ color: $a-amber; }}
.score-poor {{ color: $r-alert; }}

/* Confidence Indicators */
.conf-high {{ color: $p-green; }}
.conf-medium {{ color: $a-amber; }}
.conf-low {{ color: $r-alert; }}

/* Path Planning Indicators */
.path-viable {{ color: $p-green; }}
.path-risky {{ color: $a-amber; }}
.path-dangerous {{ color: $r-alert; }}

/* ===== TAB NAVIGATION STYLING (Phase 5.5+) ===== */

/* Tab Navigation Panel */
#tab-nav-panel {{
    column-span: 2;
    height: 9;
    background: $bg-panel;
    border: solid $cog-dash;
    border-bottom: solid $cog-dash;
    padding: 0;
    overflow-y: hidden;
    overflow-x: hidden;
}}

/* Group Selector Row */
#tab-group-selector {{
    height: 3;
    border-bottom: solid $steel;
}}

#tab-group-selector .tab-group-btn {{
    width: 1fr;
    min-width: 0;
    height: 3;
    margin: 0;
    border: none;
    border-right: solid $steel;
    background: #141a24;
    color: $text-main;
    content-align: center middle;
    text-style: bold;
    overflow: hidden;
    text-overflow: ellipsis;
}}

#tab-group-selector .tab-group-btn.active {{
    background: $p-green;
    color: #000000;
    text-style: bold;
    border-bottom: heavy $cog-dash;
}}

/* Context Tabs Row */
.tab-row {{
    height: 5;
    padding: 0;
    border-top: solid $steel;
    overflow-x: auto;
    overflow-y: hidden;
    scrollbar-gutter: stable;
}}

#tab-active-caption {{
    height: 1;
    padding: 0 1;
    color: $p-green;
    background: #111621;
    text-style: bold;
    content-align: left middle;
}}

#tab-nav-panel .tab-view-btn {{
    width: auto;
    min-width: 10;
    max-width: 18;
    height: 5;
    margin: 0;
    border: none;
    border-right: solid $steel;
    background: $bg-panel;
    color: $text-main;
    overflow: hidden;
    text-overflow: ellipsis;
}}

#tab-nav-panel .tab-view-btn.active {{
    background: $cog-opp;
    border-bottom: heavy $p-green;
    color: $text-main;
    text-style: bold;
}}

#tab-nav-panel .tab-view-btn:hover {{
    background: $cog-path;
    color: $p-green;
}}

/* Tab Container */
.tab-container {{
    width: 100%;
    height: auto;
}}

/* Tab Group */
TabGroup {{
    height: auto;
    border: solid $steel;
    padding: 1 0;
    background: $bg-panel;
}}
"""
