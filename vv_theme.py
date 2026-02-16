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
    # High-Vis Neon Palette (Primary)
    PHOSPHOR_GREEN = "#39FF14"  # Primary: Success, Active Focus, Approved
    ELECTRIC_CYAN  = "#00FFFF"  # Accent: Selection, Info, In-Progress
    AMBER_WARNING  = "#FFBF00"  # Secondary: Warnings, Pending Review
    RED_ALERT      = "#FF0000"  # Critical: Errors, Delete, Denied
    PURPLE_HAZE    = "#BD00FF"  # Campaign / Ops / Team Operations
    CRIMSON_BLOOD  = "#DC143C"  # Attack Path / Critical Impact / Sensitive Host
    
    # v3.0 OPSEC Colors (New)
    ORANGE_CAUTION  = "#FF8C00"  # Caution: Prohibited hours, Sensitive asset
    LIME_EVIDENCE   = "#00FF41"  # Evidence: Immutable artifact, Chain-of-custody
    MAGENTA_AUDIT   = "#FF1493"  # Audit: Action logged, Approval required
    TEAL_APPROVAL   = "#20B2AA"  # Approval: Approved state, Verified finding
    GRAY_DISABLED   = "#404040"  # Disabled: Locked evidence, Archived campaign
    
    # Industrial Dark Mode Neutrals
    VOID_DARK      = "#050505"  # Deepest background
    PANEL_GREY     = "#121212"  # Component background
    STEEL_BORDER   = "#444444"  # Inactive borders
    TEXT_MAIN      = "#E0E0E0"  # Readable content
    TEXT_DIM       = "#666666"  # Placeholder
    TEXT_MUTED     = "#333333"  # Dimmed / Disabled text
    
    # MITRE Coverage Heatmap (technique distribution)
    COVERAGE_NONE   = "#1a1a1a"  # 0% coverage
    COVERAGE_LOW    = "#4d0000"  # 1-25% coverage
    COVERAGE_MED    = "#ff3300"  # 26-50% coverage
    COVERAGE_HIGH   = "#ffaa00"  # 51-75% coverage
    COVERAGE_FULL   = "#39FF14"  # 76-100% coverage

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
$bg-void: {CyberColors.VOID_DARK};
$bg-panel: {CyberColors.PANEL_GREY};
$steel: {CyberColors.STEEL_BORDER};
$text-muted: {CyberColors.TEXT_MUTED};
$coverage-none: {CyberColors.COVERAGE_NONE};
$coverage-low: {CyberColors.COVERAGE_LOW};
$coverage-med: {CyberColors.COVERAGE_MED};
$coverage-high: {CyberColors.COVERAGE_HIGH};
$coverage-full: {CyberColors.COVERAGE_FULL};

/* --- GLOBAL LAYOUT --- */
Screen {{
    background: $bg-void;
    color: $p-green;
    layout: grid;
    grid-size: 2 3;
    grid-columns: 1fr 42; 
    grid-rows: 3 1fr 1;
}}

/* --- LOGIN SCREEN --- */
LoginView {{
    align: center middle;
    background: $bg-void;
    height: 100%;
}}

#login-container {{
    width: 60;
    height: auto;
    border: heavy $p-green;
    background: #000;
    padding: 2;
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
    background: #111;
    color: white;
}}

#login-input {{
    width: 100%;
    margin-bottom: 2;
    border: solid $steel;
    background: #111;
    color: white;
}}

#login-btn {{
    width: 100%;
    border: solid $p-green;
    color: $p-green;
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
    width: 64;
    height: auto;
    border: heavy $p-green;
    background: #000;
    padding: 2;
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
    width: 100%;
    border: solid $p-green;
    color: $p-green;
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
    background: #000;
    border-bottom: solid $p-green;
    height: 3;
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
    background: #080808;
    border-left: solid $steel;
    padding: 1 2;
    overflow-y: auto;
    scrollbar-gutter: stable;
}}

/* --- STATUS BAR --- */
#status-bar {{
    column-span: 2;
    background: #000;
    color: $p-green;
    border-top: solid $steel;
    content-align: left middle;
    padding-left: 1;
}}

/* --- WIDGET STYLING --- */

TextArea {{
    background: $bg-panel;
    border: none;
    padding: 0 1;
}}
TextArea:focus {{
    border-left: heavy $p-green;
}}

Input {{
    background: $bg-panel;
    border: solid $steel;
    color: #ffffff;
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
    margin-bottom: 1;
    background: $bg-panel;
    border: solid $steel;
    color: $steel;
    text-style: bold;
}}
Button:hover {{
    background: $bg-panel;
    border: heavy $e-cyan;
    color: $e-cyan;
}}
.btn-save {{ border: solid $p-green; color: $p-green; }}
.btn-save:hover {{ background: $p-green; color: black; }}
.btn-delete {{ border: solid $r-alert; color: $r-alert; }}
.btn-delete:hover {{ background: $r-alert; color: black; }}
.btn-purple {{ border: solid $p-purple; color: $p-purple; }}
.btn-purple:hover {{ background: $p-purple; color: white; }}

.info-box {{
    background: $bg-panel;
    border: solid $steel;
    padding: 1;
    margin-bottom: 1;
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
ListItem:hover {{ background: #1a1a1a; color: $e-cyan; }}

.cyber-label {{
    color: $a-amber;
    text-style: bold;
    margin-top: 1;
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
    background: #000;
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
    width: 1fr; border: none; background: #111; color: #666;
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
    background: #080808;
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
"""