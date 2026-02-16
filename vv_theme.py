"""
VectorVue v4.0 - Phosphor Cyberpunk Design System
Centralized Theme & Layout Configuration
"""

class CyberColors:
    # High-Vis Neon Palette
    PHOSPHOR_GREEN = "#39FF14"  # Primary: Success, Active Focus
    ELECTRIC_CYAN  = "#00FFFF"  # Accent: Selection, Info
    AMBER_WARNING  = "#FFBF00"  # Secondary: Warnings
    RED_ALERT      = "#FF0000"  # Critical: Errors, Delete
    PURPLE_HAZE    = "#BD00FF"  # Campaign / Ops
    CRIMSON_BLOOD  = "#DC143C"  # Attack Path / Critical Impact
    
    # Industrial Dark Mode Neutrals
    VOID_DARK      = "#050505"  # Deepest background
    PANEL_GREY     = "#121212"  # Component background
    STEEL_BORDER   = "#444444"  # Inactive borders
    TEXT_MAIN      = "#E0E0E0"  # Readable content
    TEXT_DIM       = "#666666"  # Placeholder

# Global CSS Injection
CYBER_CSS = f"""
/* --- VARIABLES --- */
$p-green: {CyberColors.PHOSPHOR_GREEN};
$e-cyan: {CyberColors.ELECTRIC_CYAN};
$a-amber: {CyberColors.AMBER_WARNING};
$r-alert: {CyberColors.RED_ALERT};
$p-purple: {CyberColors.PURPLE_HAZE};
$c-blood: {CyberColors.CRIMSON_BLOOD};
$bg-void: {CyberColors.VOID_DARK};
$bg-panel: {CyberColors.PANEL_GREY};
$steel: {CyberColors.STEEL_BORDER};

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
"""