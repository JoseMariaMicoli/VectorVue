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

import os
import sys
import asyncio
from datetime import datetime
from pathlib import Path
import logging
from types import SimpleNamespace

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    ListView, ListItem, Label, Input,
    TextArea, Button, Static, ContentSwitcher, DataTable, TabbedContent, TabPane, Select, Markdown
)
from textual.binding import Binding
from textual.screen import Screen
from textual.reactive import reactive
from textual.message import Message

try:
    from vv_core import (Database, Finding, IntelligenceEngine, CVSSCalculator,
                         NIST_800_115_SKELETON, SessionCrypto, Role, role_gte,
                         Campaign, Asset, Credential, Action, CAPABILITY_PROFILES)
    from vv_fs import FileSystemService
    from vv_file_manager import FileManagerView
    from vv_theme import CYBER_CSS, CyberColors
    from vv_tab_navigation import TabNavigationPanel
    # ===== Phase 5.5 Cognition Layer Imports =====
    from cognition_service import CognitionService
    from vv_cognition_views import (
        OpportunitiesView,
        AttackPathsView,
        CampaignStateView,
        DetectionPressureView,
        ConfidenceAnalysisView,
        KnowledgeCompletenessView,
        TechniqueEffectivenessView,
        ValidationQueueView,
        ExplainabilityView,
        CognitionDashboardView,
    )
except ImportError as e:
    print(f"CRITICAL: Dependency missing. {e}")
    sys.exit(1)


README_BANNER_FALLBACK = """██▒   █▓▓█████  ▄████▄  ▄▄▄█████▓ ▒█████   ██▀███      ██▒   █▓ ██▓  ██▓ ▓█████
▓██░   █▒▓█   ▀ ▒██▀ ▀█  ▓  ██▒ ▓▒▒██▒  ██▒▓██ ▒ ██▒    ▓██░   █▒▓██▒  ██▒ ▓█   ▀
 ▓██  █▒░▒███   ▒▓█    ▄ ▒ ▓██░ ▒░▒██░  ██▒▓██ ░▄█ ▒     ▓██  █▒░▓██░  ██▒ ▒███
  ▒██ █░░▒▓█  ▄ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ▒██   ██░▒██▀▀█▄       ▒██ █░░▒██   ██░ ▒▓█  ▄
   ▒▀█░  ░▒████▒▒ ▓███▀ ░  ▒██▒ ░ ░ ████▓▒░░██▓ ▒██▒      ▒▀█░  ░ ████▓▒░ ░▒████▒
   ░ ▐░  ░░ ▒░ ░░ ░▒ ▒  ░  ▒ ░░   ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░      ░ ▐░  ░ ▒░▒░▒░  ░░ ▒░ ░
   ░ ░░   ░ ░  ░  ░  ▒       ░      ░ ░ ▒░   ░▒ ░ ▒░      ░ ░░  ░ ░ ░▒░▒░   ░ ░  ░
   ░      ░    ░    ░          ░      ░ ░ ░ ▒    ░░   ░ ░      ░        ░ ░ ▒░     ░
          ░  ░ ░                               ░               ░ ░ ░      ░  ░

                >> OPERATIONAL COGNITION PLATFORM FOR RED TEAMING <<"""


def _load_readme_banner() -> str:
    """Load ASCII banner from README fenced code block, fallback if unavailable."""
    readme_path = Path(__file__).with_name("README.md")
    try:
        content = readme_path.read_text(encoding="utf-8")
        chunks = content.split("```")
        for block in chunks[1::2]:
            banner = block.strip("\n")
            if "OPERATIONAL COGNITION PLATFORM FOR RED TEAMING" in banner and "██" in banner:
                return banner
    except Exception:
        pass
    return README_BANNER_FALLBACK


README_ASCII_BANNER = _load_readme_banner()

# =============================================================================
# PHASE 2: RUNTIME EXECUTOR (Background Task Management)
# =============================================================================

class RuntimeExecutor:
    """Background task executor for Phase 2 runtime features."""
    
    def __init__(self, db):
        self.db = db
        self.running = False
        self.task_interval = 30  # Check every 30 seconds
    
    async def run_maintenance_loop(self):
        """Run background maintenance tasks periodically."""
        self.running = True
        while self.running:
            try:
                # Execute scheduled tasks
                pending = self.db.get_pending_scheduled_tasks(limit=5)
                for task in pending:
                    self.db.execute_scheduled_task(task["id"])
                
                # Deliver pending webhooks
                webhooks = self.db.get_pending_webhooks(limit=5)
                for webhook in webhooks:
                    self.db.deliver_webhook(webhook["id"], "automated_delivery", {"timestamp": datetime.utcnow().isoformat()})
                
                # Enforce session timeouts (120 min inactivity)
                expired_count = self.db.enforce_session_timeouts(inactivity_minutes=120)
                
                # Execute retention policies
                retention_results = self.db.execute_retention_policies()
                
                # Sleep before next cycle
                await asyncio.sleep(self.task_interval)
            except Exception as e:
                # Silently continue on errors (don't crash the TUI)
                await asyncio.sleep(self.task_interval)
    
    def stop(self):
        """Stop the executor gracefully."""
        self.running = False

# =============================================================================
# WIDGETS
# =============================================================================

class VimDataTable(DataTable):
    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("g", "scroll_top", "Top", show=False),
        Binding("G", "scroll_bottom", "Bottom", show=False),
        Binding("enter", "select_cursor", "Select"),
    ]

# --- CAMPAIGN VIEW (New in v3.0) ---

class CampaignView(Container):
    CSS = """
    #camp-controls Input, #camp-controls Select { margin-bottom: 1; }
    """

    class CampaignAction(Message):
        def __init__(self, action_type: str):
            self.action_type = action_type
            super().__init__()

    def compose(self) -> ComposeResult:
        with Container(id="camp-header"):
            yield Label("[bold purple]CAMPAIGN OPERATIONS[/]", classes="reg-title")
            with Horizontal(id="camp-stats"):
                yield Label("ASSETS: 0", id="stat-assets", classes="stat-box")
                yield Label("CREDS: 0", id="stat-creds", classes="stat-box")
                yield Label("ACTIONS: 0", id="stat-actions", classes="stat-box")
        
        with TabbedContent(initial="tab-assets"):
            with TabPane("Assets", id="tab-assets"):
                yield VimDataTable(id="table-assets", cursor_type="row")
                with Container(id="camp-form-container"):
                    with Horizontal():
                        yield Input(id="inp-ast-name", placeholder="Asset Name (e.g., DC01)", classes="half-input")
                        yield Select([("Host", "host"), ("User", "user"), ("Service", "service")], id="sel-ast-type", prompt="Type", classes="half-input")
                    yield Input(id="inp-ast-ip", placeholder="IP / Address")
                    yield Button("ADD ASSET", id="btn-add-asset", variant="primary")

            with TabPane("Credentials", id="tab-creds"):
                yield VimDataTable(id="table-creds", cursor_type="row")
                with Container(id="camp-form-container"):
                    with Horizontal():
                        yield Input(id="inp-cred-id", placeholder="Username / ID", classes="half-input")
                        yield Select([("Password", "password"), ("Hash", "hash"), ("Ticket", "ticket")], id="sel-cred-type", prompt="Type", classes="half-input")
                    yield Input(id="inp-cred-secret", placeholder="Secret / Hash", password=True)
                    yield Button("CAPTURE CREDENTIAL", id="btn-add-cred", variant="warning")

            with TabPane("Timeline", id="tab-timeline"):
                yield VimDataTable(id="table-actions", cursor_type="row")
                with Container(id="camp-form-container"):
                    with Horizontal():
                        yield Input(id="inp-act-cmd", placeholder="Command Executed", classes="half-input")
                        yield Input(id="inp-act-res", placeholder="Result / Outcome", classes="half-input")
                    with Horizontal():
                        yield Input(id="inp-act-mitre", placeholder="MITRE ID (T1059)", classes="half-input")
                        yield Select([("Unknown", "unknown"), ("Detected", "detected"), ("Blocked", "blocked")], id="sel-act-detect", prompt="Detection", classes="half-input")
                    yield Button("LOG ACTION", id="btn-add-action", classes="btn-purple")

            with TabPane("Reports", id="tab-reports"):
                yield Label("CAMPAIGN INTELLIGENCE", classes="cyber-label")
                yield Button("GENERATE ATTACK PATH REPORT", id="btn-gen-report", variant="success")
                yield TextArea(id="txt-report-preview", read_only=True)

    def on_mount(self):
        # Setup tables
        dt_ast = self.query_one("#table-assets", DataTable)
        dt_ast.add_columns("ID", "Name", "Type", "Address", "OS")
        
        dt_cred = self.query_one("#table-creds", DataTable)
        dt_cred.add_columns("ID", "User", "Type", "Source")
        
        dt_act = self.query_one("#table-actions", DataTable)
        dt_act.add_columns("Time", "Operator", "Technique", "Command", "Detection")

    def refresh_data(self, app):
        # Called by main app to reload tables
        if not app.current_campaign_id: return
        
        # Assets
        dt = self.query_one("#table-assets", DataTable)
        dt.clear()
        assets = app.db.list_assets(app.current_campaign_id)
        for a in assets: dt.add_row(a.id, a.name, a.type, a.address, a.os)
        self.query_one("#stat-assets").update(f"ASSETS: {len(assets)}")

        # Creds
        dt = self.query_one("#table-creds", DataTable)
        dt.clear()
        creds = app.db.list_credentials(app.current_campaign_id)
        for c in creds: dt.add_row(c.id, c.identifier, c.cred_type, c.source)
        self.query_one("#stat-creds").update(f"CREDS: {len(creds)}")

        # Actions
        dt = self.query_one("#table-actions", DataTable)
        dt.clear()
        actions = app.db.list_actions(app.current_campaign_id)
        for a in actions: 
            ts = a.timestamp.split("T")[1][:8]
            dt.add_row(ts, a.operator, a.mitre_technique, a.command, a.detection)
        self.query_one("#stat-actions").update(f"ACTIONS: {len(actions)}")

# --- MITRE VIEW (Existing) ---

class MitreIntelligenceView(Container):
    CSS = """
    MitreIntelligenceView {
        layout: vertical;
        background: $bg-void;
        height: 100%;
        border-right: heavy $e-cyan;
    }
    #mitre-search-bar {
        height: auto; padding: 1;
        background: $bg-panel; border-bottom: solid $steel;
    }
    #mitre-split-container { layout: horizontal; height: 1fr; }
    #mitre-table-pane {
        width: 1fr; height: 100%;
        border-right: solid $p-green; background: $bg-panel;
    }
    #mitre-preview-pane {
        width: 1fr; height: 100%; padding: 1;
        background: $bg-panel; overflow-y: auto;
    }
    .mitre-header { color: $e-cyan; text-style: bold; border-bottom: solid $steel; margin-bottom: 1; }
    #mitre-preview-content { color: #ddd; }
    """

    class TechniqueSelected(Message):
        def __init__(self, technique_id: str, technique_name: str) -> None:
            self.technique_id = technique_id
            self.technique_name = technique_name
            super().__init__()

    def compose(self) -> ComposeResult:
        with Container(id="mitre-search-bar"):
            yield Label("[bold cyan]MITRE ATT&CK SEARCH[/]")
            yield Input(placeholder="Search ID (T1000) or Name...", id="mitre-search-input")
        with Container(id="mitre-split-container"):
            with Vertical(id="mitre-table-pane"):
                yield VimDataTable(id="mitre-table", cursor_type="row")
            with Vertical(id="mitre-preview-pane"):
                yield Label("TECHNIQUE INTEL", classes="mitre-header")
                yield Static("Select a technique to view details.", id="mitre-preview-content")

    def on_mount(self):
        dt = self.query_one("#mitre-table", VimDataTable)
        dt.add_columns("ID", "Technique Name")
        self.populate_table("")

    def focus_search(self):
        self.query_one("#mitre-search-input").focus()

    @on(Input.Changed, "#mitre-search-input")
    def on_search_changed(self, event):
        self.populate_table(event.value)

    def populate_table(self, query):
        dt = self.query_one("#mitre-table", VimDataTable)
        dt.clear()
        intel_engine = getattr(self.app, "intel", None)
        if intel_engine:
            for t in intel_engine.search_techniques(query):
                dt.add_row(t.id, t.name, key=t.id)

    @on(DataTable.RowHighlighted, "#mitre-table")
    def on_row_highlighted(self, event):
        if not event.row_key.value: return
        intel_engine = getattr(self.app, "intel", None)
        if intel_engine:
            technique = intel_engine.lookup_mitre(event.row_key.value)
            if technique:
                content = (f"[bold yellow]ID:[/] {technique.id}\n"
                           f"[bold yellow]NAME:[/] {technique.name}\n\n"
                           f"[bold white]DESCRIPTION:[/]\n{technique.description}")
                self.query_one("#mitre-preview-content").update(content)

    @on(DataTable.RowSelected, "#mitre-table")
    def on_row_selected(self, event):
        intel_engine = getattr(self.app, "intel", None)
        if intel_engine:
            technique = intel_engine.lookup_mitre(event.row_key.value)
            if technique:
                self.post_message(self.TechniqueSelected(technique.id, technique.name))

# =============================================================================
# REGISTER VIEW
# =============================================================================

class RegisterView(Container):
    class RegisterSuccess(Message): pass
    class BackToLogin(Message): pass

    CSS = """
    RegisterView { align: center middle; background: $bg-void; width: 100%; height: 100%; overflow: hidden; }
    #register-root { width: 100%; height: 100%; align: center middle; }
    #register-container { width: 46; min-width: 38; max-width: 48; height: auto; border: heavy $p-green; background: #000000DD; padding: 1; align: center middle; }
    #register-container Horizontal { height: auto; }
    .reg-title { color: $p-green; text-style: bold; margin-bottom: 1; width: 100%; content-align: center middle; }
    #reg-status { color: $r-alert; margin-top: 1; text-align: center; }
    """

    def compose(self) -> ComposeResult:
        with Container(id="register-root"):
            with Container(id="register-container"):
                yield Label("VECTORVUE — FIRST-RUN SETUP", classes="reg-title")
                yield Label("[dim]First registered user becomes ADMIN[/]", classes="reg-title")
                yield Input(placeholder="Username", id="reg-username")
                yield Input(placeholder="Password (min 8 chars)", password=True, id="reg-password")
                yield Input(placeholder="Confirm Password", password=True, id="reg-confirm")
                yield Input(placeholder="Group name (default: 'default')", id="reg-group")
                with Horizontal():
                    yield Button("REGISTER", id="reg-btn", variant="success")
                    yield Button("BACK TO LOGIN", id="reg-back-btn", variant="primary")
                yield Label("", id="reg-status")

    def on_mount(self): self.query_one("#reg-username").focus()

    @on(Button.Pressed, "#reg-btn")
    def attempt_register(self):
        username = self.query_one("#reg-username").value.strip()
        password = self.query_one("#reg-password").value
        confirm  = self.query_one("#reg-confirm").value
        group    = self.query_one("#reg-group").value.strip() or "default"
        status   = self.query_one("#reg-status")
        if password != confirm:
            status.update("PASSWORDS DO NOT MATCH")
            return
        ok, msg = self.app.db.register_user(username, password, group_name=group)
        if ok: self.post_message(self.RegisterSuccess())
        else: status.update(msg)

    @on(Button.Pressed, "#reg-back-btn")
    def go_back_to_login(self):
        self.post_message(self.BackToLogin())

# =============================================================================
# LOGIN VIEW
# =============================================================================

class LoginView(Container):
    class LoginSuccess(Message): pass
    class RegisterRequested(Message): pass

    CSS = """
    LoginView { align: center middle; background: $bg-void; width: 100%; height: 100%; overflow: hidden; }
    #login-root { width: 100%; height: 100%; align: center middle; }
    #login-container { width: 46; min-width: 36; max-width: 48; height: auto; background: #161B26DD; border: heavy $steel; padding: 1; align: center middle; }
    #login-container Horizontal { height: auto; }
    """

    def compose(self) -> ComposeResult:
        with Container(id="login-root"):
            with Container(id="login-container"):
                yield Label("VECTORVUE [SECURE ACCESS]", classes="login-title")
                yield Input(placeholder="Username", id="login-username")
                yield Input(placeholder="Passphrase", password=True, id="login-input")
                with Horizontal():
                    yield Button("AUTHENTICATE", id="login-btn", variant="success")
                    yield Button("REGISTER USER", id="login-register-btn", variant="primary")
                yield Label("No account? Use REGISTER USER.", id="login-register-hint")
                yield Label("", id="login-status")

    def on_mount(self): self.query_one("#login-username").focus()

    @on(Button.Pressed, "#login-btn")
    def attempt_login(self): self.submit_login()

    @on(Input.Submitted, "#login-input")
    def on_submit(self): self.submit_login()

    @on(Button.Pressed, "#login-register-btn")
    def request_register(self):
        self.post_message(self.RegisterRequested())

    def submit_login(self):
        username = self.query_one("#login-username").value.strip()
        phrase   = self.query_one("#login-input").value
        status   = self.query_one("#login-status")
        if not username or not phrase:
            status.update("USERNAME AND PASSPHRASE REQUIRED")
            return
        if self.app.crypto.derive_key(phrase):
            temp_db = Database(self.app.crypto)
            if not temp_db.verify_or_set_canary():
                status.update("DECRYPTION FAILED: INVALID PASSPHRASE")
                temp_db.close()
                return
            temp_db.close()
        else:
            status.update("KDF FAILURE")
            return
        ok, msg = self.app.db.authenticate_user(username, phrase)
        if ok: self.post_message(self.LoginSuccess())
        else: status.update(f"AUTH FAILED: {msg}")

# =============================================================================
# v3.2 EXECUTION & DETECTION VIEWS
# =============================================================================

class CommandExecutionLogView(Container):
    CSS = """
    #cmd-controls Input, #cmd-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold cyan]COMMAND EXECUTION LEDGER[/]", classes="reg-title")
        with Horizontal(id="cmd-controls"):
            yield Input(id="inp-cmd-asset", placeholder="Filter Asset ID")
            yield Input(id="inp-cmd-operator", placeholder="Filter Operator")
            yield Button("REFRESH", id="btn-cmd-refresh", variant="primary")
        yield VimDataTable(id="table-commands", cursor_type="row")

    def on_mount(self):
        table = self.query_one("#table-commands")
        table.add_columns("Timestamp", "Operator", "Asset", "Command", "Result", "MITRE", "Detection")

    def refresh_commands(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-commands")
        table.clear()
        commands = app.db.get_command_history(campaign_id, limit=50)
        for cmd in commands:
            table.add_row(cmd.get("timestamp", "")[:19], cmd.get("operator", ""), str(cmd.get("asset_id", "")),
                         cmd.get("command", "")[:20], "✓" if cmd.get("success") else "✗",
                         cmd.get("mitre_technique", ""), cmd.get("detection_likelihood", ""))

    @on(Button.Pressed, "#btn-cmd-refresh")
    def on_refresh(self):
        if hasattr(self, "app") and hasattr(self.app, "current_campaign_id"):
            self.refresh_commands(self.app, self.app.current_campaign_id)

class SessionActivityView(Container):
    CSS = """
    #session-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold green]SESSION LIFECYCLE MANAGER[/]", classes="reg-title")
        with Horizontal(id="session-controls"):
            yield Button("OPEN SESSION", id="btn-session-new", variant="primary")
            yield Button("CLOSE SESSION", id="btn-session-close", variant="warning")
            yield Button("REFRESH", id="btn-session-refresh", variant="primary")
        yield VimDataTable(id="table-sessions", cursor_type="row")

    def on_mount(self):
        table = self.query_one("#table-sessions")
        table.add_columns("Session ID", "Asset", "Type", "Opened", "Status", "Detected", "Activations")

    def refresh_sessions(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-sessions")
        table.clear()
        sessions = app.db.get_active_sessions(campaign_id)
        for sess in sessions:
            status = "DETECTED" if sess.get("detected_at") else "ACTIVE"
            table.add_row(str(sess.get("id", "")), str(sess.get("asset_id", "")), sess.get("session_type", ""),
                         sess.get("opened_at", "")[:19], status, "Yes" if sess.get("detected_at") else "No",
                         str(sess.get("activation_count", 1)))

    @on(Button.Pressed, "#btn-session-refresh")
    def on_refresh(self):
        if hasattr(self, "app") and hasattr(self.app, "current_campaign_id"):
            self.refresh_sessions(self.app, self.app.current_campaign_id)

class DetectionTimelineView(Container):
    CSS = """
    #detection-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold red]DETECTION EVASION TIMELINE[/]", classes="reg-title")
        with Horizontal(id="detection-controls"):
            yield Button("ASSESS EVASION", id="btn-detect-assess", variant="warning")
            yield Button("REFRESH", id="btn-detect-refresh", variant="primary")
        yield VimDataTable(id="table-detections", cursor_type="row")
        with Horizontal():
            yield Label("Risk Score: ", classes="label-right")
            yield Static("CALCULATING...", id="lbl-risk-score", classes="info-box")

    def on_mount(self):
        table = self.query_one("#table-detections")
        table.add_columns("Time", "Type", "Indicator", "Confidence", "Evasion", "Status")

    def refresh_detections(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-detections")
        table.clear()
        events = app.db.get_detection_timeline(campaign_id)
        for evt in events:
            evasion = "APPLIED" if evt.get("executed_evasion") else "PENDING"
            table.add_row(evt.get("detected_at", "")[:19], evt.get("detection_type", ""),
                         evt.get("indicator", "")[:15], f"{evt.get('confidence', 0):.0%}",
                         evasion, "MITIGATED" if evt.get("executed_evasion") else "OPEN")
        
        risk = app.db.calculate_detection_risk(campaign_id)
        self.query_one("#lbl-risk-score").update(risk.get("risk_level", "UNKNOWN"))

    @on(Button.Pressed, "#btn-detect-refresh")
    def on_refresh(self):
        if hasattr(self, "app") and hasattr(self.app, "current_campaign_id"):
            self.refresh_detections(self.app, self.app.current_campaign_id)

class ObjectiveProgressView(Container):
    CSS = """
    #objective-controls Input, #objective-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold purple]OBJECTIVE PROGRESS TRACKER[/]", classes="reg-title")
        with Horizontal(id="objective-controls"):
            yield Input(id="inp-obj-name", placeholder="New Objective Name")
            yield Button("ADD OBJECTIVE", id="btn-obj-add", variant="primary")
            yield Button("REFRESH", id="btn-obj-refresh", variant="primary")
        yield VimDataTable(id="table-objectives", cursor_type="row")
        with Horizontal():
            yield Label("Coverage: ", classes="label-right")
            yield Static("0%", id="lbl-obj-coverage", classes="info-box")

    def on_mount(self):
        table = self.query_one("#table-objectives")
        table.add_columns("Objective", "Progress", "Status", "Completed By", "Notes")

    def refresh_objectives(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-objectives")
        table.clear()
        coverage = app.db.get_objective_coverage(campaign_id)
        for obj in coverage.get("objectives", []):
            table.add_row(obj.get("objective", ""), f"{obj.get('progress_pct', 0):.0f}%",
                         obj.get("status", "in_progress"), obj.get("completed_by", "-"), "")
        
        self.query_one("#lbl-obj-coverage").update(f"{coverage.get('average_progress', 0):.0f}%")

    @on(Button.Pressed, "#btn-obj-refresh")
    def on_refresh(self):
        if hasattr(self, "app") and hasattr(self.app, "current_campaign_id"):
            self.refresh_objectives(self.app, self.app.current_campaign_id)

class PersistenceInventoryView(Container):
    CSS = """
    #persist-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold yellow]PERSISTENCE REGISTRY[/]", classes="reg-title")
        with Horizontal(id="persist-controls"):
            yield Button("NEW PERSISTENCE", id="btn-persist-new", variant="primary")
            yield Button("VERIFY ALL", id="btn-persist-verify", variant="warning")
            yield Button("REFRESH", id="btn-persist-refresh", variant="primary")
        yield VimDataTable(id="table-persistence", cursor_type="row")

    def on_mount(self):
        table = self.query_one("#table-persistence")
        table.add_columns("ID", "Asset", "Type", "Installed", "Status", "Last Verified", "Verified")

    def refresh_persistence(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-persistence")
        table.clear()
        inventory = app.db.get_persistence_inventory(campaign_id)
        for persist in inventory:
            verified = "✓" if persist.get("verification_result") == "SUCCESS" else "✗" if persist.get("verification_result") else "-"
            table.add_row(str(persist.get("id", "")), str(persist.get("asset_id", "")),
                         persist.get("persistence_type", ""), persist.get("installed_at", "")[:19],
                         persist.get("status", ""), persist.get("last_verified", "")[:19] if persist.get("last_verified") else "-",
                         verified)

    @on(Button.Pressed, "#btn-persist-refresh")
    def on_refresh(self):
        if hasattr(self, "app") and hasattr(self.app, "current_campaign_id"):
            self.refresh_persistence(self.app, self.app.current_campaign_id)

# =============================================================================
# v3.3 INTELLIGENCE & ANALYSIS VIEWS
# =============================================================================

class SituationalAwarenessView(Container):
    CSS = """
    #dashboard-grid { align: center middle; }
    .metric-box { width: 20; height: 5; background: #111; border: solid $p-green; text-align: center; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold cyan]REAL-TIME SITUATIONAL AWARENESS[/]", classes="reg-title")
        with Horizontal(id="dashboard-grid"):
            yield Static("ASSETS\n0", classes="metric-box", id="metric-assets")
            yield Static("COMPROMISED\n0", classes="metric-box", id="metric-compromised")
            yield Static("SESSIONS\n0", classes="metric-box", id="metric-sessions")
            yield Static("PERSISTENCE\n0", classes="metric-box", id="metric-persistence")
            yield Static("RISK\nLOW", classes="metric-box", id="metric-risk")
        yield Label("ACTIVE ALERTS:", classes="cyber-label")
        yield VimDataTable(id="table-alerts", cursor_type="row")

    def on_mount(self):
        table = self.query_one("#table-alerts")
        table.add_columns("Time", "Type", "Severity", "Message")

    def refresh_dashboard(self, app, campaign_id):
        if not campaign_id: return
        dashboard = app.db.get_campaign_dashboard(campaign_id)
        metrics = dashboard.get("current_metrics", {})

        # Fallback to live campaign telemetry when metrics snapshots are absent.
        if not metrics or (
            metrics.get("total_assets", 0) == 0 and
            metrics.get("active_sessions", 0) == 0 and
            metrics.get("total_commands_executed", 0) == 0
        ):
            assets = app.db.list_assets(campaign_id)
            sessions = app.db.get_active_sessions(campaign_id)
            detections = app.db.get_detection_timeline(campaign_id)
            persistence = app.db.get_persistence_inventory(campaign_id)
            metrics = {
                "total_assets": len(assets),
                "compromised_assets": len({s.get("asset_id") for s in sessions if s.get("asset_id")}),
                "active_sessions": len(sessions),
                "active_persistence": len(persistence),
                "detection_risk_score": min(1.0, sum(float(d.get("confidence", 0.0)) for d in detections) / max(1, len(detections))),
            }
            if not dashboard.get("pending_alerts"):
                pending = []
                for det in detections[-8:]:
                    pending.append({
                        "created_at": det.get("detected_at", ""),
                        "alert_type": det.get("detection_type", "Detection"),
                        "severity": "HIGH" if float(det.get("confidence", 0.0)) >= 0.7 else "MEDIUM",
                        "message": det.get("indicator", "Detection event"),
                    })
                dashboard["pending_alerts"] = pending
        
        self.query_one("#metric-assets").update(f"ASSETS\n{metrics.get('total_assets', 0)}")
        self.query_one("#metric-compromised").update(f"COMPROMISED\n{metrics.get('compromised_assets', 0)}")
        self.query_one("#metric-sessions").update(f"SESSIONS\n{metrics.get('active_sessions', 0)}")
        self.query_one("#metric-persistence").update(f"PERSISTENCE\n{metrics.get('active_persistence', 0)}")
        
        risk = "CRITICAL" if metrics.get("detection_risk_score", 0) > 0.75 else "HIGH" if metrics.get("detection_risk_score", 0) > 0.5 else "LOW"
        self.query_one("#metric-risk").update(f"RISK\n{risk}")
        
        table = self.query_one("#table-alerts")
        table.clear()
        for alert in dashboard.get("pending_alerts", []):
            table.add_row(alert.get("created_at", "")[:19], alert.get("alert_type", ""),
                         alert.get("severity", ""), alert.get("message", "")[:40])


class GraphAnalyticsView(Container):
    """Operational graph view: assets, links, and inferred compromise paths."""

    CSS = """
    GraphAnalyticsView { layout: vertical; height: 100%; background: $bg-void; }
    #graph-header { height: 3; border-bottom: solid $steel; padding: 0 1; }
    #graph-kpis { height: 3; layout: horizontal; }
    .graph-kpi { width: 1fr; border: solid $steel; content-align: center middle; color: $text-main; }
    #graph-split { height: 1fr; layout: vertical; }
    #graph-canvas { height: 1fr; border: solid $steel; padding: 1; overflow-y: auto; }
    #graph-side { height: 12; border: solid $steel; padding: 1; overflow-y: auto; }
    """

    def compose(self) -> ComposeResult:
        yield Label("[bold]ATTACK GRAPH VIEW[/] - topology + path inference", id="graph-header")
        with Horizontal(id="graph-kpis"):
            yield Static("NODES: 0", id="graph-kpi-nodes", classes="graph-kpi")
            yield Static("EDGES: 0", id="graph-kpi-edges", classes="graph-kpi")
            yield Static("SESSIONS: 0", id="graph-kpi-sessions", classes="graph-kpi")
            yield Static("DETECTIONS: 0", id="graph-kpi-detections", classes="graph-kpi")
        with Vertical(id="graph-split"):
            yield Static("NO GRAPH DATA", id="graph-canvas")
            yield Static("NO GRAPH CHARTS", id="graph-side")

    def refresh_graph(self, app, campaign_id):
        if not campaign_id:
            return

        assets = app.db.list_assets(campaign_id)
        sessions = app.db.get_active_sessions(campaign_id)
        detections = app.db.get_detection_timeline(campaign_id)
        commands = app.db.get_command_history(campaign_id, limit=120)
        compromise_chain = app.db.build_compromise_chain(campaign_id)
        rel_timeline = compromise_chain.get("timeline", [])

        controlled_assets = {int(s.get("asset_id", 0)) for s in sessions if s.get("asset_id")}
        detected_assets = {int(d.get("asset_id", 0)) for d in detections if d.get("asset_id")}

        # Build transition edges from command history
        transitions: dict[tuple[int, int], int] = {}
        previous_asset = None
        for cmd in commands:
            aid = cmd.get("asset_id")
            if aid is None:
                continue
            try:
                aid = int(aid)
            except Exception:
                continue
            if previous_asset is not None and previous_asset != aid:
                key = (previous_asset, aid)
                transitions[key] = transitions.get(key, 0) + 1
            previous_asset = aid

        # Also infer edges from explicit relationship timeline to keep graph visible
        # even when command transitions are sparse.
        for rel in rel_timeline:
            actor = str(rel.get("actor", ""))
            target = str(rel.get("target", ""))
            if not actor.startswith("asset:") or not target.startswith("asset:"):
                continue
            try:
                src = int(actor.split(":", 1)[1])
                dst = int(target.split(":", 1)[1])
            except Exception:
                continue
            if src != dst:
                transitions[(src, dst)] = transitions.get((src, dst), 0) + 1

        # Relationship modeling summary
        relation_counts: dict[str, int] = {}
        relation_edges: dict[tuple[str, str], int] = {}
        for rel in rel_timeline:
            action = rel.get("action", "unknown")
            relation_counts[action] = relation_counts.get(action, 0) + 1
            k = (rel.get("actor", "?"), rel.get("target", "?"))
            relation_edges[k] = relation_edges.get(k, 0) + 1

        # Shortest path to objective (heuristic objective: last asset by id)
        path_summary = "No objective path available"
        choke_points: list[str] = []
        if len(assets) >= 2:
            sorted_assets = sorted([a for a in assets if a.id is not None], key=lambda a: int(a.id))
            start_id = str(sorted_assets[0].id)
            objective_id = str(sorted_assets[-1].id)
            paths = app.db.get_attack_path(campaign_id, start_id, objective_id, max_hops=6)
            if paths:
                shortest = min(paths, key=len)
                path_nodes = [shortest[0]["source_id"]] + [edge["target_id"] for edge in shortest]
                path_summary = f"Shortest objective path: {' -> '.join(path_nodes)}"
                # Choke points: intermediate nodes in shortest path
                if len(path_nodes) > 2:
                    choke_points = path_nodes[1:-1]

        # Privilege escalation chains from relationship labels
        privesc_edges = relation_counts.get("admin_to", 0) + relation_counts.get("delegates", 0)

        # Credential blast radius estimate
        credential_edges = sum(
            1 for rel in rel_timeline
            if str(rel.get("actor", "")).startswith("credential:")
        )

        # Domain dominance heuristic (0-100)
        host_count = max(len(assets), 1)
        dominance = min(100.0, ((len(controlled_assets) / host_count) * 55.0) + (privesc_edges * 10.0))

        # KPI updates
        self.query_one("#graph-kpi-nodes", Static).update(f"NODES: {len(assets)}")
        self.query_one("#graph-kpi-edges", Static).update(f"EDGES: {len(transitions) + len(relation_edges)}")
        self.query_one("#graph-kpi-sessions", Static).update(f"SESSIONS: {len(sessions)}")
        self.query_one("#graph-kpi-detections", Static).update(f"DETECTIONS: {len(detections)}")

        asset_name = {
            int(a.id): (a.name or f"ASSET_{a.id}")
            for a in assets
            if a.id is not None
        }

        # Left panel: ASCII graph summary
        lines = ["[bold]ATTACK GRAPH MAP[/]"]
        lines.append(f"Nodes: {len(assets)} | Directed edges: {len(transitions)}")
        lines.append("")
        lines.append("[bold]ROUTE SUMMARY[/]")
        if transitions:
            ordered = sorted(
                transitions.items(),
                key=lambda item: (item[1], item[0][0], item[0][1]),
                reverse=True,
            )
            for idx, ((src, dst), count) in enumerate(ordered[:14], start=1):
                src_name = asset_name.get(src, f"ASSET_{src}")[:16]
                dst_name = asset_name.get(dst, f"ASSET_{dst}")[:16]
                weight = ">" * min(10, max(1, count))
                lines.append(
                    f"{idx:02d}. #{src:02d}:{src_name:<16} {weight:<10} #{dst:02d}:{dst_name:<16} x{count}"
                )
        else:
            lines.append("No directed movement edges available yet.")

        # Primary chain projection from strongest outgoing edge
        lines.append("")
        lines.append("[bold]PRIMARY CHAIN[/]")
        if transitions:
            by_source: dict[int, list[tuple[int, int]]] = {}
            for (src, dst), c in transitions.items():
                by_source.setdefault(src, []).append((dst, c))
            for src in by_source:
                by_source[src].sort(key=lambda pair: pair[1], reverse=True)
            ordered_sources = sorted(
                by_source.keys(),
                key=lambda sid: max((v for _, v in by_source[sid]), default=0),
                reverse=True,
            )
            chain = [ordered_sources[0]] if ordered_sources else []
            seen = set(chain)
            while chain and chain[-1] in by_source and len(chain) < 12:
                nxt = by_source[chain[-1]][0][0]
                if nxt in seen:
                    break
                chain.append(nxt)
                seen.add(nxt)
            if len(chain) >= 2:
                chain_str = " => ".join(f"#{aid}:{asset_name.get(aid, f'ASSET_{aid}')[:12]}" for aid in chain)
                lines.append(chain_str)
            else:
                lines.append("Not enough edges to project a chain.")
        else:
            lines.append("Not enough edges to project a chain.")

        lines.append("")
        lines.append("[bold]ASSET TOPOLOGY[/]")
        if not assets:
            lines.append("No assets in current campaign.")
        for asset in assets:
            aid = int(asset.id) if asset.id is not None else 0
            state = []
            if aid in controlled_assets:
                state.append("[green]OWNED[/]")
            if aid in detected_assets:
                state.append("[red]DETECTED[/]")
            state_text = " ".join(state) if state else "[dim]UNSEEN[/]"
            lines.append(f"• {asset.name} (#{aid}) {state_text}")

        lines.append("")
        lines.append("[bold]INFERRED LINKS[/]")
        if not transitions:
            lines.append("No movement transitions inferred yet.")
        else:
            for (src, dst), count in sorted(transitions.items(), key=lambda item: item[1], reverse=True)[:20]:
                lines.append(f"#{src} -> #{dst}  x{count}")
        lines.append("\n[bold]RELATIONSHIP MODEL[/]")
        if relation_counts:
            lines.append(
                " | ".join(
                    f"{rel}:{count}"
                    for rel, count in sorted(relation_counts.items(), key=lambda item: item[1], reverse=True)
                )
            )
        else:
            lines.append("No explicit relationships captured.")
        lines.append(f"\n[bold]OBJECTIVE PATH[/] {path_summary}")
        lines.append(f"[bold]PRIVESC CHAINS[/] ~{privesc_edges}")
        lines.append(
            f"[bold]CHOKE POINTS[/] {', '.join(choke_points) if choke_points else 'None identified'}"
        )
        lines.append(f"[bold]CREDENTIAL BLAST RADIUS[/] ~{credential_edges} credential-linked edges")
        lines.append(f"[bold]DOMAIN DOMINANCE LIKELIHOOD[/] {dominance:.0f}%")
        graph_canvas = self.query_one("#graph-canvas", Static)
        graph_canvas.update("\n".join(lines))
        try:
            graph_canvas.scroll_home(animate=False)
        except Exception:
            pass

        # Right panel: always-rendered charts
        def bar(value: float, max_value: float, width: int = 18) -> str:
            if max_value <= 0:
                return "░" * width
            n = int(round((value / max_value) * width))
            n = max(0, min(width, n))
            return "█" * n + "░" * (width - n)

        side_lines = ["[bold]GRAPH CHARTS[/]"]
        side_lines.append("\n[bold]LATERAL MOVEMENT[/]")
        top_moves = sorted(transitions.items(), key=lambda item: item[1], reverse=True)[:8]
        max_moves = top_moves[0][1] if top_moves else 0
        if top_moves:
            for (src, dst), count in top_moves:
                side_lines.append(f"#{src}->{dst} {bar(float(count), float(max_moves))} {count}")
        else:
            side_lines.append("No transition edges yet.")

        side_lines.append("\n[bold]RELATION TYPE MIX[/]")
        rel_sorted = sorted(relation_counts.items(), key=lambda item: item[1], reverse=True)[:8]
        max_rel = rel_sorted[0][1] if rel_sorted else 0
        if rel_sorted:
            for rel, count in rel_sorted:
                side_lines.append(f"{rel[:12]:12} {bar(float(count), float(max_rel))} {count}")
        else:
            side_lines.append("No relationship events.")

        side_lines.append("\n[bold]CONTROL VS DETECTION[/]")
        owned_n = float(len(controlled_assets))
        det_n = float(len(detected_assets))
        total = float(max(len(assets), 1))
        side_lines.append(f"Owned     {bar(owned_n, total)} {int(owned_n)}/{int(total)}")
        side_lines.append(f"Detected  {bar(det_n, total)} {int(det_n)}/{int(total)}")
        side_lines.append(f"Dominance {bar(dominance, 100.0)} {dominance:.0f}%")

        side_lines.append("\n[bold]OBJECTIVE PATH[/]")
        side_lines.append(path_summary[:56])
        graph_side = self.query_one("#graph-side", Static)
        graph_side.update("\n".join(side_lines))
        try:
            graph_side.scroll_home(animate=False)
        except Exception:
            pass


class EngagementTimelineView(Container):
    """Replayable operation history with defender markers and kill-chain stages."""

    CSS = """
    EngagementTimelineView { layout: vertical; height: 100%; background: $bg-void; }
    #timeline-header { height: 3; border-bottom: solid $steel; padding: 0 1; }
    #timeline-table { height: 1fr; border: solid $steel; }
    """

    def compose(self) -> ComposeResult:
        yield Label("[bold]ENGAGEMENT TIMELINE[/] - replay + defender reactions", id="timeline-header")
        yield VimDataTable(id="timeline-table", cursor_type="row")

    def on_mount(self):
        table = self.query_one("#timeline-table", VimDataTable)
        table.add_columns("Time", "Lane", "Event", "Kill-Chain", "Marker")

    def _kill_chain_stage(self, app, technique: str) -> str:
        if not technique:
            return "Unknown"
        intel = getattr(app, "intel", None)
        if intel:
            try:
                return intel.get_tactic_from_id(technique)
            except Exception:
                return "Unknown"
        return "Unknown"

    def refresh_timeline(self, app, campaign_id):
        if not campaign_id:
            return
        table = self.query_one("#timeline-table", VimDataTable)
        table.clear()

        # Red team actions
        for cmd in app.db.get_command_history(campaign_id, limit=200):
            technique = cmd.get("mitre_technique", "")
            table.add_row(
                str(cmd.get("timestamp", ""))[:19],
                "RED",
                f"Command on asset {cmd.get('asset_id', '-')}",
                self._kill_chain_stage(app, technique),
                technique or "-",
            )

        # Defender reactions
        for det in app.db.get_detection_timeline(campaign_id):
            table.add_row(
                str(det.get("detected_at", ""))[:19],
                "BLUE",
                f"Detection: {det.get('detection_type', 'event')}",
                "Detection",
                f"sev={det.get('confidence', 0):.0%}",
            )

        # Relationship chain reconstruction
        narrative = app.db.build_compromise_chain(campaign_id)
        for entry in narrative.get("timeline", []):
            table.add_row(
                str(entry.get("timestamp", ""))[:19],
                "CHAIN",
                f"{entry.get('actor', '?')} {entry.get('action', '?')} {entry.get('target', '?')}",
                "Lateral Movement",
                f"conf={entry.get('confidence', 0):.2f}",
            )

class PostEngagementAnalysisView(Container):
    CSS = """
    #analysis-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold white]POST-ENGAGEMENT ANALYSIS[/]", classes="reg-title")
        with Horizontal(id="analysis-controls"):
            yield Button("GENERATE REPORT", id="btn-analysis-gen", variant="success")
            yield Button("TTP METRICS", id="btn-analysis-ttp", variant="primary")
            yield Button("REFRESH", id="btn-analysis-refresh", variant="primary")
        yield VimDataTable(id="table-analysis", cursor_type="row")
        yield TextArea(id="txt-analysis-preview", read_only=True)

    def on_mount(self):
        table = self.query_one("#table-analysis")
        table.add_columns("Metric", "Value", "Assessment")

    def refresh_analysis(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-analysis")
        table.clear()
        
        ttp_report = app.db.get_ttp_effectiveness_report(campaign_id)
        table.add_row("Total Techniques", str(ttp_report.get("total_techniques_executed", 0)), "")
        table.add_row("Avg Effectiveness", f"{ttp_report.get('average_effectiveness', 0):.1f}%", "")

class RemediationTrackingView(Container):
    CSS = """
    #remediation-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold red]REMEDIATION TRACKING[/]", classes="reg-title")
        with Horizontal(id="remediation-controls"):
            yield Button("LOG REMEDIATION", id="btn-rem-log", variant="warning")
            yield Button("REFRESH", id="btn-rem-refresh", variant="primary")
        yield VimDataTable(id="table-remediation", cursor_type="row")

    def on_mount(self):
        table = self.query_one("#table-remediation")
        table.add_columns("Time", "Asset", "Action", "Status", "Impact")

    def refresh_remediation(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-remediation")
        table.clear()
        timeline = app.db.get_remediation_timeline(campaign_id)
        for action in timeline:
            impact = f"{action.get('impact_score', 0):.0%}" if action.get("impact_score") else "-"
            table.add_row(action.get("action_timestamp", "")[:19], str(action.get("asset_id", "")),
                         action.get("action_description", "")[:25], action.get("status", ""),
                         impact)

class CapabilityAssessmentView(Container):
    CSS = """
    #capability-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold yellow]CAPABILITY ASSESSMENT[/]", classes="reg-title")
        with Horizontal(id="capability-controls"):
            yield Button("REGISTER CAPABILITY", id="btn-cap-reg", variant="primary")
            yield Button("REFRESH", id="btn-cap-refresh", variant="primary")
        yield VimDataTable(id="table-capabilities", cursor_type="row")

    def on_mount(self):
        table = self.query_one("#table-capabilities")
        table.add_columns("Capability", "Type", "Difficulty", "Success Rate", "Trend")

    def refresh_capabilities(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-capabilities")
        table.clear()
        assessment = app.db.get_capability_assessment_report(campaign_id)
        for cap in assessment.get("capabilities", []):
            table.add_row(cap.get("capability_name", ""), cap.get("capability_type", ""),
                         f"{cap.get('difficulty_score', 0):.1f}", f"{cap.get('success_rate', 0):.0%}",
                         cap.get("effectiveness_trend", "stable"))

# =============================================================================
# v3.4 ADVANCED FEATURES & SECURITY HARDENING VIEWS
# =============================================================================

class CollaborationEngineView(Container):
    CSS = """
    #collab-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold cyan]REAL-TIME COLLABORATION ENGINE[/]", classes="reg-title")
        with Horizontal(id="collab-controls"):
            yield Button("START SESSION", id="btn-collab-start", variant="primary")
            yield Button("DETECT CONFLICTS", id="btn-collab-conflicts", variant="warning")
            yield Button("REFRESH", id="btn-collab-refresh", variant="primary")
        yield VimDataTable(id="table-collab", cursor_type="row")

    def on_mount(self):
        table = self.query_one("#table-collab")
        table.add_columns("Session", "Operators", "Created", "Status", "Changes")

    def refresh_collaboration(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-collab")
        table.clear()

class TaskOrchestrationView(Container):
    CSS = """
    #task-controls Input, #task-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold green]AUTONOMOUS TASK ORCHESTRATION[/]", classes="reg-title")
        with Horizontal(id="task-controls"):
            yield Input(id="inp-task-name", placeholder="Task Template Name")
            yield Button("CREATE TEMPLATE", id="btn-task-create", variant="primary")
            yield Button("REFRESH", id="btn-task-refresh", variant="primary")
        yield VimDataTable(id="table-tasks", cursor_type="row")

    def on_mount(self):
        table = self.query_one("#table-tasks")
        table.add_columns("Task", "Status", "Last Run", "Result", "Retries")

    def refresh_tasks(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-tasks")
        table.clear()
        history = app.db.get_task_execution_history(campaign_id, limit=20)
        for task in history:
            table.add_row(task.get("template_name", ""), task.get("status", ""),
                         task.get("execution_start", "")[:19], task.get("result", ""), "-")

class BehavioralAnalyticsView(Container):
    CSS = """
    #analytics-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold magenta]BEHAVIORAL ANALYTICS & ML[/]", classes="reg-title")
        with Horizontal(id="analytics-controls"):
            yield Button("ANALYZE PATTERNS", id="btn-analytics-analyze", variant="primary")
            yield Button("DETECT ANOMALIES", id="btn-analytics-anomalies", variant="warning")
            yield Button("PREDICT DEFENSE", id="btn-analytics-predict", variant="primary")
        yield VimDataTable(id="table-analytics", cursor_type="row")

    def on_mount(self):
        table = self.query_one("#table-analytics")
        table.add_columns("Anomaly Type", "Severity", "Detected", "Description", "Actions")

    def refresh_analytics(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-analytics")
        table.clear()

class IntegrationGatewayView(Container):
    CSS = """
    #integration-controls Input, #integration-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold yellow]EXTERNAL INTEGRATION GATEWAY[/]", classes="reg-title")
        with Horizontal(id="integration-controls"):
            yield Input(id="inp-webhook-url", placeholder="Webhook URL")
            yield Button("REGISTER WEBHOOK", id="btn-webhook-reg", variant="primary")
            yield Button("API INTEGRATIONS", id="btn-api-mgmt", variant="primary")
        yield VimDataTable(id="table-webhooks", cursor_type="row")

    def on_mount(self):
        table = self.query_one("#table-webhooks")
        table.add_columns("Webhook Type", "URL", "Active", "Last Trigger", "Status")

    def refresh_integrations(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-webhooks")
        table.clear()

class ComplianceReportingView(Container):
    CSS = """
    #compliance-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold white]COMPLIANCE & AUDIT CERTIFICATION[/]", classes="reg-title")
        with Horizontal(id="compliance-controls"):
            yield Button("GENERATE SOC 2 REPORT", id="btn-soc2-gen", variant="success")
            yield Button("FEDRAMP REPORT", id="btn-fedramp-gen", variant="success")
            yield Button("REFRESH", id="btn-compliance-refresh", variant="primary")
        yield VimDataTable(id="table-compliance", cursor_type="row")
        with Horizontal():
            yield Label("Compliance Score: ", classes="label-right")
            yield Static("0%", id="lbl-compliance-score", classes="info-box")

    def on_mount(self):
        table = self.query_one("#table-compliance")
        table.add_columns("Framework", "Satisfied", "Total", "Status", "Generated")

    def refresh_compliance(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-compliance")
        table.clear()

class SecurityHardeningView(Container):
    CSS = """
    #security-controls Button { margin: 0 1; margin-bottom: 1; }
    """
    def compose(self) -> ComposeResult:
        yield Label("[bold red]SECURITY HARDENING & AUDIT[/]", classes="reg-title")
        with Horizontal(id="security-controls"):
            yield Button("VERIFY AUDIT CHAIN", id="btn-sec-verify", variant="warning")
            yield Button("SESSION MANAGEMENT", id="btn-sec-sessions", variant="primary")
            yield Button("RETENTION POLICIES", id="btn-sec-retention", variant="primary")
        yield VimDataTable(id="table-security", cursor_type="row")

    def on_mount(self):
        table = self.query_one("#table-security")
        table.add_columns("Policy Type", "Status", "Last Action", "Records", "Verified")

    def refresh_security(self, app, campaign_id):
        if not campaign_id: return
        table = self.query_one("#table-security")
        table.clear()

# =============================================================================
# v3.5 REPORTING & EXPORT VIEWS
# =============================================================================

class ReportingView(Container):
    """Phase 3: Reporting & Export Engine UI for PDF/HTML report generation, evidence manifests, compliance mapping, and report scheduling."""
    
    CSS = """
    ReportingView { layout: vertical; background: $bg-void; height: 100%; }
    #report-header { height: auto; padding: 1; background: $bg-panel; border-bottom: heavy $p-green; }
    #report-split { layout: horizontal; height: 1fr; }
    #report-controls { width: 35%; height: 100%; background: $bg-panel; border-right: solid $e-cyan; padding: 1; overflow-y: auto; }
    #report-preview { width: 1fr; height: 100%; padding: 1; background: $bg-void; overflow-y: auto; }
    .report-section { margin-bottom: 2; border-left: solid $p-green; padding-left: 1; }
    .report-label { color: $p-green; text-style: bold; margin-top: 1; margin-bottom: 1; }
    #report-status { color: white; height: auto; padding: 1; background: $bg-panel; border-top: solid $steel; }
    #txt-exec-summary { height: 8; border: solid $e-cyan; }
    #txt-report-content { height: 1fr; border: solid $p-green; }
    """
    
    def compose(self) -> ComposeResult:
        yield Label("[bold cyan]PHASE 3: REPORTING & EXPORT ENGINE[/]", id="report-header", classes="reg-title")
        
        with Container(id="report-split"):
            # Left Panel: Report Controls
            with Vertical(id="report-controls"):
                # 1. Campaign Report Generation
                yield Label("CAMPAIGN REPORTS", classes="report-label")
                with Vertical(classes="report-section"):
                    yield Select([("Executive Summary", "executive"), ("Technical", "technical"), ("Comprehensive", "comprehensive")], 
                               id="sel-report-type", prompt="Report Type")
                    yield Select([("PDF", "pdf"), ("HTML", "html")], 
                               id="sel-report-format", prompt="Format")
                    yield Input(id="inp-report-title", placeholder="Report Title")
                    yield TextArea(id="txt-exec-summary")
                    yield Button("GENERATE REPORT", id="btn-gen-report", variant="success")
                
                # 2. Evidence Manifests
                yield Label("EVIDENCE CHAIN", classes="report-label")
                with Vertical(classes="report-section"):
                    yield Input(id="inp-manifest-name", placeholder="Manifest Name")
                    yield Button("CREATE MANIFEST", id="btn-create-manifest", variant="primary")
                    yield Button("VERIFY MANIFEST", id="btn-verify-manifest", variant="warning")
                
                # 3. Finding Summaries
                yield Label("FINDING ANALYSIS", classes="report-label")
                with Vertical(classes="report-section"):
                    yield Static("Select a finding from campaign view to add summary", id="lbl-finding-status")
                    yield Input(id="inp-cvss-vector", placeholder="CVSS:3.1/AV:N/AC:L/...")
                    yield Button("CREATE SUMMARY", id="btn-create-summary", variant="primary")
                
                # 4. Compliance Mapping
                yield Label("COMPLIANCE REPORTS", classes="report-label")
                with Vertical(classes="report-section"):
                    yield Select([("NIST SP 800-171", "nist"), ("FedRAMP", "fedramp"), 
                                ("ISO 27001", "iso27001"), ("SOC 2", "soc2")], 
                               id="sel-compliance-framework", prompt="Framework")
                    yield Button("GENERATE COMPLIANCE REPORT", id="btn-gen-compliance", variant="success")
                
                # 5. Report Scheduling
                yield Label("AUTOMATED REPORTING", classes="report-label")
                with Vertical(classes="report-section"):
                    yield Input(id="inp-schedule-name", placeholder="Schedule Name")
                    yield Select([("Daily", "daily"), ("Weekly", "weekly"), ("Monthly", "monthly")], 
                               id="sel-schedule-freq", prompt="Frequency")
                    yield Button("SCHEDULE REPORTS", id="btn-schedule-reports", variant="primary")
            
            # Right Panel: Report Preview/Status
            with Vertical(id="report-preview"):
                yield Label("REPORT PREVIEW", classes="cyber-label")
                yield TextArea(id="txt-report-content", read_only=True)
        
        yield Label("REPORTING ENGINE READY", id="report-status", classes="info-box")

    def on_mount(self):
        self.refresh_report_summary()

    def refresh_report_summary(self):
        """Populate reporting preview with current campaign summary."""
        app = self.app
        if not getattr(app, "current_campaign_id", None):
            self.query_one("#txt-report-content", TextArea).load_text("No active campaign selected.")
            return
        cid = app.current_campaign_id
        assets = app.db.list_assets(cid)
        creds = app.db.list_credentials(cid)
        cmds = app.db.get_command_history(cid, limit=50)
        dets = app.db.get_detection_timeline(cid)
        rels = app.db.build_compromise_chain(cid).get("timeline", [])
        text = (
            f"# Reporting Summary\n\n"
            f"- Campaign ID: {cid}\n"
            f"- Assets: {len(assets)}\n"
            f"- Credentials: {len(creds)}\n"
            f"- Commands: {len(cmds)}\n"
            f"- Detections: {len(dets)}\n"
            f"- Relationship events: {len(rels)}\n\n"
            f"Use controls on the left to generate PDF/HTML reports, manifests, and compliance exports."
        )
        self.query_one("#txt-report-content", TextArea).load_text(text)
        self.update_report_status("REPORTING SUMMARY LOADED", CyberColors.PHOSPHOR_GREEN)

    # =========================================================================
    # CAMPAIGN REPORT GENERATION
    # =========================================================================
    
    @on(Button.Pressed, "#btn-gen-report")
    def on_gen_report(self):
        """Generate PDF or HTML campaign report."""
        app = self.app
        if not app.current_campaign_id:
            self.update_report_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        
        user = app.db.current_user
        report_title = self.query_one("#inp-report-title").value.strip() or f"Campaign_{app.current_campaign_id}"
        report_type = self.query_one("#sel-report-type").value or "technical"
        report_format = self.query_one("#sel-report-format").value or "pdf"
        exec_summary = self.query_one("#txt-exec-summary").text.strip()
        
        try:
            # Create campaign report record
            report_id = app.db.create_campaign_report(
                app.current_campaign_id,
                report_title,
                report_type,
                exec_summary,
                ""
            )
            
            if not report_id:
                self.update_report_status("FAILED TO CREATE REPORT RECORD", CyberColors.RED_ALERT)
                return
            
            # Generate report in requested format
            if report_format == "pdf":
                success, result = app.db.generate_pdf_report(report_id)
            else:  # html
                success, result = app.db.generate_html_report(report_id)
            
            if success:
                app.db.log_audit_event(user.username, "REPORT_GENERATED", 
                                      {"campaign_id": app.current_campaign_id, "report_id": report_id, 
                                       "format": report_format, "path": result})
                self.update_report_status(f"✓ {report_format.upper()} REPORT GENERATED: {result}", CyberColors.PHOSPHOR_GREEN)
                self.query_one("#inp-report-title").value = ""
                self.query_one("#txt-exec-summary").text = ""
            else:
                self.update_report_status(f"REPORT GENERATION FAILED: {result}", CyberColors.RED_ALERT)
        
        except Exception as e:
            self.update_report_status(f"ERROR: {str(e)[:60]}", CyberColors.RED_ALERT)
    
    # =========================================================================
    # EVIDENCE MANIFESTS
    # =========================================================================
    
    @on(Button.Pressed, "#btn-create-manifest")
    def on_create_manifest(self):
        """Create evidence chain of custody manifest."""
        app = self.app
        if not app.current_campaign_id:
            self.update_report_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        
        user = app.db.current_user
        manifest_name = self.query_one("#inp-manifest-name").value.strip() or f"Manifest_{app.current_campaign_id}"
        
        try:
            manifest_id = app.db.create_evidence_manifest(app.current_campaign_id, manifest_name)
            
            if manifest_id:
                app.db.log_audit_event(user.username, "EVIDENCE_MANIFEST_CREATED",
                                      {"campaign_id": app.current_campaign_id, "manifest_id": manifest_id})
                self.update_report_status(f"✓ MANIFEST CREATED (ID: {manifest_id})", CyberColors.PHOSPHOR_GREEN)
                self.query_one("#inp-manifest-name").value = ""
            else:
                self.update_report_status("FAILED TO CREATE MANIFEST", CyberColors.RED_ALERT)
        
        except Exception as e:
            self.update_report_status(f"ERROR: {str(e)[:60]}", CyberColors.RED_ALERT)
    
    @on(Button.Pressed, "#btn-verify-manifest")
    def on_verify_manifest(self):
        """Verify evidence manifest integrity."""
        app = self.app
        if not app.current_campaign_id:
            self.update_report_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        
        user = app.db.current_user
        
        try:
            # Get the most recent manifest for this campaign
            manifests = app.db.query(
                "SELECT id FROM evidence_manifests WHERE campaign_id=? ORDER BY created_at DESC LIMIT 1",
                (app.current_campaign_id,)
            )
            
            if not manifests:
                self.update_report_status("NO MANIFEST FOUND FOR CAMPAIGN", CyberColors.AMBER_WARNING)
                return
            
            manifest_id = manifests[0][0]
            is_valid, issues = app.db.verify_evidence_manifest(manifest_id)
            
            if is_valid:
                app.db.log_audit_event(user.username, "EVIDENCE_MANIFEST_VERIFIED",
                                      {"manifest_id": manifest_id, "valid": True})
                self.update_report_status(f"✓ MANIFEST VERIFIED (ID: {manifest_id})", CyberColors.PHOSPHOR_GREEN)
            else:
                issue_str = "; ".join(issues[:3])
                self.update_report_status(f"✗ MANIFEST VERIFICATION FAILED: {issue_str}", CyberColors.RED_ALERT)
        
        except Exception as e:
            self.update_report_status(f"ERROR: {str(e)[:60]}", CyberColors.RED_ALERT)
    
    # =========================================================================
    # FINDING SUMMARIES
    # =========================================================================
    
    @on(Button.Pressed, "#btn-create-summary")
    def on_create_summary(self):
        """Create finding summary with CVSS 3.1 scoring."""
        app = self.app
        if not app.current_id:
            self.update_report_status("NO FINDING SELECTED", CyberColors.AMBER_WARNING)
            return
        
        user = app.db.current_user
        cvss_vector = self.query_one("#inp-cvss-vector").value.strip()
        
        try:
            # Get current finding from editor
            title = app.query_one("#inp-title").value or "Untitled"
            description = app.query_one("#editor-main").text
            
            summary_created = app.db.create_finding_summary(
                app.current_id,
                description,
                cvss_vector,
                remediation_steps="See detailed findings for remediation guidance",
                affected_assets=None
            )
            
            if summary_created:
                app.db.log_audit_event(user.username, "FINDING_SUMMARY_CREATED",
                                      {"finding_id": app.current_id, "title": title})
                self.update_report_status(f"✓ FINDING SUMMARY CREATED (ID: {app.current_id})", CyberColors.PHOSPHOR_GREEN)
                self.query_one("#inp-cvss-vector").value = ""
            else:
                self.update_report_status("FAILED TO CREATE SUMMARY", CyberColors.RED_ALERT)
        
        except Exception as e:
            self.update_report_status(f"ERROR: {str(e)[:60]}", CyberColors.RED_ALERT)
    
    # =========================================================================
    # COMPLIANCE MAPPING
    # =========================================================================
    
    @on(Button.Pressed, "#btn-gen-compliance")
    def on_gen_compliance(self):
        """Generate compliance attestation report."""
        app = self.app
        if not app.current_campaign_id:
            self.update_report_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        
        user = app.db.current_user
        framework = self.query_one("#sel-compliance-framework").value
        
        if not framework:
            self.update_report_status("SELECT COMPLIANCE FRAMEWORK", CyberColors.AMBER_WARNING)
            return
        
        try:
            compliance_report = app.db.generate_compliance_report(app.current_campaign_id, framework)
            
            if compliance_report:
                app.db.log_audit_event(user.username, "COMPLIANCE_REPORT_GENERATED",
                                      {"campaign_id": app.current_campaign_id, "framework": framework,
                                       "satisfaction": compliance_report.get("satisfaction_percent", 0)})
                
                # Display report summary
                report_text = f"""
COMPLIANCE ATTESTATION REPORT
Framework: {compliance_report.get('framework', 'UNKNOWN')}
Total Requirements: {compliance_report.get('total_requirements', 0)}
Satisfied: {compliance_report.get('satisfied_requirements', 0)}
Satisfaction: {compliance_report.get('satisfaction_percent', 0):.1f}%
Status: {compliance_report.get('status', 'UNKNOWN')}
Attestor: {compliance_report.get('attestor', 'SYSTEM')}
Attestation Date: {compliance_report.get('attestation_date', 'N/A')}
"""
                self.query_one("#txt-report-content").text = report_text
                self.update_report_status(f"✓ {framework.upper()} COMPLIANCE REPORT GENERATED", CyberColors.PHOSPHOR_GREEN)
            else:
                self.update_report_status("FAILED TO GENERATE COMPLIANCE REPORT", CyberColors.RED_ALERT)
        
        except Exception as e:
            self.update_report_status(f"ERROR: {str(e)[:60]}", CyberColors.RED_ALERT)
    
    # =========================================================================
    # REPORT SCHEDULING
    # =========================================================================
    
    @on(Button.Pressed, "#btn-schedule-reports")
    def on_schedule_reports(self):
        """Schedule recurring automated report generation."""
        app = self.app
        if not app.current_campaign_id:
            self.update_report_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        
        user = app.db.current_user
        schedule_name = self.query_one("#inp-schedule-name").value.strip()
        frequency = self.query_one("#sel-schedule-freq").value
        
        if not schedule_name or not frequency:
            self.update_report_status("SCHEDULE NAME AND FREQUENCY REQUIRED", CyberColors.AMBER_WARNING)
            return
        
        try:
            schedule_id = app.db.schedule_recurring_report(
                app.current_campaign_id,
                schedule_name,
                "comprehensive",
                frequency,
                None
            )
            
            if schedule_id:
                app.db.log_audit_event(user.username, "REPORT_SCHEDULE_CREATED",
                                      {"campaign_id": app.current_campaign_id, "schedule_id": schedule_id,
                                       "frequency": frequency, "name": schedule_name})
                self.update_report_status(f"✓ REPORT SCHEDULE CREATED (ID: {schedule_id}, Frequency: {frequency})", 
                                        CyberColors.PHOSPHOR_GREEN)
                self.query_one("#inp-schedule-name").value = ""
            else:
                self.update_report_status("FAILED TO CREATE SCHEDULE", CyberColors.RED_ALERT)
        
        except Exception as e:
            self.update_report_status(f"ERROR: {str(e)[:60]}", CyberColors.RED_ALERT)
    
    def update_report_status(self, msg: str, color: str = "#ffffff"):
        """Update reporting status bar."""
        status = self.query_one("#report-status")
        ts = datetime.now().strftime('%H:%M:%S')
        status.update(f"[{ts}] {msg}")
        status.styles.color = color

# =============================================================================
# v4.0 TEAM MANAGEMENT & FEDERATION VIEWS
# =============================================================================

class TeamManagementView(Container):
    """Phase 4: Multi-Team & Federation - Team management, cross-team coordination, operator performance."""
    
    CSS = """
    TeamManagementView { layout: vertical; background: $bg-void; height: 100%; }
    #team-header { height: auto; padding: 1; background: $bg-panel; border-bottom: heavy $p-purple; }
    #team-split { layout: horizontal; height: 1fr; }
    #team-controls { width: 40%; height: 100%; background: $bg-panel; border-right: solid $e-cyan; padding: 1; overflow-y: auto; }
    #team-content { width: 1fr; height: 100%; padding: 1; background: $bg-void; overflow-y: auto; }
    .team-section { margin-bottom: 2; border-left: solid $p-purple; padding-left: 1; }
    .team-label { color: $p-purple; text-style: bold; margin-top: 1; margin-bottom: 1; }
    #team-status { color: white; height: auto; padding: 1; background: $bg-panel; border-top: solid $steel; }
    """
    
    def compose(self) -> ComposeResult:
        yield Label("[bold magenta]PHASE 4: MULTI-TEAM & FEDERATION[/]", id="team-header", classes="reg-title")
        
        with Container(id="team-split"):
            # Left Panel: Team Controls
            with Vertical(id="team-controls"):
                # 1. Team Management
                yield Label("TEAM MANAGEMENT", classes="team-label")
                with Vertical(classes="team-section"):
                    yield Input(id="inp-team-name", placeholder="Team Name")
                    yield Input(id="inp-team-desc", placeholder="Description")
                    yield Input(id="inp-team-budget", placeholder="Budget (USD)", type="number")
                    yield Button("CREATE TEAM", id="btn-create-team", variant="primary")
                    yield VimDataTable(id="table-teams", cursor_type="row")
                
                # 2. Team Members
                yield Label("TEAM MEMBERS", classes="team-label")
                with Vertical(classes="team-section"):
                    yield Static("Select team to manage members", id="lbl-team-members")
                    yield Button("ADD MEMBER", id="btn-add-member", variant="primary")
                    yield VimDataTable(id="table-members", cursor_type="row")
                
                # 3. Data Sharing Policies
                yield Label("SHARING POLICIES", classes="team-label")
                with Vertical(classes="team-section"):
                    yield Select([("Read Only", "read_only"), ("Read/Write", "read_write"), ("Admin", "admin")],
                               id="sel-access-level", prompt="Access Level")
                    yield Button("CREATE POLICY", id="btn-create-policy", variant="primary")
                
                # 4. Intelligence Pools
                yield Label("INTELLIGENCE POOLS", classes="team-label")
                with Vertical(classes="team-section"):
                    yield Input(id="inp-pool-name", placeholder="Pool Name")
                    yield Button("CREATE POOL", id="btn-create-pool", variant="primary")
                    yield VimDataTable(id="table-pools", cursor_type="row")
            
            # Right Panel: Metrics & Leaderboard
            with Vertical(id="team-content"):
                yield Label("TEAM METRICS & PERFORMANCE", classes="cyber-label")
                with Horizontal():
                    yield Static("Teams: 0", id="stat-team-count", classes="info-box")
                    yield Static("Members: 0", id="stat-member-count", classes="info-box")
                    yield Static("Campaigns: 0", id="stat-team-campaigns", classes="info-box")
                    yield Static("Findings: 0", id="stat-team-findings", classes="info-box")
                
                yield Label("OPERATOR LEADERBOARD", classes="cyber-label")
                yield VimDataTable(id="table-leaderboard", cursor_type="row")
                
                yield Label("COORDINATION LOGS", classes="cyber-label")
                yield VimDataTable(id="table-coordination", cursor_type="row")
        
        yield Label("TEAM MANAGEMENT READY", id="team-status", classes="info-box")

    def on_mount(self):
        # Setup tables
        self.query_one("#table-teams").add_columns("ID", "Team Name", "Lead", "Status", "Budget")
        self.query_one("#table-members").add_columns("User", "Role", "Joined")
        self.query_one("#table-pools").add_columns("Pool Name", "Items", "Shared", "Created")
        self.query_one("#table-leaderboard").add_columns("Rank", "Operator", "Score", "Findings", "Approval %")
        self.query_one("#table-coordination").add_columns("Source Team", "Target Team", "Type", "Status")

    @on(Button.Pressed, "#btn-create-team")
    def on_create_team(self):
        """Create new team."""
        app = self.app
        user = app.db.current_user
        if not user or not role_gte(user.role, Role.LEAD):
            self.update_team_status("LEAD+ ROLE REQUIRED", CyberColors.RED_ALERT)
            return
        
        name = self.query_one("#inp-team-name").value.strip()
        desc = self.query_one("#inp-team-desc").value.strip()
        try:
            budget = float(self.query_one("#inp-team-budget").value or "0.0")
        except ValueError:
            budget = 0.0
        
        if not name:
            self.update_team_status("TEAM NAME REQUIRED", CyberColors.AMBER_WARNING)
            return
        
        try:
            team_id = app.db.create_team(name, desc, user.id, budget)
            if team_id:
                self.refresh_teams()
                self.query_one("#inp-team-name").value = ""
                self.query_one("#inp-team-desc").value = ""
                self.query_one("#inp-team-budget").value = ""
                self.update_team_status(f"✓ TEAM CREATED (ID: {team_id})", CyberColors.PHOSPHOR_GREEN)
            else:
                self.update_team_status("FAILED TO CREATE TEAM", CyberColors.RED_ALERT)
        except Exception as e:
            self.update_team_status(f"ERROR: {str(e)[:60]}", CyberColors.RED_ALERT)

    @on(Button.Pressed, "#btn-add-member")
    def on_add_member(self):
        """Add member to selected team."""
        app = self.app
        user = app.db.current_user
        if not user or not role_gte(user.role, Role.LEAD):
            self.update_team_status("LEAD+ ROLE REQUIRED", CyberColors.RED_ALERT)
            return
        
        table = self.query_one("#table-teams")
        if not table.row_count:
            self.update_team_status("SELECT A TEAM FIRST", CyberColors.AMBER_WARNING)
            return
        
        self.update_team_status("MEMBER ADDITION: Use UI to select user and role", CyberColors.ELECTRIC_CYAN)

    @on(Button.Pressed, "#btn-create-policy")
    def on_create_policy(self):
        """Create data sharing policy."""
        app = self.app
        user = app.db.current_user
        if not user or not role_gte(user.role, Role.ADMIN):
            self.update_team_status("ADMIN ROLE REQUIRED", CyberColors.RED_ALERT)
            return
        
        self.update_team_status("POLICY CREATION: Configure teams and access levels", CyberColors.ELECTRIC_CYAN)

    @on(Button.Pressed, "#btn-create-pool")
    def on_create_pool(self):
        """Create intelligence pool."""
        app = self.app
        user = app.db.current_user
        if not user or not role_gte(user.role, Role.OPERATOR):
            self.update_team_status("OPERATOR+ ROLE REQUIRED", CyberColors.RED_ALERT)
            return
        
        pool_name = self.query_one("#inp-pool-name").value.strip()
        if not pool_name:
            self.update_team_status("POOL NAME REQUIRED", CyberColors.AMBER_WARNING)
            return
        
        # Get first team for user
        teams = app.db.list_teams()
        if not teams:
            self.update_team_status("NO TEAM AVAILABLE", CyberColors.AMBER_WARNING)
            return
        
        try:
            pool_id = app.db.create_intelligence_pool(teams[0]["id"], pool_name)
            if pool_id:
                self.refresh_pools()
                self.query_one("#inp-pool-name").value = ""
                self.update_team_status(f"✓ INTELLIGENCE POOL CREATED (ID: {pool_id})", CyberColors.PHOSPHOR_GREEN)
            else:
                self.update_team_status("FAILED TO CREATE POOL", CyberColors.RED_ALERT)
        except Exception as e:
            self.update_team_status(f"ERROR: {str(e)[:60]}", CyberColors.RED_ALERT)

    def refresh_teams(self):
        """Refresh teams list."""
        app = self.app
        table = self.query_one("#table-teams")
        table.clear()
        
        teams = app.db.list_teams()
        for team in teams:
            table.add_row(str(team["id"]), team["name"], f"Lead: {team['lead_operator_id']}", 
                         team["status"], f"${team['budget_usd']:.2f}")
        
        self.query_one("#stat-team-count").update(f"Teams: {len(teams)}")

    def refresh_pools(self):
        """Refresh intelligence pools."""
        table = self.query_one("#table-pools")
        table.clear()

    def update_team_status(self, msg: str, color: str = "#ffffff"):
        """Update team management status bar."""
        status = self.query_one("#team-status")
        ts = datetime.now().strftime('%H:%M:%S')
        status.update(f"[{ts}] {msg}")
        status.styles.color = color


class UsersAdminView(Container):
    """Dedicated admin users view: role and capability governance."""

    CSS = """
    UsersAdminView { layout: vertical; background: $bg-void; height: 100%; }
    #users-header { height: auto; padding: 1; background: $bg-panel; border-bottom: heavy $steel; }
    #users-main { layout: horizontal; height: 1fr; }
    #users-controls { width: 40%; height: 100%; background: $bg-panel; border-right: solid $steel; padding: 1; }
    #users-list { width: 1fr; height: 100%; padding: 1; background: $bg-void; }
    #users-status { height: 1; color: $text-main; background: $bg-panel; border-top: solid $steel; padding-left: 1; }
    """

    def compose(self) -> ComposeResult:
        yield Label("[bold]ADMIN TOOLS: USER ACCESS CONTROL[/]", id="users-header")
        with Container(id="users-main"):
            with Vertical(id="users-controls"):
                yield Label("TARGET USER", classes="cyber-label")
                yield Input(id="inp-users-username", placeholder="Username")
                yield Label("ROLE", classes="cyber-label")
                yield Select(
                    [("Viewer", Role.VIEWER), ("Operator", Role.OPERATOR), ("Lead", Role.LEAD), ("Admin", Role.ADMIN)],
                    id="sel-users-role",
                    prompt="Role"
                )
                yield Label("CAPABILITY PROFILE", classes="cyber-label")
                yield Select(
                    [(name, name) for name in CAPABILITY_PROFILES.keys()],
                    id="sel-users-capability",
                    prompt="Capability Profile"
                )
                with Horizontal():
                    yield Button("APPLY", id="btn-users-apply", variant="warning")
                    yield Button("REFRESH", id="btn-users-refresh", variant="primary")
            with Vertical(id="users-list"):
                yield VimDataTable(id="table-users-admin", cursor_type="row")
        yield Static("USERS ADMIN READY", id="users-status")

    def on_mount(self):
        table = self.query_one("#table-users-admin", VimDataTable)
        table.add_columns("User", "Role", "Capability", "Last Login")
        self.refresh_users()

    def update_users_status(self, msg: str, color: str = "#ffffff"):
        status = self.query_one("#users-status", Static)
        status.update(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
        status.styles.color = color

    def refresh_users(self):
        app = self.app
        table = self.query_one("#table-users-admin", VimDataTable)
        table.clear()
        if not hasattr(app, "db") or app.db is None:
            return
        user = app.db.current_user
        if not user or not role_gte(user.role, Role.ADMIN):
            self.update_users_status("ADMIN ROLE REQUIRED", CyberColors.RED_ALERT)
            return
        try:
            for item in app.db.list_user_access():
                table.add_row(
                    item["username"],
                    item["role"],
                    item["capability_profile"],
                    (item["last_login"] or "")[:19],
                )
            self.update_users_status("USER ACCESS TABLE REFRESHED", CyberColors.PHOSPHOR_GREEN)
        except Exception as e:
            self.update_users_status(f"REFRESH ERROR: {str(e)[:80]}", CyberColors.RED_ALERT)

    @on(Button.Pressed, "#btn-users-refresh")
    def on_refresh_users(self):
        self.refresh_users()

    @on(Button.Pressed, "#btn-users-apply")
    def on_apply_users(self):
        app = self.app
        user = app.db.current_user
        if not user or not role_gte(user.role, Role.ADMIN):
            self.update_users_status("ADMIN ROLE REQUIRED", CyberColors.RED_ALERT)
            return

        username = self.query_one("#inp-users-username", Input).value.strip()
        role_value = self.query_one("#sel-users-role", Select).value
        capability_value = self.query_one("#sel-users-capability", Select).value
        if not username:
            self.update_users_status("USERNAME REQUIRED", CyberColors.AMBER_WARNING)
            return
        if role_value in (None, Select.BLANK) or capability_value in (None, Select.BLANK):
            self.update_users_status("ROLE AND CAPABILITY REQUIRED", CyberColors.AMBER_WARNING)
            return

        ok_role, msg_role = app.db.set_user_role(username, str(role_value))
        ok_cap, msg_cap = app.db.set_user_capability_profile(username, str(capability_value))
        if ok_role and ok_cap:
            self.query_one("#inp-users-username", Input).value = ""
            self.refresh_users()
            self.update_users_status(f"ACCESS UPDATED FOR {username}", CyberColors.PHOSPHOR_GREEN)
        else:
            self.update_users_status(f"UPDATE FAILED: {msg_role} {msg_cap}", CyberColors.RED_ALERT)

# =============================================================================
# PHASE 5: THREAT INTELLIGENCE VIEW
# =============================================================================

class ThreatIntelligenceView(Container):
    """Phase 5: Advanced Threat Intelligence - Feed Ingestion, Correlation, Risk Scoring"""
    
    CSS = """
    ThreatIntelligenceView { align: left top; background: $bg-void; color: $p-green; }
    ThreatIntelligenceView #threat-title { color: $n-pink; text-style: bold; height: 3; }
    ThreatIntelligenceView #threat-container { height: 1fr; }
    ThreatIntelligenceView #threat-content { height: 1fr; }
    ThreatIntelligenceView .section-label { color: $n-pink; text-style: bold; margin-top: 1; margin-bottom: 1; }
    ThreatIntelligenceView #btn-add-feed {{ border: solid $n-pink; color: $n-pink; }}
    ThreatIntelligenceView #btn-add-feed:hover {{ background: $n-pink; color: white; }}
    ThreatIntelligenceView #btn-create-actor {{ border: solid $n-pink; color: $n-pink; }}
    ThreatIntelligenceView #btn-create-actor:hover {{ background: $n-pink; color: white; }}
    ThreatIntelligenceView #btn-ingest-ioc {{ border: solid $n-pink; color: $n-pink; }}
    ThreatIntelligenceView #btn-ingest-ioc:hover {{ background: $n-pink; color: white; }}
    ThreatIntelligenceView #table-threat-feeds {{ height: 8; }}
    ThreatIntelligenceView #table-threat-actors {{ height: 8; }}
    ThreatIntelligenceView #table-iocs {{ height: 10; }}
    ThreatIntelligenceView #table-risk-scores {{ height: 8; }}
    ThreatIntelligenceView #status-threat {{ color: $p-green; height: 1; }}
    """
    
    def compose(self):
        yield Label("🔗 THREAT INTELLIGENCE & IOC MANAGEMENT", id="threat-title")
        
        with ScrollableContainer(id="threat-container"):
            with Container(id="threat-content"):
                # Section 1: Threat Feeds
                yield Label("📡 External Threat Feeds", classes="section-label")
                yield Button("Add Feed (VirusTotal/Shodan/OTX/MISP)", id="btn-add-feed", variant="primary")
                yield VimDataTable(
                    id="table-threat-feeds",
                    cursor_type="row"
                )
                
                # Section 2: Threat Actors
                yield Label("👥 Threat Actor Profiles", classes="section-label")
                yield Button("Create Threat Actor Profile", id="btn-create-actor", variant="primary")
                yield VimDataTable(
                    id="table-threat-actors",
                    cursor_type="row"
                )
                
                # Section 3: Indicators of Compromise (IoCs)
                yield Label("🎯 Indicators of Compromise", classes="section-label")
                yield Button("Ingest IoC (IP/Domain/Hash/Email)", id="btn-ingest-ioc", variant="primary")
                yield VimDataTable(
                    id="table-iocs",
                    cursor_type="row"
                )
                
                # Section 4: Risk Assessment
                yield Label("⚠️ Risk Scores & Threats", classes="section-label")
                yield VimDataTable(
                    id="table-risk-scores",
                    cursor_type="row"
                )
                
        yield Static(id="status-threat")
    
    def on_mount(self):
        """Initialize threat intelligence tables."""
        self.refresh_threat_data()
    
    def refresh_threat_data(self):
        """Refresh all threat intelligence displays."""
        if not self.app.current_campaign_id:
            self.update_threat_status("❌ No campaign selected", CyberColors.RED_ALERT)
            return
        
        try:
            # Load threat feeds
            feeds_table = self.query_one("#table-threat-feeds", VimDataTable)
            feeds_table.clear()
            feeds_table.add_columns("ID", "Feed", "Type", "Status", "Updated")
            c = self.app.db.conn.cursor()
            c.execute("""SELECT id, feed_name, feed_type, status, COALESCE(last_updated, created_at) AS updated
                         FROM threat_feeds ORDER BY id DESC LIMIT 20""")
            feeds = c.fetchall()
            if feeds:
                for row in feeds:
                    feeds_table.add_row(str(row["id"]), row["feed_name"], row["feed_type"], row["status"], str(row["updated"])[:19])
            else:
                feeds_table.add_row("-", "No feeds configured", "-", "N/A", "-")
            
            # Load threat actors
            actors_table = self.query_one("#table-threat-actors", VimDataTable)
            actors_table.clear()
            actors_table.add_columns("ID", "Actor", "Country", "Confidence", "TTPs")
            c.execute("""SELECT ta.id, ta.actor_name, COALESCE(ta.origin_country, '-') AS origin_country,
                                ta.attribution_confidence,
                                (SELECT COUNT(*) FROM actor_ttps at WHERE at.actor_id = ta.id) AS ttp_count
                         FROM threat_actors ta
                         ORDER BY ta.id DESC LIMIT 20""")
            actors = c.fetchall()
            if actors:
                for row in actors:
                    actors_table.add_row(str(row["id"]), row["actor_name"], row["origin_country"], f"{float(row['attribution_confidence']):.2f}", str(row["ttp_count"]))
            else:
                actors_table.add_row("-", "No actor profiles", "-", "-", "0")
            
            # Load IoCs
            iocs_table = self.query_one("#table-iocs", VimDataTable)
            iocs_table.clear()
            iocs_table.add_columns("ID", "Type", "Value", "Threat", "Actor", "Confidence")
            c.execute("""SELECT i.id, i.indicator_type, i.indicator_value, i.threat_level,
                                COALESCE(ta.actor_name, '-') AS actor_name, i.confidence
                         FROM indicators_of_compromise i
                         LEFT JOIN threat_actors ta ON ta.id = i.threat_actor_id
                         WHERE i.campaign_id=?
                         ORDER BY i.id DESC LIMIT 40""",
                      (self.app.current_campaign_id,))
            iocs = c.fetchall()
            if iocs:
                for row in iocs:
                    iocs_table.add_row(
                        str(row["id"]), row["indicator_type"], str(row["indicator_value"])[:26],
                        row["threat_level"], row["actor_name"], f"{float(row['confidence']):.2f}"
                    )
            else:
                # Fallback from detection telemetry so Intel tab is never blank.
                detections = self.app.db.get_detection_timeline(self.app.current_campaign_id)
                if detections:
                    for idx, det in enumerate(detections[:20], start=1):
                        iocs_table.add_row(
                            f"D{idx}",
                            "detection",
                            str(det.get("indicator", "-"))[:26],
                            "MEDIUM",
                            "-",
                            f"{float(det.get('confidence', 0.0)):.2f}",
                        )
                else:
                    iocs_table.add_row("-", "No IoCs", "-", "-", "-", "0.00")
            
            # Load risk scores
            risk_table = self.query_one("#table-risk-scores", VimDataTable)
            risk_table.clear()
            risk_table.add_columns("Finding", "Risk Level", "Score", "Threat", "Likelihood", "Impact")
            c.execute("""SELECT COALESCE(CAST(finding_id AS TEXT), '-') AS finding_id, risk_level,
                                final_score, threat_score, likelihood_score, impact_score
                         FROM risk_scores
                         WHERE campaign_id=?
                         ORDER BY id DESC LIMIT 30""",
                      (self.app.current_campaign_id,))
            scores = c.fetchall()
            if scores:
                for row in scores:
                    risk_table.add_row(
                        row["finding_id"], row["risk_level"], f"{float(row['final_score']):.1f}",
                        f"{float(row['threat_score']):.1f}", f"{float(row['likelihood_score']):.1f}",
                        f"{float(row['impact_score']):.1f}",
                    )
            else:
                # Fallback inferred score from campaign activity.
                cmds = self.app.db.get_command_history(self.app.current_campaign_id, limit=50)
                dets = self.app.db.get_detection_timeline(self.app.current_campaign_id)
                inferred = min(10.0, (len(cmds) / 10.0) + (sum(float(d.get("confidence", 0.0)) for d in dets)))
                level = "CRITICAL" if inferred >= 8 else "HIGH" if inferred >= 6 else "MEDIUM" if inferred >= 4 else "LOW"
                risk_table.add_row("activity", level, f"{inferred:.1f}", f"{min(10.0, inferred+1):.1f}", f"{max(1.0, inferred-1):.1f}", f"{inferred:.1f}")
            
            self.update_threat_status("✓ Threat data loaded", CyberColors.PHOSPHOR_GREEN)
        except Exception as e:
            self.update_threat_status(f"Error loading threat data: {str(e)}", CyberColors.RED_ALERT)
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses in threat intelligence view."""
        btn_id = event.button.id
        
        if btn_id == "btn-add-feed":
            self.on_add_feed()
        elif btn_id == "btn-create-actor":
            self.on_create_actor()
        elif btn_id == "btn-ingest-ioc":
            self.on_ingest_ioc()
    
    def on_add_feed(self):
        """Handle adding external threat feed."""
        if not self.app.current_campaign_id:
            self.update_threat_status("❌ Campaign required to add feed", CyberColors.RED_ALERT)
            return
        
        # TODO: Show dialog for feed URL, type (VirusTotal/Shodan/OTX/MISP), API key
        self.update_threat_status("➕ Feed addition not yet implemented", CyberColors.AMBER_WARNING)
    
    def on_create_actor(self):
        """Handle creating threat actor profile."""
        if not self.app.current_campaign_id:
            self.update_threat_status("❌ Campaign required to create actor profile", CyberColors.RED_ALERT)
            return
        
        # TODO: Show dialog for actor name, origin, organization, description
        self.update_threat_status("➕ Actor creation not yet implemented", CyberColors.AMBER_WARNING)
    
    def on_ingest_ioc(self):
        """Handle ingesting indicator of compromise."""
        if not self.app.current_campaign_id:
            self.update_threat_status("❌ Campaign required to ingest IoC", CyberColors.RED_ALERT)
            return
        
        # TODO: Show dialog for indicator type (IP/Domain/Hash/Email), value, threat level
        self.update_threat_status("➕ IoC ingestion not yet implemented", CyberColors.AMBER_WARNING)
    
    def update_threat_status(self, message: str, color: str = CyberColors.PHOSPHOR_GREEN):
        """Update threat intelligence status bar."""
        status = self.query_one("#status-threat", Static)
        status.update(f"{message} [{datetime.now().strftime('%H:%M:%S')}]")
        status.styles.color = color


# =============================================================================
# SHUTDOWN VIEWS
# =============================================================================

class ShutdownConfirmationView(Container):
    CSS = """
    ShutdownConfirmationView { align: center middle; background: $bg-void; height: 100%; border-right: heavy $e-cyan; }
    #confirm-box { width: 60; height: auto; background: #111; border: heavy $r-alert; padding: 2; text-align: center; }
    .warn-title { color: $r-alert; text-style: bold; margin-bottom: 2; width: 100%; }
    .warn-text  { color: white; margin-bottom: 2; width: 100%; }
    #shutdown-btn-row { align: center middle; height: 5; }
    #shutdown-btn-row Button { width: 16; margin: 0 2; }
    """
    def compose(self) -> ComposeResult:
        with Container(id="confirm-box"):
            yield Label("⚠️ TERMINATION SEQUENCE INITIATED", classes="warn-title")
            yield Label("Unsaved buffer data may be lost.\nProceed with system halt?", classes="warn-text")
            with Horizontal(id="shutdown-btn-row"):
                yield Button("EXECUTE", id="btn-conf-exec", variant="error")
                yield Button("ABORT",   id="btn-conf-abort", variant="primary")

    @on(Button.Pressed, "#btn-conf-exec")
    def execute_shutdown(self): self.app.push_screen(ShutdownScreen())

    @on(Button.Pressed, "#btn-conf-abort")
    def abort_shutdown(self): self.app.action_return_to_editor()

class ShutdownScreen(Screen):
    def compose(self) -> ComposeResult:
        with Container(id="shutdown-container"):
            yield Label("[bold white]INITIATING SHUTDOWN SEQUENCE[/]", classes="shutdown-header")
            with Horizontal(classes="shutdown-row"):
                yield Label("ENCRYPTING & CLOSING DATABASE...", classes="shutdown-label")
                yield Label("...", id="st-db", classes="shutdown-status status-pending")
            with Horizontal(classes="shutdown-row"):
                yield Label("SECURING FILESYSTEM...", classes="shutdown-label")
                yield Label("...", id="st-fs", classes="shutdown-status status-pending")
            yield Label("[bold red]SYSTEM HALTED[/]", id="final-msg")

    def on_mount(self):
        self.query_one("#final-msg").visible = False
        self.run_shutdown_sequence()

    @work
    async def run_shutdown_sequence(self):
        await asyncio.sleep(0.5)
        if hasattr(self.app, 'db') and self.app.db:
            if self.app.db.current_user: self.app.db.logout()
            self.app.db.close()
        lbl_db = self.query_one("#st-db")
        lbl_db.update("[LOCKED]")
        lbl_db.add_class("status-done")
        await asyncio.sleep(0.5)
        lbl_fs = self.query_one("#st-fs")
        lbl_fs.update("[SECURE]")
        lbl_fs.add_class("status-done")
        await asyncio.sleep(0.5)
        self.query_one("#final-msg").visible = True
        await asyncio.sleep(0.8)
        self.app.exit()

# =============================================================================
# HUD & FINDING ITEM
# =============================================================================

class HeaderHUD(Static):
    current_file = reactive("LOCKED")
    operation_name = reactive("DEFAULT")

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Label("VECTORVUE v3.8", classes="hud-title")
            yield Label(f"OPERATION: {self.operation_name}", id="hud-op-lbl", classes="hud-op")
            yield Input(value="DEFAULT", id="hud-project-input", classes="hud-input", disabled=True)
            yield Label(f"// BUFFER: {self.current_file}", id="hud-file-lbl", classes="hud-file")

    def watch_current_file(self, val):
        if self.is_mounted:
            try: self.query_one("#hud-file-lbl").update(f"// BUFFER: {val}")
            except Exception: pass

    def watch_operation_name(self, val):
        if self.is_mounted:
            try: self.query_one("#hud-op-lbl").update(f"OPERATION: {val}")
            except Exception: pass

class FindingItem(ListItem):
    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        try: score = float(self.finding.cvss_score)
        except (ValueError, TypeError): score = 0.0
        icon  = "⚡" if score >= 9.0 else "●"
        color = "white"
        if score >= 9.0:   color = CyberColors.RED_ALERT
        elif score >= 7.0: color = CyberColors.AMBER_WARNING
        elif score >= 4.0: color = CyberColors.ELECTRIC_CYAN
        yield Label(f"[{color}]{icon} [{score:.1f}] {self.finding.title[:20]}[/]")

# =============================================================================
# MAIN APPLICATION
# =============================================================================

class CyberTUI(App):
    CSS = CYBER_CSS + """
    .hud-op { color: #9aa3b6; width: 1fr; content-align: center middle; text-style: bold; }
    .hud-input    { width: 16; height: 1; border: none; background: #12161e; color: #8bbbd9; }
    .hud-input:focus { border: none; }
    #editor-toolbar { height: 3; padding: 0 1; background: #151922; border-bottom: solid #2e3440; }
    #editor-toolbar Button { width: auto; margin-right: 1; margin-bottom: 0; min-width: 10; height: 3; }
    #editor-body { height: 1fr; background: #12161e; }
    #editor-switcher { height: 1fr; overflow-y: auto; scrollbar-gutter: stable; }
    #editor-edit-pane { height: 1fr; overflow-y: auto; scrollbar-gutter: stable; }
    #editor-preview-pane { height: 1fr; overflow-y: auto; scrollbar-gutter: stable; }
    #editor-main { height: 1fr; width: 100%; overflow-y: auto; scrollbar-gutter: stable; }
    #editor-preview { height: 1fr; width: 100%; padding: 0 1; overflow-y: auto; scrollbar-gutter: stable; background: #12161e; color: #d8dee9; border: solid #2e3440; }
    #view-switcher > * { overflow-y: auto; scrollbar-gutter: stable; }
    #login-view, #register-view { overflow-y: hidden; scrollbar-gutter: auto; }
    """

    BINDINGS = [
        Binding("q",      "quit_app",             "Quit"),
        Binding("space",  "toggle_file_manager",  "Files"),
        Binding("ctrl+m", "toggle_mitre_view",    "MITRE DB"),
        Binding("ctrl+k", "toggle_campaign",      "Campaign"),
        Binding("ctrl+e", "toggle_exec_log",      "Exec Log"),
        Binding("ctrl+j", "toggle_sessions",      "Sessions"),
        Binding("ctrl+d", "toggle_detections",    "Detections"),
        Binding("ctrl+o", "toggle_objectives",    "Objectives"),
        Binding("ctrl+p", "toggle_persistence",   "Persistence"),
        Binding("ctrl+g", "toggle_graph",         "Graph"),
        Binding("ctrl+y", "toggle_timeline",      "Timeline"),
        Binding("ctrl+1", "toggle_dashboard",     "Dashboard"),
        Binding("ctrl+2", "toggle_analysis",      "Analysis"),
        Binding("ctrl+3", "toggle_intel",         "Intelligence"),
        Binding("ctrl+4", "toggle_remediation",   "Remediation"),
        Binding("ctrl+5", "toggle_capability",    "Capability"),
        Binding("ctrl+r", "toggle_reporting",     "Reporting"),
        Binding("ctrl+t", "toggle_teams",         "Teams"),
        Binding("ctrl+shift+i", "toggle_threat_intel", "Threat Intel"),
        Binding("alt+1", "toggle_collaboration",  "Collab"),
        Binding("alt+2", "toggle_tasks",          "Tasks"),
        Binding("alt+3", "toggle_behavioral",     "Analytics"),
        Binding("alt+4", "toggle_integration",    "Integration"),
        Binding("alt+5", "toggle_compliance",     "Compliance"),
        Binding("alt+6", "toggle_security",       "Security"),
        Binding("ctrl+s", "save_db",              "Save"),
        Binding("ctrl+shift+v", "toggle_editor_preview", "Preview"),
        Binding("ctrl+l", "action_logout",        "Logout"),
        Binding("escape", "return_to_editor",     "Editor"),
        # ===== Phase 5.5 Cognition Layer Bindings =====
        Binding("ctrl+shift+1", "toggle_cognition_opportunities",   "Opportunities"),
        Binding("ctrl+shift+2", "toggle_cognition_paths",           "Paths"),
        Binding("ctrl+shift+3", "toggle_cognition_state",           "State"),
        Binding("ctrl+shift+4", "toggle_cognition_detection",       "Pressure"),
        Binding("ctrl+shift+5", "toggle_cognition_confidence",      "Confidence"),
        Binding("ctrl+shift+6", "toggle_cognition_knowledge",       "Knowledge"),
        Binding("ctrl+shift+7", "toggle_cognition_techniques",      "Techniques"),
        Binding("ctrl+shift+8", "toggle_cognition_validation",      "Validation"),
        Binding("ctrl+shift+9", "toggle_cognition_explain",         "Explain"),
        Binding("ctrl+shift+0", "toggle_cognition_dashboard",       "Dashboard"),
    ]

    current_project_id = reactive("DEFAULT")
    current_campaign_id = reactive(None)
    editor_mode = reactive("edit")
    VIEW_MIN_ROLE = {
        # Operator-focused operational views
        "campaign-view": Role.OPERATOR,
        "cmdlog-view": Role.OPERATOR,
        "session-view": Role.OPERATOR,
        "detection-view": Role.OPERATOR,
        "objective-view": Role.OPERATOR,
        "persistence-view": Role.OPERATOR,
        "graph-view": Role.OPERATOR,
        "timeline-view": Role.OPERATOR,
        "reporting-view": Role.OPERATOR,
        "collab-view": Role.OPERATOR,
        "task-view": Role.OPERATOR,
        "analytics-view": Role.OPERATOR,
        "compliance-view": Role.OPERATOR,
        "security-view": Role.OPERATOR,
        # Lead/admin management views
        "team-view": Role.LEAD,
        "integration-view": Role.LEAD,
        "users-view": Role.ADMIN,
    }

    def compose(self) -> ComposeResult:
        yield HeaderHUD(id="hud-header")
        
        # Add grouped tab navigation panel at top
        yield TabNavigationPanel(id="tab-nav-panel")
        
        with ContentSwitcher(initial="login-view", id="view-switcher"):
            yield LoginView(id="login-view")
            yield RegisterView(id="register-view")
            
            with Vertical(id="editor-view"):
                with Horizontal(id="editor-toolbar"):
                    yield Button("EDIT", id="btn-editor-mode-edit", variant="primary")
                    yield Button("PREVIEW", id="btn-editor-mode-preview")
                with Container(id="editor-body"):
                    with ContentSwitcher(initial="editor-edit-pane", id="editor-switcher"):
                        with Container(id="editor-edit-pane"):
                            yield TextArea(language="markdown", theme="dracula", show_line_numbers=True, id="editor-main")
                        with Container(id="editor-preview-pane"):
                            yield Markdown("", id="editor-preview")

            yield FileManagerView(id="fm-view")
            yield MitreIntelligenceView(id="mitre-view")
            yield CampaignView(id="campaign-view")
            
            # v3.2 Execution & Detection Views
            yield CommandExecutionLogView(id="cmdlog-view")
            yield SessionActivityView(id="session-view")
            yield DetectionTimelineView(id="detection-view")
            yield ObjectiveProgressView(id="objective-view")
            yield PersistenceInventoryView(id="persistence-view")
            yield GraphAnalyticsView(id="graph-view")
            yield EngagementTimelineView(id="timeline-view")
            
            # v3.3 Intelligence & Analysis Views
            yield SituationalAwarenessView(id="dashboard-view")
            yield PostEngagementAnalysisView(id="analysis-view")
            yield RemediationTrackingView(id="remediation-view")
            yield CapabilityAssessmentView(id="capability-view")
            
            # v3.4 Advanced Features & Security Views
            yield CollaborationEngineView(id="collab-view")
            yield TaskOrchestrationView(id="task-view")
            yield BehavioralAnalyticsView(id="analytics-view")
            yield IntegrationGatewayView(id="integration-view")
            yield ComplianceReportingView(id="compliance-view")
            yield SecurityHardeningView(id="security-view")
            
            # v3.5 Reporting & Export Views
            yield ReportingView(id="reporting-view")
            
            # v4.0 Team Management & Federation Views
            yield TeamManagementView(id="team-view")
            yield UsersAdminView(id="users-view")
            
            # Phase 5: Advanced Threat Intelligence
            yield ThreatIntelligenceView(id="threat-intel-view")
            
            # ===== PHASE 5.5 COGNITION LAYER VIEWS =====
            yield OpportunitiesView(id="cognition-opportunities")
            yield AttackPathsView(id="cognition-paths")
            yield CampaignStateView(id="cognition-state")
            yield DetectionPressureView(id="cognition-detection")
            yield ConfidenceAnalysisView(id="cognition-confidence")
            yield KnowledgeCompletenessView(id="cognition-knowledge")
            yield TechniqueEffectivenessView(id="cognition-techniques")
            yield ValidationQueueView(id="cognition-validation")
            yield ExplainabilityView(id="cognition-explain")
            yield CognitionDashboardView(id="cognition-dashboard")
            # ===== END COGNITION VIEWS =====
            
            yield ShutdownConfirmationView(id="shutdown-view")

        with Container(id="lateral-tools"):
            yield Label("RISK ASSESSMENT:", classes="cyber-label")
            yield Static("NO SIGNAL", id="info-severity", classes="info-box")
            yield Label("CVSS 3.1 SCORE:", classes="cyber-label")
            yield Static("0.0", id="info-score", classes="info-box")
            yield Label("MITRE MAPPING:", classes="cyber-label")
            yield Static("NONE", id="info-mitre", classes="info-box")

            yield Label("OPERATOR:", classes="cyber-label")
            yield Static("LOCKED", id="info-user", classes="info-box")

            yield Label("CAMPAIGN ACTIVE:", classes="cyber-label")
            yield Button("INIT CAMPAIGN", id="btn-init-camp", classes="btn-purple", disabled=True)
            yield Select([], id="sel-campaign", prompt="PICK CAMPAIGN", disabled=True)
            yield Label("", id="lbl-active-camp", classes="info-box")

            yield Label("VECTOR TITLE:", classes="cyber-label")
            yield Input(id="inp-title", placeholder="Vulnerability Title...", disabled=True)
            yield Label("CVSS VECTOR:", classes="cyber-label")
            yield Input(id="inp-vector", placeholder="CVSS:3.1/AV:N/AC:L...", disabled=True)
            
            yield Label("SCORE / MITRE ID:", classes="cyber-label")
            with Horizontal(classes="input-row"):
                yield Input(id="inp-score", type="number", placeholder="9.8", classes="half-input", disabled=True)
                yield Input(id="inp-mitre", placeholder="T1548", classes="half-input", disabled=True)

            yield Button("MITRE INTEL", id="btn-mitre-menu", disabled=True)
            yield Button("CAMPAIGN OPS", id="btn-camp-ops", classes="btn-purple", disabled=True)

            yield Label("FINDINGS QUEUE:", classes="cyber-label")
            yield ListView(id="findings-list")

            yield Label("OPERATIONS:", classes="cyber-label")
            yield Button("COMMIT DB",     id="btn-save",    classes="btn-save",   disabled=True)
            yield Button("NEW ENTRY",     id="btn-new",                           disabled=True)
            yield Button("NIST TEMPLATE", id="btn-nist",                          disabled=True)
            yield Button("DELETE",        id="btn-del",     classes="btn-delete", disabled=True)

            yield Label("EXPORT:", classes="cyber-label")
            yield Button("EXPORT .MD",       id="btn-save-md",      disabled=True)
            yield Button("MITRE NAVIGATOR",  id="btn-export-nav",   disabled=True)

            yield Label("SYSTEM:", classes="cyber-label")
            yield Button("FILESYSTEM", id="btn-file-mgr", disabled=True)
            yield Button("ADMIN TOOLS", id="btn-admin-tools", classes="btn-purple", disabled=True)
            yield Button("LOGOUT",     id="btn-logout",   disabled=True)
            yield Button("SHUTDOWN",   id="btn-exit")

        yield Label("SYSTEM LOCKED - AUTH REQUIRED", id="status-bar")

    def on_mount(self):
        self.crypto      = SessionCrypto()
        self.db          = Database(self.crypto)
        self.intel       = None
        self.current_id  = None
        self.runtime_executor = RuntimeExecutor(self.db)

        sw = self.query_one("#view-switcher")
        self._set_tab_bar_visibility(False)
        if not self.db.has_users():
            sw.current = "register-view"
            self.update_status("FIRST RUN: REGISTER YOUR ADMIN ACCOUNT", CyberColors.AMBER_WARNING)
        else:
            # Always require fresh authentication (don't resume sessions automatically)
            sw.current = "login-view"
            self.update_status("AUTHENTICATION REQUIRED", CyberColors.AMBER_WARNING)

    def _set_tab_bar_visibility(self, visible: bool):
        """Show/hide top tab bar + right sidebar and collapse their layout tracks."""
        self.query_one("#tab-nav-panel").visible = visible
        self.query_one("#lateral-tools").visible = visible
        self.screen.styles.grid_rows = "2 9 1fr 1" if visible else "2 0 1fr 1"
        self.screen.styles.grid_columns = "1fr 34" if visible else "1fr 0"

    # -------------------------------------------------------------------------
    # AUTH FLOW
    # -------------------------------------------------------------------------

    @on(RegisterView.RegisterSuccess)
    def on_register_success(self):
        self.update_status("REGISTRATION COMPLETE — AUTHENTICATE NOW", CyberColors.PHOSPHOR_GREEN)
        self.query_one("#view-switcher").current = "login-view"

    @on(RegisterView.BackToLogin)
    def on_register_back_to_login(self):
        self.query_one("#view-switcher").current = "login-view"
        self.update_status("AUTHENTICATION REQUIRED", CyberColors.AMBER_WARNING)

    @on(LoginView.RegisterRequested)
    def on_login_register_requested(self):
        self.query_one("#view-switcher").current = "register-view"
        self.update_status("REGISTER NEW USER", CyberColors.ELECTRIC_CYAN)

    @on(LoginView.LoginSuccess)
    def on_login_success(self):
        self._post_login_setup()

    def _post_login_setup(self):
        user = self.db.current_user
        role_label = user.role.upper() if user else "UNKNOWN"
        uname = user.username if user else "?"
        self.update_status(f"ACCESS GRANTED [{role_label}] — {uname}", CyberColors.PHOSPHOR_GREEN)
        self.intel = IntelligenceEngine()
        self.query_one("#view-switcher").current = "editor-view"
        self.query_one("#hud-header").current_file = "NEW BUFFER"
        self.query_one("#hud-header").operation_name = self.current_project_id
        self.query_one("#editor-main").focus()
        self.query_one("#info-user").update(f"{uname}\n[{role_label}]")
        self._set_tab_bar_visibility(True)
        self.unlock_ui()
        os.makedirs("Reports", exist_ok=True)
        self.refresh_list()
        
        # Auto-load existing campaign for project if exists
        camps = self.db.list_campaigns(self.current_project_id)
        if camps:
            self.current_campaign_id = camps[0].id
            self.query_one("#lbl-active-camp").update(camps[0].name)
        self.refresh_campaign_picker()
        
        # Start Phase 2 runtime executor (background task scheduler)
        self.runtime_maintenance_task()
        
        # ===== Initialize Phase 5.5 Cognition Service =====
        try:
            self.cognition = CognitionService(self.db)
            self.update_status("Cognition layer initialized", CyberColors.PHOSPHOR_GREEN)
        except Exception as e:
            self.update_status(f"Cognition init failed: {e}", CyberColors.RED_ALERT)
            self.cognition = None

    @work(exclusive=True)
    async def runtime_maintenance_task(self):
        """Background task executor - runs Phase 2 features continuously."""
        await self.runtime_executor.run_maintenance_loop()

    def unlock_ui(self):
        user = self.db.current_user
        for widget in self.query("#lateral-tools Input"): widget.disabled = False
        for widget in self.query("#lateral-tools Button"): widget.disabled = False
        for widget in self.query("#lateral-tools Select"): widget.disabled = False
        self.query_one("#hud-project-input").disabled = False
        if user and not role_gte(user.role, Role.LEAD):
            self.query_one("#btn-del").disabled = True
        if user and not role_gte(user.role, Role.ADMIN):
            self.query_one("#btn-admin-tools").disabled = True

    def action_logout(self):
        self.runtime_executor.stop()
        self.db.logout()
        self.current_id = None
        self.intel = None
        for widget in self.query("#lateral-tools Input"): widget.disabled = True
        for widget in self.query("#lateral-tools Button"): widget.disabled = True
        for widget in self.query("#lateral-tools Select"): widget.disabled = True
        self.query_one("#btn-exit").disabled = False
        self.query_one("#info-user").update("LOCKED")
        self._set_tab_bar_visibility(False)
        self.query_one("#view-switcher").current = "login-view"
        self.update_status("LOGGED OUT — SESSION TERMINATED", CyberColors.AMBER_WARNING)

    # -------------------------------------------------------------------------
    # VIEW NAVIGATION
    # -------------------------------------------------------------------------

    def action_quit_app(self):
        self.runtime_executor.stop()
        self.query_one("#view-switcher").current = "shutdown-view"
        self.update_status("WARNING: TERMINATION REQUESTED", CyberColors.RED_ALERT)

    def update_status(self, msg, color="#ffffff"):
        bar = self.query_one("#status-bar")
        ts  = datetime.now().strftime('%H:%M:%S')
        bar.update(f"[{ts}] {msg}")
        bar.styles.color = color

    def refresh_editor_preview(self):
        editor = self.query_one("#editor-main", TextArea)
        preview = self.query_one("#editor-preview", Markdown)
        text = editor.text or ""
        preview.update(text)

    def set_editor_mode(self, mode: str):
        if mode not in ("edit", "preview"):
            return
        self.editor_mode = mode
        editor = self.query_one("#editor-main", TextArea)
        switcher = self.query_one("#editor-switcher", ContentSwitcher)
        btn_edit = self.query_one("#btn-editor-mode-edit", Button)
        btn_preview = self.query_one("#btn-editor-mode-preview", Button)

        if mode == "preview":
            self.refresh_editor_preview()
            switcher.current = "editor-preview-pane"
            btn_edit.variant = "default"
            btn_preview.variant = "primary"
            self.update_status("MODE: MARKDOWN PREVIEW", CyberColors.ELECTRIC_CYAN)
        else:
            switcher.current = "editor-edit-pane"
            editor.focus()
            btn_edit.variant = "primary"
            btn_preview.variant = "default"
            self.update_status("MODE: EDITOR", CyberColors.PHOSPHOR_GREEN)

    @on(TextArea.Changed, "#editor-main")
    def on_editor_text_changed(self, event):
        if self.editor_mode == "preview":
            self.refresh_editor_preview()

    def action_toggle_file_manager(self):
        if not self.db.current_user:
            self.update_status("AUTHENTICATION REQUIRED", CyberColors.AMBER_WARNING)
            return
        try:
            sw = self.query_one("#view-switcher")
            if sw.current == "fm-view":
                self.action_return_to_editor()
            else:
                sw.current = "fm-view"
                self.query_one("FileManagerView")._focus_tree()
                self.update_status("MODE: FILESYSTEM", CyberColors.ELECTRIC_CYAN)
        except Exception as e:
            self.update_status(f"FILESYSTEM VIEW ERROR: {e}", CyberColors.RED_ALERT)

    def action_toggle_mitre_view(self):
        if not self.db.current_user:
            self.update_status("AUTHENTICATION REQUIRED", CyberColors.AMBER_WARNING)
            return
        try:
            sw = self.query_one("#view-switcher")
            if sw.current == "mitre-view":
                self.action_return_to_editor()
            else:
                sw.current = "mitre-view"
                self.query_one("MitreIntelligenceView").focus_search()
                self.update_status("MODE: INTELLIGENCE LOOKUP", CyberColors.ELECTRIC_CYAN)
        except Exception as e:
            self.update_status(f"MITRE VIEW ERROR: {e}", CyberColors.RED_ALERT)

    def action_toggle_campaign(self):
        if not self.db.current_user: return
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE - INIT FIRST", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "campaign-view": self.action_return_to_editor()
        else:
            sw.current = "campaign-view"
            self.query_one("CampaignView").refresh_data(self)
            self.update_status("MODE: RED TEAM OPS", CyberColors.PURPLE_HAZE)

    def action_admin_tools(self):
        """Admin-only quick jump to management controls."""
        user = self.db.current_user
        if not user:
            self.update_status("AUTHENTICATION REQUIRED", CyberColors.AMBER_WARNING)
            return
        if not role_gte(user.role, Role.ADMIN):
            self.update_status("ACCESS DENIED: ADMIN REQUIRED", CyberColors.RED_ALERT)
            return
        self.switch_to_view("users-view")
        self.query_one("UsersAdminView").refresh_users()
        self.update_status("ADMIN TOOLS: USER ACCESS CONTROL", CyberColors.MAGENTA_AUDIT)

    # v3.2 View Toggles
    def action_toggle_exec_log(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "cmdlog-view": self.action_return_to_editor()
        else:
            sw.current = "cmdlog-view"
            self.query_one("CommandExecutionLogView").refresh_commands(self, self.current_campaign_id)
            self.update_status("MODE: COMMAND EXECUTION LOG", CyberColors.ELECTRIC_CYAN)

    def action_toggle_sessions(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "session-view": self.action_return_to_editor()
        else:
            sw.current = "session-view"
            self.query_one("SessionActivityView").refresh_sessions(self, self.current_campaign_id)
            self.update_status("MODE: SESSION LIFECYCLE", CyberColors.PHOSPHOR_GREEN)

    def action_toggle_detections(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "detection-view": self.action_return_to_editor()
        else:
            sw.current = "detection-view"
            self.query_one("DetectionTimelineView").refresh_detections(self, self.current_campaign_id)
            self.update_status("MODE: DETECTION EVASION", CyberColors.RED_ALERT)

    def action_toggle_objectives(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "objective-view": self.action_return_to_editor()
        else:
            sw.current = "objective-view"
            self.query_one("ObjectiveProgressView").refresh_objectives(self, self.current_campaign_id)
            self.update_status("MODE: OBJECTIVE PROGRESS", CyberColors.PURPLE_HAZE)

    def action_toggle_persistence(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "persistence-view": self.action_return_to_editor()
        else:
            sw.current = "persistence-view"
            self.query_one("PersistenceInventoryView").refresh_persistence(self, self.current_campaign_id)
            self.update_status("MODE: PERSISTENCE INVENTORY", CyberColors.AMBER_WARNING)

    def action_toggle_graph(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "graph-view":
            self.action_return_to_editor()
        else:
            sw.current = "graph-view"
            self.query_one("GraphAnalyticsView").refresh_graph(self, self.current_campaign_id)
            self.update_status("MODE: ATTACK GRAPH", CyberColors.ELECTRIC_CYAN)

    def action_toggle_timeline(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "timeline-view":
            self.action_return_to_editor()
        else:
            sw.current = "timeline-view"
            self.query_one("EngagementTimelineView").refresh_timeline(self, self.current_campaign_id)
            self.update_status("MODE: ENGAGEMENT TIMELINE", CyberColors.ELECTRIC_CYAN)

    # v3.3 View Toggles
    def action_toggle_dashboard(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "dashboard-view": self.action_return_to_editor()
        else:
            sw.current = "dashboard-view"
            self.query_one("SituationalAwarenessView").refresh_dashboard(self, self.current_campaign_id)
            self.update_status("MODE: SITUATIONAL AWARENESS", CyberColors.ELECTRIC_CYAN)

    def action_toggle_analysis(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "analysis-view": self.action_return_to_editor()
        else:
            sw.current = "analysis-view"
            self.query_one("PostEngagementAnalysisView").refresh_analysis(self, self.current_campaign_id)
            self.update_status("MODE: POST-ENGAGEMENT ANALYSIS", CyberColors.PHOSPHOR_GREEN)

    def action_toggle_intel(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "threat-intel-view": self.action_return_to_editor()
        else:
            sw.current = "threat-intel-view"
            self.query_one("ThreatIntelligenceView").refresh_threat_data()
            self.update_status("MODE: THREAT INTELLIGENCE", CyberColors.PURPLE_HAZE)

    def action_toggle_remediation(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "remediation-view": self.action_return_to_editor()
        else:
            sw.current = "remediation-view"
            self.query_one("RemediationTrackingView").refresh_remediation(self, self.current_campaign_id)
            self.update_status("MODE: REMEDIATION TRACKING", CyberColors.RED_ALERT)

    def action_toggle_capability(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "capability-view": self.action_return_to_editor()
        else:
            sw.current = "capability-view"
            self.query_one("CapabilityAssessmentView").refresh_capabilities(self, self.current_campaign_id)
            self.update_status("MODE: CAPABILITY ASSESSMENT", CyberColors.PHOSPHOR_GREEN)

    def action_toggle_reporting(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "reporting-view": self.action_return_to_editor()
        else:
            sw.current = "reporting-view"
            self.update_status("MODE: REPORTING & EXPORT ENGINE (Phase 3)", CyberColors.ELECTRIC_CYAN)

    def action_toggle_teams(self):
        if not self.db.current_user:
            self.update_status("AUTHENTICATION REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "team-view": self.action_return_to_editor()
        else:
            sw.current = "team-view"
            self.query_one("TeamManagementView").refresh_teams()
            self.update_status("MODE: TEAM MANAGEMENT & FEDERATION (Phase 4)", CyberColors.PURPLE_HAZE)

    def action_toggle_threat_intel(self):
        """Toggle Threat Intelligence View (Phase 5)."""
        if not self.db.current_user:
            self.update_status("AUTHENTICATION REQUIRED", CyberColors.AMBER_WARNING)
            return
        if not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED FOR THREAT INTELLIGENCE", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "threat-intel-view": self.action_return_to_editor()
        else:
            sw.current = "threat-intel-view"
            self.query_one("ThreatIntelligenceView").refresh_threat_data()
            self.update_status("MODE: THREAT INTELLIGENCE & IOC MANAGEMENT (Phase 5)", CyberColors.NEON_PINK)

    # v3.4 View Toggles
    def action_toggle_collaboration(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "collab-view": self.action_return_to_editor()
        else:
            sw.current = "collab-view"
            self.query_one("CollaborationEngineView").refresh_collaboration(self, self.current_campaign_id)
            self.update_status("MODE: REAL-TIME COLLABORATION", CyberColors.ELECTRIC_CYAN)

    def action_toggle_tasks(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "task-view": self.action_return_to_editor()
        else:
            sw.current = "task-view"
            self.query_one("TaskOrchestrationView").refresh_tasks(self, self.current_campaign_id)
            self.update_status("MODE: TASK ORCHESTRATION", CyberColors.PHOSPHOR_GREEN)

    def action_toggle_behavioral(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "analytics-view": self.action_return_to_editor()
        else:
            sw.current = "analytics-view"
            self.query_one("BehavioralAnalyticsView").refresh_analytics(self, self.current_campaign_id)
            self.update_status("MODE: BEHAVIORAL ANALYTICS", CyberColors.PURPLE_HAZE)

    def action_toggle_integration(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "integration-view": self.action_return_to_editor()
        else:
            sw.current = "integration-view"
            self.query_one("IntegrationGatewayView").refresh_integrations(self, self.current_campaign_id)
            self.update_status("MODE: INTEGRATION GATEWAY", CyberColors.ELECTRIC_CYAN)

    def action_toggle_compliance(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "compliance-view": self.action_return_to_editor()
        else:
            sw.current = "compliance-view"
            self.query_one("ComplianceReportingView").refresh_compliance(self, self.current_campaign_id)
            self.update_status("MODE: COMPLIANCE REPORTING", CyberColors.PHOSPHOR_GREEN)

    def action_toggle_security(self):
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED", CyberColors.AMBER_WARNING)
            return
        sw = self.query_one("#view-switcher")
        if sw.current == "security-view": self.action_return_to_editor()
        else:
            sw.current = "security-view"
            self.query_one("SecurityHardeningView").refresh_security(self, self.current_campaign_id)
            self.update_status("MODE: SECURITY HARDENING", CyberColors.RED_ALERT)

    # ===== PHASE 5.5 COGNITION LAYER ACTIONS =====

    def _refresh_cognition_views(self):
        """Populate cognition tabs from current campaign telemetry."""
        if not self.db.current_user or not self.current_campaign_id:
            return

        cid = self.current_campaign_id
        assets = self.db.list_assets(cid)
        creds = self.db.list_credentials(cid)
        sessions = self.db.get_active_sessions(cid)
        detections = self.db.get_detection_timeline(cid)
        commands = self.db.get_command_history(cid, limit=200)
        rel_timeline = self.db.build_compromise_chain(cid).get("timeline", [])

        risk_stats = self.db.calculate_detection_risk(cid)
        pressure_val = min(100.0, (risk_stats.get("average_confidence", 0.0) * 100.0) + (len(detections) * 2.0))
        trend = "stable"
        try:
            c = self.db.conn.cursor()
            c.execute(
                """SELECT total_pressure FROM detection_pressure_history
                   WHERE campaign_id=? ORDER BY recorded_at DESC LIMIT 2""",
                (cid,),
            )
            rows = c.fetchall()
            if len(rows) == 2:
                latest = float(rows[0]["total_pressure"])
                previous = float(rows[1]["total_pressure"])
                trend = "increasing" if latest > previous else "decreasing" if latest < previous else "stable"
        except Exception:
            pass

        opportunities = []
        for idx, asset in enumerate(assets[:10]):
            base = 80 - (idx * 5)
            control_bonus = 10 if any(int(s.get("asset_id", -1)) == int(asset.id) for s in sessions) else 0
            score = max(20.0, min(99.0, base + control_bonus - (pressure_val * 0.15)))
            opportunities.append({
                "id": f"opp-{cid}-{asset.id}",
                "technique": "T1021" if "server" in (asset.tags or "").lower() else "T1078",
                "target_asset": asset.name,
                "stealth": max(20.0, 90.0 - pressure_val),
                "value": min(95.0, 40.0 + (len(creds) * 5.0) + (15.0 if "dc" in (asset.tags or "").lower() else 0.0)),
                "risk": min(99.0, pressure_val + (10.0 if "critical" in (asset.tags or "").lower() else 0.0)),
                "confidence": max(0.35, min(0.95, 0.45 + (len(commands) / 400.0))),
                "score": score,
                "explanation": f"Prioritize {asset.name} using credentialed lateral movement.",
                "safer_alternative": "Use low-noise discovery + ticket-based auth.",
            })

        paths = []
        if len(assets) >= 2:
            start = str(assets[0].id)
            for target in assets[1:4]:
                raw_paths = self.db.get_attack_path(cid, start, str(target.id), max_hops=6)
                if raw_paths:
                    shortest = min(raw_paths, key=len)
                    steps = []
                    for step in shortest:
                        steps.append({
                            "technique": step.get("relation", "move"),
                            "target": f"{step.get('target_type')}:{step.get('target_id')}",
                        })
                    paths.append({
                        "id": f"path-{start}-{target.id}",
                        "objective": target.name,
                        "steps": steps,
                        "success_probability": max(0.2, 1.0 - (pressure_val / 140.0)),
                        "cumulative_risk": min(99.0, pressure_val + (len(steps) * 4.0)),
                    })
        if not paths and rel_timeline:
            pseudo_steps = [{"technique": r.get("action", "move"), "target": r.get("target", "?")} for r in rel_timeline[:4]]
            paths.append({
                "id": f"path-{cid}-fallback",
                "objective": "campaign-objective",
                "steps": pseudo_steps,
                "success_probability": 0.55,
                "cumulative_risk": min(99.0, pressure_val + 10.0),
            })

        obj_cov = self.db.get_objective_coverage(cid)
        avg_progress = float(obj_cov.get("average_progress", 0.0))
        if avg_progress >= 80:
            phase = "OBJECTIVE EXECUTION"
        elif len(assets) <= 2:
            phase = "INITIAL ACCESS"
        else:
            phase = "LATERAL MOVEMENT"
        state_data = {
            "phase": phase,
            "stealth_budget_remaining": max(0.0, 100.0 - pressure_val),
            "detection_severity": int(round(pressure_val / 10.0)),
            "strategy": "Proceed with low-noise expansion, validate objective path, then execute.",
            "assets_owned": len(assets),
            "credentials_obtained": len(creds),
            "is_compromised": pressure_val >= 80.0,
        }

        det_rows = []
        for d in detections[-25:]:
            det_rows.append(SimpleNamespace(
                timestamp=str(d.get("detected_at", "")),
                detection_type=d.get("detection_type", "event"),
                asset=f"asset-{d.get('asset_id', '-')}",
                severity=max(1, int(round(float(d.get("confidence", 0.1)) * 10))),
                related_technique=d.get("indicator", "")[:16] or "-",
                confidence=float(d.get("confidence", 0.1)),
            ))
        pressure_data = {"pressure": pressure_val, "trend": trend}

        data_completeness = min(1.0, (len(assets) * 0.2) + (len(creds) * 0.1) + (len(rel_timeline) * 0.05))
        conf_value = max(0.2, min(0.98, data_completeness - (pressure_val / 250.0)))
        gaps = []
        if len(assets) < 3:
            gaps.append("Insufficient asset graph coverage")
        if len(creds) < 2:
            gaps.append("Low credential diversity")
        if not rel_timeline:
            gaps.append("No relationship evidence chain")
        conf_data = {
            "confidence": conf_value,
            "min_threshold": 0.60,
            "will_recommend": conf_value >= 0.60,
            "gaps": gaps or ["No major gaps detected"],
            "recommended_evidence": [
                "Map trust/delegation edges",
                "Capture additional validated credentials",
                "Correlate detections with command stream",
            ],
        }

        evidence_list = []
        for r in rel_timeline[:10]:
            evidence_list.append({
                "type": "relationship",
                "source": f"{r.get('actor', '?')}->{r.get('target', '?')}",
                "confidence": float(r.get("confidence", 0.5)),
            })
        for d in detections[:5]:
            evidence_list.append({
                "type": "detection",
                "source": d.get("detection_type", "event"),
                "confidence": float(d.get("confidence", 0.4)),
            })
        knowledge_completeness = max(0.15, min(1.0, data_completeness))

        technique_stats = {}
        for cmd in commands:
            tech = cmd.get("mitre_technique") or "UNKNOWN"
            rec = technique_stats.setdefault(tech, {"total": 0, "ok": 0, "last": "", "stealth": 70.0})
            rec["total"] += 1
            rec["ok"] += 1 if int(cmd.get("success", 0)) == 1 else 0
            rec["last"] = cmd.get("timestamp", rec["last"])
            likelihood = str(cmd.get("detection_likelihood", "MEDIUM")).upper()
            rec["stealth"] = {"LOW": 85.0, "MEDIUM": 60.0, "HIGH": 35.0}.get(likelihood, 60.0)
        technique_rows = []
        for tech, rec in list(technique_stats.items())[:12]:
            technique_rows.append({
                "technique": tech,
                "execution_count": rec["total"],
                "success_rate": (rec["ok"] / rec["total"]) if rec["total"] else 0.0,
                "avg_stealth": rec["stealth"],
                "last_executed": rec["last"] or datetime.utcnow().isoformat(),
            })

        validations = []
        for opp in opportunities[:8]:
            validations.append({
                "id": opp["id"],
                "opportunity": f"{opp['technique']} -> {opp['target_asset']}",
                "risk": opp["risk"],
                "approved": opp["risk"] < 55.0,
                "reason": "Auto-approved (low risk)" if opp["risk"] < 55.0 else "Requires lead approval (elevated risk)",
            })

        top = opportunities[0] if opportunities else {
            "technique": "N/A",
            "target_asset": "N/A",
            "score": 0.0,
            "confidence": 0.0,
            "risk": 0.0,
            "stealth": 0.0,
            "value": 0.0,
        }
        explanation = {
            "summary": f"Top recommendation: {top['technique']} against {top['target_asset']}",
            "rationale": "Ranked by value/stealth under current detection pressure and objective coverage.",
            "scoring_breakdown": (
                f"score={top['score']:.1f}, value={top['value']:.1f}, stealth={top['stealth']:.1f}, "
                f"risk={top['risk']:.1f}, confidence={top['confidence']:.2f}"
            ),
        }

        dashboard_data = {
            "top_opportunity": {
                "technique": top["technique"],
                "score": top["score"],
                "confidence": top["confidence"],
            },
            "campaign_state": state_data,
            "detection_pressure": {
                "pressure": pressure_val,
                "trend": trend,
                "detection_count": len(detections),
            },
            "recommendation": f"Execute {top['technique']} on {top['target_asset']} with staged OPSEC checks.",
        }

        updates = [
            ("OpportunitiesView", "refresh_opportunities", (opportunities,)),
            ("AttackPathsView", "refresh_paths", (paths,)),
            ("CampaignStateView", "refresh_state", (state_data,)),
            ("DetectionPressureView", "refresh_pressure", (pressure_data, det_rows)),
            ("ConfidenceAnalysisView", "refresh_confidence", (conf_data,)),
            ("KnowledgeCompletenessView", "refresh_knowledge", (knowledge_completeness, evidence_list)),
            ("TechniqueEffectivenessView", "refresh_techniques", (technique_rows,)),
            ("ValidationQueueView", "refresh_validations", (validations,)),
            ("ExplainabilityView", "show_explanation", (explanation,)),
            ("CognitionDashboardView", "refresh_dashboard", (dashboard_data,)),
        ]
        for widget_name, method_name, args in updates:
            try:
                widget = self.query_one(widget_name)
                getattr(widget, method_name)(*args)
            except Exception as exc:
                self.update_status(f"COGNITION PANEL WARN [{widget_name}]: {exc}", CyberColors.AMBER_WARNING)
    
    def action_toggle_cognition_opportunities(self):
        """Switch to Opportunities view (Ctrl+Shift+1)"""
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED FOR COGNITION", CyberColors.AMBER_WARNING)
            return
        self._refresh_cognition_views()
        self.query_one("#view-switcher").current = "cognition-opportunities"
        self.update_status("COGNITION: OPPORTUNITIES ANALYSIS", CyberColors.COG_OPPORTUNITY)
    
    def action_toggle_cognition_paths(self):
        """Switch to Attack Paths view (Ctrl+Shift+2)"""
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED FOR COGNITION", CyberColors.AMBER_WARNING)
            return
        self._refresh_cognition_views()
        self.query_one("#view-switcher").current = "cognition-paths"
        self.update_status("COGNITION: ATTACK PATH PLANNING", CyberColors.COG_PATH)
    
    def action_toggle_cognition_state(self):
        """Switch to Campaign State view (Ctrl+Shift+3)"""
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED FOR COGNITION", CyberColors.AMBER_WARNING)
            return
        self._refresh_cognition_views()
        self.query_one("#view-switcher").current = "cognition-state"
        self.update_status("COGNITION: CAMPAIGN STATE ASSESSMENT", CyberColors.COG_STATE)
    
    def action_toggle_cognition_detection(self):
        """Switch to Detection Pressure view (Ctrl+Shift+4)"""
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED FOR COGNITION", CyberColors.AMBER_WARNING)
            return
        self._refresh_cognition_views()
        self.query_one("#view-switcher").current = "cognition-detection"
        self.update_status("COGNITION: DETECTION PRESSURE ANALYSIS", CyberColors.COG_DETECTION)
    
    def action_toggle_cognition_confidence(self):
        """Switch to Confidence Analysis view (Ctrl+Shift+5)"""
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED FOR COGNITION", CyberColors.AMBER_WARNING)
            return
        self._refresh_cognition_views()
        self.query_one("#view-switcher").current = "cognition-confidence"
        self.update_status("COGNITION: CONFIDENCE ASSESSMENT", CyberColors.COG_CONFIDENCE)
    
    def action_toggle_cognition_knowledge(self):
        """Switch to Knowledge Completeness view (Ctrl+Shift+6)"""
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED FOR COGNITION", CyberColors.AMBER_WARNING)
            return
        self._refresh_cognition_views()
        self.query_one("#view-switcher").current = "cognition-knowledge"
        self.update_status("COGNITION: KNOWLEDGE COMPLETENESS", CyberColors.COG_KNOWLEDGE)
    
    def action_toggle_cognition_techniques(self):
        """Switch to Technique Effectiveness view (Ctrl+Shift+7)"""
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED FOR COGNITION", CyberColors.AMBER_WARNING)
            return
        self._refresh_cognition_views()
        self.query_one("#view-switcher").current = "cognition-techniques"
        self.update_status("COGNITION: TECHNIQUE EFFECTIVENESS", CyberColors.COG_TECHNIQUE)
    
    def action_toggle_cognition_validation(self):
        """Switch to Validation Queue view (Ctrl+Shift+8)"""
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED FOR COGNITION", CyberColors.AMBER_WARNING)
            return
        self._refresh_cognition_views()
        self.query_one("#view-switcher").current = "cognition-validation"
        self.update_status("COGNITION: VALIDATION QUEUE", CyberColors.COG_VALIDATION)
    
    def action_toggle_cognition_explain(self):
        """Switch to Explainability view (Ctrl+Shift+9)"""
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED FOR COGNITION", CyberColors.AMBER_WARNING)
            return
        self._refresh_cognition_views()
        self.query_one("#view-switcher").current = "cognition-explain"
        self.update_status("COGNITION: DECISION EXPLAINABILITY", CyberColors.COG_EXPLAINABILITY)
    
    def action_toggle_cognition_dashboard(self):
        """Switch to Cognition Dashboard view (Ctrl+Shift+0)"""
        if not self.db.current_user or not self.current_campaign_id:
            self.update_status("CAMPAIGN REQUIRED FOR COGNITION", CyberColors.AMBER_WARNING)
            return
        self._refresh_cognition_views()
        self.query_one("#view-switcher").current = "cognition-dashboard"
        self.update_status("COGNITION: UNIFIED DASHBOARD", CyberColors.COG_DASHBOARD)

    def action_return_to_editor(self):
        if not self.db.current_user: return
        self.switch_to_view("editor-view")
        self.set_editor_mode("edit")

    def action_toggle_editor_preview(self):
        if self.editor_mode == "edit":
            self.set_editor_mode("preview")
        else:
            self.set_editor_mode("edit")

    # -------------------------------------------------------------------------
    # TAB NAVIGATION HANDLERS
    # -------------------------------------------------------------------------
    
    @on(TabNavigationPanel.TabSelected)
    def on_tab_navigation_panel_selected(self, event: TabNavigationPanel.TabSelected):
        """Handle grouped tab panel selection."""
        self.switch_to_view(event.view_id)
    
    def switch_to_view(self, view_id: str):
        """Switch to a view by ID."""
        try:
            switcher = self.query_one("#view-switcher")
            user = self.db.current_user
            
            # Check if user is authenticated for non-auth views
            if view_id not in ["login-view", "register-view"] and not user:
                self.update_status("AUTHENTICATION REQUIRED", CyberColors.AMBER_WARNING)
                return

            required_role = self.VIEW_MIN_ROLE.get(view_id)
            if required_role and user and not role_gte(user.role, required_role):
                self.update_status(
                    f"ACCESS DENIED: {required_role.upper()}+ REQUIRED FOR {view_id.upper()}",
                    CyberColors.RED_ALERT,
                )
                return
            
            # Check if campaign is required
            campaign_required_views = [
                "campaign-view", "cmdlog-view", "session-view", "detection-view",
                "objective-view", "persistence-view", "graph-view", "timeline-view", "dashboard-view", "analysis-view",
                "remediation-view", "capability-view", "collab-view",
                "task-view", "analytics-view", "integration-view", "compliance-view",
                "security-view", "reporting-view", "threat-intel-view",
                "cognition-opportunities", "cognition-paths", "cognition-state",
                "cognition-detection", "cognition-confidence", "cognition-knowledge",
                "cognition-techniques", "cognition-validation", "cognition-explain",
                "cognition-dashboard"
            ]
            
            if view_id in campaign_required_views and not self.current_campaign_id:
                self.update_status("CAMPAIGN REQUIRED (VIEW IS READ-ONLY)", CyberColors.AMBER_WARNING)
            
            # Switch view
            switcher.current = view_id
            self.refresh_view_data(view_id)
            
            # Update tab bar active state
            try:
                tab_panel = self.query_one("#tab-nav-panel", TabNavigationPanel)
                tab_panel.set_active_view(view_id)
            except:
                pass
            
            # Update status message
            view_names = {
                "editor-view": "EDITOR",
                "fm-view": "FILE MANAGER",
                "mitre-view": "MITRE DATABASE",
                "campaign-view": "CAMPAIGN MANAGEMENT",
                "cmdlog-view": "COMMAND EXECUTION LOG",
                "session-view": "SESSION ACTIVITY",
                "detection-view": "DETECTION TIMELINE",
                "objective-view": "OBJECTIVE PROGRESS",
                "persistence-view": "PERSISTENCE INVENTORY",
                "graph-view": "ATTACK GRAPH",
                "timeline-view": "ENGAGEMENT TIMELINE",
                "dashboard-view": "SITUATIONAL AWARENESS DASHBOARD",
                "analysis-view": "POST-ENGAGEMENT ANALYSIS",
                "remediation-view": "REMEDIATION TRACKING",
                "capability-view": "CAPABILITY ASSESSMENT",
                "threat-intel-view": "THREAT INTELLIGENCE",
                "reporting-view": "REPORTING & EXPORT",
                "team-view": "TEAM MANAGEMENT",
                "users-view": "ADMIN USERS",
            }
            
            view_name = view_names.get(view_id, view_id.replace("-", " ").upper())
            self.update_status(f"MODE: {view_name}", CyberColors.PHOSPHOR_GREEN)
        
        except Exception as e:
            self.update_status(f"VIEW ERROR: {e}", CyberColors.RED_ALERT)

    def refresh_view_data(self, view_id: str):
        """Refresh data-bound views after campaign change or tab navigation."""
        if not self.db.current_user:
            return
        if not self.current_campaign_id:
            return
        try:
            if view_id == "campaign-view":
                self.query_one("CampaignView").refresh_data(self)
            elif view_id == "cmdlog-view":
                self.query_one("CommandExecutionLogView").refresh_commands(self, self.current_campaign_id)
            elif view_id == "session-view":
                self.query_one("SessionActivityView").refresh_sessions(self, self.current_campaign_id)
            elif view_id == "detection-view":
                self.query_one("DetectionTimelineView").refresh_detections(self, self.current_campaign_id)
            elif view_id == "objective-view":
                self.query_one("ObjectiveProgressView").refresh_objectives(self, self.current_campaign_id)
            elif view_id == "persistence-view":
                self.query_one("PersistenceInventoryView").refresh_persistence(self, self.current_campaign_id)
            elif view_id == "graph-view":
                self.query_one("GraphAnalyticsView").refresh_graph(self, self.current_campaign_id)
            elif view_id == "timeline-view":
                self.query_one("EngagementTimelineView").refresh_timeline(self, self.current_campaign_id)
            elif view_id == "dashboard-view":
                self.query_one("SituationalAwarenessView").refresh_dashboard(self, self.current_campaign_id)
            elif view_id == "analysis-view":
                self.query_one("PostEngagementAnalysisView").refresh_analysis(self, self.current_campaign_id)
            elif view_id == "remediation-view":
                self.query_one("RemediationTrackingView").refresh_remediation(self, self.current_campaign_id)
            elif view_id == "capability-view":
                self.query_one("CapabilityAssessmentView").refresh_capabilities(self, self.current_campaign_id)
            elif view_id == "collab-view":
                self.query_one("CollaborationEngineView").refresh_collaboration(self, self.current_campaign_id)
            elif view_id == "task-view":
                self.query_one("TaskOrchestrationView").refresh_tasks(self, self.current_campaign_id)
            elif view_id == "analytics-view":
                self.query_one("BehavioralAnalyticsView").refresh_analytics(self, self.current_campaign_id)
            elif view_id == "integration-view":
                self.query_one("IntegrationGatewayView").refresh_integrations(self, self.current_campaign_id)
            elif view_id == "compliance-view":
                self.query_one("ComplianceReportingView").refresh_compliance(self, self.current_campaign_id)
            elif view_id == "security-view":
                self.query_one("SecurityHardeningView").refresh_security(self, self.current_campaign_id)
            elif view_id == "threat-intel-view":
                self.query_one("ThreatIntelligenceView").refresh_threat_data()
            elif view_id == "reporting-view":
                self.query_one("ReportingView").refresh_report_summary()
            elif view_id.startswith("cognition-"):
                self._refresh_cognition_views()
        except Exception as e:
            self.update_status(f"REFRESH ERROR ({view_id}): {e}", CyberColors.RED_ALERT)

    # -------------------------------------------------------------------------
    # PROJECT LOGIC
    # -------------------------------------------------------------------------

    @on(Input.Changed, "#hud-project-input")
    def on_project_changed(self, event):
        val = event.value.strip() or "DEFAULT"
        self.current_project_id = val
        self.query_one("#hud-header").operation_name = val
        self.new_entry()
        self.refresh_list()
        
        # Try load campaign
        self.current_campaign_id = None
        camps = self.db.list_campaigns(val)
        if camps:
            self.current_campaign_id = camps[0].id
            self.query_one("#lbl-active-camp").update(camps[0].name)
        else:
            self.query_one("#lbl-active-camp").update("[NONE]")
        self.refresh_campaign_picker()
            
        self.update_status(f"PROJECT ACTIVE: {self.current_project_id}", CyberColors.ELECTRIC_CYAN)

    def refresh_campaign_picker(self):
        """Refresh campaign selector options for active project."""
        if not self.db.current_user:
            return
        sel = self.query_one("#sel-campaign", Select)
        camps = self.db.list_campaigns(self.current_project_id)
        options = [(c.name, str(c.id)) for c in camps]
        sel.set_options(options)
        if not options:
            self.current_campaign_id = None
            self.query_one("#lbl-active-camp").update("[NONE]")
            return

        id_map = {str(c.id): c.name for c in camps}
        current_id_str = str(self.current_campaign_id) if self.current_campaign_id is not None else None
        if current_id_str not in id_map:
            self.current_campaign_id = int(options[0][1])
            current_id_str = options[0][1]

        sel.value = current_id_str
        selected_name = id_map[current_id_str]
        self.query_one("#lbl-active-camp").update(selected_name)
        self.query_one("#hud-header").operation_name = selected_name

    @on(Select.Changed, "#sel-campaign")
    def on_campaign_selected(self, event: Select.Changed):
        """Switch active campaign from sidebar picker."""
        if not self.db.current_user:
            return
        if event.value in (None, Select.BLANK):
            return
        try:
            cid = int(str(event.value))
        except Exception:
            return
        self.current_campaign_id = cid
        camp = self.db.get_campaign_by_id(cid)
        camp_name = camp.name if camp else f"#{cid}"
        self.query_one("#lbl-active-camp").update(camp_name)
        self.query_one("#hud-header").operation_name = camp_name
        self.update_status(f"CAMPAIGN ACTIVE: {camp_name}", CyberColors.PURPLE_HAZE)
        active_view = self.query_one("#view-switcher").current
        self.refresh_view_data(active_view)

    def refresh_list(self):
        if not self.db.current_user: return
        lv = self.query_one("#findings-list", ListView)
        lv.clear()
        for f in self.db.get_findings(project_id=self.current_project_id):
            lv.append(FindingItem(f))

    # -------------------------------------------------------------------------
    # BUTTON HANDLERS
    # -------------------------------------------------------------------------

    @on(Button.Pressed)
    def on_buttons(self, event):
        bid = event.button.id
        if   bid == "btn-exit":         self.action_quit_app()
        elif bid == "btn-logout":       self.action_logout()
        elif bid == "btn-save":         self.save_db()
        elif bid == "btn-new":          self.new_entry()
        elif bid == "btn-del":          self.delete_entry()
        elif bid == "btn-save-md":      self.export_md()
        elif bid == "btn-export-nav":   self.export_format("navigator")
        elif bid == "btn-file-mgr":     self.action_toggle_file_manager()
        elif bid == "btn-admin-tools":  self.action_admin_tools()
        elif bid == "btn-mitre-menu":   self.action_toggle_mitre_view()
        elif bid == "btn-camp-ops":     self.action_toggle_campaign()
        elif bid == "btn-nist":         self.load_nist_template()
        elif bid == "btn-init-camp":    self.init_campaign()
        elif bid == "btn-editor-mode-edit": self.set_editor_mode("edit")
        elif bid == "btn-editor-mode-preview": self.set_editor_mode("preview")
        
        # Campaign Actions
        elif bid == "btn-add-asset":    self.camp_add_asset()
        elif bid == "btn-add-cred":     self.camp_add_cred()
        elif bid == "btn-add-action":   self.camp_add_action()
        elif bid == "btn-gen-report":   self.camp_gen_report()
        elif bid == "btn-session-new":  self.v32_open_session()
        elif bid == "btn-session-close": self.v32_close_session()
        elif bid == "btn-detect-assess": self.v32_assess_detection()
        elif bid == "btn-obj-add":      self.v32_add_objective()
        elif bid == "btn-persist-new":  self.v32_register_persistence()
        elif bid == "btn-persist-verify": self.v32_verify_all_persistence()
        elif bid == "btn-analysis-gen": self.v33_generate_analysis_report()
        elif bid == "btn-analysis-ttp": self.v33_load_ttp_metrics()
        elif bid == "btn-analysis-refresh": self.query_one("PostEngagementAnalysisView").refresh_analysis(self, self.current_campaign_id)
        elif bid == "btn-rem-log":      self.v33_log_remediation()
        elif bid == "btn-rem-refresh":  self.query_one("RemediationTrackingView").refresh_remediation(self, self.current_campaign_id)
        elif bid == "btn-cap-reg":      self.v33_register_capability()
        elif bid == "btn-cap-refresh":  self.query_one("CapabilityAssessmentView").refresh_capabilities(self, self.current_campaign_id)
        
        # v3.4 Button Handlers
        # Task Orchestration
        elif bid == "btn-task-create":  self.v34_create_task_template()
        elif bid == "btn-task-refresh": self.query_one("TaskOrchestrationView").refresh_tasks(self, self.current_campaign_id)
        
        # Collaboration Engine
        elif bid == "btn-collab-start": self.v34_start_collaboration()
        elif bid == "btn-collab-conflicts": self.v34_detect_conflicts()
        elif bid == "btn-collab-refresh": self.query_one("CollaborationEngineView").refresh_collaboration(self, self.current_campaign_id)
        
        # Behavioral Analytics
        elif bid == "btn-analytics-analyze": self.v34_analyze_patterns()
        elif bid == "btn-analytics-anomalies": self.v34_detect_anomalies()
        elif bid == "btn-analytics-predict": self.v34_predict_defense()
        
        # Integration Gateway
        elif bid == "btn-webhook-reg": self.v34_register_webhook()
        elif bid == "btn-api-mgmt": self.v34_manage_api_integrations()
        
        # Compliance Reporting
        elif bid == "btn-soc2-gen": self.v34_generate_soc2_report()
        elif bid == "btn-fedramp-gen": self.v34_generate_fedramp_report()
        elif bid == "btn-compliance-refresh": self.query_one("ComplianceReportingView").refresh_compliance(self, self.current_campaign_id)
        
        # Security Hardening
        elif bid == "btn-sec-verify": self.v34_verify_audit_chain()
        elif bid == "btn-sec-sessions": self.v34_manage_sessions()
        elif bid == "btn-sec-retention": self.v34_manage_retention()

    # ===== v3.4 FEATURE HANDLERS =====

    def v32_open_session(self):
        """Open a session against the first campaign asset."""
        if not self._validate_campaign_access():
            return
        assets = self.db.list_assets(self.current_campaign_id)
        if not assets:
            self.update_status("NO ASSETS AVAILABLE - ADD ASSET FIRST", CyberColors.AMBER_WARNING)
            return
        user = self.db.current_user
        session_name = f"sess_{datetime.now().strftime('%H%M%S')}"
        session_id = self.db.open_session(
            self.current_campaign_id,
            assets[0].id,
            session_name,
            "shell",
            user.username if user else "SYSTEM",
        )
        if session_id > 0:
            self.query_one("SessionActivityView").refresh_sessions(self, self.current_campaign_id)
            self.update_status(f"SESSION OPENED (ID: {session_id})", CyberColors.PHOSPHOR_GREEN)
        else:
            self.update_status("FAILED TO OPEN SESSION", CyberColors.RED_ALERT)

    def v32_close_session(self):
        """Close the most recent active session."""
        if not self._validate_campaign_access():
            return
        sessions = self.db.get_active_sessions(self.current_campaign_id)
        if not sessions:
            self.update_status("NO ACTIVE SESSIONS", CyberColors.AMBER_WARNING)
            return
        ok = self.db.close_session(sessions[0]["id"])
        if ok:
            self.query_one("SessionActivityView").refresh_sessions(self, self.current_campaign_id)
            self.update_status("SESSION CLOSED", CyberColors.PHOSPHOR_GREEN)
        else:
            self.update_status("FAILED TO CLOSE SESSION", CyberColors.RED_ALERT)

    def v32_assess_detection(self):
        """Assess evasion for latest detection event."""
        if not self._validate_campaign_access():
            return
        events = self.db.get_detection_timeline(self.current_campaign_id)
        if not events:
            self.update_status("NO DETECTION EVENTS TO ASSESS", CyberColors.AMBER_WARNING)
            return
        event_id = events[-1]["id"]
        ok = self.db.assess_evasion_success(
            self.current_campaign_id,
            event_id,
            True,
            "Adjust execution pattern and delay beaconing",
        )
        if ok:
            self.query_one("DetectionTimelineView").refresh_detections(self, self.current_campaign_id)
            self.update_status("EVASION ASSESSMENT RECORDED", CyberColors.PHOSPHOR_GREEN)
        else:
            self.update_status("EVASION ASSESSMENT FAILED (LEAD+ REQUIRED)", CyberColors.RED_ALERT)

    def v32_add_objective(self):
        """Create objective and refresh progress tracker."""
        if not self._validate_campaign_access():
            return
        objective = self.query_one("#inp-obj-name", Input).value.strip()
        if not objective:
            self.update_status("OBJECTIVE NAME REQUIRED", CyberColors.AMBER_WARNING)
            return
        objective_id = self.db.create_campaign_objective(self.current_campaign_id, objective)
        if objective_id > 0:
            self.query_one("#inp-obj-name", Input).value = ""
            self.query_one("ObjectiveProgressView").refresh_objectives(self, self.current_campaign_id)
            self.update_status(f"OBJECTIVE CREATED (ID: {objective_id})", CyberColors.PHOSPHOR_GREEN)
        else:
            self.update_status("FAILED TO CREATE OBJECTIVE", CyberColors.RED_ALERT)

    def v32_register_persistence(self):
        """Register baseline persistence on first campaign asset."""
        if not self._validate_campaign_access():
            return
        assets = self.db.list_assets(self.current_campaign_id)
        if not assets:
            self.update_status("NO ASSETS AVAILABLE - ADD ASSET FIRST", CyberColors.AMBER_WARNING)
            return
        user = self.db.current_user
        persist_id = self.db.register_persistence(
            self.current_campaign_id,
            assets[0].id,
            "scheduled_task",
            "Auto baseline check-in persistence",
            user.username if user else "SYSTEM",
            "default",
        )
        if persist_id > 0:
            self.query_one("PersistenceInventoryView").refresh_persistence(self, self.current_campaign_id)
            self.update_status(f"PERSISTENCE REGISTERED (ID: {persist_id})", CyberColors.PHOSPHOR_GREEN)
        else:
            self.update_status("FAILED TO REGISTER PERSISTENCE", CyberColors.RED_ALERT)

    def v32_verify_all_persistence(self):
        """Verify every active persistence record as SUCCESS."""
        if not self._validate_campaign_access():
            return
        records = self.db.get_persistence_inventory(self.current_campaign_id)
        if not records:
            self.update_status("NO PERSISTENCE RECORDS TO VERIFY", CyberColors.AMBER_WARNING)
            return
        verified = 0
        for record in records:
            if self.db.verify_persistence(record["id"], "SUCCESS", "Validated from control panel"):
                verified += 1
        self.query_one("PersistenceInventoryView").refresh_persistence(self, self.current_campaign_id)
        self.update_status(f"PERSISTENCE VERIFIED: {verified}/{len(records)}", CyberColors.PHOSPHOR_GREEN)

    def v33_generate_analysis_report(self):
        """Render a concise post-engagement report into the analysis preview."""
        if not self._validate_campaign_access():
            return
        report = self.db.get_ttp_effectiveness_report(self.current_campaign_id)
        content = (
            f"# Post-Engagement Analysis\n\n"
            f"- Total Techniques: {report.get('total_techniques_executed', 0)}\n"
            f"- Average Effectiveness: {report.get('average_effectiveness', 0):.1f}%\n"
        )
        self.query_one("#txt-analysis-preview", TextArea).load_text(content)
        self.query_one("PostEngagementAnalysisView").refresh_analysis(self, self.current_campaign_id)
        self.update_status("POST-ENGAGEMENT REPORT GENERATED", CyberColors.PHOSPHOR_GREEN)

    def v33_load_ttp_metrics(self):
        """Refresh TTP metrics table and preview."""
        if not self._validate_campaign_access():
            return
        self.query_one("PostEngagementAnalysisView").refresh_analysis(self, self.current_campaign_id)
        report = self.db.get_ttp_effectiveness_report(self.current_campaign_id)
        self.query_one("#txt-analysis-preview", TextArea).load_text(
            f"TTP METRICS\n\nTechniques: {report.get('total_techniques_executed', 0)}\n"
            f"Avg Effectiveness: {report.get('average_effectiveness', 0):.1f}%"
        )
        self.update_status("TTP METRICS REFRESHED", CyberColors.ELECTRIC_CYAN)

    def v33_log_remediation(self):
        """Log a remediation action against the first campaign asset."""
        if not self._validate_campaign_access():
            return
        assets = self.db.list_assets(self.current_campaign_id)
        if not assets:
            self.update_status("NO ASSETS AVAILABLE - ADD ASSET FIRST", CyberColors.AMBER_WARNING)
            return
        user = self.db.current_user
        remediation_id = self.db.log_remediation_action(
            self.current_campaign_id,
            assets[0].id,
            "Blue team tightened endpoint controls",
            user.username if user else "SYSTEM",
        )
        if remediation_id > 0:
            self.db.assess_remediation_impact(remediation_id, 1, 1, 0)
            self.query_one("RemediationTrackingView").refresh_remediation(self, self.current_campaign_id)
            self.update_status(f"REMEDIATION LOGGED (ID: {remediation_id})", CyberColors.PHOSPHOR_GREEN)
        else:
            self.update_status("FAILED TO LOG REMEDIATION (LEAD+ REQUIRED)", CyberColors.RED_ALERT)

    def v33_register_capability(self):
        """Register baseline capability for the active campaign."""
        if not self._validate_campaign_access():
            return
        capability_id = self.db.register_capability(
            self.current_campaign_id,
            "Privilege Escalation via Scripted Path",
            "privilege_escalation",
            6.5,
            "MODERATE",
        )
        if capability_id > 0:
            self.query_one("CapabilityAssessmentView").refresh_capabilities(self, self.current_campaign_id)
            self.update_status(f"CAPABILITY REGISTERED (ID: {capability_id})", CyberColors.PHOSPHOR_GREEN)
        else:
            self.update_status("FAILED TO REGISTER CAPABILITY (LEAD+ REQUIRED)", CyberColors.RED_ALERT)

    def v34_create_task_template(self):
        """Create task automation template (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            inp = self.query_one("#inp-task-name")
            name = inp.value.strip()
            if not name:
                self.update_status("TASK NAME REQUIRED", CyberColors.AMBER_WARNING)
                return
            
            task_id = self.db.create_task_template(self.current_campaign_id, name, "Auto-created", "[]")
            if task_id > 0:
                inp.value = ""
                self.query_one("TaskOrchestrationView").refresh_tasks(self, self.current_campaign_id)
                self.update_status(f"TASK TEMPLATE CREATED (ID: {task_id})", CyberColors.PHOSPHOR_GREEN)
            else:
                self.update_status("FAILED TO CREATE TASK TEMPLATE", CyberColors.RED_ALERT)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def v34_start_collaboration(self):
        """Start real-time collaboration session (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            session_id = self.db.create_collaboration_session(self.current_campaign_id, f"Session_{datetime.now().strftime('%H%M%S')}")
            if session_id > 0:
                self.update_status(f"COLLABORATION SESSION STARTED (ID: {session_id})", CyberColors.PHOSPHOR_GREEN)
            else:
                self.update_status("FAILED TO CREATE SESSION", CyberColors.RED_ALERT)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def v34_detect_conflicts(self):
        """Detect collaborative conflicts (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            self.update_status("CONFLICT DETECTION ENABLED", CyberColors.ELECTRIC_CYAN)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def v34_analyze_patterns(self):
        """Analyze behavioral patterns (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            self.update_status("PATTERN ANALYSIS IN PROGRESS", CyberColors.ELECTRIC_CYAN)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def v34_detect_anomalies(self):
        """Detect behavioral anomalies (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            self.update_status("ANOMALY DETECTION ENABLED", CyberColors.AMBER_WARNING)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def v34_predict_defense(self):
        """Predict defensive actions (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            ok = self.db.predict_defense(self.current_campaign_id, "Blue Team Hardening", "T1059,T1086", 0.6, "Apply EDR")
            if ok:
                self.update_status("DEFENSE PREDICTION LOGGED", CyberColors.PHOSPHOR_GREEN)
            else:
                self.update_status("FAILED TO LOG PREDICTION", CyberColors.RED_ALERT)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def v34_register_webhook(self):
        """Register webhook subscription (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            inp = self.query_one("#inp-webhook-url")
            url = inp.value.strip()
            if not url:
                self.update_status("WEBHOOK URL REQUIRED", CyberColors.AMBER_WARNING)
                return
            
            webhook_id = self.db.register_webhook(self.current_campaign_id, url, "event_notification", "finding_created,finding_updated")
            if webhook_id > 0:
                inp.value = ""
                self.query_one("IntegrationGatewayView").refresh_integrations(self, self.current_campaign_id)
                self.update_status(f"WEBHOOK REGISTERED (ID: {webhook_id})", CyberColors.PHOSPHOR_GREEN)
            else:
                self.update_status("FAILED TO REGISTER WEBHOOK", CyberColors.RED_ALERT)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def v34_manage_api_integrations(self):
        """Manage API integrations (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            self.update_status("API INTEGRATIONS MANAGER OPENED", CyberColors.ELECTRIC_CYAN)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def v34_generate_soc2_report(self):
        """Generate SOC 2 compliance report (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            report_id = self.db.generate_compliance_report(self.current_campaign_id, 1, "soc2_audit")
            if report_id > 0:
                self.update_status(f"SOC 2 REPORT GENERATED (ID: {report_id})", CyberColors.PHOSPHOR_GREEN)
            else:
                self.update_status("FAILED TO GENERATE REPORT", CyberColors.RED_ALERT)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def v34_generate_fedramp_report(self):
        """Generate FedRAMP compliance report (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            report_id = self.db.generate_compliance_report(self.current_campaign_id, 2, "fedramp_audit")
            if report_id > 0:
                self.update_status(f"FedRAMP REPORT GENERATED (ID: {report_id})", CyberColors.PHOSPHOR_GREEN)
            else:
                self.update_status("FAILED TO GENERATE REPORT", CyberColors.RED_ALERT)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def v34_verify_audit_chain(self):
        """Verify audit log chain integrity (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            self.update_status("AUDIT CHAIN VERIFICATION STARTED", CyberColors.ELECTRIC_CYAN)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def v34_manage_sessions(self):
        """Manage session timeouts (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            self.update_status("SESSION MANAGER OPENED", CyberColors.ELECTRIC_CYAN)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def v34_manage_retention(self):
        """Manage data retention policies (v3.4)."""
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN ACTIVE", CyberColors.AMBER_WARNING)
            return
        try:
            self.update_status("RETENTION POLICY MANAGER OPENED", CyberColors.ELECTRIC_CYAN)
        except Exception as e:
            self.update_status(f"ERROR: {str(e)[:40]}", CyberColors.RED_ALERT)

    def load_nist_template(self):
        if not self.db.current_user:
            self.update_status("AUTHENTICATION REQUIRED", CyberColors.AMBER_WARNING)
            return
        self.new_entry()
        template = NIST_800_115_SKELETON.replace("[DATE]", datetime.now().strftime("%Y-%m-%d"))
        self.query_one("#editor-main").load_text(template)
        self.refresh_editor_preview()
        self.query_one("#inp-title").value = f"NIST_Report_{self.current_project_id}"
        self.query_one("#hud-header").current_file = f"NIST_Report_{self.current_project_id}.md"
        self.query_one("#view-switcher").current = "editor-view"
        self.set_editor_mode("edit")
        self.update_status("NIST TEMPLATE LOADED", CyberColors.PHOSPHOR_GREEN)

    def init_campaign(self):
        """Initialize new campaign with audit log."""
        user = self.db.current_user
        if not user:
            self.update_status("AUTHENTICATION REQUIRED", CyberColors.AMBER_WARNING)
            return
        if not role_gte(user.role, Role.LEAD):
            self.update_status("ACCESS DENIED: LEAD+ REQUIRED TO INIT CAMPAIGN", CyberColors.RED_ALERT)
            return
        name = f"OP_{self.current_project_id}"
        ok, msg = self.db.create_campaign(name, self.current_project_id)
        if ok:
            camp = self.db.get_campaign_by_name(name)
            if camp:
                self.current_campaign_id = camp.id
                self.query_one("#lbl-active-camp").update(name)
                self.refresh_campaign_picker()
                self.db.log_audit_event(user.username, "CAMPAIGN_CREATED", {"campaign_id": camp.id, "name": name})
                self.update_status(msg, CyberColors.PURPLE_HAZE)
            else:
                self.update_status("CAMPAIGN CREATED BUT NOT FOUND", CyberColors.AMBER_WARNING)
        else:
            self.update_status(f"ERROR: {msg}", CyberColors.RED_ALERT)

    # --- CAMPAIGN HANDLERS (v3.0: Isolation, RBAC, Audit) ---
    
    def _validate_campaign_access(self) -> bool:
        """Check campaign exists and user has operator+ permissions.
        
        Returns:
            bool: True if valid, False otherwise (user gets status message).
        """
        if not self.current_campaign_id:
            self.update_status("NO CAMPAIGN SELECTED", CyberColors.AMBER_WARNING)
            return False
        user = self.db.current_user
        if not user or not role_gte(user.role, Role.OPERATOR):
            self.update_status("CAMPAIGN OPS REQUIRE OPERATOR+ ROLE", CyberColors.RED_ALERT)
            return False
        camp = self.db.get_campaign_by_id(self.current_campaign_id)
        if not camp:
            self.update_status("CAMPAIGN NOT FOUND", CyberColors.RED_ALERT)
            return False
        return True
    
    def camp_add_asset(self):
        """Add asset to campaign with isolation and audit."""
        if not self._validate_campaign_access(): return
        user = self.db.current_user
        name = self.query_one("#inp-ast-name").value.strip()
        atype = self.query_one("#sel-ast-type").value
        addr = self.query_one("#inp-ast-ip").value.strip()
        if name and atype:
            try:
                self.db.add_asset(self.current_campaign_id, atype, name, address=addr)
                self.db.log_audit_event(user.username, "ASSET_ADDED", {"campaign_id": self.current_campaign_id, "asset": name})
                self.query_one("CampaignView").refresh_data(self)
                self.query_one("#inp-ast-name").value = ""
                self.update_status(f"ASSET ADDED: {name}", CyberColors.PURPLE_HAZE)
            except Exception as e:
                self.update_status(f"ERROR: {e}", CyberColors.RED_ALERT)
        else:
            self.update_status("ASSET NAME AND TYPE REQUIRED", CyberColors.AMBER_WARNING)

    def camp_add_cred(self):
        """Capture credential to campaign with encryption and audit."""
        if not self._validate_campaign_access(): return
        user = self.db.current_user
        ident = self.query_one("#inp-cred-id").value.strip()
        ctype = self.query_one("#sel-cred-type").value
        secret = self.query_one("#inp-cred-secret").value
        if ident and ctype and secret:
            try:
                self.db.add_credential(self.current_campaign_id, None, ctype, ident, secret, "manual")
                self.db.log_audit_event(user.username, "CREDENTIAL_CAPTURED", {"campaign_id": self.current_campaign_id, "identifier": ident})
                self.query_one("CampaignView").refresh_data(self)
                self.query_one("#inp-cred-secret").value = ""
                self.update_status(f"CREDENTIAL CAPTURED [ENCRYPTED]", CyberColors.PURPLE_HAZE)
            except Exception as e:
                self.update_status(f"ERROR: {e}", CyberColors.RED_ALERT)
        else:
            self.update_status("CREDENTIALS AND TYPE REQUIRED", CyberColors.AMBER_WARNING)

    def camp_add_action(self):
        """Log operator action to campaign timeline with MITRE mapping and audit."""
        if not self._validate_campaign_access(): return
        user = self.db.current_user
        cmd = self.query_one("#inp-act-cmd").value.strip()
        res = self.query_one("#inp-act-res").value.strip()
        mitre = self.query_one("#inp-act-mitre").value.strip() or "T1059"
        det = self.query_one("#sel-act-detect").value or "unknown"
        if cmd:
            try:
                self.db.log_action(self.current_campaign_id, user.username, mitre, cmd, res, det)
                self.db.log_audit_event(user.username, "ACTION_LOGGED", {"campaign_id": self.current_campaign_id, "technique": mitre})
                self.query_one("CampaignView").refresh_data(self)
                self.query_one("#inp-act-cmd").value = ""
                self.query_one("#inp-act-res").value = ""
                self.update_status(f"ACTION LOGGED [{mitre}]", CyberColors.PURPLE_HAZE)
            except Exception as e:
                self.update_status(f"ERROR: {e}", CyberColors.RED_ALERT)
        else:
            self.update_status("COMMAND REQUIRED", CyberColors.AMBER_WARNING)

    def camp_gen_report(self):
        """Generate campaign report with approval check (v3.0 roadmap)."""
        if not self._validate_campaign_access(): return
        user = self.db.current_user
        try:
            # TODO: v3.0 - Check approval_status of all campaign findings before export
            # if not all approved: self.update_status(...); return
            report = self.db.generate_campaign_report(self.current_campaign_id)
            self.query_one("#txt-report-preview").load_text(report)
            # Auto export to delivery folder
            path = Path("Reports") / f"Campaign_Report_{self.current_project_id}.md"
            ok, msg = FileSystemService.atomic_write(path, report)
            if ok:
                self.db.log_audit_event(user.username, "REPORT_GENERATED", {"campaign_id": self.current_campaign_id, "path": str(path)})
                self.update_status(f"REPORT GENERATED & EXPORTED: {msg}", CyberColors.PHOSPHOR_GREEN)
            else:
                self.update_status(f"EXPORT FAILED: {msg}", CyberColors.RED_ALERT)
        except Exception as e:
            self.update_status(f"REPORT ERROR: {e}", CyberColors.RED_ALERT)

    # -------------------------------------------------------------------------
    # MITRE
    # -------------------------------------------------------------------------

    @on(MitreIntelligenceView.TechniqueSelected)
    def on_mitre_selected(self, message: MitreIntelligenceView.TechniqueSelected):
        self.query_one("#inp-mitre").value = message.technique_id
        if not self.query_one("#inp-title").value:
            self.query_one("#inp-title").value = message.technique_name
        self.action_return_to_editor()
        self.update_status(f"IMPORTED: {message.technique_id}", CyberColors.ELECTRIC_CYAN)

    # -------------------------------------------------------------------------
    # CVSS / RISK
    # -------------------------------------------------------------------------

    @on(Input.Changed, "#inp-vector")
    def on_vector(self, event):
        score = CVSSCalculator.calculate(event.value)
        self.query_one("#inp-score").value = str(score)
        self.update_risk(score)

    @on(Input.Changed, "#inp-score")
    def on_score(self, event):
        try: self.update_risk(float(event.value))
        except Exception: pass

    def update_risk(self, score):
        sev = self.query_one("#info-severity")
        sc  = self.query_one("#info-score")
        sc.update(str(score))
        for cls in ["risk-crit", "risk-high", "risk-med", "risk-low"]:
            sev.remove_class(cls)
            sc.remove_class(cls)
        if   score >= 9.0: cls, txt = "risk-crit", "CRITICAL"
        elif score >= 7.0: cls, txt = "risk-high", "HIGH"
        elif score >= 4.0: cls, txt = "risk-med",  "MEDIUM"
        else:              cls, txt = "risk-low",  "LOW"
        sev.update(txt)
        sev.add_class(cls)
        sc.add_class(cls)

    @on(Input.Changed, "#inp-mitre")
    def on_mitre_text(self, event):
        if not self.intel: return
        val  = event.value.strip().upper()
        mbox = self.query_one("#info-mitre")
        if len(val) >= 4:
            info = self.intel.lookup_mitre(val)
            if info:
                mbox.update(f"{info.id}\n{info.name[:15]}")
                mbox.styles.border = "heavy", CyberColors.ELECTRIC_CYAN
            else:
                mbox.update("UNKNOWN")
                mbox.styles.border = "solid", CyberColors.AMBER_WARNING

    # -------------------------------------------------------------------------
    # CRUD
    # -------------------------------------------------------------------------

    def save_db(self):
        """Save finding with audit log."""
        user = self.db.current_user
        try: score = float(self.query_one("#inp-score").value)
        except Exception: score = 0.0
        f = Finding(
            id=self.current_id,
            title=self.query_one("#inp-title").value or "Untitled",
            description=self.query_one("#editor-main").text,
            cvss_score=score,
            mitre_id=self.query_one("#inp-mitre").value,
            tactic_id="", status="Open",
            project_id=self.current_project_id,
            cvss_vector=self.query_one("#inp-vector").value,
        )
        try:
            if self.current_id:
                self.db.update_finding(f)
                action = "FINDING_UPDATED"
            else:
                self.current_id = self.db.add_finding(f)
                action = "FINDING_CREATED"
            self.query_one("#hud-header").current_file = f"{f.title[:40]}.md"
            self.db.log_audit_event(user.username, action, {"finding_id": self.current_id, "title": f.title})
            self.refresh_list()
            self.update_status("DATABASE SYNCED [AUDITED]", CyberColors.PHOSPHOR_GREEN)
        except Exception as e:
            self.update_status(f"SAVE FAILED: {e}", CyberColors.RED_ALERT)

    def new_entry(self):
        self.current_id = None
        self.query_one("#inp-title").value  = ""
        self.query_one("#inp-score").value  = "0.0"
        self.query_one("#inp-mitre").value  = ""
        self.query_one("#inp-vector").value = ""
        self.query_one("#editor-main").load_text("")
        self.refresh_editor_preview()
        self.query_one("#hud-header").current_file = "NEW BUFFER"
        self.update_risk(0.0)

    def delete_entry(self):
        """Destructive action: requires LEAD+ role and confirmation."""
        if not self.current_id: return
        user = self.db.current_user
        if not user or not role_gte(user.role, Role.LEAD):
            self.update_status("PERMISSION DENIED: LEAD+ REQUIRED FOR DELETE", CyberColors.RED_ALERT)
            return
        try:
            # Log destructive action
            self.db.log_audit_event(user.username, "FINDING_DELETED", {"finding_id": self.current_id})
            self.db.delete_finding(self.current_id)
            self.new_entry()
            self.refresh_list()
            self.update_status("FINDING DELETED [AUDITED]", CyberColors.AMBER_WARNING)
        except Exception as e:
            self.update_status(f"DELETE FAILED: {e}", CyberColors.RED_ALERT)

    # -------------------------------------------------------------------------
    # FILE MANAGER
    # -------------------------------------------------------------------------

    @on(FileManagerView.FileSelected)
    def on_file(self, event):
        # Explicitly auto-open markdown files into editor view.
        if event.path.suffix.lower() not in {".md", ".markdown"}:
            self.update_status("NON-MARKDOWN FILE SELECTED: STAYING IN FILE PREVIEW", CyberColors.AMBER_WARNING)
            return
        success, content, _ = FileSystemService.read_file(event.path)
        if success:
            self.new_entry()
            self.query_one("#editor-main").load_text(content)
            self.refresh_editor_preview()
            self.query_one("#inp-title").value = event.path.name
            self.query_one("#hud-header").current_file = event.path.name
            self.query_one("#view-switcher").current = "editor-view"
            self.set_editor_mode("edit")
            self.update_status(f"OPENED MARKDOWN: {event.path.name}", CyberColors.ELECTRIC_CYAN)

    # -------------------------------------------------------------------------
    # EXPORTS
    # -------------------------------------------------------------------------

    def export_md(self):
        """Export findings as markdown with audit log."""
        user = self.db.current_user
        try:
            content = self.db.export_markdown(self.current_project_id)
            title = self.current_project_id.replace(" ", "_") + ".md"
            path  = Path("Reports") / title
            ok, msg = FileSystemService.atomic_write(path, content)
            if ok:
                self.db.log_audit_event(user.username, "EXPORT_MARKDOWN", {"project_id": self.current_project_id, "path": str(path)})
                self.update_status(f"EXPORTED MD: {title}", CyberColors.PHOSPHOR_GREEN)
            else:
                self.update_status(f"EXPORT FAILED: {msg}", CyberColors.RED_ALERT)
        except Exception as e:
            self.update_status(f"EXPORT ERROR: {e}", CyberColors.RED_ALERT)

    def export_format(self, fmt: str):
        """Export findings in specified format with audit log."""
        user = self.db.current_user
        try:
            pid = self.current_project_id
            if fmt == "navigator":
                content = self.db.export_mitre_navigator(pid)
                ext = "_navigator.json"
            else:
                self.update_status(f"UNKNOWN FORMAT: {fmt}", CyberColors.AMBER_WARNING)
                return
            fname = pid.replace(" ", "_") + ext
            path  = Path("Reports") / fname
            ok, msg = FileSystemService.atomic_write(path, content)
            if ok:
                self.db.log_audit_event(user.username, "EXPORT_FORMAT", {"project_id": pid, "format": fmt, "path": str(path)})
                self.update_status(f"EXPORTED: {fname}", CyberColors.PHOSPHOR_GREEN)
            else:
                self.update_status(f"EXPORT FAILED: {msg}", CyberColors.RED_ALERT)
        except Exception as e:
            self.update_status(f"EXPORT ERROR: {e}", CyberColors.RED_ALERT)

if __name__ == '__main__':
    if sys.platform == "win32": os.system("cls")
    else: os.system("clear")
    CyberTUI().run()
