import os
import sys
import asyncio
from datetime import datetime
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    ListView, ListItem, Label, Input,
    TextArea, Button, Static, ContentSwitcher, DataTable
)
from textual.binding import Binding
from textual.screen import Screen
from textual.reactive import reactive
from textual.message import Message

try:
    from vv_core import (Database, Finding, IntelligenceEngine, CVSSCalculator,
                         NIST_800_115_SKELETON, SessionCrypto, Role, role_gte)
    from vv_fs import FileSystemService
    from vv_file_manager import FileManagerView
    from vv_theme import CYBER_CSS, CyberColors
except ImportError as e:
    print(f"CRITICAL: Dependency missing. {e}")
    sys.exit(1)

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
        if not event.row_key.value:
            return
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
# REGISTER VIEW (shown when no users exist)
# =============================================================================

class RegisterView(Container):
    """First-run registration screen. First user becomes ADMIN automatically."""

    class RegisterSuccess(Message):
        pass

    CSS = """
    RegisterView {
        align: center middle;
        background: $bg-void;
        height: 100%;
    }
    #register-container {
        width: 64; height: auto;
        border: heavy $p-green; background: #000; padding: 2;
        align: center middle;
    }
    .reg-title {
        color: $p-green; text-style: bold;
        margin-bottom: 2; width: 100%; content-align: center middle;
    }
    #reg-status { color: $r-alert; margin-top: 1; text-align: center; }
    """

    def compose(self) -> ComposeResult:
        with Container(id="register-container"):
            yield Label("VECTORVUE — FIRST-RUN SETUP", classes="reg-title")
            yield Label("[dim]First registered user becomes ADMIN[/]", classes="reg-title")
            yield Input(placeholder="Username", id="reg-username")
            yield Input(placeholder="Password (min 8 chars)", password=True, id="reg-password")
            yield Input(placeholder="Confirm Password", password=True, id="reg-confirm")
            yield Input(placeholder="Group name (default: 'default')", id="reg-group")
            yield Button("REGISTER", id="reg-btn", variant="success")
            yield Label("", id="reg-status")

    def on_mount(self):
        self.query_one("#reg-username").focus()

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
        if ok:
            self.post_message(self.RegisterSuccess())
        else:
            status.update(msg)

# =============================================================================
# LOGIN VIEW
# =============================================================================

class LoginView(Container):
    """Standard login after users exist."""

    class LoginSuccess(Message):
        pass

    def compose(self) -> ComposeResult:
        with Container(id="login-container"):
            yield Label("VECTORVUE [SECURE ACCESS]", classes="login-title")
            yield Input(placeholder="Username", id="login-username")
            yield Input(placeholder="Passphrase", password=True, id="login-input")
            yield Button("AUTHENTICATE", id="login-btn", variant="success")
            yield Label("", id="login-status")

    def on_mount(self):
        self.query_one("#login-username").focus()

    @on(Button.Pressed, "#login-btn")
    def attempt_login(self):
        self.submit_login()

    @on(Input.Submitted, "#login-input")
    def on_submit(self):
        self.submit_login()

    def submit_login(self):
        username = self.query_one("#login-username").value.strip()
        phrase   = self.query_one("#login-input").value
        status   = self.query_one("#login-status")

        if not username or not phrase:
            status.update("USERNAME AND PASSPHRASE REQUIRED")
            return

        # Derive DB encryption key from passphrase (canary check)
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

        # Authenticate user against RBAC user table
        ok, msg = self.app.db.authenticate_user(username, phrase)
        if ok:
            self.post_message(self.LoginSuccess())
        else:
            status.update(f"AUTH FAILED: {msg}")

# =============================================================================
# SHUTDOWN VIEWS
# =============================================================================

class ShutdownConfirmationView(Container):
    CSS = """
    ShutdownConfirmationView {
        align: center middle; background: $bg-void; height: 100%;
        border-right: heavy $e-cyan;
    }
    #confirm-box {
        width: 60; height: auto; background: #111;
        border: heavy $r-alert; padding: 2; text-align: center;
    }
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
    def execute_shutdown(self):
        self.app.push_screen(ShutdownScreen())

    @on(Button.Pressed, "#btn-conf-abort")
    def abort_shutdown(self):
        self.app.action_return_to_editor()

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
            if self.app.db.current_user:
                self.app.db.logout()
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

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Label("VECTORVUE v2.5 [TACTICAL]", classes="hud-title")
            yield Label(" PROJECT:", classes="hud-label-sm")
            yield Input(value="DEFAULT", id="hud-project-input", classes="hud-input", disabled=True)
            yield Label(f"// BUFFER: {self.current_file}", id="hud-file-lbl", classes="hud-file")

    def watch_current_file(self, val):
        if self.is_mounted:
            try:
                self.query_one("#hud-file-lbl").update(f"// BUFFER: {val}")
            except Exception:
                pass

class FindingItem(ListItem):
    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        try:
            score = float(self.finding.cvss_score)
        except (ValueError, TypeError):
            score = 0.0
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
    .hud-label-sm { color: #666; content-align: center middle; width: 10; padding-top: 1; }
    .hud-input    { width: 20; height: 1; border: none; background: #111; color: #00FFFF; }
    .hud-input:focus { border: none; }
    """

    BINDINGS = [
        Binding("q",      "quit_app",             "Quit"),
        Binding("space",  "toggle_file_manager",  "Files"),
        Binding("ctrl+m", "toggle_mitre_view",    "MITRE DB"),
        Binding("ctrl+s", "save_db",              "Save"),
        Binding("ctrl+l", "action_logout",        "Logout"),
        Binding("escape", "return_to_editor",     "Editor"),
    ]

    current_project_id = reactive("DEFAULT")

    def compose(self) -> ComposeResult:
        yield HeaderHUD(id="hud-header")

        with ContentSwitcher(initial="login-view", id="view-switcher"):
            yield LoginView(id="login-view")
            yield RegisterView(id="register-view")

            with Container(id="editor-view"):
                yield TextArea(language="markdown", theme="dracula", id="editor-main")

            yield FileManagerView(id="fm-view")
            yield MitreIntelligenceView(id="mitre-view")
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

            yield Label("VECTOR TITLE:", classes="cyber-label")
            yield Input(id="inp-title", placeholder="Vulnerability Title...", disabled=True)
            yield Label("CVSS VECTOR:", classes="cyber-label")
            yield Input(id="inp-vector", placeholder="CVSS:3.1/AV:N/AC:L...", disabled=True)
            yield Label("SCORE / MITRE ID:", classes="cyber-label")
            with Horizontal(classes="input-row"):
                yield Input(id="inp-score", type="number", placeholder="9.8",
                            classes="half-input", disabled=True)
                yield Input(id="inp-mitre", placeholder="T1548",
                            classes="half-input", disabled=True)

            yield Button("MITRE INTEL", id="btn-mitre-menu", disabled=True)

            yield Label("FINDINGS QUEUE:", classes="cyber-label")
            yield ListView(id="findings-list")

            yield Label("OPERATIONS:", classes="cyber-label")
            yield Button("COMMIT DB",     id="btn-save",    classes="btn-save",   disabled=True)
            yield Button("NEW ENTRY",     id="btn-new",                           disabled=True)
            yield Button("NIST TEMPLATE", id="btn-nist",                          disabled=True)
            yield Button("DELETE",        id="btn-del",     classes="btn-delete", disabled=True)

            yield Label("EXPORT:", classes="cyber-label")
            yield Button("EXPORT .MD",       id="btn-save-md",      disabled=True)
            yield Button("EXPORT .JSON",     id="btn-export-json",  disabled=True)
            yield Button("EXPORT .CSV",      id="btn-export-csv",   disabled=True)
            yield Button("MITRE NAVIGATOR",  id="btn-export-nav",   disabled=True)

            yield Label("SYSTEM:", classes="cyber-label")
            yield Button("FILESYSTEM", id="btn-file-mgr", disabled=True)
            yield Button("LOGOUT",     id="btn-logout",   disabled=True)
            yield Button("SHUTDOWN",   id="btn-exit")

        yield Label("SYSTEM LOCKED - AUTH REQUIRED", id="status-bar")

    def on_mount(self):
        self.crypto      = SessionCrypto()
        self.db          = Database(self.crypto)
        self.intel       = None
        self.current_id  = None

        # Route to register or login based on whether users exist
        sw = self.query_one("#view-switcher")
        if not self.db.has_users():
            sw.current = "register-view"
            self.update_status("FIRST RUN: REGISTER YOUR ADMIN ACCOUNT", CyberColors.AMBER_WARNING)
        else:
            # Attempt session resume
            if self.db.resume_session():
                self._post_login_setup()
            else:
                sw.current = "login-view"

    # -------------------------------------------------------------------------
    # AUTH FLOW
    # -------------------------------------------------------------------------

    @on(RegisterView.RegisterSuccess)
    def on_register_success(self):
        self.update_status("REGISTRATION COMPLETE — AUTHENTICATE NOW", CyberColors.PHOSPHOR_GREEN)
        self.query_one("#view-switcher").current = "login-view"

    @on(LoginView.LoginSuccess)
    def on_login_success(self):
        self._post_login_setup()

    def _post_login_setup(self):
        user = self.db.current_user
        role_label = user.role.upper() if user else "UNKNOWN"
        uname = user.username if user else "?"
        self.update_status(
            f"ACCESS GRANTED [{role_label}] — {uname}", CyberColors.PHOSPHOR_GREEN)
        self.intel = IntelligenceEngine()
        self.query_one("#view-switcher").current = "editor-view"
        self.query_one("#hud-header").current_file = "NEW BUFFER"
        self.query_one("#editor-main").focus()
        self.query_one("#info-user").update(f"{uname}\n[{role_label}]")
        self.unlock_ui()
        os.makedirs("05-Delivery", exist_ok=True)
        self.refresh_list()

    def unlock_ui(self):
        user = self.db.current_user
        for widget in self.query("#lateral-tools Input"):
            widget.disabled = False
        for widget in self.query("#lateral-tools Button"):
            widget.disabled = False
        self.query_one("#hud-project-input").disabled = False

        # Restrict delete to LEAD+
        if user and not role_gte(user.role, Role.LEAD):
            self.query_one("#btn-del").disabled = True

    def action_logout(self):
        self.db.logout()
        self.current_id = None
        self.intel = None
        for widget in self.query("#lateral-tools Input"):
            widget.disabled = True
        for widget in self.query("#lateral-tools Button"):
            widget.disabled = True
        self.query_one("#btn-exit").disabled = False
        self.query_one("#info-user").update("LOCKED")
        self.query_one("#view-switcher").current = "login-view"
        self.update_status("LOGGED OUT — SESSION TERMINATED", CyberColors.AMBER_WARNING)

    # -------------------------------------------------------------------------
    # VIEW NAVIGATION
    # -------------------------------------------------------------------------

    def action_quit_app(self):
        self.query_one("#view-switcher").current = "shutdown-view"
        self.update_status("WARNING: TERMINATION REQUESTED", CyberColors.RED_ALERT)

    def update_status(self, msg, color="#ffffff"):
        bar = self.query_one("#status-bar")
        ts  = datetime.now().strftime('%H:%M:%S')
        bar.update(f"[{ts}] {msg}")
        bar.styles.color = color

    def action_toggle_file_manager(self):
        if not self.db.current_user: return
        sw = self.query_one("#view-switcher")
        if sw.current == "fm-view":
            self.action_return_to_editor()
        else:
            sw.current = "fm-view"
            self.query_one("FileManagerView")._focus_tree()
            self.update_status("MODE: FILESYSTEM", CyberColors.ELECTRIC_CYAN)

    def action_toggle_mitre_view(self):
        if not self.db.current_user: return
        sw = self.query_one("#view-switcher")
        if sw.current == "mitre-view":
            self.action_return_to_editor()
        else:
            sw.current = "mitre-view"
            self.query_one("MitreIntelligenceView").focus_search()
            self.update_status("MODE: INTELLIGENCE LOOKUP", CyberColors.ELECTRIC_CYAN)

    def action_return_to_editor(self):
        if not self.db.current_user: return
        self.query_one("#view-switcher").current = "editor-view"
        self.query_one("#editor-main").focus()
        self.update_status("MODE: EDITOR", CyberColors.PHOSPHOR_GREEN)

    # -------------------------------------------------------------------------
    # PROJECT LOGIC
    # -------------------------------------------------------------------------

    @on(Input.Changed, "#hud-project-input")
    def on_project_changed(self, event):
        val = event.value.strip() or "DEFAULT"
        self.current_project_id = val
        self.new_entry()
        self.refresh_list()
        self.update_status(f"PROJECT ACTIVE: {self.current_project_id}", CyberColors.ELECTRIC_CYAN)

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
        elif bid == "btn-export-json":  self.export_format("json")
        elif bid == "btn-export-csv":   self.export_format("csv")
        elif bid == "btn-export-nav":   self.export_format("navigator")
        elif bid == "btn-file-mgr":     self.action_toggle_file_manager()
        elif bid == "btn-mitre-menu":   self.action_toggle_mitre_view()
        elif bid == "btn-nist":         self.load_nist_template()

    def load_nist_template(self):
        self.new_entry()
        template = NIST_800_115_SKELETON.replace("[DATE]", datetime.now().strftime("%Y-%m-%d"))
        self.query_one("#editor-main").load_text(template)
        self.query_one("#inp-title").value = f"NIST_Report_{self.current_project_id}"
        self.update_status("NIST TEMPLATE LOADED", CyberColors.PHOSPHOR_GREEN)

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
        try:
            self.update_risk(float(event.value))
        except Exception:
            pass

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
        try:
            score = float(self.query_one("#inp-score").value)
        except Exception:
            score = 0.0

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
            else:
                self.current_id = self.db.add_finding(f)
            self.refresh_list()
            self.update_status("DATABASE SYNCED", CyberColors.PHOSPHOR_GREEN)
        except PermissionError as e:
            self.update_status(f"PERMISSION DENIED: {e}", CyberColors.RED_ALERT)

    def new_entry(self):
        self.current_id = None
        self.query_one("#inp-title").value  = ""
        self.query_one("#inp-score").value  = "0.0"
        self.query_one("#inp-mitre").value  = ""
        self.query_one("#inp-vector").value = ""
        self.query_one("#editor-main").load_text("")
        self.query_one("#hud-header").current_file = "NEW BUFFER"
        self.update_risk(0.0)

    def delete_entry(self):
        if not self.current_id: return
        try:
            self.db.delete_finding(self.current_id)
            self.new_entry()
            self.refresh_list()
            self.update_status("FINDING DELETED", CyberColors.AMBER_WARNING)
        except PermissionError as e:
            self.update_status(f"PERMISSION DENIED: {e}", CyberColors.RED_ALERT)

    # -------------------------------------------------------------------------
    # FILE MANAGER
    # -------------------------------------------------------------------------

    @on(FileManagerView.FileSelected)
    def on_file(self, event):
        success, content, _ = FileSystemService.read_file(event.path)
        if success:
            self.new_entry()
            self.query_one("#editor-main").load_text(content)
            self.query_one("#inp-title").value = event.path.name
            self.query_one("#view-switcher").current = "editor-view"

    # -------------------------------------------------------------------------
    # EXPORTS
    # -------------------------------------------------------------------------

    def export_md(self):
        try:
            content = self.db.export_markdown(self.current_project_id)
            title = self.current_project_id.replace(" ", "_") + ".md"
            path  = Path("05-Delivery") / title
            FileSystemService.atomic_write(path, content)
            self.update_status(f"EXPORTED MD: {title}", CyberColors.PHOSPHOR_GREEN)
        except PermissionError as e:
            self.update_status(f"PERMISSION DENIED: {e}", CyberColors.RED_ALERT)

    def export_format(self, fmt: str):
        try:
            pid = self.current_project_id
            if fmt == "json":
                content = self.db.export_json(pid)
                ext = ".json"
            elif fmt == "csv":
                content = self.db.export_csv(pid)
                ext = ".csv"
            elif fmt == "navigator":
                content = self.db.export_mitre_navigator(pid)
                ext = "_navigator.json"
            else:
                return
            fname = pid.replace(" ", "_") + ext
            path  = Path("05-Delivery") / fname
            FileSystemService.atomic_write(path, content)
            self.update_status(f"EXPORTED: {fname}", CyberColors.PHOSPHOR_GREEN)
        except PermissionError as e:
            self.update_status(f"PERMISSION DENIED: {e}", CyberColors.RED_ALERT)

if __name__ == '__main__':
    if sys.platform == "win32":
        os.system("cls")
    else:
        os.system("clear")
    CyberTUI().run()