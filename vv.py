import os
import sys
import asyncio
from datetime import datetime
from pathlib import Path

# Textual TUI
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    ListView, ListItem, Label, Input, 
    TextArea, Button, Static, ContentSwitcher, DataTable
)
from textual.binding import Binding
from textual.screen import Screen, ModalScreen
from textual.reactive import reactive
from textual.message import Message

# Custom Modules
try:
    from vv_core import Database, Finding, IntelligenceEngine, CVSSCalculator, NIST_800_115_SKELETON
    from vv_fs import FileSystemService
    from vv_file_manager import FileManagerView
    from vv_theme import CYBER_CSS, CyberColors
except ImportError as e:
    print(f"CRITICAL: Dependency missing. {e}")
    sys.exit(1)

# --- CUSTOM WIDGETS & VIEWS ---

class VimDataTable(DataTable):
    """DataTable with Vim-style navigation bindings"""
    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("g", "scroll_top", "Top", show=False),
        Binding("G", "scroll_bottom", "Bottom", show=False),
        Binding("enter", "select_cursor", "Select"),
    ]

class MitreIntelligenceView(Container):
    """
    Integrated View for MITRE ATT&CK Knowledge Base.
    Replaces the modal lookup screen.
    """
    CSS = """
    MitreIntelligenceView {
        layout: vertical;
        background: $bg-void;
        height: 100%;
        border-right: heavy $e-cyan;
    }
    
    #mitre-search-bar {
        height: auto;
        padding: 1;
        background: $bg-panel;
        border-bottom: solid $steel;
    }

    #mitre-split-container {
        layout: horizontal;
        height: 1fr;
    }

    #mitre-table-pane {
        width: 1fr;
        height: 100%;
        border-right: solid $p-green;
        background: $bg-panel;
    }

    #mitre-preview-pane {
        width: 1fr;
        height: 100%;
        padding: 1;
        background: $bg-panel;
        overflow-y: auto;
        scrollbar-gutter: stable;
    }

    .mitre-header {
        color: $e-cyan;
        text-style: bold;
        border-bottom: solid $steel;
        margin-bottom: 1;
    }

    #mitre-preview-content {
        color: #ddd;
    }
    """

    class TechniqueSelected(Message):
        """Message sent when a technique is chosen."""
        def __init__(self, technique_id: str, technique_name: str) -> None:
            self.technique_id = technique_id
            self.technique_name = technique_name
            super().__init__()

    def compose(self) -> ComposeResult:
        # Search Bar
        with Container(id="mitre-search-bar"):
            yield Label("[bold cyan]MITRE ATT&CK SEARCH[/]")
            yield Input(placeholder="Search ID (T1000) or Name...", id="mitre-search-input")

        # Split View (Table + Preview)
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
        
        # Access IntelligenceEngine from the main App
        if hasattr(self.app, "intel"):
            results = self.app.intel.search_techniques(query)
            for t in results:
                # Store full object in key for retrieval
                dt.add_row(t.id, t.name, key=t.id)

    @on(DataTable.RowHighlighted, "#mitre-table")
    def on_row_highlighted(self, event):
        """Update preview pane when moving through the list"""
        if not event.row_key.value:
            return
            
        tech_id = event.row_key.value
        technique = self.app.intel.lookup_mitre(tech_id)
        
        preview = self.query_one("#mitre-preview-content")
        if technique:
            content = (
                f"[bold yellow]ID:[/] {technique.id}\n"
                f"[bold yellow]NAME:[/] {technique.name}\n\n"
                f"[bold white]DESCRIPTION:[/]\n{technique.description}"
            )
            preview.update(content)

    @on(DataTable.RowSelected, "#mitre-table")
    def on_row_selected(self, event):
        """Handle selection (Enter/Click)"""
        tech_id = event.row_key.value
        technique = self.app.intel.lookup_mitre(tech_id)
        if technique:
            self.post_message(self.TechniqueSelected(technique.id, technique.name))

class HeaderHUD(Static):
    """Top Banner with Project & File Info"""
    current_file = reactive("NO FILE ACTIVE")
    
    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Label("VECTORVUE v2.4 [TACTICAL]", classes="hud-title")
            # Project Input in Header
            yield Label(" PROJECT:", classes="hud-label-sm")
            yield Input(value="DEFAULT", id="hud-project-input", classes="hud-input")
            yield Label(f"// BUFFER: {self.current_file}", id="hud-file-lbl", classes="hud-file")

    def watch_current_file(self, val):
        if self.is_mounted:
            try:
                self.query_one("#hud-file-lbl").update(f"// BUFFER: {val}")
            except Exception:
                pass

class ShutdownScreen(Screen):
    """Cinematic Exit Screen"""
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
        if self.app.db: self.app.db.close()
        self.query_one("#st-db").update("[LOCKED]").add_class("status-done")
        
        await asyncio.sleep(0.5)
        self.query_one("#st-fs").update("[SECURE]").add_class("status-done")
        
        await asyncio.sleep(0.5)
        self.query_one("#final-msg").visible = True
        await asyncio.sleep(0.8)
        self.app.exit()

class FindingItem(ListItem):
    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self.finding = finding

    def compose(self) -> ComposeResult:
        try:
            score = float(self.finding.cvss_score)
        except (ValueError, TypeError):
            score = 0.0
            
        score_fmt = f"{score:.1f}"
        icon = "⚡" if score >= 9.0 else "●"
        
        color = "white"
        if score >= 9.0: color = CyberColors.RED_ALERT
        elif score >= 7.0: color = CyberColors.AMBER_WARNING
        elif score >= 4.0: color = CyberColors.ELECTRIC_CYAN
        
        yield Label(f"[{color}]{icon} [{score_fmt}] {self.finding.title[:20]}[/]")

# --- MAIN APPLICATION ---

class CyberTUI(App):
    CSS = CYBER_CSS + """
    .hud-label-sm { color: #666; content-align: center middle; width: 10; padding-top: 1;}
    .hud-input { width: 20; height: 1; border: none; background: #111; color: #00FFFF; }
    .hud-input:focus { border: none; }
    """
    
    BINDINGS = [
        Binding("q", "quit_app", "Quit"),
        Binding("space", "toggle_file_manager", "Files"),
        Binding("ctrl+m", "toggle_mitre_view", "MITRE DB"),
        Binding("ctrl+s", "save_db", "Save"),
        Binding("escape", "return_to_editor", "Editor"),
    ]
    
    current_project_id = reactive("DEFAULT")

    def compose(self) -> ComposeResult:
        yield HeaderHUD(id="hud-header")
        
        # Main Viewport Switcher
        with ContentSwitcher(initial="editor-view", id="view-switcher"):
            # 1. Editor View
            with Container(id="editor-view"):
                yield TextArea(language="markdown", theme="dracula", id="editor-main")
            
            # 2. File Manager View
            yield FileManagerView(id="fm-view")

            # 3. MITRE Intelligence View (New)
            yield MitreIntelligenceView(id="mitre-view")

        # Sidebar / Tooling
        with Container(id="lateral-tools"):
            # Risk Info
            yield Label("RISK ASSESSMENT:", classes="cyber-label")
            yield Static("NO SIGNAL", id="info-severity", classes="info-box")
            
            yield Label("CVSS 3.1 SCORE:", classes="cyber-label")
            yield Static("0.0", id="info-score", classes="info-box")
            
            yield Label("MITRE MAPPING:", classes="cyber-label")
            yield Static("NONE", id="info-mitre", classes="info-box")

            # Inputs
            yield Label("VECTOR TITLE:", classes="cyber-label")
            yield Input(id="inp-title", placeholder="Vulnerability Title...")
            
            yield Label("CVSS VECTOR:", classes="cyber-label")
            yield Input(id="inp-vector", placeholder="CVSS:3.1/AV:N/AC:L...")
            
            yield Label("SCORE / MITRE ID:", classes="cyber-label")
            with Horizontal(classes="input-row"):
                yield Input(id="inp-score", type="number", placeholder="9.8", classes="half-input")
                yield Input(id="inp-mitre", placeholder="T1548", classes="half-input")
            
            yield Button("MITRE INTEL", id="btn-mitre-menu")

            yield Label("FINDINGS QUEUE:", classes="cyber-label")
            yield ListView(id="findings-list")
            
            yield Label("OPERATIONS:", classes="cyber-label")
            yield Button("COMMIT DB", id="btn-save", classes="btn-save")
            yield Button("NEW ENTRY", id="btn-new")
            yield Button("NIST TEMPLATE", id="btn-nist")
            yield Button("DELETE", id="btn-del", classes="btn-delete")
            
            yield Label("SYSTEM:", classes="cyber-label")
            yield Button("FILESYSTEM", id="btn-file-mgr")
            yield Button("EXPORT .MD", id="btn-save-md")
            yield Button("SHUTDOWN", id="btn-exit")
        
        yield Label("SYSTEM READY", id="status-bar")

    def on_mount(self):
        self.db = Database()
        self.intel = IntelligenceEngine()
        self.current_id = None
        os.makedirs("05-Delivery", exist_ok=True)
        self.refresh_list()
        self.query_one("#editor-main").focus()

    def action_quit_app(self):
        self.push_screen(ShutdownScreen())

    def update_status(self, msg, color="#ffffff"):
        bar = self.query_one("#status-bar")
        ts = datetime.now().strftime('%H:%M:%S')
        bar.update(f"[{ts}] {msg}")
        bar.styles.color = color

    # --- VIEW NAVIGATION ---
    
    def action_toggle_file_manager(self):
        sw = self.query_one("#view-switcher")
        if sw.current == "fm-view":
            self.action_return_to_editor()
        else:
            sw.current = "fm-view"
            self.query_one("FileManagerView")._focus_tree()
            self.update_status("MODE: FILESYSTEM", CyberColors.ELECTRIC_CYAN)

    def action_toggle_mitre_view(self):
        sw = self.query_one("#view-switcher")
        if sw.current == "mitre-view":
            self.action_return_to_editor()
        else:
            sw.current = "mitre-view"
            self.query_one("MitreIntelligenceView").focus_search()
            self.update_status("MODE: INTELLIGENCE LOOKUP", CyberColors.ELECTRIC_CYAN)

    def action_return_to_editor(self):
        self.query_one("#view-switcher").current = "editor-view"
        self.query_one("#editor-main").focus()
        self.update_status("MODE: EDITOR", CyberColors.PHOSPHOR_GREEN)

    # --- MITRE EVENT HANDLING ---

    @on(MitreIntelligenceView.TechniqueSelected)
    def on_mitre_selected(self, message: MitreIntelligenceView.TechniqueSelected):
        """Handler for when a user selects a technique from the integrated view"""
        # 1. Update Inputs
        self.query_one("#inp-mitre").value = message.technique_id
        
        # Only overwrite title if it's empty to avoid wiping user work
        current_title = self.query_one("#inp-title").value
        if not current_title:
            self.query_one("#inp-title").value = message.technique_name
        
        # 2. Switch back to editor
        self.action_return_to_editor()
        
        # 3. Notify
        self.update_status(f"IMPORTED: {message.technique_id}", CyberColors.ELECTRIC_CYAN)

    # --- PROJECT LOGIC ---
    @on(Input.Changed, "#hud-project-input")
    def on_project_changed(self, event):
        val = event.value.strip()
        if not val: val = "DEFAULT"
        self.current_project_id = val
        self.new_entry() # Clear editor to prevent cross-contamination
        self.refresh_list()
        self.update_status(f"PROJECT ACTIVE: {self.current_project_id}", CyberColors.ELECTRIC_CYAN)

    def refresh_list(self):
        lv = self.query_one("#findings-list", ListView)
        lv.clear() # CRITICAL: Explicitly clear before reloading
        findings = self.db.get_findings(project_id=self.current_project_id)
        for f in findings:
            lv.append(FindingItem(f))

    # --- BUTTON HANDLERS ---
    @on(Button.Pressed)
    def on_buttons(self, event):
        bid = event.button.id
        if bid == "btn-exit": self.action_quit_app()
        elif bid == "btn-save": self.save_db()
        elif bid == "btn-new": self.new_entry()
        elif bid == "btn-del": self.delete_entry()
        elif bid == "btn-save-md": self.export_md()
        elif bid == "btn-file-mgr": self.action_toggle_file_manager()
        elif bid == "btn-mitre-menu": self.action_toggle_mitre_view()
        elif bid == "btn-nist": self.load_nist_template()

    def load_nist_template(self):
        # Loads the NIST 800-115 Skeleton into the editor
        self.new_entry()
        template = NIST_800_115_SKELETON.replace("[DATE]", datetime.now().strftime("%Y-%m-%d"))
        self.query_one("#editor-main").load_text(template)
        self.query_one("#inp-title").value = f"NIST_Report_{self.current_project_id}"
        self.update_status("NIST TEMPLATE LOADED", CyberColors.PHOSPHOR_GREEN)

    # --- CORE LOGIC (CVSS, MITRE, FILES) ---
    @on(Input.Changed, "#inp-vector")
    def on_vector(self, event):
        score = CVSSCalculator.calculate(event.value)
        self.query_one("#inp-score").value = str(score)
        self.update_risk(score)

    @on(Input.Changed, "#inp-score")
    def on_score(self, event):
        try: self.update_risk(float(event.value))
        except: pass

    def update_risk(self, score):
        sev = self.query_one("#info-severity")
        sc = self.query_one("#info-score")
        sc.update(str(score))
        for c in ["risk-crit","risk-high","risk-med","risk-low"]:
            sev.remove_class(c); sc.remove_class(c)
        
        if score >= 9.0: cls="risk-crit"; txt="CRITICAL"
        elif score >= 7.0: cls="risk-high"; txt="HIGH"
        elif score >= 4.0: cls="risk-med"; txt="MEDIUM"
        else: cls="risk-low"; txt="LOW"
        
        sev.update(txt); sev.add_class(cls); sc.add_class(cls)

    # MITRE Input Handler (Direct typing in Sidebar)
    @on(Input.Changed, "#inp-mitre")
    def on_mitre_text(self, event):
        val = event.value.strip().upper()
        mbox = self.query_one("#info-mitre")
        if len(val) >= 4:
            info = self.intel.lookup_mitre(val)
            if info:
                mbox.update(f"{info.id}\n{info.name[:15]}")
                mbox.styles.border = "heavy", CyberColors.ELECTRIC_CYAN
            else:
                mbox.update("UNKNOWN"); mbox.styles.border = "solid", CyberColors.AMBER_WARNING

    def save_db(self):
        try: score = float(self.query_one("#inp-score").value)
        except: score = 0.0
        
        f = Finding(
            id=self.current_id,
            title=self.query_one("#inp-title").value or "Untitled",
            description=self.query_one("#editor-main").text,
            cvss_score=score,
            mitre_id=self.query_one("#inp-mitre").value,
            tactic_id="", status="Open",
            project_id=self.current_project_id, # STRICT PROJECT ID SAVE
            cvss_vector=self.query_one("#inp-vector").value
        )
        
        if self.current_id: self.db.update_finding(f)
        else: self.current_id = self.db.add_finding(f)
        
        self.refresh_list()
        self.update_status("DATABASE SYNCED", CyberColors.PHOSPHOR_GREEN)

    def new_entry(self):
        self.current_id = None
        self.query_one("#inp-title").value = ""
        self.query_one("#inp-score").value = "0.0"
        self.query_one("#inp-mitre").value = ""
        self.query_one("#inp-vector").value = ""
        self.query_one("#editor-main").load_text("")
        self.query_one("#hud-header").current_file = "NEW BUFFER"
        self.update_risk(0.0)

    def delete_entry(self):
        if self.current_id:
            self.db.delete_finding(self.current_id)
            self.new_entry()
            self.refresh_list()

    @on(FileManagerView.FileSelected)
    def on_file(self, event):
        success, content, _ = FileSystemService.read_file(event.path)
        if success:
            self.new_entry() # Prepare UI
            self.query_one("#editor-main").load_text(content)
            self.query_one("#inp-title").value = event.path.name
            self.query_one("#view-switcher").current = "editor-view"

    def export_md(self):
        title = self.query_one("#inp-title").value.replace(" ","_") or "Untitled"
        if not title.endswith(".md"): title += ".md"
        path = Path("05-Delivery") / title
        FileSystemService.atomic_write(path, self.query_one("#editor-main").text)
        self.update_status(f"EXPORTED: {title}", CyberColors.PHOSPHOR_GREEN)

if __name__ == '__main__':
    if sys.platform == "win32": os.system("cls")
    else: os.system("clear")
    app = CyberTUI()
    app.run()