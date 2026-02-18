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

from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, Button, Label
from textual.message import Message


class TabItem(Static):
    """Individual tab item."""
    
    class Selected(Message):
        """Tab was selected."""
        def __init__(self, tab_id: str, tab_name: str):
            self.tab_id = tab_id
            self.tab_name = tab_name
            super().__init__()
    
    DEFAULT_CSS = """
    TabItem {
        width: 1fr;
        height: 3;
        border: solid $accent;
        padding: 0 1;
        background: $panel;
    }
    
    TabItem.active {
        background: $boost;
        border-top: heavy $accent;
        color: #FFB86B;
    }
    
    TabItem:hover {
        background: $boost;
    }
    
    TabItem Label {
        width: 100%;
        content-align: center middle;
        text-style: bold;
    }
    """
    
    def __init__(self, tab_id: str, tab_name: str, keybinding: str = None):
        super().__init__()
        self.tab_id = tab_id
        self.tab_name = tab_name
        self.keybinding = keybinding
        self.is_active = False
        self.add_class("tab-item")
    
    def render(self):
        """Render the tab with optional keybinding."""
        if self.keybinding:
            return f"{self.tab_name}\n[{self.keybinding}]"
        return self.tab_name
    
    def on_click(self, _event):
        """Handle click."""
        self.post_message(self.Selected(self.tab_id, self.tab_name))
    
    def set_active(self, active: bool):
        """Set tab active state."""
        self.is_active = active
        self.set_class(active, "active")


class TabGroup(Container):
    """Group of related tabs."""
    
    DEFAULT_CSS = """
    TabGroup {
        height: auto;
        border: solid $accent;
        padding: 1 0;
        background: $panel;
    }
    
    TabGroup .tab-group-label {
        width: 100%;
        height: 1;
        background: $boost;
        color: #FFB86B;
        text-style: bold;
        content-align: left middle;
        padding-left: 1;
    }
    
    TabGroup .tab-container {
        width: 100%;
        height: auto;
    }
    """
    
    def __init__(self, group_name: str, tabs_data: list):
        """
        Initialize tab group.
        
        Args:
            group_name: Name of this tab group (e.g., "Core UI Navigation")
            tabs_data: List of dicts with keys: id, name, keybinding
        """
        super().__init__()
        self.group_name = group_name
        self.tabs_data = tabs_data
        self.tabs = {}
        self.current_tab = None
    
    def compose(self):
        """Compose tab group."""
        yield Label(self.group_name, classes="tab-group-label")
        
        with Horizontal(classes="tab-container"):
            for tab_data in self.tabs_data:
                tab = TabItem(
                    tab_id=tab_data["id"],
                    tab_name=tab_data["name"],
                    keybinding=tab_data.get("keybinding")
                )
                self.tabs[tab_data["id"]] = tab
                yield tab
    
    def set_active_tab(self, tab_id: str | None):
        """Set active tab by ID."""
        if self.current_tab:
            self.tabs[self.current_tab].set_active(False)
            self.current_tab = None
        if tab_id in self.tabs:
            self.tabs[tab_id].set_active(True)
            self.current_tab = tab_id


class TabNavigationPanel(Container):
    """Two-level nav: one row of groups and one row of tabs for selected group."""
    
    DEFAULT_CSS = """
    TabNavigationPanel {
        height: auto;
        border: none;
        background: $surface;
        overflow-y: auto;
    }
    """
    
    class TabSelected(Message):
        """Tab was selected."""
        def __init__(self, view_id: str, view_name: str):
            self.view_id = view_id
            self.view_name = view_name
            super().__init__()
    
    def __init__(self, *, name=None, id=None, classes=None, disabled=False):
        super().__init__(name=name, id=id, classes=classes, disabled=disabled)
        self.group_buttons = {}
        self.context_buttons = {}
        self.context_button_views = {}
        self.view_mapping = {}
        self.view_to_group = {}
        self.active_group = None
        self.active_view = None
        self.max_tabs = 10
        self.group_short_labels = {
            "Core UI Navigation": "Core",
            "Analytics Views": "Analytics",
            "Advanced Views": "Advanced",
            "Phase 3-5 Views": "Reporting & Team Ops",
            "Phase 5.5 Cognition": "Cognition",
        }

        # Five top-level groups. Tabs shown in second row depend on selected group.
        self.categories = {
            "Core UI Navigation": [
                {"id": "editor-view", "name": "Editor", "keybinding": "Esc"},
                {"id": "fm-view", "name": "Files", "keybinding": "Space"},
                {"id": "mitre-view", "name": "MITRE DB", "keybinding": "Ctrl+M"},
                {"id": "campaign-view", "name": "Campaign", "keybinding": "Ctrl+K"},
                {"id": "cmdlog-view", "name": "Cmd Log", "keybinding": "Ctrl+E"},
                {"id": "session-view", "name": "Sessions", "keybinding": "Ctrl+J"},
                {"id": "detection-view", "name": "Detections", "keybinding": "Ctrl+D"},
                {"id": "objective-view", "name": "Objectives", "keybinding": "Ctrl+O"},
                {"id": "persistence-view", "name": "Persistence", "keybinding": "Ctrl+P"},
            ],
            "Analytics Views": [
                {"id": "graph-view", "name": "Graph", "keybinding": "Ctrl+G"},
                {"id": "timeline-view", "name": "Timeline", "keybinding": "Ctrl+Y"},
                {"id": "dashboard-view", "name": "Dashboard", "keybinding": "Ctrl+1"},
                {"id": "analysis-view", "name": "Analysis", "keybinding": "Ctrl+2"},
                {"id": "remediation-view", "name": "Remediation", "keybinding": "Ctrl+4"},
                {"id": "capability-view", "name": "Capability", "keybinding": "Ctrl+5"},
            ],
            "Advanced Views": [
                {"id": "collab-view", "name": "Collaboration", "keybinding": "Alt+1"},
                {"id": "task-view", "name": "Tasks", "keybinding": "Alt+2"},
                {"id": "analytics-view", "name": "Analytics", "keybinding": "Alt+3"},
                {"id": "integration-view", "name": "Integration", "keybinding": "Alt+4"},
                {"id": "compliance-view", "name": "Compliance", "keybinding": "Alt+5"},
                {"id": "security-view", "name": "Security", "keybinding": "Alt+6"},
            ],
            "Phase 3-5 Views": [
                {"id": "reporting-view", "name": "Reporting", "keybinding": "Ctrl+R"},
                {"id": "team-view", "name": "Teams", "keybinding": "Ctrl+T"},
                {"id": "users-view", "name": "Users", "keybinding": "Admin"},
                {"id": "threat-intel-view", "name": "Threat Intel", "keybinding": "Ctrl+Shift+I"},
            ],
            "Phase 5.5 Cognition": [
                {"id": "cognition-opportunities", "name": "Opportunities", "keybinding": "Ctrl+Shift+1"},
                {"id": "cognition-paths", "name": "Paths", "keybinding": "Ctrl+Shift+2"},
                {"id": "cognition-state", "name": "State", "keybinding": "Ctrl+Shift+3"},
                {"id": "cognition-detection", "name": "Pressure", "keybinding": "Ctrl+Shift+4"},
                {"id": "cognition-confidence", "name": "Confidence", "keybinding": "Ctrl+Shift+5"},
                {"id": "cognition-knowledge", "name": "Knowledge", "keybinding": "Ctrl+Shift+6"},
                {"id": "cognition-techniques", "name": "Techniques", "keybinding": "Ctrl+Shift+7"},
                {"id": "cognition-validation", "name": "Validation", "keybinding": "Ctrl+Shift+8"},
                {"id": "cognition-explain", "name": "Explain", "keybinding": "Ctrl+Shift+9"},
                {"id": "cognition-dashboard", "name": "Dashboard", "keybinding": "Ctrl+Shift+0"},
            ],
        }
        for group_name, tabs in self.categories.items():
            for tab in tabs:
                self.view_to_group[tab["id"]] = group_name
    
    def compose(self):
        """Compose group selector row and fixed tab slots for active group."""
        with Horizontal(id="tab-group-selector"):
            for idx, group_name in enumerate(self.categories.keys()):
                short_label = self.group_short_labels.get(group_name, group_name)
                btn = Button(short_label, id=f"tab-group-btn-{idx}", classes="tab-group-btn")
                btn.tooltip = group_name
                self.group_buttons[group_name] = btn
                yield btn

        with Horizontal(id="tab-context-row", classes="tab-row"):
            for idx in range(self.max_tabs):
                btn = Button("", id=f"tab-slot-{idx}", classes="tab-view-btn")
                btn.visible = False
                self.context_buttons[idx] = btn
                yield btn

        yield Label("ACTIVE: NONE", id="tab-active-caption")

    def on_mount(self):
        if self.categories:
            self.set_active_group(next(iter(self.categories.keys())))

    def on_button_pressed(self, event: Button.Pressed):
        button_id = event.button.id or ""
        if button_id.startswith("tab-group-btn-"):
            group_index = int(button_id.rsplit("-", 1)[-1])
            group_name = list(self.categories.keys())[group_index]
            self.set_active_group(group_name)
            return
        if button_id.startswith("tab-slot-"):
            slot = int(button_id.rsplit("-", 1)[-1])
            view_id = self.context_button_views.get(slot)
            if not view_id:
                return
            view_name = self.view_mapping.get(view_id, view_id)
            self.post_message(self.TabSelected(view_id, view_name))

    def set_active_group(self, group_name: str):
        """Show tabs for selected group and mark group button active."""
        if group_name not in self.categories:
            return
        self.active_group = group_name
        for name, btn in self.group_buttons.items():
            btn.set_class(name == group_name, "active")
        self._populate_group_slots(group_name)

    def _populate_group_slots(self, group_name: str):
        """Update fixed slots to display tabs for selected group."""
        tabs = self.categories.get(group_name, [])
        self.context_button_views = {}

        for idx in range(self.max_tabs):
            btn = self.context_buttons[idx]
            if idx < len(tabs):
                tab = tabs[idx]
                tab_name = tab["name"]
                view_id = tab["id"]
                self.view_mapping[view_id] = tab_name
                self.context_button_views[idx] = view_id
                btn.label = tab_name
                btn.tooltip = tab.get("keybinding") or ""
                btn.visible = True
                btn.remove_class("active")
                if view_id == self.active_view:
                    btn.add_class("active")
            else:
                btn.visible = False
                btn.label = ""
                btn.tooltip = ""
                btn.remove_class("active")

        active_label = None
        for idx, view_id in self.context_button_views.items():
            if view_id == self.active_view:
                active_label = str(self.context_buttons[idx].label)
                break
        if active_label:
            self.query_one("#tab-active-caption", Label).update(f"ACTIVE: {active_label}")
        else:
            self.query_one("#tab-active-caption", Label).update(f"GROUP: {group_name}")
    
    def set_active_view(self, view_id: str):
        """Set active tab and switch to its parent group if needed."""
        self.active_view = view_id
        group_name = self.view_to_group.get(view_id)
        if group_name:
            self.set_active_group(group_name)


class TabNavigationBar(Container):
    """Compact horizontal tab bar (alternative to full panel)."""
    
    DEFAULT_CSS = """
    TabNavigationBar {
        height: 6;
        background: $panel;
        border: solid $accent;
        padding: 0;
    }

    TabNavigationBar .tab-rows {
        width: 100%;
        height: 100%;
    }

    TabNavigationBar .tab-row {
        width: 100%;
        height: 1fr;
    }
    
    TabNavigationBar .tab-item-compact {
        width: 1fr;
        min-width: 0;
        height: 1fr;
        min-height: 1;
        border: none;
        background: $surface;
        color: $text;
        text-style: none;
        content-align: center middle;
    }
    
    TabNavigationBar .tab-item-compact.active {
        background: $boost;
        color: #FFB86B;
        text-style: bold;
    }
    
    TabNavigationBar .tab-item-compact:hover {
        background: $boost;
    }
    """
    
    class TabSelected(Message):
        """Tab was selected."""
        def __init__(self, view_id: str):
            self.view_id = view_id
            super().__init__()
    
    def __init__(self, *, name=None, id=None, classes=None, disabled=False):
        super().__init__(name=name, id=id, classes=classes, disabled=disabled)
        # Define compact tab items (most important views)
        self.tabs = {
            "editor-view": ("Edit", "Esc"),
            "campaign-view": ("Camp", "Ctrl+K"),
            "graph-view": ("Graph", "Ctrl+G"),
            "timeline-view": ("Time", "Ctrl+Y"),
            "cmdlog-view": ("CmdLog", "Ctrl+E"),
            "session-view": ("Sess", "Ctrl+J"),
            "detection-view": ("Detect", "Ctrl+D"),
            "objective-view": ("Obj", "Ctrl+O"),
            "dashboard-view": ("Dash", "Ctrl+1"),
            "threat-intel-view": ("Intel", "Ctrl+Shift+I"),
            "reporting-view": ("Rpt", "Ctrl+R"),
            "users-view": ("Users", "Admin"),
            "cognition-opportunities": ("Opp", "Ctrl+Shift+1"),
            "cognition-paths": ("Paths", "Ctrl+Shift+2"),
            "cognition-state": ("State", "Ctrl+Shift+3"),
            "cognition-detection": ("Press", "Ctrl+Shift+4"),
            "cognition-confidence": ("Conf", "Ctrl+Shift+5"),
            "cognition-knowledge": ("Know", "Ctrl+Shift+6"),
            "cognition-techniques": ("Tech", "Ctrl+Shift+7"),
            "cognition-validation": ("Valid", "Ctrl+Shift+8"),
            "cognition-explain": ("Expl", "Ctrl+Shift+9"),
            "cognition-dashboard": ("CDash", "Ctrl+Shift+0"),
        }
        self.current_tab = None
    
    def compose(self):
        """Compose compact tab bar."""
        tab_items = list(self.tabs.items())
        split = (len(tab_items) + 1) // 2
        top_row = tab_items[:split]
        bottom_row = tab_items[split:]

        with Vertical(classes="tab-rows"):
            with Horizontal(classes="tab-row"):
                for view_id, (name, keybinding) in top_row:
                    button = Button(name, id=f"tab-{view_id}")
                    button.tooltip = keybinding
                    button.classes = "tab-item-compact"
                    yield button
            with Horizontal(classes="tab-row"):
                for view_id, (name, keybinding) in bottom_row:
                    button = Button(name, id=f"tab-{view_id}")
                    button.tooltip = keybinding
                    button.classes = "tab-item-compact"
                    yield button
    
    def set_active_tab(self, view_id: str):
        """Set active tab."""
        if self.current_tab:
            try:
                old_btn = self.query_one(f"#tab-{self.current_tab}")
                old_btn.remove_class("active")
            except:
                pass
        
        try:
            new_btn = self.query_one(f"#tab-{view_id}")
            new_btn.add_class("active")
            self.current_tab = view_id
        except:
            pass


class TabNavigationContainer(Container):
    """Container with both tab bar and main content area."""
    
    DEFAULT_CSS = """
    TabNavigationContainer {
        width: 100%;
        height: 100%;
        border: none;
    }
    
    TabNavigationContainer .tab-bar {
        width: 100%;
        height: auto;
        border-bottom: solid $accent;
    }
    
    TabNavigationContainer .tab-sidebar {
        width: 30;
        height: 100%;
        border-right: solid $accent;
        overflow-y: auto;
    }
    
    TabNavigationContainer .tab-content {
        width: 1fr;
        height: 100%;
        border: none;
    }
    """
    
    def __init__(
        self,
        content_switcher_id: str = "view-switcher",
        *,
        name=None,
        id=None,
        classes=None,
        disabled=False,
    ):
        """
        Initialize container.
        
        Args:
            content_switcher_id: ID of the ContentSwitcher widget to control
        """
        super().__init__(name=name, id=id, classes=classes, disabled=disabled)
        self.content_switcher_id = content_switcher_id
        self.nav_panel = None
