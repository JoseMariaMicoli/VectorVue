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

from pathlib import Path
from typing import Optional

from textual import on, work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Vertical, Horizontal
from textual.widgets import DirectoryTree, Label, Input, TextArea
from textual.reactive import reactive
from textual.message import Message

from vv_fs import FileSystemService
from vv_theme import CYBER_CSS

class VimDirectoryTree(DirectoryTree):
    """Custom Directory Tree with Vim Bindings"""
    BINDINGS = [
        Binding("j", "cursor_down", "Down", show=False),
        Binding("k", "cursor_up", "Up", show=False),
        Binding("g", "scroll_home", "Top", show=False),
        Binding("G", "scroll_end", "Bottom", show=False),
        Binding("enter", "select_cursor", "Select"),
    ]

class FileManagerView(Container):
    CSS = """
    FileManagerView {
        layout: grid;
        grid-size: 2 2;
        grid-columns: 1fr 2fr;
        grid-rows: 1fr auto;
        background: $bg-void;
        height: 100%;
        border-right: heavy $e-cyan;
    }

    #fm-left-pane {
        row-span: 1;
        border-right: solid $p-green;
        background: $bg-panel;
        height: 100%;
    }

    #fm-preview-pane {
        background: $bg-panel;
        padding: 0;
        height: 100%;
        overflow-y: hidden;
    }
    
    #fm-preview-text {
        height: 100%;
        border: none;
        background: $bg-panel;
        color: $e-cyan;
    }

    #fm-status-bar {
        column-span: 2;
        height: 3;
        background: #000000;
        border-top: solid #333;
        color: #fff;
        align: left middle;
        padding-left: 1;
    }
    
    #fm-input {
        display: none;
        background: $bg-panel;
        border: none;
        color: #fff;
        width: 100%;
    }
    
    #fm-input.visible { display: block; }
    #fm-status-label { width: auto; padding-right: 1; }
    """

    BINDINGS = [
        Binding("n", "new_file", "New File"),
        Binding("N", "new_folder", "New Folder"), 
        Binding("d", "trigger_delete", "Delete"),
        Binding("r", "refresh", "Refresh"),
        Binding("escape", "cancel_action", "Cancel/Exit"),
    ]

    class FileSelected(Message):
        """Message sent when a file is selected for opening"""
        def __init__(self, path: Path):
            self.path = path
            super().__init__()

    current_mode = reactive("NAV") 
    status_msg = reactive("READY")
    selected_path: Optional[Path] = None
    action_pending: Optional[str] = None 

    def compose(self) -> ComposeResult:
        with Vertical(id="fm-left-pane"):
            yield Label("[bold cyan]PROJECT FILES[/]")
            yield VimDirectoryTree("./", id="fm-tree")
        
        with Vertical(id="fm-preview-pane"):
            yield Label("[bold yellow]PREVIEW[/]")
            yield TextArea("", id="fm-preview-text", read_only=True, language="markdown")

        with Horizontal(id="fm-status-bar", classes="mode-nav"):
            yield Label("READY", id="fm-status-label")
            yield Input(id="fm-input", placeholder="Enter filename...")

    def on_mount(self):
        self.call_after_refresh(self._focus_tree)
        self._update_status("NAVIGATION MODE - [j/k] Move, [Enter] Open, [n] New, [d] Delete")

    def _focus_tree(self):
        self.query_one("#fm-tree").focus()

    def watch_current_mode(self, mode: str):
        bar = self.query_one("#fm-status-bar")
        bar.remove_class("mode-nav", "mode-input", "mode-confirm")
        
        inp = self.query_one("#fm-input")
        inp.remove_class("visible")

        if mode == "NAV":
            bar.add_class("mode-nav")
            self.query_one("#fm-tree").focus()
        elif mode == "INPUT":
            bar.add_class("mode-input")
            inp.add_class("visible")
            inp.focus()
        elif mode == "CONFIRM":
            bar.add_class("mode-confirm")
            self.query_one("#fm-tree").focus()

    def on_directory_tree_node_highlighted(self, event: DirectoryTree.NodeHighlighted):
        if event.node.data:
            self.selected_path = event.node.data.path
            self._load_preview(self.selected_path)

    @on(DirectoryTree.FileSelected)
    def on_file_selected(self, event):
        # Propagate the event to the Main App
        self.post_message(self.FileSelected(event.path))

    @work(exclusive=True, thread=True)
    def _load_preview(self, path: Path):
        if path.is_dir():
            try:
                count = len(list(path.iterdir()))
                info = f"Directory: {path.name}\nItems: {count}\nPath: {path}"
            except PermissionError:
                info = "Directory: Access Denied"
            
            self.app.call_from_thread(self.query_one("#fm-preview-text", TextArea).load_text, info)
            return
        
        success, content, _ = FileSystemService.read_file(path)
        if success:
            preview_content = content[:2000]
            if len(content) > 2000: preview_content += "\n\n... [TRUNCATED PREVIEW] ..."
            self.app.call_from_thread(self.query_one("#fm-preview-text", TextArea).load_text, preview_content)
        else:
            self.app.call_from_thread(self.query_one("#fm-preview-text", TextArea).load_text, f"No Preview: {content}")

    def action_new_file(self):
        self.action_pending = "create_file"
        self.current_mode = "INPUT"
        self._update_status("NEW FILE: Enter name")

    def action_new_folder(self):
        self.action_pending = "create_dir"
        self.current_mode = "INPUT"
        self._update_status("NEW FOLDER: Enter name")

    def action_trigger_delete(self):
        if not self.selected_path: return
        self.action_pending = "delete"
        self.current_mode = "CONFIRM"
        self._update_status(f"DELETE {self.selected_path.name}? [y/n]")

    def action_cancel_action(self):
        if self.current_mode == "NAV": return 
        self.current_mode = "NAV"
        self.query_one("#fm-input").value = ""
        self._update_status("Cancelled.")

    def action_refresh(self):
        self.query_one("#fm-tree", DirectoryTree).reload()
        self._update_status("Refreshed.")

    @on(Input.Submitted)
    def handle_input(self, event: Input.Submitted):
        val = event.value.strip()
        if not val: return

        if self.selected_path:
            base = self.selected_path.parent if self.selected_path.is_file() else self.selected_path
        else:
            base = Path(".")
        
        target = base / val
        success, msg = False, ""

        if self.action_pending == "create_file":
            if not val.endswith(".md"): target = base / f"{val}.md"
            success, msg = FileSystemService.create_node(target, False)
        elif self.action_pending == "create_dir":
            success, msg = FileSystemService.create_node(target, True)

        self._finalize_action(success, msg)

    def on_key(self, event):
        if self.current_mode == "CONFIRM":
            if event.key == "y":
                success, msg = FileSystemService.delete_node(self.selected_path)
                self._finalize_action(success, msg)
            elif event.key == "n":
                self.action_cancel_action()

    def _finalize_action(self, success: bool, msg: str):
        self.query_one("#fm-tree", DirectoryTree).reload()
        self.current_mode = "NAV"
        self.query_one("#fm-input").value = ""
        self._update_status(f"[{'SUCCESS' if success else 'ERROR'}] {msg}")

    def _update_status(self, msg: str):
        self.query_one("#fm-status-label").update(msg)