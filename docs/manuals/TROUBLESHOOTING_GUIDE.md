# Troubleshooting Guide

![Level](https://img.shields.io/badge/Level-L1_Support-orange?style=flat-square)

This guide provides diagnostic steps and resolutions for common issues encountered during the operation of VectorVue v2.1.

## 1. Visual Anomalies

### Symptom: "Rectangles instead of Icons"
*   **Description:** The UI displays `[]` or `?` blocks instead of lightning bolts (`⚡`) or dots (`●`).
*   **Root Cause:** The terminal font does not support Unicode glyphs or Nerd Fonts.
*   **Resolution:**
    1.  Download a Nerd Font (e.g., **JetBrains Mono Nerd Font**).
    2.  Install the font on your OS.
    3.  Configure your terminal emulator to use this font.

### Symptom: "No Syntax Highlighting"
*   **Description:** The Markdown editor text is monochrome (white/grey) instead of colored.
*   **Root Cause:** The `tree-sitter` bindings were not installed during setup.
*   **Resolution:**
    Execute the following command in your virtual environment:
    ```bash
    pip install textual[syntax]
    ```

## 2. Runtime Errors

### Error: `ImportError: Dependency missing`
*   **Description:** The application crashes immediately upon launch with a critical error message.
*   **Root Cause:** The auxiliary Python modules (`vv_core.py`, `vv_fs.py`, etc.) are not in the same directory as `vv.py`.
*   **Resolution:** Ensure all `vv_*.py` files are located in the root execution directory.

### Error: `sqlite3.OperationalError: database is locked`
*   **Description:** The application freezes or crashes when clicking "COMMIT DB".
*   **Root Cause:** Another process (e.g., DB Browser for SQLite) has an exclusive lock on `vectorvue.db`.
*   **Resolution:**
    1.  Close any external database viewers.
    2.  If the issue persists, delete the `.db-journal` or `.db-wal` files in the directory (ensure the app is closed first).

## 3. Data Issues

### Symptom: "Unknown format code 'f' for object of type 'str'"
*   **Description:** Crash when rendering the Findings List.
*   **Root Cause:** Legacy data in the database stored the CVSS score as a raw string instead of a float.
*   **Resolution:** This is patched in v2.1 via the `FindingItem` class using explicit type casting. Update your `vv.py` file to the latest version.

---
**Still stuck?** Check the terminal output logs for Python tracebacks and report them to the development team.
