# VectorVue v3.0 Troubleshooting Guide

![Level](https://img.shields.io/badge/Level-L1_Support-39FF14?style=flat-square) ![Version](https://img.shields.io/badge/Version-3.0-00FFFF?style=flat-square)

Diagnostic steps and resolutions for issues encountered during VectorVue v3.0 operation. This guide covers authentication, database, cryptography, file I/O, and MITRE lookup problems.

---

## 1. Authentication & Login Issues

### "Not Authenticated" Error on Startup
**Symptom:** Application shows "Not Authenticated" and prevents any operations  
**Root Cause:** User session expired or session table corrupted

**Resolution:**
1. Log out completely (press `Q`)
2. Close application
3. Log back in with valid credentials
4. Session will be re-established

### "Username not found" When Logging In
**Symptom:** Login fails with "User does not exist"  
**Root Cause:** User account not created (first admin must be created at startup)

**Resolution:**
1. First launch should prompt to create admin user
2. If missed, delete `vectorvue.db` and restart:
   ```bash
   rm vectorvue.db
   python3 vv.py
   # Follow admin creation prompt
   ```
3. Once admin exists, use ADMIN view to create additional users

### "Campaign Not Found" After Login
**Symptom:** Login succeeds but campaign context is missing  
**Root Cause:** User has no campaigns assigned or first campaign not created

**Resolution:**
1. Create first campaign (Ctrl+N)
   - Fill in: Name, Client, Team, Objective
   - Save (Ctrl+S)
2. Campaign is now active and all views will refresh
3. To switch campaigns, press Ctrl+C to view all campaigns

### "Wrong Password" Error Persists
**Symptom:** Correct password rejected repeatedly  
**Root Cause:** Cached credentials or password hash corruption

**Resolution:**
1. Clear terminal buffer (Ctrl+L)
2. Try again with CAPS LOCK off
3. If persistent, reset admin password:
   ```bash
   # As ADMIN: Delete user and recreate
   sqlite3 vectorvue.db "DELETE FROM users WHERE username='USERNAME';"
   # Restart app to create new admin
   ```

---

## 2. Database Integrity Issues

### "sqlite3.OperationalError: database is locked"
**Symptom:** Application freezes when creating/saving findings  
**Root Cause:** Another process holds exclusive lock on `vectorvue.db`

**Resolution:**
1. Close any external database browsers (DB Browser for SQLite, etc.)
2. Check for stale processes:
   ```bash
   ps aux | grep "vv.py"
   kill -9 [PID]  # Force terminate if needed
   ```
3. Remove journal files:
   ```bash
   rm -f vectorvue.db-journal vectorvue.db-wal
   ```
4. Restart application

### "UNIQUE constraint failed"
**Symptom:** Error when creating finding or asset with duplicate name  
**Root Cause:** Same title already exists in campaign (unique constraint violation)

**Resolution:**
1. Use different name/title for new finding
2. Or rename existing finding first
3. No duplicates allowed per campaign

### "Foreign Key Constraint Failed"
**Symptom:** Error when saving finding or asset  
**Root Cause:** Referenced campaign or user doesn't exist

**Resolution:**
1. Ensure campaign is created first (Ctrl+N)
2. Ensure you're logged in as valid user
3. Check campaign_id in findings table matches existing campaign

### Database Corrupted / Won't Start
**Symptom:** Application crashes with SQLite error on launch  
**Root Cause:** Corrupted database file (partial write, disk full, etc.)

**Resolution:**
1. Backup existing database:
   ```bash
   cp vectorvue.db vectorvue.db.backup
   ```
2. Attempt repair:
   ```bash
   sqlite3 vectorvue.db "PRAGMA integrity_check;"
   ```
3. If repair fails, delete and recreate:
   ```bash
   rm vectorvue.db vectorvue.db-wal vectorvue.db-journal
   python3 vv.py  # Recreate schema
   ```
4. Note: All data will be lost; restore from backup if available

---

## 3. Cryptography & Encryption Issues

### "PBKDF2 Key Derivation Failed"
**Symptom:** Passwords rejected after password reset  
**Root Cause:** Salt file corrupted or wrong Python version

**Resolution:**
1. Verify Python version >= 3.10:
   ```bash
   python3 --version
   ```
2. Check salt file exists:
   ```bash
   ls -la vectorvue.salt
   ```
3. If missing, delete and recreate:
   ```bash
   rm vectorvue.salt
   python3 vv.py  # Recreate salt
   ```

### "Fernet Key Invalid"
**Symptom:** Cannot decrypt credentials or evidence  
**Root Cause:** Encryption key derivation failure or database moved between systems

**Resolution:**
1. Ensure `vectorvue.salt` is in same directory as `vectorvue.db`
2. Verify file permissions:
   ```bash
   chmod 600 vectorvue.salt  # Owner read/write only
   ```
3. Ensure Python cryptography module is installed:
   ```bash
   pip install cryptography
   ```

### "Evidence Hash Mismatch"
**Symptom:** Evidence displays warning "Hash Mismatch"  
**Root Cause:** Evidence file was modified after collection (integrity violation)

**Resolution:**
1. This is intentional (immutability by design)
2. Check activity_log for who modified it:
   - Press V to view timeline
   - Look for modification entry
3. Original file cannot be recovered (immutable)
4. If error, ask LEAD to reject finding and recreate with correct evidence

---

## 4. File I/O & Atomic Write Failures

### "Atomic Write Failed: Permission Denied"
**Symptom:** Cannot save findings or export reports  
**Root Cause:** No write permission to directory

**Resolution:**
```bash
# Check directory permissions
ls -ld /home/xoce/Workspace/VectorVue

# Fix if needed
chmod 755 /home/xoce/Workspace/VectorVue

# Or change to different directory with write perms
cd ~
python3 /path/to/vv.py
```

### "Disk Full" During Report Export
**Symptom:** Report generation fails halfway through  
**Root Cause:** Not enough disk space

**Resolution:**
1. Check disk usage:
   ```bash
   df -h
   ```
2. Free up space or move to different drive
3. Try exporting smaller campaigns first
4. If atomic write succeeds, report will be complete (crash-safe)

### "File Manager Won't Delete"
**Symptom:** Press D to delete file but nothing happens  
**Root Cause:** File in use or permission denied

**Resolution:**
1. Ensure file is not currently open in editor
2. Check file permissions:
   ```bash
   ls -l [filename]
   ```
3. Use terminal to delete if needed:
   ```bash
   rm [filename]
   ```
4. Refresh file manager (press Esc and return)

---

## 5. MITRE Intelligence Lookup Failures

### "mitre_reference.txt Not Found"
**Symptom:** Application starts but MITRE lookups show "No technique found"  
**Root Cause:** MITRE reference file missing

**Resolution:**
1. Check file exists in root directory:
   ```bash
   ls -la mitre_reference.txt
   ```
2. If missing, MITRE features are disabled (non-critical)
3. Application still works without MITRE data
4. Manual technique entry still supported

### "Technique ID Not Found"
**Symptom:** Type T-Code but system says "UNKNOWN"  
**Root Cause:** Incorrect T-Code format or not in MITRE database

**Resolution:**
1. Verify T-Code format: `TXXXX` (e.g., `T1566`)
2. Check MITRE reference has matching entry:
   ```bash
   grep "T1566" mitre_reference.txt
   ```
3. If missing from file, manually type technique name
4. Application accepts both T-Codes and descriptions

### "MITRE Coverage Matrix Won't Generate"
**Symptom:** Report generation fails when trying to include MITRE coverage  
**Root Cause:** Findings missing MITRE technique mapping

**Resolution:**
1. Ensure all findings have MITRE technique assigned
2. Map findings to techniques:
   - Edit finding (press E)
   - Set MITRE Technique field
   - Save (Ctrl+S)
3. Try report generation again

---

## 6. RBAC & Permission Issues

### "You Don't Have Permission to Approve"
**Symptom:** Try to approve finding but get permission error  
**Root Cause:** User role is OPERATOR (needs LEAD+)

**Resolution:**
1. Only LEAD, ADMIN can approve findings
2. Ask LEAD to approve on your behalf
3. Or request role upgrade from ADMIN

### "Cannot Edit Approved Finding"
**Symptom:** Try to edit finding but it's locked  
**Root Cause:** By design - approved findings are immutable

**Resolution:**
1. This is correct behavior (audit trail protection)
2. If changes needed, ask LEAD to reject finding
3. OPERATOR re-opens and edits
4. Re-submit for approval

### "Cannot Delete Campaign"
**Symptom:** Try to delete campaign but permission denied  
**Root Cause:** Only ADMIN can delete campaigns

**Resolution:**
1. Ask ADMIN to delete campaign
2. Or use ARCHIVE status instead (soft delete)

---

## 7. UI/UX Issues

### "Colors Not Rendering (Monochrome)"
**Symptom:** Terminal shows only white/grey instead of Phosphor green/cyan  
**Root Cause:** Terminal doesn't support 24-bit TrueColor

**Resolution:**
1. Use recommended terminal:
   - Kitty ✅
   - Alacritty ✅
   - iTerm2 ✅
   - Windows Terminal ✅
   - Standard Linux terminal ⚠️ (may need config)
2. Verify terminal setting:
   ```bash
   echo $TERM  # Should show "xterm-256color" or "kitty"
   ```
3. If using SSH, enable color forwarding:
   ```bash
   ssh -E /tmp/ssh_debug.log user@host
   ```

### "Unicode Glyphs Show as Boxes"
**Symptom:** Icons display as `[]` instead of symbols  
**Root Cause:** Font doesn't support Unicode or Nerd Font icons

**Resolution:**
1. Install Nerd Font:
   - Download from [nerdfonts.com](https://nerdfonts.com)
   - Recommended: JetBrains Mono Nerd Font, FiraCode Nerd Font
2. Configure terminal to use font
3. Restart terminal and VectorVue

### "Text Editor is Slow"
**Symptom:** Typing feels laggy when editing findings  
**Root Cause:** Large description or slow system

**Resolution:**
1. Check system resources:
   ```bash
   top  # Look for CPU/memory usage
   ```
2. Close other applications
3. Break large findings into multiple smaller ones
4. Consider SSD vs HDD performance

---

## 8. Performance & Optimization

### "Campaign List is Slow to Load"
**Symptom:** Takes >5 seconds to load campaign list  
**Root Cause:** Large number of campaigns or slow disk

**Resolution:**
1. Check database size:
   ```bash
   ls -lh vectorvue.db
   ```
2. Archive old campaigns (soft delete)
3. If very large (>500MB), consider backing up and archiving

### "Report Generation Takes Too Long"
**Symptom:** Export report hangs or is very slow  
**Root Cause:** Large campaign with many findings/evidence

**Resolution:**
1. Generate report for smaller date range
2. Exclude non-critical evidence items
3. Use CSV format instead of Markdown (smaller)
4. Check disk space available

---

## 9. Common Errors by Component

### vv_core.py (Database Layer) Errors
| Error | Cause | Fix |
|-------|-------|-----|
| `AttributeError: 'NoneType'` | No campaign selected | Create or switch campaign (Ctrl+C) |
| `sqlite3.IntegrityError` | Constraint violation | Check for duplicate data |
| `KeyError` in finding dict | Missing field | Ensure all required fields filled |

### vv.py (UI Layer) Errors
| Error | Cause | Fix |
|-------|-------|-----|
| `IndexError` in list | Empty list access | Create at least one finding first |
| `ValueError` in CVSS score | Invalid number | Enter 0.0-10.0 |
| `PermissionError` | Role insufficient | Check user role |

### vv_fs.py (File I/O) Errors
| Error | Cause | Fix |
|-------|-------|-----|
| `FileNotFoundError` | File missing | Verify file exists |
| `PermissionError` | Access denied | Check file permissions |
| `OSError: [Errno 28] No space left` | Disk full | Free disk space |

### vv_theme.py (Theme) Errors
| Error | Cause | Fix |
|-------|-------|-----|
| `CSS Syntax Error` | Invalid CSS in theme | Reload theme file |
| Color not applying | CSS selector wrong | Check widget class names |

---

## 10. Getting Help

### Before Reporting Issues

1. **Check this guide** - Most issues documented here
2. **Check activity log** - Press V to view timeline
3. **Verify permissions** - Ensure your role is sufficient
4. **Check logs** - Review terminal output for Python tracebacks
5. **Test isolation** - Try with small, fresh campaign

### Collecting Debug Information

If you need to report a bug:

```bash
# 1. Capture Python version
python3 --version

# 2. Check dependencies
pip list | grep -E "textual|cryptography|pydantic"

# 3. Verify database integrity
sqlite3 vectorvue.db "PRAGMA integrity_check;"

# 4. Get error traceback
python3 vv.py 2>&1 | tee debug.log
# Reproduce error, then save debug.log
```

### Contact Support

- **Internal:** Reach out to Internal Engineering Lead
- **GitHub:** Submit issue with debug information
- **Email:** team@vectorvue.local

---

## Quick Reference Table

| Symptom | Quick Fix | Detailed Help |
|---------|-----------|---------------|
| Can't log in | Create admin user | Section 1 |
| Database locked | Close DB browser | Section 2 |
| Crypto error | Recreate salt file | Section 3 |
| Can't save | Check permissions | Section 4 |
| MITRE not found | Install reference file | Section 5 |
| Permission denied | Check user role | Section 6 |
| Monochrome UI | Use Nerd Font | Section 7 |
| Slow performance | Archive old campaigns | Section 8 |

---

**VectorVue v3.0** | Red Team Campaign Management Platform | v3.0-RC1

Need more help? Check `.github/copilot-instructions.md` for development patterns or contact your team lead.
