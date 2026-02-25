# VectorVue v3.4 Troubleshooting Guide

![Troubleshooting](https://img.shields.io/badge/Troubleshooting-v3.4-00FFFF?style=flat-square) ![Status](https://img.shields.io/badge/Status-Complete-39FF14)

Comprehensive troubleshooting guide for VectorVue v3.4 with solutions for common operational, database, runtime, and security issues.

## 1. Installation & Startup Issues

### Issue: "ModuleNotFoundError: No module named 'textual'"
**Symptoms:**
```
Traceback (most recent call last):
  File "vv.py", line 10, in <module>
    from textual.app import ComposeResult
ModuleNotFoundError: No module named 'textual'
```

**Cause:** Dependencies not installed

**Solution:**
```bash
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python -c "import textual; print(f'Textual installed')"
```

### Issue: "Terminal colors wrong (pink instead of green)"
**Symptoms:** UI shows pink/brown instead of Phosphor green (#39FF14)

**Cause:** Terminal doesn't support 24-bit TrueColor

**Solution:** Update to Alacritty, Kitty, or Windows Terminal (v1.5+)

### Issue: "Cannot open database file"
**Cause:** Write permission denied or disk full

**Solution:**
```bash
chmod 600 vectorvue.db vectorvue.salt
df -h  # Check disk space (need 100MB+)
```

## 2. Database Issues

### Issue: "CRYPTO_AVAILABLE = False" / Encryption errors
**Solution:**
```bash
pip install cryptography
```

### Issue: "Database is locked"
**Cause:** Another process has database open

**Solution:**
```bash
lsof | grep vectorvue.db
kill -9 <PID>
rm -f .vectorvue.db-wal .vectorvue.db-shm
python3 vv.py
```

### Issue: "41 tables don't exist" / Schema mismatch
**Cause:** Corrupted database or old schema version

**Solution:**
```bash
sqlite3 vectorvue.db ".tables"  # Should show 41 tables
# If missing, restore from backup
tar xzf vectorvue-backup-YYYYMMDD.tar.gz
```

### Issue: "Duplicate campaign_id" / Integrity constraint
**Cause:** Attempted to create campaign with existing ID

**Solution:** Use UI (Ctrl+K) to create campaigns, not direct database inserts

## 3. Authentication & Session Issues

### Issue: "Login fails with 'Invalid credentials'"
**Cause:** User account doesn't exist or password changed

**Solution:**
```bash
# Check user exists
sqlite3 vectorvue.db "SELECT username, role FROM users"
# If missing, ADMIN must invite new operator (Ctrl+6 → Team Management)
```

### Issue: "Session timeout after 30 minutes (not 120)"
**Cause:** Custom retention policy overrides default TTL

**Solution:**
1. Press Ctrl+6 (Security Hardening) → Policies Tab
2. Click `r` key (Reset to defaults)
3. Confirm reset

### Issue: "Logged out unexpectedly"
**Cause:** Session TTL expired or admin force-logged user

**Solution:** Login again, increase TTL in Ctrl+6 → Policies Tab

## 4. Finding & Evidence Issues

### Issue: "Finding won't save (Ctrl+S pressed, no response)"
**Cause:**
1. Campaign status is not ACTIVE (check with Ctrl+2)
2. Disk space exhausted
3. Database write permission denied
4. Background executor error

**Solution:**
```bash
df -h  # Check disk space
# Change campaign status to ACTIVE (Ctrl+Shift+S)
# Check Ctrl+5 Task Orchestrator for executor errors
```

### Issue: "Evidence hash mismatch"
**Cause:** File was modified between uploads (evidence is immutable)

**Solution:** Evidence system is correct - verify original file matches hash with:
```bash
sha256sum original-file.bin
```

### Issue: "Approval stuck (LEAD clicked approve, still PENDING)"
**Cause:** Background executor (webhook executor) is busy

**Solution:**
1. Wait 30 seconds for scheduler to process
2. Press `r` key to refresh view
3. Check Ctrl+5 Task Orchestrator status

### Issue: "Can't delete finding (Permission Denied)"
**Cause:**
1. User is not LEAD (check status bar)
2. Client Safe Mode enabled
3. Finding is in APPROVED status (write-protected)

**Solution:**
- Verify role is LEAD or higher (ask ADMIN to promote)
- Press Ctrl+6 → Policies Tab, toggle Client Safe Mode OFF
- Reject the approval first (Ctrl+Shift+R), then delete

## 5. Background Task & Runtime Issues

### Issue: "Task executor error / Scheduler Failed"
**Cause:**
1. Database connectivity lost
2. RuntimeExecutor encountered exception
3. Task executor thread crashed

**Solution:**
```bash
# Check executor status
# Press Ctrl+5 (Task Orchestrator)
# All 5 executors should show green status (RUNNING)
# Check logs: press l key
# Reset: press R key (Resume)
```

### Issue: "Report generation hangs (Ctrl+Shift+G pressed, no progress)"
**Cause:** Report generator task timed out (>10 min) or large campaign

**Solution:**
1. Check task status (Ctrl+5 Task Orchestrator)
2. Cancel long-running task: select and press `c`
3. Try again with smaller scope (HIGH/CRITICAL only)
4. Restart app: Logout and login

### Issue: "Webhook delivery failed (Slack/webhook integration not working)"
**Cause:**
1. Webhook endpoint URL is incorrect
2. Network connectivity issue
3. Webhook payload format wrong

**Solution:**
1. Verify webhook URL (Ctrl+6 → Integration Tab)
2. Test manually: curl to webhook endpoint
3. Check delivery logs (Ctrl+5 Task Orchestrator)
4. Toggle webhook OFF then ON and retry

## 6. Encryption & Security Issues

### Issue: "Cannot decrypt finding / Crypto error"
**Cause:**
1. Encryption key changed
2. Salt file (vectorvue.salt) was modified or deleted
3. Finding data corrupted

**Solution:**
1. Restore from backup (includes salt file):
   ```bash
   tar xzf vectorvue-backup-YYYYMMDD.tar.gz
   ```
2. If data still corrupted, check database:
   ```bash
   sqlite3 vectorvue.db "PRAGMA integrity_check"
   ```

### Issue: "Sensitive data visible / Client Safe Mode not working"
**Cause:** Client Safe Mode not enabled

**Solution:**
1. Press Ctrl+6 (Security Hardening)
2. Toggle "Client Safe Mode" ON
3. Now reports will redact IPs, hide credential hashes, etc.

## 7. MITRE & Technique Mapping Issues

### Issue: "MITRE view empty (no techniques shown)"
**Cause:** mitre_reference.txt missing or corrupted

**Solution:**
1. Check file: `ls -la mitre_reference.txt`
2. If missing, download from https://attack.mitre.org/
3. File format: CSV with T-code,Name,Tactic,Description
4. Restart app (Ctrl+L logout, then login)

### Issue: "Can't link finding to technique"
**Cause:**
1. MITRE data not loaded (view empty)
2. Finding not saved yet
3. Technique list empty

**Solution:**
1. Verify MITRE data (Ctrl+3 should show tactics)
2. Save finding first (Ctrl+S)
3. Link technique: Ctrl+3, navigate to technique, press `l`

## 8. Performance & Optimization

### Issue: "Application slow / UI lag"
**Cause:**
1. Large campaign (10k+ findings)
2. Background executor consuming CPU
3. Database query slow

**Solution:**
1. Check executor status (Ctrl+5)
2. Switch to smaller campaign (Ctrl+Shift+K)
3. Optimize database:
   ```bash
   sqlite3 vectorvue.db "VACUUM"
   sqlite3 vectorvue.db "ANALYZE"
   ```

### Issue: "Database growing too large (>500MB)"
**Cause:** Old data not being purged (retention policies not running)

**Solution:**
1. Check retention policies (Ctrl+6 → Policies Tab)
2. Force retention cleanup:
   ```bash
   sqlite3 vectorvue.db "DELETE FROM findings WHERE created_at < datetime('now', '-90 days')"
   sqlite3 vectorvue.db "VACUUM"
   ```

## 9. Data Recovery & Backup

### Issue: "Accidentally deleted finding / Data loss"
**Cause:** Deletion is permanent (secure-deleted if policies enabled)

**Solution:**
1. Restore from recent backup:
   ```bash
   tar xzf vectorvue-backup-20250120.tar.gz
   ```
2. If no backup, check activity log for deletion details

### Issue: "Backup is corrupted / Can't extract"
**Cause:** Backup file corrupted during save

**Solution:**
```bash
tar tzf vectorvue-backup-20250120.tar.gz > /dev/null  # Test integrity
# If fails, try older backup
ls -lt vectorvue-backup-*.tar.gz | head -5  # Show last 5 backups
tar xzf vectorvue-backup-OLDER.tar.gz  # Use older backup
```

## 10. Asking for Help

### Information to collect before contacting support

```bash
grep "__version__" vv.py  # VectorVue version
sqlite3 vectorvue.db ".tables"  # Database schema (should show 41 tables)
python --version  # Python version (should be 3.10+)
uname -a  # OS and kernel
ls -lh vectorvue.db  # Database file size
```

**Reproduction steps:**
- "1. Click X
- 2. Press Y
- 3. See error Z"

---

**VectorVue v3.4** | Troubleshooting Complete | Contact Support | Production Ready
