<!-- Copyright (c) 2026 José María Micoli | Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'} -->

# VectorVue v3.8 Troubleshooting Guide

![Version](https://img.shields.io/badge/Version-v3.8-39FF14) ![Phase](https://img.shields.io/badge/Phase-5.5_Complete-39FF14)

Common issues and solutions for VectorVue v3.8 red team campaign management platform with Operational Cognition support.

---

## Table of Contents

1. [Installation & Setup](#installation)
2. [Authentication & Sessions](#auth)
3. [Database & Storage](#database)
4. [UI & Display](#ui)
5. [Campaign Operations](#campaigns)
6. [Evidence & Reporting (Phase 3)](#phase3)
7. [Team Management (Phase 4)](#phase4)
8. [Threat Intelligence (Phase 5)](#phase5)
9. [Operational Cognition (Phase 5.5)](#phase5.5)
10. [Background Tasks & Performance](#background)
11. [Cryptography & Security](#crypto)
12. [Advanced Troubleshooting](#advanced)

---

## <a name="installation"></a>Installation & Setup

### Issue: "ModuleNotFoundError: No module named 'textual'"

**Cause:** Textual framework not installed or virtual environment not activated.

**Solution:**

```bash
# Verify you're in venv
which python  # Linux/macOS
where python  # Windows
# Should show /path/to/venv/bin/python

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Verify installation
python -c "import textual; print(textual.__version__)"
```

### Issue: "ModuleNotFoundError: No module named 'cryptography'"

**Cause:** Cryptography library missing (needed for AES-256-GCM encryption).

**Solution:**

```bash
pip install cryptography>=42.0.0

# If build fails on Linux, install dev packages:
sudo apt-get install python3-dev libssl-dev

# Retry install
pip install cryptography --force-reinstall
```

### Issue: "Terminal colors not displaying correctly"

**Cause:** Terminal doesn't support 256-color or TrueColor mode.

**Solution:**

```bash
# Check color support
echo $TERM

# Force color mode
export TERM=xterm-256color
python3 vv.py

# Or try specific terminal
# Kitty: works natively
# Alacritty: works natively
# iTerm2: works natively
# Windows Terminal: works natively v1.5+
```

### Issue: "MITRE reference file not found"

**Cause:** `mitre_reference.txt` not in root directory (optional but recommended).

**Solution:**

```bash
# If using MITRE ATT&CK data, ensure file exists
ls -l mitre_reference.txt

# If not available, create empty file
touch mitre_reference.txt

# File format (CSV):
# technique_id,tactic,name,description
# T1110,Credential Access,Brute Force,Attack that...
```

---

## <a name="auth"></a>Authentication & Sessions

### Issue: "AUTHENTICATION REQUIRED" every startup

**Expected behavior in v3.7:**
VectorVue requires fresh login on every startup for security. There is **no automatic session resumption**.

**This is NOT a bug** - it's a security feature to prevent unauthorized access.

**Solution:**
Simply log in with your credentials each time:
1. App loads
2. Login screen appears
3. Enter username + password
4. Press LOGIN
5. Main editor loads

**Why?** Cached session tokens on disk could be stolen. Fresh login ensures you control access.

### Issue: "Failed login attempts exceeded, account locked"

**Cause:** Too many incorrect password attempts (security feature).

**Solution:**

```bash
# Wait 15 minutes for auto-unlock, OR

# Manually unlock (admin only):
sqlite3 vectorvue.db
UPDATE users SET failed_login_attempts = 0, locked_until = NULL 
WHERE username = 'john.operator';
```

### Issue: "Session expired, please log in again"

**Cause:** Inactivity timeout (120 minutes without activity).

**Solution:**

This is intentional for security. Simply log in again:
1. Press **Ctrl+L** to logout
2. Re-enter credentials
3. Session restored

**To adjust timeout (admin):**
```bash
sqlite3 vectorvue.db
UPDATE system_settings SET setting_value = '180' 
WHERE setting_key = 'session_timeout_minutes';
```

### Issue: "MFA verification required but no MFA method set up"

**Cause:** MFA enabled in system settings but user hasn't registered MFA.

**Solution (Admin):**
```bash
# Disable MFA requirement
sqlite3 vectorvue.db
UPDATE system_settings SET setting_value = '0' 
WHERE setting_key = 'mfa_required';
```

---

## <a name="database"></a>Database & Storage

### Issue: "SQLite database locked"

**Cause:** Another VectorVue instance is using the database.

**Solution:**

```bash
# Check for running processes
ps aux | grep vv.py

# Kill if stuck
pkill -9 -f vv.py

# Verify no lock files
ls -la /tmp/.sqlite_lock_vectorvue*

# Restart
python3 vv.py
```

### Issue: "Database file corrupted"

**Cause:** Hard crash during database write, or disk failure.

**Solution:**

```bash
# Check database integrity
sqlite3 vectorvue.db "PRAGMA integrity_check;"

# If corrupt, attempt repair
sqlite3 vectorvue.db ".recover" > vectorvue_recovered.db
mv vectorvue_recovered.db vectorvue.db

# Restart application
python3 vv.py
```

### Issue: "Disk space error: cannot write to database"

**Cause:** Storage device full.

**Solution:**

```bash
# Check free space
df -h

# Free up space
# Large findings/credentials can be deleted:
sqlite3 vectorvue.db
DELETE FROM findings WHERE created_at < '2026-01-01' AND status = 'archived';

# Or expand disk allocation
```

### Issue: "Cannot decrypt credential/finding"

**Cause:** Encryption key derivation failed, or database corrupted.

**Solution:**

```bash
# Verify salt file exists
ls -l vectorvue.salt

# Check salt integrity
file vectorvue.salt  # Should be binary, 32 bytes

# If salt corrupted, can't recover passwords (data is lost)
# Regenerate with new salt
rm vectorvue.salt
python3 -c "from vv_core import SessionCrypto; SessionCrypto()"
```

---

## <a name="ui"></a>UI & Display

### Issue: "Text rendering looks corrupted/garbled"

**Cause:** Terminal doesn't support UTF-8, or font missing special characters.

**Solution:**

```bash
# Check UTF-8 support
locale

# Ensure UTF-8 locale
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8

# Restart
python3 vv.py
```

### Issue: "Keybindings not working (Ctrl+K, Ctrl+M, etc.)"

**Cause:** Terminal doesn't send proper escape sequences, or keybinding disabled.

**Solution:**

```bash
# Try different terminal
# If Ctrl+K not working in xterm, try:
export TERM=xterm-new
python3 vv.py

# Or check keybinding settings in UI preferences
```

### Issue: "Data table slow to scroll/navigate"

**Cause:** Large dataset (1000+ rows) causes lag.

**Solution:**

1. **Filter data:**
   - Use search function to limit visible rows
   - Filter by campaign, severity, status

2. **Archive old data:**
   ```bash
   # Delete findings from old campaigns
   sqlite3 vectorvue.db
   DELETE FROM findings 
   WHERE campaign_id NOT IN (SELECT id FROM campaigns WHERE status = 'active');
   ```

3. **Increase table timeout (vv_theme.py):**
   Change `TABLE_ROW_TIMEOUT` from 30s to 60s

---

## <a name="campaigns"></a>Campaign Operations

### Issue: "Cannot create campaign: 'object has no attribute campaign_id'"

**Cause:** Campaign context not set after creation.

**Solution:**

```bash
# Restart app
python3 vv.py

# Or manually set active campaign
sqlite3 vectorvue.db
SELECT id FROM campaigns;

# Note the campaign ID, then restart app
# App should auto-select most recent campaign
```

### Issue: "Asset/credential not appearing in campaign view"

**Cause:** Asset belongs to different campaign than current context.

**Solution:**

1. **Check which campaign is active:**
   - View status bar (shows "CAMPAIGN ACTIVE: [name]")

2. **Switch campaign:**
   - Press **Ctrl+K**
   - Click desired campaign name

3. **Verify asset belongs to campaign:**
   ```bash
   sqlite3 vectorvue.db
   SELECT campaign_id, name FROM assets WHERE name = '192.168.1.10';
   ```

### Issue: "Cannot find finding I just created"

**Cause:** Finding not yet saved to database.

**Solution:**

1. **Click COMMIT DB** after creating finding
   - Status bar shows "✓ COMMITTED" (green)

2. **If COMMIT fails:**
   ```bash
   # Check database for errors
   python3 -m py_compile vv.py
   
   # Restart app
   python3 vv.py
   ```

### Issue: "Deletion of campaign failed: 'Foreign key constraint failed'"

**Cause:** Campaign has findings/assets/credentials that reference it.

**Solution:**

```bash
# Option 1: Delete referenced data first
sqlite3 vectorvue.db
DELETE FROM findings WHERE campaign_id = 1;
DELETE FROM assets WHERE campaign_id = 1;
DELETE FROM credentials WHERE campaign_id = 1;
DELETE FROM campaigns WHERE id = 1;

# Option 2: Mark campaign as archived instead
UPDATE campaigns SET status = 'archived' WHERE id = 1;
# Then manually delete findings later
```

---

## <a name="phase3"></a>Evidence & Reporting (Phase 3)

### Issue: "Cannot generate report: 'No findings to include'"

**Cause:** Either no findings created, or all findings have status 'draft'.

**Solution:**

1. **Create findings:**
   - Type markdown in editor
   - Fill title + CVSS in lateral panel
   - Click **NEW ENTRY** → **COMMIT DB**

2. **Approve findings:**
   - In Report view, select finding
   - Click **APPROVE** (LEAD+ only)
   - Status changes to "approved"

3. **Retry report generation:**
   - Press **Ctrl+R**
   - Click **GENERATE REPORT**

### Issue: "Report generation timeout/hangs"

**Cause:** Large number of findings (100+), or slow disk I/O.

**Solution:**

```bash
# Cancel current operation
Press Ctrl+C in terminal

# Restart app
python3 vv.py

# Generate smaller report:
# Use FILTER to select only HIGH/CRITICAL findings
```

### Issue: "Evidence file hash mismatch"

**Cause:** Evidence file was modified after collection (integrity check failed).

**Solution:**

```bash
# **DO NOT modify evidence files after collection**
# Immutability is a feature, not a bug

# If corruption is suspected:
1. Delete evidence item
2. Re-collect evidence
3. Store in secure location

# To verify hash:
sha256sum /path/to/evidence.file
# Compare with value in VectorVue database
```

### Issue: "Cannot export report as PDF"

**Cause:** ReportLab library missing, or permission denied on file write.

**Solution:**

```bash
# Install ReportLab
pip install reportlab>=4.0.0

# Check write permissions
ls -l Reports/  # Should be writable

# Chmod if needed
chmod 755 Reports/

# Retry report generation
```

### Issue: "Report watermark not appearing"

**Cause:** Classification level not set on campaign or report.

**Solution:**

1. **Set campaign classification:**
   - Press **Ctrl+K**
   - Select campaign
   - Set **Classification: CONFIDENTIAL**

2. **Regenerate report:**
   - Press **Ctrl+R**
   - Report now includes watermark

---

## <a name="phase4"></a>Team Management (Phase 4)

### Issue: "Cannot create team: 'Team name already exists'"

**Cause:** Team with same name already exists.

**Solution:**

```bash
# Use unique team name
# E.g., "Red Team Alpha" instead of "Red Team"

# Or delete old team (admin only)
sqlite3 vectorvue.db
DELETE FROM teams WHERE team_name = 'Red Team';
```

### Issue: "Team member cannot see findings"

**Cause:** Member's role doesn't have "view_findings" permission, or finding belongs to different team.

**Solution:**

1. **Check team permissions:**
   - Press **Ctrl+T**
   - Select team
   - Click **EDIT PERMISSIONS**
   - Ensure role has "view_findings" checked

2. **Check campaign assignment:**
   - Campaign must be assigned to team
   - In Team view: Campaign must appear in team's campaign list

3. **Check data sharing policy:**
   ```bash
   sqlite3 vectorvue.db
   SELECT * FROM data_sharing_policies 
   WHERE team_id = (SELECT id FROM teams WHERE team_name = 'Red Team Alpha');
   ```

### Issue: "Approval workflow not triggering"

**Cause:** User is ADMIN or team_lead (auto-approve), or approval not required.

**Solution:**

1. **Verify finding status:**
   - Finding must have status "created" or "reviewed"
   - Not "approved" or "exported"

2. **Check approval requirement:**
   ```bash
   sqlite3 vectorvue.db
   SELECT setting_value FROM system_settings 
   WHERE setting_key = 'require_approval';
   # Should be '1' for on
   ```

3. **Request approval as OPERATOR:**
   - Create finding as OPERATOR
   - Status shows "pending_approval"
   - LEAD logs in and approves

---

## <a name="phase5"></a>Threat Intelligence (Phase 5)

### Issue: "Cannot add threat feed: 'Invalid feed URL'"

**Cause:** URL is malformed, or endpoint requires authentication.

**Solution:**

```bash
# Verify URL format
# ✓ Correct: https://api.virustotal.com/api/v3/feeds
# ❌ Wrong: http://virustotal (missing /api/v3/feeds)

# Test feed URL with curl
curl -H "x-apikey: YOUR_API_KEY" "https://api.virustotal.com/api/v3/feeds"

# Get proper API endpoint from feed documentation:
# VirusTotal: https://developers.virustotal.com/
# Shodan: https://shodan.readthedocs.io/
# OTX: https://otx.alienvault.com/api
# MISP: https://misp.readthedocs.io/
```

### Issue: "Threat feed never updates"

**Cause:** Background executor not running, or feed update interval too long.

**Solution:**

1. **Check background executor status:**
   - Press **Alt+2** (Background Tasks)
   - Verify executor is "Running"
   - If not, logout and re-login (executor starts on login)

2. **Check feed update interval:**
   - In Threat Intelligence view
   - Click **EDIT FEED**
   - Change update_interval_hours to 1 (hourly)
   - Or click **REFRESH NOW**

3. **Check for errors:**
   ```bash
   sqlite3 vectorvue.db
   SELECT * FROM threat_feed_refresh_log 
   WHERE feed_id = 1 
   ORDER BY refresh_time DESC LIMIT 5;
   ```

### Issue: "IoC enrichment data not appearing"

**Cause:** Feed not yet enriched, or enrichment service timeout.

**Solution:**

1. **Force re-enrichment:**
   - In Threat Intelligence view
   - Select IoC
   - Click **ENRICH NOW**

2. **Check enrichment cache:**
   ```bash
   sqlite3 vectorvue.db
   SELECT * FROM enrichment_data 
   WHERE data_key = '192.168.1.100';
   ```

3. **Clear cache if stale:**
   ```bash
   sqlite3 vectorvue.db
   DELETE FROM enrichment_data 
   WHERE expires_at < datetime('now');
   ```

### Issue: "Risk score shows 0.0 for all findings"

**Cause:** Risk scoring rules not configured, or CVSS vectors missing.

**Solution:**

1. **Ensure CVSS vectors are set:**
   - For each finding, fill **CVSS Vector: CVSS:3.1/AV:N/AC:L/...**
   - Without CVSS, risk score cannot be calculated

2. **Check risk scoring rules:**
   ```bash
   sqlite3 vectorvue.db
   SELECT * FROM risk_scoring_rules WHERE is_active = 1;
   ```

3. **Manually recalculate risk scores:**
   - Press **Ctrl+Shift+I**
   - Click **RECALCULATE ALL RISK SCORES**

### Issue: "Threat actor profile not linking to findings"

**Cause:** Manual linking required, or technique mismatch.

**Solution:**

1. **Link manually:**
   - Open Threat Intelligence view
   - Select threat actor
   - Click **LINK TO FINDING**
   - Select finding with matching technique
   - Confirm

2. **Auto-linking requires:**
   - Finding must have MITRE technique (T-number)
   - Actor profile must have that technique in actor_ttps
   - Technique must have high confidence_score

### Issue: "Behavioral anomaly detection fires constantly"

**Cause:** Baseline thresholds too strict, or operator behavior genuinely anomalous.

**Solution:**

1. **Adjust anomaly sensitivity:**
   ```bash
   sqlite3 vectorvue.db
   UPDATE anomaly_rules SET threshold_sigma = 4 
   WHERE metric = 'findings_per_hour';
   # Higher = less sensitive (default 3)
   ```

2. **Review operator behavior:**
   - Press **Alt+3** (Analytics)
   - View operator metrics
   - Check if behavior is actually unusual

---

## <a name="phase5.5"></a>Operational Cognition (Phase 5.5)

### Issue: "Cognition recommendations not appearing"

**Cause:** Cognition modules not initialized or insufficient data for confidence threshold.

**Solution:**

1. **Verify cognition initialization:**
   - Open campaign
   - Press **Ctrl+Shift+C** (Cognition panel)
   - Check status message

2. **Check confidence level:**
   - Confidence must be ≥ 0.3 for recommendations
   - View current confidence: **Ctrl+Shift+O** (Objective view)
   - If low, you need more campaign data (assets, credentials)

3. **Force cognition refresh:**
   ```python
   # In Python shell
   from vv_cognition_integration import CognitionOrchestrator
   co = CognitionOrchestrator(campaign_id=1)
   co.refresh_full_state()
   ```

### Issue: "Attack graph shows no paths to objective"

**Cause:** Disconnected assets (no compromise relationships found) or objective unreachable from controlled assets.

**Solution:**

1. **Verify controlled assets:**
   - Add assets you actually control to campaign
   - Ensure relationships are established between assets
   - Press **Ctrl+Shift+G** to view attack graph

2. **Check asset relationships:**
   ```sql
   sqlite3 vectorvue.db
   SELECT * FROM asset_relationships 
   WHERE campaign_id = [your_campaign_id];
   ```

3. **Manually establish relationships:**
   - In Campaign view, link assets with exploit/credential requirements
   - Specify technique used (T-number if possible)

### Issue: "Detection pressure stuck at low value"

**Cause:** Activity log not recording detections, or pressure calculation disabled.

**Solution:**

1. **Verify activity log entries:**
   ```sql
   sqlite3 vectorvue.db
   SELECT COUNT(*), action_type 
   FROM activity_log 
   WHERE campaign_id = [your_campaign_id] 
   GROUP BY action_type;
   ```

2. **Check for detection events:**
   - Log detections explicitly in detection log
   - Press **Ctrl+D** → Add Detection

3. **Force pressure recalculation:**
   ```python
   from vv_detection_pressure import DetectionPressureEngine
   dpe = DetectionPressureEngine(campaign_id=1)
   state = dpe.calculate_pressure()
   print(f"Pressure: {state.value}")
   ```

### Issue: "Operator tempo recommendations seem off"

**Cause:** Insufficient action history or tempo tracking disabled.

**Solution:**

1. **Check action history:**
   ```sql
   sqlite3 vectorvue.db
   SELECT COUNT(*) as action_count, 
          strftime('%Y-%m-%d %H:%M', created_at) as hour
   FROM activity_log 
   WHERE campaign_id = [your_campaign_id]
   GROUP BY hour;
   ```

2. **Verify tempo metrics:**
   - Press **Ctrl+Shift+O** → View Metrics
   - Check "Last 6 Hours" action count

3. **Reset tempo baseline (if needed):**
   ```python
   from vv_tempo import TempoEngine
   te = TempoEngine(campaign_id=1)
   analysis = te.analyze_tempo()
   print(f"Intensity: {analysis.action_intensity}")
   ```

### Issue: "OpSec simulation shows unrealistic probabilities"

**Cause:** Missing asset metadata or outdated technique profiles.

**Solution:**

1. **Verify asset properties:**
   - Each asset needs: type (Windows/Linux), criticality (critical/high/medium/low), environment (prod/staging/dev)
   - Update in Campaign view → Assets

2. **Check technique profile data:**
   ```python
   from vv_opsec import OpSecSimulator
   opsec = OpSecSimulator()
   # Profiles built-in for 10 MITRE techniques:
   # T1566, T1071, T1570, T1059, T1548, T1098, T1547, T1134, T1197, T1110
   ```

3. **Simulate specific action manually:**
   ```python
   from vv_cognition import OperatorAction
   from vv_opsec import OpSecSimulator
   
   action = OperatorAction(
       technique_id="T1566",
       target_asset_id=5,
       description="Phishing email"
   )
   opsec = OpSecSimulator()
   result = opsec.simulate(action)
   print(result)
   ```

### Issue: "Confidence score always low (<0.3)"

**Cause:** Insufficient environment mapping or incomplete observations.

**Solution:**

1. **Check data completeness:**
   - Press **Ctrl+Shift+O** → Confidence Analysis
   - View "Data Gaps" section

2. **Add missing information:**
   - Discover more assets (increase asset count)
   - Harvest more credentials
   - Log detections observed during campaign

3. **View confidence factors:**
   ```python
   from vv_confidence import ConfidenceEngine
   ce = ConfidenceEngine(campaign_id=1)
   conf = ce.calculate_confidence()
   print(f"Data: {conf.data_completeness}")
   print(f"Observations: {conf.observation_count}")
   print(f"Path Stability: {conf.path_stability}")
   print(f"Overall: {conf.overall_confidence}")
   ```

### Issue: "C2 infrastructure burn level marked as 'burned' incorrectly"

**Cause:** False positive in detection correlation, or manual entry error.

**Solution:**

1. **Review burn detections:**
   - Press **Ctrl+Shift+C** → Infrastructure Burn
   - Click to view detections attributed to this C2

2. **Verify detection log entries:**
   ```sql
   sqlite3 vectorvue.db
   SELECT detection_log.*, detection_events.description
   FROM detection_log
   JOIN detection_events ON ...
   WHERE campaign_id = [your_campaign_id]
   AND detection_description LIKE '%C2%' OR '%192.168.1.50%';
   ```

3. **Manually adjust burn probability:**
   ```python
   from vv_infra_burn import InfraBurnEngine
   ibe = InfraBurnEngine(campaign_id=1)
   # Reset specific C2
   ibe.update_burn(c2_id=123, manual_override=True, burn_level="warm")
   ```

### Issue: "Event replay log seems incomplete"

**Cause:** Events not being recorded, or replay initialization failed.

**Solution:**

1. **Verify replay events exist:**
   ```sql
   sqlite3 vectorvue.db
   SELECT COUNT(*) FROM replay_events 
   WHERE campaign_id = [your_campaign_id];
   ```

2. **Force event recording on next action:**
   - Perform any operator action (e.g., add finding)
   - Event should be recorded automatically

3. **Generate campaign narrative:**
   - Press **Ctrl+Shift+C** → Campaign Narrative
   - Should show event timeline

### Issue: "Recommendation scores all zero"

**Cause:** Recommendation engine not loaded, or no valid actions to score.

**Solution:**

1. **Verify recommendation engine:**
   ```python
   from vv_recommend import RecommendationEngine
   re = RecommendationEngine(campaign_id=1)
   recommendations = re.score_recommendations(available_actions=[
       {"technique_id": "T1566", "asset_id": 1}
   ])
   print(recommendations)
   ```

2. **Ensure valid actions specified:**
   - Actions need: technique_id (MITRE T-number), asset_id (target)
   - Asset must exist in campaign

3. **Check scoring formula:**
   - Scores are 0.0-1.0 range
   - Low scores indicate high risk
   - High scores indicate safe/valuable recommendations

---

## <a name="background"></a>Background Tasks & Performance

### Issue: "Background executor keeps crashing"

**Cause:** Task execution error, or memory leak.

**Solution:**

1. **Check executor logs:**
   - Press **Alt+2** (Background Tasks)
   - View task execution history
   - Look for failed tasks

2. **Disable problematic task:**
   ```bash
   sqlite3 vectorvue.db
   UPDATE scheduled_tasks SET is_enabled = 0 
   WHERE task_name = '[problematic_task]';
   ```

3. **Restart executor:**
   ```bash
   # Logout and re-login
   Press Ctrl+L → Login
   # Executor restarts on login
   ```

### Issue: "Application memory usage keeps growing"

**Cause:** Background tasks accumulating data, or UI not releasing memory.

**Solution:**

1. **Check open data tables:**
   - Each open table view consumes ~50MB per 1000 rows
   - Close unused views (press Escape)

2. **Purge old data:**
   ```bash
   sqlite3 vectorvue.db
   # Delete findings from archived campaigns
   DELETE FROM findings 
   WHERE campaign_id IN 
     (SELECT id FROM campaigns WHERE status = 'archived' AND end_date < date('now', '-90 days'));
   
   # Delete old command outputs
   DELETE FROM command_output 
   WHERE stored_at < date('now', '-30 days');
   ```

3. **Restart application:**
   ```bash
   # Logout
   Press Ctrl+L
   
   # Quit completely
   Press Ctrl+Q
   
   # Restart
   python3 vv.py
   ```

### Issue: "Webhook delivery timeout"

**Cause:** External endpoint is slow, or network unreachable.

**Solution:**

1. **Test webhook endpoint:**
   ```bash
   curl -X POST "https://your-webhook.endpoint.com" \
     -H "Content-Type: application/json" \
     -d '{"test": "data"}'
   ```

2. **Check webhook delivery logs:**
   ```bash
   sqlite3 vectorvue.db
   SELECT * FROM webhook_deliveries 
   WHERE webhook_url = 'https://...' 
   ORDER BY sent_at DESC LIMIT 5;
   ```

3. **Increase retry count:**
   - In Integration view
   - Select webhook
   - Set "Max Retries: 5"

---

## <a name="crypto"></a>Cryptography & Security

### Issue: "Cannot derive encryption key from password"

**Cause:** Corrupted salt file, or invalid password encoding.

**Solution:**

```bash
# Verify salt file
ls -l vectorvue.salt
file vectorvue.salt  # Should be binary, 32 bytes

# If corrupted, regenerate (will lose all encrypted data!)
rm vectorvue.salt
python3 vv.py

# Create new admin account with new salt
```

### Issue: "HMAC signature verification failed"

**Cause:** Database row was modified externally, or corruption.

**Solution:**

```bash
# This is a security feature - tampering detected!

# Check row integrity
sqlite3 vectorvue.db
SELECT id, username, hmac_signature FROM users WHERE username = 'john.operator';

# If HMAC invalid, row has been tampered with
# Options:
# 1. Delete tampered row
# 2. Manually recompute HMAC (dangerous)
# 3. Restore from backup
```

### Issue: "Password hash doesn't match, but password is correct"

**Cause:** Password hash algorithm mismatch, or salt changed.

**Solution:**

```bash
# Never directly compare passwords!
# VectorVue uses Argon2 for password hashing

# If user locked out:
# Admin can reset password:

sqlite3 vectorvue.db
-- Don't modify password directly, use:
-- (Admin must use proper password change workflow in UI)

# For now, delete user and recreate:
DELETE FROM users WHERE username = 'john.operator';
# Then restart app and re-register
```

---

## <a name="advanced"></a>Advanced Troubleshooting

### Debug Mode

**Enable verbose logging:**

```bash
export VECTORVUE_DEBUG=1
python3 vv.py
```

**Check logs:**

```bash
tail -f /tmp/vectorvue.log
```

### Database Inspection

**View all tables:**

```bash
sqlite3 vectorvue.db ".tables"
```

**Check data integrity:**

```bash
sqlite3 vectorvue.db "PRAGMA integrity_check;"
```

**Vacuum/optimize database:**

```bash
sqlite3 vectorvue.db "VACUUM;"
```

### Testing Encryption

**Test key derivation:**

```bash
python3 -c "
from vv_core import SessionCrypto
crypto = SessionCrypto()
key = crypto.derive_key('test_password')
print(f'Key length: {len(key)} bytes')
print(f'Key (hex): {key.hex()[:64]}...')
"
```

**Test encryption/decryption:**

```bash
python3 -c "
from vv_core import SessionCrypto
crypto = SessionCrypto()
key = crypto.derive_key('test_password')

plaintext = 'sensitive data'
encrypted = crypto.encrypt_with_key(plaintext, key)
decrypted = crypto.decrypt_with_key(encrypted, key)

print(f'Original: {plaintext}')
print(f'Encrypted: {encrypted.hex()[:64]}...')
print(f'Decrypted: {decrypted}')
print(f'Match: {plaintext == decrypted}')
"
```

### Getting Help

**Check documentation:**
1. [GETTING_STARTED.md](./GETTING_STARTED.md) - Initial setup
2. [OPERATOR_MANUAL.md](./OPERATOR_MANUAL.md) - Operations guide
3. [ARCHITECTURE_SPEC.md](./ARCHITECTURE_SPEC.md) - Technical details
4. [COMPLETE_FEATURES.md](./COMPLETE_FEATURES.md) - Feature reference

**Report bugs:**
```
File issue at: https://github.com/vectorvue/issues

Include:
- VectorVue version: python3 vv.py --version
- Error message (full traceback)
- Steps to reproduce
- Database state: sqlite3 vectorvue.db ".dump" > db_dump.sql
```

---

**VectorVue v3.7** | Phase 5/8 Complete | Troubleshooting Guide v2.1
