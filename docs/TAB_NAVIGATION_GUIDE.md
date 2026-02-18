# Copyright (c) 2026 José María Micoli
# Licensed under {'license_type': 'BSL1.1', 'change_date': '2033-02-17'}
#
# You may:
# ✔ Study
# ✔ Modify
# ✔ Use for internal security testing
#
# You may NOT:
# ✘ Offer as a commercial service
# ✘ Sell derived competing products

"""
VectorVue Tab Navigation System - Operator Guide

Version: v3.8+
Phase: 5.5 UI Enhancement

The visual tab system provides three ways to navigate between views:
1. Keybindings (fastest)
2. Mouse clicks on tabs
3. Keyboard navigation between tabs

============================================================================
CORE UI NAVIGATION TABS
============================================================================

┌─────────────────────────────────────────────────────────────────────┐
│ Files │ MITRE │ Campaign │ Cmd Log │ Sessions │ Detections │ ...  │
└─────────────────────────────────────────────────────────────────────┘

FILES MANAGER (Space)
  - Browse workspace files
  - Upload evidence artifacts
  - Download reports
  - Manage file organization
  
MITRE DATABASE (Ctrl+M)
  - Search MITRE ATT&CK techniques
  - Link findings to tactics/techniques
  - View technique details & controls
  - MITRE Navigator export
  
CAMPAIGN MANAGEMENT (Ctrl+K)
  - Create/switch campaigns
  - Configure client context
  - Set Rules of Engagement
  - Manage campaign objectives
  - Define sensitive assets
  
COMMAND EXECUTION LOG (Ctrl+E)
  - View executed commands
  - Track command output & timing
  - Associate with MITRE techniques
  - Filter by operator/asset
  
ACTIVE SESSIONS (Ctrl+J)
  - Monitor active shells/callbacks
  - Track C2 connections
  - Session metadata (PID, user, host)
  - Session termination
  
DETECTIONS OBSERVED (Ctrl+D)
  - Log defender detections
  - Track alerts & responses
  - Timeline of defensive actions
  - Detection correlation
  
OBJECTIVE PROGRESS (Ctrl+O)
  - Track campaign goals
  - Measure progress toward objective
  - Mark objectives complete
  - Update objective status
  
PERSISTENCE MECHANISMS (Ctrl+P)
  - Inventory backdoors/persistence
  - Track persistence mechanisms
  - Scheduled tasks, registry keys, etc.
  - Persistence removal tracking

============================================================================
ANALYTICS VIEWS TABS
============================================================================

┌──────────────────────────────────────────────────────┐
│ Dashboard │ Analysis │ Intel │ Remediation │ ...    │
└──────────────────────────────────────────────────────┘

SITUATIONAL AWARENESS DASHBOARD (Ctrl+1)
  - Real-time campaign metrics
  - Risk heat map
  - Detection pressure gauge
  - Objective distance meter
  - Recommended next actions
  
POST-ENGAGEMENT ANALYSIS (Ctrl+2)
  - TTP analysis
  - Attack pattern identification
  - Technique effectiveness rates
  - Campaign timeline
  - Operator performance metrics
  
THREAT INTELLIGENCE (LEGACY) (Ctrl+3)
  - Legacy threat feeds
  - IoC management (Phase 5)
  - Threat actor profiles
  - Risk scoring (Phase 5)
  
REMEDIATION TRACKING (Ctrl+4)
  - Recommended remediation actions
  - Client remediation status
  - Tracking verification
  - Remediation metrics
  
CAPABILITY ASSESSMENT (Ctrl+5)
  - Team capability matrix
  - Operator skill assessment
  - Tool/technique proficiency
  - Team performance scoring

============================================================================
ADVANCED VIEWS TABS
============================================================================

┌───────────────────────────────────────────────────────┐
│ Collab │ Tasks │ Analytics │ Integration │ ...       │
└───────────────────────────────────────────────────────┘

COLLABORATION ENGINE (Alt+1)
  - Multi-operator session management
  - Operator presence/status
  - Real-time communication
  - Shared campaign context

TASK ORCHESTRATION (Alt+2)
  - Background task scheduler
  - Webhook delivery management
  - Task execution history
  - Scheduled task queue

BEHAVIORAL ANOMALY DETECTION (Alt+3)
  - Operator behavior patterns
  - Anomaly detection alerts
  - Behavioral learning
  - Timeline analysis

INTEGRATION GATEWAY (Alt+4)
  - Webhook endpoint management
  - External system integration
  - API connectivity
  - Integration testing

COMPLIANCE ATTESTATION (Alt+5)
  - Compliance report generation
  - Framework mapping (PCI, HIPAA, etc.)
  - Audit trail verification
  - Evidence validation

SECURITY HARDENING (Alt+6)
  - TLP color labeling
  - Audit log review
  - Retention policy enforcement
  - Access control verification

============================================================================
PHASE 3-5 SPECIALIZED VIEWS TABS
============================================================================

┌────────────────────────────────────────────┐
│ Reporting │ Teams │ Threat Intel │ ...    │
└────────────────────────────────────────────┘

REPORTING & EXPORT (Ctrl+R)
  - PDF/HTML report generation
  - Evidence manifest creation
  - Compliance report export
  - MITRE Navigator export
  
TEAM MANAGEMENT (Ctrl+T)
  - Create/manage teams
  - Role assignment
  - Operator performance tracking
  - Team approval workflows
  
THREAT INTELLIGENCE ANALYSIS (Ctrl+Shift+I)
  - Feed ingestion (VirusTotal, Shodan, OTX)
  - IoC management (IPs, domains, hashes)
  - Threat actor profiling
  - Risk scoring & correlation
  - Attack timeline visualization

============================================================================
PHASE 5.5 COGNITION TABS
============================================================================

COGNITION LAYER = Deterministic decision-support with 10 modules

┌──────────────────────────────────────────────────────────────┐
│ Opp │ Paths │ State │ Pressure │ Confidence │ Knowledge │ .. │
└──────────────────────────────────────────────────────────────┘

OPPORTUNITIES ANALYSIS (Ctrl+Shift+1)
  Module: Recommendation Engine
  - Top-scored actions ranked by risk/value
  - Alternative safer actions
  - OPSEC simulation for each action
  - Confidence scoring

ATTACK PATHS & PATHFINDING (Ctrl+Shift+2)
  Module: Attack Graph Engine
  - Dijkstra's shortest path to objective
  - Alternative paths enumeration
  - Path confidence scoring
  - Privilege escalation chains

CAMPAIGN STATE (Ctrl+Shift+3)
  Module: Campaign State Engine
  - Environment map overview
  - Asset compromise relationships
  - Credential effectiveness
  - Operational progress tracking

DETECTION PRESSURE (Ctrl+Shift+4)
  Module: Detection Pressure Engine
  - Real-time pressure score (0-100)
  - Pressure state (QUIET → HUNTING → COMPROMISED)
  - Recent alert timeline
  - Trending indicators (↑ ↓ →)

CONFIDENCE ANALYSIS (Ctrl+Shift+5)
  Module: Confidence Engine
  - Overall decision confidence (0.0-1.0)
  - Data completeness %
  - Observation count
  - Path stability metrics
  - Known unknowns

KNOWLEDGE COMPLETENESS (Ctrl+Shift+6)
  Module: Knowledge Engine
  - Environment mapping progress
  - Asset discovery coverage
  - Credential harvesting ratio
  - Detection data completeness
  - Intelligence gaps

TECHNIQUE EFFECTIVENESS (Ctrl+Shift+7)
  Module: Technique Memory Engine
  - Success rates by asset type
  - Failed techniques to avoid
  - Average time-to-compromise
  - Operator effectiveness history

VALIDATION QUEUE (Ctrl+Shift+8)
  Module: Validation Engine
  - Pending finding approvals
  - Finding quality assessment
  - Evidence chain verification
  - Approval workflows

EXPLAINABILITY (Ctrl+Shift+9)
  Module: Explainability Engine
  - Explain any recommendation
  - Show reasoning chain
  - Justify risk assessments
  - Transparency for all decisions

COGNITION DASHBOARD (Ctrl+Shift+0)
  - Unified view of all 10 modules
  - Recommended next action (top-scored)
  - Campaign health overview
  - Detection pressure gauge
  - Objective progress meter
  - Confidence indicator

============================================================================
HOW TO USE TABS
============================================================================

METHOD 1: KEYBINDINGS (FASTEST)
  Ctrl+K             → Switch to Campaign view
  Ctrl+E             → Switch to Command Log
  Ctrl+Shift+1       → Switch to Opportunities (Cognition)
  Space              → File Manager
  
METHOD 2: MOUSE CLICKS
  1. Look at tab bar at top of screen
  2. Click on the tab name (e.g., "Campaign")
  3. View switches immediately
  
METHOD 3: ARROW KEYS (Keyboard Navigation)
  ← / →    → Move between tabs in current group
  ↑ / ↓    → Move to next/previous tab group
  Enter    → Select tab and switch view
  
METHOD 4: TAB GROUP SWITCHING
  - Tab bar groups related views together
  - "Core UI Navigation": Campaign, Cmd Log, Sessions, etc.
  - "Analytics Views": Dashboard, Analysis, etc.
  - "Advanced Views": Collaboration, Tasks, Security, etc.
  - "Phase 3-5 Views": Reporting, Teams, Threat Intel, etc.
  - "Phase 5.5 Cognition": All 10 cognition modules

============================================================================
TAB BAR INDICATORS
============================================================================

Tab Appearance:
┌─────────────────────┐
│ Campaign [Ctrl+K]   │  ← Tab Name + Keybinding
└─────────────────────┘

Tab Colors:
  - GREEN (#39FF14)     = Active/selected tab
  - PURPLE (#BD00FF)    = Hover state
  - GRAY (#404040)      = Inactive tab
  - RED (#FF0000)       = Alert/critical tabs

Tab Status Indicators:
  [*] = Unsaved changes in this view
  [!] = Alert/notification in this view
  [✓] = Data verified/approved
  [⟳] = Auto-refreshing
  [≡] = Expanded/detailed view

============================================================================
NAVIGATION TIPS
============================================================================

TIP 1: Quick View Switching
  - Keybindings are fastest (Ctrl+K, Space, Ctrl+Shift+1)
  - Mouse clicks useful for discovery
  - Use arrow keys for sequential tabs

TIP 2: Campaign Operations Flow
  Typical workflow uses these tabs in order:
  1. Campaign (Ctrl+K) - Select active campaign
  2. Cmd Log (Ctrl+E) - Log commands
  3. Sessions (Ctrl+J) - Manage sessions
  4. Detections (Ctrl+D) - Log detections
  5. Dashboard (Ctrl+1) - Review metrics
  6. Cognition tabs (Ctrl+Shift+1-9) - Plan next action

TIP 3: Intelligence-Driven Ops
  1. Threat Intel (Ctrl+Shift+I) - Ingest IoCs/actors
  2. Opportunities (Ctrl+Shift+1) - Get recommendations
  3. Paths (Ctrl+Shift+2) - See attack graph
  4. Pressure (Ctrl+Shift+4) - Check detection state
  5. Confidence (Ctrl+Shift+5) - Assess decision confidence

TIP 4: Reporting & Evidence
  1. Reporting (Ctrl+R) - Generate reports
  2. Teams (Ctrl+T) - Coordination & approval
  3. Compliance (Alt+5) - Verify compliance

============================================================================
ACCESSIBILITY & CUSTOMIZATION
============================================================================

Tab Display Options:
  1. Compact Bar (default) - Shows most important views
  2. Full Panel (expandable) - Shows all tabs grouped
  3. Keyboard-only - Use arrow keys + Enter
  
Keybinding Customization:
  - Edit vv.py BINDINGS list to reassign keybindings
  - Restart app to apply changes
  
Color Customization:
  - Edit vv_theme.py CyberColors class
  - Tab colors follow Phosphor Cyberpunk palette
  - Restart app to apply changes

Accessibility Features:
  - Tab bar shows keybinding for every tab
  - All views accessible via keyboard
  - Status messages confirm view changes
  - Error messages for missing prerequisites (auth, campaign)

============================================================================
TROUBLESHOOTING
============================================================================

Issue: Tab doesn't respond to click
  → Check status bar for error message
  → May require authentication (login first)
  → May require campaign selection (Ctrl+K)

Issue: Can't find a view
  → Expand full tab panel (look for expand button)
  → Or use keyboard: arrow keys to navigate
  → Check documentation for correct keybinding

Issue: Tab bar disappeared
  → Toggle with dedicated keybinding (check config)
  → Or use keyboard (Alt+` to show/hide)

Issue: Keybinding conflicts
  → Check for conflicting OS/terminal keybindings
  → Edit vv.py BINDINGS to change VectorVue keybinding
  → Restart app to apply

============================================================================

For more information, see:
- docs/manuals/OPERATOR_MANUAL.md (Phase 5.5 section)
- docs/manuals/ARCHITECTURE_SPEC.md (Tab Navigation system)
- vv_tab_navigation.py (Source code)
"""
