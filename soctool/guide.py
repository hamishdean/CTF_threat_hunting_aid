# -*- coding: utf-8 -*-
"""Text of the built-in How-To Guide tab."""

GUIDE_TEXT = """\
================================================================================
        UNIFIED SOC ANALYST & THREAT HUNTER - HOW-TO GUIDE
================================================================================

TABLE OF CONTENTS
-----------------
  1. Getting Started (Prerequisites & Configuration)
  2. Tab-by-Tab Walkthrough
     2a. Configuration
     2b. Flag Hints
     2c. Threat Hunter
     2d. Azure SOC Agent
     2d.1 IOC Extractor
     2e. Flag Bank (Context)
     2f. Flag Summary
     2g. Report Editor
     2h. Incident Report Generator
     2i. Session Manager
  3. Typical Investigation Workflow
  4. Tips & Troubleshooting


================================================================================
1. GETTING STARTED
================================================================================

PREREQUISITES
  - Python 3.9+
  - Required libraries (install with pip):
      pip install openai pypdf azure-identity azure-monitor-query pandas
      pip install colorama python-docx
  - Optional AI providers (install as needed):
      pip install anthropic          (for Claude support)
      pip install google-genai        (for Gemini support)
  - An API key for your chosen AI provider:
      OpenAI: https://platform.openai.com
      Google Gemini: https://aistudio.google.com
      Anthropic Claude: https://console.anthropic.com
  - An Azure Log Analytics Workspace ID (for the SOC Agent tab)
  - Azure credentials: run "az login" (Azure CLI), or just click
    "Test Azure Connection" in Configuration and sign in via the browser
    window that opens.

FIRST LAUNCH
  1. Run the tool:  python unifiedsoctool.py
  2. Go to the "Configuration" tab.
  3. Select your AI Provider (OpenAI, Gemini, or Claude).
  4. Paste the corresponding API key.
  5. Paste your Log Analytics Workspace ID (for SOC Agent tab).
     If the workspace lives in a tenant where you are a guest (typical for
     CTFs and client engagements), also paste that Tenant ID.
  6. Click "Test Azure Connection" - it should turn green.
  7. You are now ready to use all features.


================================================================================
2. TAB-BY-TAB WALKTHROUGH
================================================================================

--------------------------------------------------------------------------------
2a. CONFIGURATION TAB
--------------------------------------------------------------------------------
  PURPOSE: Store your AI provider settings and API keys in memory.

  HOW TO USE:
  - Select your AI Provider (OpenAI, Gemini, or Claude).
  - Paste your API key(s) in the corresponding field(s) (masked for security).
  - Paste your Azure Log Analytics Workspace ID in the Azure Settings section.
  - Optional: paste the Azure Tenant ID that owns the workspace.
  - Click "Test Azure Connection". Green = signed in and the workspace answered.
    Red = a one-line explanation of what to fix (sign-in, wrong ID, missing role).
  - These credentials are NOT saved to disk unless you use Session Manager.
  - Tip: API keys can be set via environment variables:
    OPENAI_API_KEY, GEMINI_API_KEY, ANTHROPIC_API_KEY


--------------------------------------------------------------------------------
2b. FLAG HINTS TAB
--------------------------------------------------------------------------------
  PURPOSE: Add and analyze CTF hints. The AI generates investigative clues
  and suggests KQL queries based on each hint.

  HOW TO USE:
  1. Select a flag number from the "Assign to Flag" dropdown (Flag 1-100).
  2. Type or paste the hint text in the text area.
  3. Choose an AI model (gpt-4o is recommended for best results).
  4. Click "Analyze Hint".
  5. The AI will return:
     - A clue (what artifact to look for).
     - A suggested KQL query to find it.
  6. Results appear in the "Active Hints" panel below.

  TIP: Use the "Investigation Focus" dropdown at the top of the window to
  filter which hints are sent to the AI during investigations. Set it to
  a specific flag to focus, or "General/All" to use all hints.


--------------------------------------------------------------------------------
2c. THREAT HUNTER TAB
--------------------------------------------------------------------------------
  PURPOSE: Load files (PDF, TXT, LOG, JSONL) and let the AI scan them for
  security threats, flags, and suspicious activity.

  HOW TO USE:
  1. Click "Add Files" and select one or more supported files.
  2. Choose an AI model.
  3. Click "START HUNT".
  4. The AI reads the files in batches and looks for threats.
  5. When a finding is discovered, it appears in the "Potential Flag" editor:
     - Click "Verify & Save" to confirm and save the finding.
     - Click "Discard" to skip it.
  6. Verified findings are added to the Flag Summary instantly.

  AUTO-REFRESH: By default, verifying a flag does NOT regenerate the Incident
  Report or Flag Bank narrative (those cost API calls and overwrite manual
  edits). Tick "Auto-refresh reports on verify" in the action row if you want
  that automatically; otherwise refresh them on demand from their own tabs.

  MANUAL FLAG: Click "Manually Add Flag" to enter a finding by hand
  (useful if you spot something the AI missed).


--------------------------------------------------------------------------------
2d. AZURE SOC AGENT TAB
--------------------------------------------------------------------------------
  PURPOSE: Query Azure Log Analytics using natural language. The AI converts
  your question into KQL and executes it against your workspace.

  HOW TO USE:
  1. Type your investigation question in the prompt box, e.g.:
     "Find all failed sign-ins from external IPs in the last 7 days"
     "Show process executions on device WKS01"
     "Search for PowerShell activity across all devices"
  2. Click "Run AI Investigation":
     - AI generates a KQL query.
     - Query runs against Azure Log Analytics (up to 1 year of data).
     - Results are analyzed for threats automatically.
     - Findings are pushed to the Threat Hunter for verification.
  3. Click "Stop AI" at any time to halt a running investigation.

  OTHER BUTTONS:
  - "Generate KQL Only": See the AI-generated query without running it.
  - "Open Manual KQL Editor": Write and execute your own KQL query directly.
  - "List Tables": Show every table that has data in the last year, with row
    counts. Name one of them in your prompt to steer the AI's KQL.
  - "Export Log to File": Save the console output to a .txt file.
  - "Self-Heal Last KQL": If a query fails, the AI attempts to fix and
    re-run it automatically.

  TIME RANGE:
  - The tool searches up to 1 year (365 days) of log data by default.
  - The AI can adjust this based on your query (e.g., "last 7 days").
  - Manual KQL queries also support up to 1 year.

  TABLES:
  You can query ANY table in your Azure Log Analytics workspace.
  Just name the table in your query and the AI will use it.
  Common tables include:
  - DeviceProcessEvents     - DeviceNetworkEvents
  - DeviceLogonEvents       - DeviceFileEvents
  - DeviceRegistryEvents    - DeviceImageLoadEvents
  - EmailEvents             - EmailAttachmentInfo
  - IdentityLogonEvents     - CloudAppEvents
  - SigninLogs              - AuditLogs
  - AzureActivity           - SecurityAlert
  - SecurityIncident        - SecurityEvent
  - Syslog                  - CommonSecurityLog
  - ThreatIntelligenceIndicator  - BehaviorAnalytics
  - ...and any other table in your workspace


--------------------------------------------------------------------------------
2d.1 IOC EXTRACTOR TAB
--------------------------------------------------------------------------------
  PURPOSE: Pull indicators of compromise out of your data with no AI/API calls.
  Extracts IPv4/IPv6, domains, URLs, emails, MD5/SHA1/SHA256 hashes, CVEs, and
  MITRE ATT&CK technique IDs. Understands defanged IOCs (hxxp://, 1.2.3[.]4).

  HOW TO USE:
  1. Load files in the Threat Hunter tab (or accumulate findings / SOC results).
  2. Click "Extract from Loaded Files" or "Extract from Findings & Logs".
  3. Review the categorized indicators in the table.
  4. Select one or more indicators, then:
     - "Pivot Selected -> SOC Agent" prefills a hunt query for those IOCs.
     - "Copy Selected" copies them to the clipboard.
  5. "Export CSV" / "Export JSON" saves the full IOC set for reporting.


--------------------------------------------------------------------------------
2e. FLAG BANK (CONTEXT) TAB
--------------------------------------------------------------------------------
  PURPOSE: AI-generated narrative that connects all your verified findings
  into a coherent story.

  HOW TO USE:
  1. Click "Update Understanding with AI" to generate/refresh the narrative.
  2. The AI reviews all verified flags and hints, then writes a cohesive
     summary connecting the dots.
  3. Click "Export Narrative to Incident Report" to push this context into
     the Incident Report Generator's template.


--------------------------------------------------------------------------------
2f. FLAG SUMMARY TAB
--------------------------------------------------------------------------------
  PURPOSE: View all verified flags and their analyst notes in one place.

  HOW TO USE:
  - Click "Refresh Display" to update.
  - Flags are listed with their title, focus ID, and note.
  - This is your master list of confirmed findings.


--------------------------------------------------------------------------------
2g. REPORT EDITOR TAB (Threat Hunt Reporter)
--------------------------------------------------------------------------------
  PURPOSE: Build a formal threat hunt report with findings, methodology,
  KQL queries, and screenshots, then export as a Word (.docx) document.

  HOW TO USE:
  1. Fill in "Author Name" and "Event/Engagement".
  2. For each finding:
     a. Enter Challenge/Title, select a Category.
     b. Describe the finding and your methodology.
     c. Paste the KQL query used.
     d. Enter the flag/artifact value.
     e. Optionally attach screenshots with captions.
     f. Click "Add Entry to Report".
  3. Review entries in the "Entries Queued" list.
  4. Click "GENERATE WORD DOC REPORT" to create the .docx file.

  SUB-TAB "Help & Instructions": Quick reference for this module.


--------------------------------------------------------------------------------
2h. INCIDENT REPORT GENERATOR TAB
--------------------------------------------------------------------------------
  PURPOSE: Generate a formal incident investigation report using ALL data
  available in the program, plus optional uploaded documents.

  DATA SOURCES (auto-included via checkboxes):
  - Verified Flags & Answers: All confirmed findings with exact answers.
  - CTF Hints & Clues: All hints and AI-generated investigation clues.
  - Flag Bank Narrative: The AI-generated incident understanding story.
  - SOC Agent Console & Queries: All KQL queries run, plus latest results.
  - Uploaded Document (optional): Any .docx, .txt, or .pdf file.

  HOW TO USE:
  1. (Optional) Click "Browse" to attach a source log file.
  2. Check/uncheck the internal data sources you want to include.
  3. Edit the report template if desired (Who/What/When/Where/Why/How).
  4. Click "Generate Report":
     - The AI gathers all checked internal data automatically.
     - Reads the uploaded document (if any).
     - Creates a timeline of events.
     - Fills in the template with all findings and flag answers.
     - References KQL queries and evidence used.
  5. Click "Save Report to .txt" to export.

  NOTE: You do NOT need an uploaded file. The report can be generated
  entirely from internal data (flags, hints, SOC queries, etc.).


--------------------------------------------------------------------------------
2i. SESSION MANAGER TAB
--------------------------------------------------------------------------------
  PURPOSE: Save and restore your entire application state.

  HOW TO USE:
  - "Save Full Session": Saves everything (API keys, hints, flags, queries,
    reports, console output) to a JSON file.
  - "Load Full Session": Restores a previously saved session.

  TIP: Save your session frequently, especially during long investigations.


================================================================================
3. TYPICAL INVESTIGATION WORKFLOW
================================================================================

  Step 1: CONFIGURE
     Set up API key and Workspace ID in the Configuration tab.

  Step 2: ADD HINTS (if applicable)
     Go to Flag Hints tab and add any hints or leads you have.
     Let the AI analyze them for investigative clues.

  Step 3: INVESTIGATE WITH SOC AGENT
     Go to the Azure SOC Agent tab.
     Ask questions in natural language:
       "Show all sign-in failures for user john@company.com"
       "Find devices with suspicious PowerShell execution"
       "Search for lateral movement activity"
     The AI generates KQL, runs it, and analyzes results.

  Step 4: REVIEW & VERIFY FINDINGS
     Switch to Threat Hunter when findings appear.
     Verify or discard each finding.
     Add manual flags for anything the AI missed.

  Step 5: BUILD CONTEXT
     Go to Flag Bank and click "Update Understanding with AI".
     Review the AI's narrative connecting all findings.

  Step 6: GENERATE REPORTS
     Use the Report Editor for detailed per-finding reports with screenshots.
     Use the Incident Report Generator for a formal investigation summary.

  Step 7: SAVE SESSION
     Save your session in the Session Manager tab for future reference.


================================================================================
4. TIPS & TROUBLESHOOTING
================================================================================

  QUERY TIPS:
  - Be specific in your questions: "failed logins for admin on WKS01"
    works better than "show me everything suspicious".
  - If a query fails, click "Self-Heal Last KQL" to auto-fix.
  - Use "Generate KQL Only" to preview queries before running them.
  - For complex queries the AI can't handle, use "Open Manual KQL Editor".

  KQL SYNTAX QUICK REFERENCE:
  - Filter:    | where ColumnName == "value"
  - Contains:  | where ColumnName contains "partial"
  - Starts:    | where ColumnName startswith "prefix"
  - Time:      | where TimeGenerated > ago(7d)
  - Limit:     | take 100
  - Sort:      | order by TimeGenerated desc
  - Search:    search "keyword" | take 100

  COMMON ISSUES:
  - "No results found": Try a wider time range or broader search terms.
    The tool searches up to 1 year by default.
  - "Query failed": Click "Self-Heal Last KQL". The AI will diagnose and
    fix the syntax error.
  - "API key error": Make sure your API key is valid and has credits.
    Ensure the correct provider is selected in the Configuration tab.
  - "Azure sign-in failed": Run "az login" (add --tenant <id> for a guest
    tenant), or set the Tenant ID in Configuration and click "Test Azure
    Connection" to sign in through the browser.
  - "Workspace not found": Re-check the Workspace ID and that you are signed
    in to the tenant that owns it.
  - "Access denied": You need the Log Analytics Reader role on the workspace.
  - "Missing library": Run the pip install command shown at startup.

  KEYBOARD & MOUSE:
  - Mousewheel scrolls all text areas.
  - Standard copy/paste shortcuts work everywhere (Ctrl+C, Ctrl+V).
  - Tab key navigates between fields.

================================================================================
"""
