# Unified SOC Analyst & Threat Hunter (CTF Edition)

A desktop GUI application for Security Operations Center (SOC) analysts and CTF competitors. It combines AI-powered KQL query generation, Azure Sentinel log analysis, file-based threat hunting, and automated incident reporting into a single unified interface.

## Overview

This tool bridges the gap between CTF flag hunting and real-world SOC investigation workflows. It uses OpenAI GPT models to generate KQL queries from natural language, analyze log data for indicators of compromise, and produce professional incident reports — all from a tabbed tkinter interface.

### Key Capabilities

- **Natural-language to KQL translation** — describe what you're looking for and the AI generates valid Kusto queries targeting 30+ Azure Sentinel / Defender tables.
- **Live Azure Log Analytics execution** — run generated (or hand-written) KQL directly against your workspace and get results in-app.
- **File-based threat hunting** — load PDFs, DOCX, TXT, or JSONL log exports and let the AI scan them page-by-page for flags and IOCs.
- **AI-assisted finding verification** — each candidate finding is presented for human review before being promoted to a verified flag.
- **Flag Bank & narrative builder** — accumulate verified findings and let the AI synthesize them into a cohesive incident narrative.
- **DOCX report generation** — export individual finding write-ups (with screenshots, KQL queries, and evidence) to a formatted Word document.
- **Incident report generator** — feed all findings, hints, and context into a template-driven AI report writer.
- **Full session save/load** — persist your entire investigation state (config, hints, flags, queries, reports) to a JSON file.

## Screenshots

*The application uses a tabbed interface with the following tabs:*

| Tab | Purpose |
|-----|---------|
| ⚙️ Configuration | API key and workspace ID setup |
| 🧩 Flag Hints | Add CTF hints; AI suggests what to look for and generates starter KQL |
| 🕵️ Threat Hunter | Load log files, run AI-driven page-by-page analysis, verify/discard findings |
| 🛡️ Azure SOC Agent | Natural-language → KQL → execute → AI analysis pipeline against live Azure |
| 🏦 Flag Bank | AI-generated narrative connecting all verified findings |
| 🏆 Flag Summary | Overview of all verified flags |
| 📝 Report Editor | Build per-finding entries with screenshots for Word export |
| 📑 Incident Report Generator | Template-driven AI report covering the full investigation |
| 💾 Session Manager | Save and restore full investigation state |
| 📖 How-To Guide | Built-in usage guide |

## Requirements

### Python Version

- Python 3.9+

### Dependencies

```bash
pip install openai pypdf azure-identity azure-monitor-query pandas colorama python-docx
```

### External Services

| Service | Required For | How to Configure |
|---------|-------------|-----------------|
| **OpenAI API key** | All AI features (KQL generation, log analysis, report writing) | Enter in the Configuration tab or set `OPENAI_API_KEY` env var |
| **Azure Log Analytics Workspace ID** | SOC Agent tab (live KQL execution) | Enter in the Configuration tab |
| **Azure credentials** | SOC Agent tab | Run `az login` or set Azure credential environment variables (`DefaultAzureCredential`) |

> The Threat Hunter, Flag Hints, Report Editor, and Incident Report Generator tabs work without Azure — they only need the OpenAI API key.

## Installation

```bash
# Clone the repository
git clone https://gitlab.com/<your-namespace>/unifiedsoctool.git
cd unifiedsoctool

# Install dependencies
pip install openai pypdf azure-identity azure-monitor-query pandas colorama python-docx

# Run
python unifiedsoctool.py
```

## Usage

### Quick-Start Workflow

1. **Configure** — open the ⚙️ Configuration tab and enter your OpenAI API key (and optionally your Azure Workspace ID).
2. **Add hints** — in 🧩 Flag Hints, paste CTF challenge hints. The AI will suggest what artifacts to look for and generate starter KQL queries.
3. **Set investigation focus** — use the top-bar flag selector to tell the AI which hint/flag you're currently working on.
4. **Hunt** — either:
   - Load log files into 🕵️ Threat Hunter and click **Start Hunt** for file-based analysis, or
   - Use 🛡️ Azure SOC Agent to query live Azure Sentinel data with natural language.
5. **Verify findings** — review each AI candidate. Click ✅ Verify to promote it or ❌ Discard to skip.
6. **Build context** — go to 🏦 Flag Bank and click **Update Understanding with AI** to synthesize all findings into a narrative.
7. **Generate reports** — use 📝 Report Editor for detailed per-finding write-ups with screenshots, or 📑 Incident Report Generator for a full investigation summary.
8. **Save your session** — use 💾 Session Manager to persist everything to a JSON file.

### SOC Agent — Natural Language Queries

In the 🛡️ Azure SOC Agent tab, type queries like:

- `"Show failed logins for admin accounts in the last 7 days"`
- `"Find devices with suspicious PowerShell execution"`
- `"Search for lateral movement activity"`
- `"Any emails with malicious attachments this week"`

The AI translates your request into KQL, executes it against Azure Log Analytics, and analyzes the results for findings.

**Self-healing queries:** if a query fails, click **Self-Heal Last KQL** and the AI will diagnose and fix the syntax error automatically.

### Supported Azure Tables

The KQL generator supports 30+ tables out of the box, including:

`DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceLogonEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `EmailEvents`, `EmailAttachmentInfo`, `SigninLogs`, `AuditLogs`, `SecurityAlert`, `SecurityIncident`, `SecurityEvent`, `Syslog`, `CommonSecurityLog`, `CloudAppEvents`, `IdentityLogonEvents`, `BehaviorAnalytics`, `Anomalies`, `ThreatIntelligenceIndicator`, and more.

Any valid table name in your workspace will also work — the AI is not limited to the built-in list.

### Supported AI Models

- `gpt-4o` (default)
- `gpt-4o-mini`
- `gpt-5.2`
- `gpt-5-mini`

Each tab has its own model selector so you can use faster models for simple tasks and more capable models for complex analysis.

## Project Structure

```
unifiedsoctool.py    # Single-file application — all logic, UI, and prompts
```

### Architecture

The application is structured into four layers inside the single file:

1. **Shared Configuration & Utils** — file extraction (PDF/DOCX/TXT), session logging, output formatting
2. **Prompts & AI Utils** — system prompts for KQL generation, threat hunting, and incident reporting; Azure Log Analytics execution; AI analysis functions
3. **Report Generator Logic** — `ThreatHuntReporterTab` class for building and exporting DOCX reports
4. **GUI Application** — `UnifiedSOCTool` class containing all tabs and application state

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `"No results found"` | Try a wider time range or broader search terms. Default is up to 1 year. |
| `"Query failed"` | Click **Self-Heal Last KQL** — the AI will diagnose and fix the syntax. |
| `"API key error"` | Verify your OpenAI key is valid and has credits. |
| `"Azure auth error"` | Run `az login` in your terminal, or set Azure credential environment variables. |
| `"Missing library"` | Run the `pip install` command listed under [Dependencies](#dependencies). |

## License

*GNU General Public License v3 (GPLv3)*

## Contributing

1. Fork this repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Merge Request