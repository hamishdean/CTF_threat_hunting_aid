"""Headless end-to-end exercise of the Unified SOC Tool with mocked AI + Azure.

Drives every tab the way an analyst would (settings -> Azure test -> list tables/schema
-> hint -> KQL -> agent retry -> execute -> parallel hunt -> verify -> results grid ->
timeline -> IOCs (ATT&CK names) -> narrative -> incident report -> docx -> session
round-trip) with ai_chat_completion and the Azure LogsQueryClient replaced by fakes,
so it needs no API keys or network. Tk still needs a display:

    python3 tests/test_e2e_mocked.py              # desktop
    xvfb-run -a python3 tests/test_e2e_mocked.py  # headless Linux / CI

Exit code is 0 when every check passes.
"""
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import importlib  # noqa: E402
import pkgutil  # noqa: E402
import soctool  # noqa: E402
import tkinter as tk  # noqa: E402
from azure.monitor.query import LogsQueryResult, LogsTable  # noqa: E402

# The app is a package; the code under test imports helpers by name into each
# module, so a monkeypatch has to land in every module that holds the name.
# This proxy reads from the first module that has the attribute and writes to
# all of them, which keeps the checks below as simple as `u.name = fake`.
_MODULES = [importlib.import_module(m.name) for m in pkgutil.walk_packages(soctool.__path__, "soctool.")] + [soctool]


class _PackageProxy:
    def __getattr__(self, name):
        for m in _MODULES:
            if hasattr(m, name):
                return getattr(m, name)
        raise AttributeError(name)

    def __setattr__(self, name, value):
        hit = False
        for m in _MODULES:
            if hasattr(m, name):
                setattr(m, name, value)
                hit = True
        if not hit:
            raise AttributeError(f"{name} not found in any soctool module")


u = _PackageProxy()
FAILURES = []


def check(cond, msg):
    print(("  PASS " if cond else "  FAIL ") + msg)
    if not cond:
        FAILURES.append(msg)


# ---------------------------------------------------------------- fake AI
AI_CALLS = []
KQL_PROMPTS = []   # full text of every KQL-generation prompt


def fake_ai(provider, api_key, model, messages, json_mode=False, max_tokens=4096, temperature=None, json_schema=None):
    joined = "\n".join(m["content"] for m in messages)
    AI_CALLS.append((model, json_mode, bool(json_schema), joined[:80].replace("\n", " ")))
    if "A query against Azure Log Analytics failed" in joined:          # fix_kql
        return json.dumps({"fixed_kql": "DeviceProcessEvents | where ProcessCommandLine has 'whoami' | take 5",
                           "explanation": "loosened filter"})
    if "expert Azure KQL" in joined:                                     # KQL generator
        KQL_PROMPTS.append(joined)
        if "brokenquery" in joined:
            kql = "DeviceProcessEvents | where FAILME"
        else:
            kql = "```kql\nDeviceProcessEvents | where ProcessCommandLine has 'powershell'\n```"
        assert json_schema and json_schema["name"] == "kql_query", "KQL generation should use the KQL schema"
        return json.dumps({"table_name": "DeviceProcessEvents", "kql_query": kql, "rationale": "look for powershell",
                           "fields": "TimeGenerated, DeviceName", "time_range_hours": 720})
    if "expert CTF Flag Hunter and SOC Analyst" in joined:                # hunt_on_records
        assert json_schema and json_schema["name"] == "findings"
        return "Here you go:\n```json\n" + json.dumps({"findings": [
            {"title": "Encoded PowerShell", "description": "base64 launcher", "flag_answer": "powershell -enc AAA",
             "confidence": "High", "severity": "High", "evidence": "powershell -enc AAA", "log_lines": ["powershell -enc AAA"]},
            {"title": "Same thing, different title", "description": "dupe", "flag_answer": "POWERSHELL -ENC AAA",
             "confidence": "High", "severity": "High", "evidence": "", "log_lines": []},
        ]}) + "\n```"
    if "You are a CTF Flag Hunter. Analyze this log excerpt" in joined:  # file hunter
        if "flag{" in joined:
            return json.dumps({"findings": [{
                "title": "File Flag", "description": "flag string in log", "flag_answer": "flag{deadbeef}",
                "severity": "High", "confidence": "High", "evidence": "line with flag{deadbeef}", "log_lines": []}]})
        return json.dumps({"findings": []})
    if "Write a very brief (1-sentence) note" in joined:
        return "The flag is flag{deadbeef}"
    if "You are a CTF Assistant" in joined:
        return json.dumps({"clue": "Look at process events", "kql": "DeviceProcessEvents | take 10"})
    if "Lead Incident Responder" in joined:
        return "NARRATIVE: attacker used encoded PowerShell (T1059.001)."
    if "Senior Security Operations Center" in joined:
        return "INCIDENT REPORT\nTimeline...\nMITRE T1059.001"
    if "senior threat hunter guiding an investigation" in joined:        # next steps
        return json.dumps({"assessment": "PowerShell launcher seen on ws01.",
                           "suggestions": [{"question": "Show network connections from ws01 around 2025-01-01T10:00Z", "why": "C2 check"},
                                           {"question": "Find logons to ws01 in the last 7 days", "why": "who ran it"}]})
    raise AssertionError("Unrecognised prompt: " + joined[:200])


u.ai_chat_completion = fake_ai

# Run worker threads synchronously: without a running mainloop, Tk rejects
# root.after() from a non-main thread ("main thread is not in main loop"),
# which cannot happen in the real app. Semantics of the code under test are
# unchanged; only scheduling is. (ThreadPoolExecutor batches stay real threads;
# the code under test keeps them Tk-free.)
import threading as _threading  # noqa: E402


class _SyncThread:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._t, self._a, self._k = target, args, kwargs or {}

    def start(self):
        self._t(*self._a, **self._k)

    def join(self, *a):
        pass

    def is_alive(self):
        return False


class _FakeThreading:
    Thread = _SyncThread
    Event = _threading.Event
    Lock = _threading.Lock


u.threading = _FakeThreading

# ---------------------------------------------------------------- fake Azure
QUERIES = []


def _table(columns, rows, types=None):
    return LogsTable(name="PrimaryResult", columns=columns, columns_types=types or ["string"] * len(columns), rows=rows)


class FakeLogsClient:
    def __init__(self, credential=None, **kw):
        pass

    def query_workspace(self, workspace_id, query, timespan):
        QUERIES.append((workspace_id, query, timespan))
        if "FAILME" in query:
            raise RuntimeError("Semantic error: 'FAILME' unknown")
        if workspace_id == "bad-ws":
            raise RuntimeError("(PathNotFoundError) The requested path does not exist")
        if query.startswith("print ok=1"):
            return LogsQueryResult(tables=[_table(["ok"], [[1]], ["long"])])
        if query.startswith("union withsource=TableName"):
            return LogsQueryResult(tables=[_table(["TableName", "Rows", "Latest"],
                                                  [["DeviceProcessEvents", 1200, "2025-01-01T11:00:00Z"],
                                                   ["SigninLogs", 40, "2025-01-01T09:00:00Z"]],
                                                  ["string", "long", "datetime"])])
        if "| getschema" in query:
            table = query.split()[0]
            cols = {"DeviceProcessEvents": ["TimeGenerated", "DeviceName", "ProcessCommandLine", "AccountName"],
                    "SigninLogs": ["TimeGenerated", "UserPrincipalName", "IPAddress"]}[table]
            return LogsQueryResult(tables=[_table(["ColumnName", "ColumnType"], [[c, "string"] for c in cols])])
        return LogsQueryResult(tables=[_table(
            ["TimeGenerated", "DeviceName", "ProcessCommandLine", "RemoteIP"],
            [["2025-01-01T10:00:00Z", "ws01", "powershell -enc AAA", "10.10.10.5"],
             ["2025-01-01T11:00:00Z", "ws02", "cmd /c whoami", "203.0.113[.]7"]],
            ["datetime", "string", "string", "string"])])


u.LogsQueryClient = FakeLogsClient
CRED_KWARGS = []


def _fake_credential(**kw):
    CRED_KWARGS.append(kw)
    return object()


u.DefaultAzureCredential = _fake_credential

# ---------------------------------------------------------------- fake dialogs
DIALOGS = []


class FakeMB:
    def __getattr__(self, name):
        def f(title="", msg="", **kw):
            DIALOGS.append((name, title, str(msg)[:80]))
            return True
        return f


u.messagebox = FakeMB()
ASK_RETURN = {"value": "The flag is flag{deadbeef}"}
u.simpledialog = type("SD", (), {"askstring": staticmethod(lambda *a, **k: ASK_RETURN["value"])})()
tmpdir = tempfile.mkdtemp()
SAVE_PATH = {"value": os.path.join(tmpdir, "out.json")}
u.filedialog = type("FD", (), {
    "asksaveasfilename": staticmethod(lambda *a, **k: SAVE_PATH["value"]),
    "askopenfilename": staticmethod(lambda *a, **k: SAVE_PATH["value"]),
    "askopenfilenames": staticmethod(lambda *a, **k: []),
})()
u.SETTINGS_PATH = os.path.join(tmpdir, "settings", "config.json")

# ---------------------------------------------------------------- build app
os.chdir(tmpdir)
u.CAPTURE_DIR = os.path.join(tmpdir, "soc_captured_logs")
root = tk.Tk()
app = u.UnifiedSOCTool(root)


def pump(n=5):
    for _ in range(n):
        root.update()
        time.sleep(0.02)


def toplevels():
    return [w for w in root.winfo_children() if isinstance(w, tk.Toplevel)]


def find_widgets(parent, cls):
    out = []
    for w in parent.winfo_children():
        if isinstance(w, cls):
            out.append(w)
        out.extend(find_widgets(w, cls))
    return out


def click_dialog(win, button_text, select_index=None):
    if select_index is not None:
        for lb in find_widgets(win, tk.Listbox):
            lb.selection_set(select_index)
    for b in find_widgets(win, u.ttk.Button):
        if b.cget("text") == button_text:
            b.invoke()
            return True
    return False


app.api_key_vars["OpenAI"].set("sk-test")
app.workspace_id_var.set("ws-1234")
console = lambda: app.soc_console.get("1.0", "end")  # noqa: E731

print("\n== 0. Azure connection test + tables/schema ==")
app.test_azure_connection()
pump()
check("✅" in app.azure_status_lbl.cget("text"), f"connection test green: {app.azure_status_lbl.cget('text')!r}")
check(CRED_KWARGS and CRED_KWARGS[-1].get("exclude_interactive_browser_credential") is False, "browser sign-in fallback enabled")
app.tenant_id_var.set("tenant-guid")
app.test_azure_connection()
pump()
check(CRED_KWARGS[-1].get("interactive_browser_tenant_id") == "tenant-guid", "tenant id passed to credential")
app.workspace_id_var.set("bad-ws")
app.test_azure_connection()
pump()
check("❌" in app.azure_status_lbl.cget("text") and "not found" in app.azure_status_lbl.cget("text"),
      f"bad workspace explained: {app.azure_status_lbl.cget('text')[:70]!r}")
app.workspace_id_var.set("ws-1234")
app.soc_list_tables()
pump()
check("DeviceProcessEvents" in console() and "2 table(s)" in console(), "list tables printed to console")
check(app.schema_cache.get("DeviceProcessEvents") == ["TimeGenerated", "DeviceName", "ProcessCommandLine", "AccountName"],
      f"schema fetched via getschema: {app.schema_cache}")
check("ProcessCommandLine" in app._schema_text() and "SigninLogs (40 rows)" in app._schema_text(), "schema text formatted for prompts")
check(len(app.results_tree.get_children()) == 2, "table listing shown in Results grid")
QUERIES.clear()

print("\n== 1. Flag Hints ==")
app.hint_input.insert("1.0", "The attacker ran an encoded PowerShell command")
app.new_hint_flag_var.set("Flag 1")
app._hint_thread("The attacker ran an encoded PowerShell command", "Flag 1")
pump()
check(len(app.ctf_hints) == 1 and app.ctf_hints[0]["kql"], "hint stored with KQL")
app.active_flag_var.set("Flag 1")
check(len(app.get_active_hints()) == 1, "active hints filter by focus")
app.hints_run_kql()
pump()
picker = toplevels()[-1]
check(click_dialog(picker, "OK", select_index=0), "run-hint picker opened and confirmed")
pump()
editors = [w for w in toplevels() if w.title() == "Manual KQL Editor"]
check(len(editors) == 1, "manual KQL editor opened from hint")
if editors:
    txt = find_widgets(editors[0], tk.Text)[0].get("1.0", "end").strip()
    check(txt == "DeviceProcessEvents | take 10", f"editor prefilled with the hint KQL: {txt!r}")
    editors[0].destroy()

print("\n== 2. SOC Agent: NL -> KQL (with schema) -> execute -> parallel hunt -> suggestions ==")
app.soc_prompt_text.insert("1.0", "find suspicious powershell")
app._soc_ai_thread("find suspicious powershell")
pump()
check(len(QUERIES) == 1, "one KQL executed against workspace")
kql_sent = QUERIES[0][1] if QUERIES else ""
check("```" not in kql_sent and "| take 500" in kql_sent, f"KQL sanitised (fences stripped, take added): {kql_sent!r}")
check(QUERIES[0][2].total_seconds() == 720 * 3600, "time_range_hours honoured")
check(KQL_PROMPTS and "WORKSPACE SCHEMA" in KQL_PROMPTS[-1] and "ProcessCommandLine" in KQL_PROMPTS[-1],
      "workspace schema injected into the KQL prompt")
check("FLAGS / ANSWERS FOUND (1)" in console(), "SOC console reports findings, duplicate answer dropped")
check(app.last_kql == kql_sent and app.last_error == "", "last_kql captured for self-heal")
caps = os.listdir(u.CAPTURE_DIR) if os.path.isdir(u.CAPTURE_DIR) else []
check(len(caps) == 1 and caps[0].endswith(".jsonl"), f"raw logs captured to jsonl: {caps}")
check(any(f.endswith(".jsonl") for f in app.th_files), "capture file added to Threat Hunter list")
check(len(app.soc_memory) == 1, "query stored in soc_memory")
editor = app.th_editor.get("1.0", "end")
check("Encoded PowerShell" in editor, "SOC finding pushed to Threat Hunter editor for verification")
check('"KQL": "DeviceProcessEvents' in editor and "EvidenceRows" in editor and "ws01" in editor,
      "candidate carries the KQL and matching raw rows as evidence")
check(app.soc_run_btn.instate(["!disabled"]), "run button re-enabled after SOC run")
check(len(app.results_tree.get_children()) == 2 and "ProcessCommandLine" in app.results_columns, "Results grid populated with query rows")
check("Agent assessment" in console() and "Suggested next pivots" in console(), "agent printed assessment + pivots")
check(app.soc_next_combo["values"] and "ws01" in app.soc_next_var.get(), "next-pivot combobox populated")
# Results grid: filter, sort, copy, pivot picker
app.results_filter_var.set("whoami")
app._results_render()
check(len(app.results_tree.get_children()) == 1, "results filter narrows rows")
app._results_clear_filter()
app._results_sort_by("DeviceName")
app._results_sort_by("DeviceName")
first = app.results_tree.item(app.results_tree.get_children()[0], "values")[1]
check(first == "ws02", "results sort descending by column")
app.results_tree.selection_set(app.results_tree.get_children()[0])
app.results_send_to_hunter()
check(any("selected_rows_" in f for f in app.th_files), "selected rows sent to Threat Hunter as JSONL")

print("\n== 2b. Agent auto-retry on a failing query ==")
QUERIES.clear()
app._soc_ai_thread("brokenquery please")
pump()
check(any("FAILME" in q[1] for q in QUERIES) and any("whoami" in q[1] for q in QUERIES), "failed query was auto-fixed and re-run")
check("Agent-fixed KQL" in console() and "attempt 1/2" in console(), "console shows the agent's fix attempt")
check(app.last_error == "" and len(app.soc_last_records) == 2, "retry produced results")
app.soc_auto_retry_var.set(0)
QUERIES.clear()
app._soc_ai_thread("brokenquery again")
pump()
check(len(QUERIES) == 1 and "Semantic error" in app.last_error, "retries disabled -> single attempt, error kept for Self-Heal")
app.soc_auto_retry_var.set(2)

print("\n== 3. Verify finding (AI note) ==")
app.th_verify()
pump()
check(len(app.verified_flags_data) == 1, "finding verified and stored")
if app.verified_flags_data:
    vf = app.verified_flags_data[0]
    check(vf["source"].startswith("SOC query"), f"provenance kept: {vf['source']}")
    check(vf["focus_id"] == "Flag 1", "focus id recorded")
    check(vf["flag_answer"] == "powershell -enc AAA" and vf["kql"].startswith("DeviceProcessEvents") and vf["evidence_rows"],
          "verified finding keeps answer, KQL and evidence rows")
check("powershell -enc aaa" in app.th_found_answers, "normalized answer recorded for dedupe")
check("ANSWER: powershell -enc AAA" in app.summary_text.get("1.0", "end"), "summary shows the answer")
check(app._th_verifying is False and app._th_candidate_shown is False, "verify guards reset")
check(len(app.timeline_tree.get_children()) >= 1 and any("Finding" in app.timeline_tree.item(i, "values")[1]
                                                          for i in app.timeline_tree.get_children()), "timeline tab lists the finding")
# A re-run must not re-propose the verified answer.
QUERIES.clear()
app._soc_ai_thread("find suspicious powershell again")
pump()
check("No flags or answers found" in console().split("STARTING AI INVESTIGATION")[-1], "already-verified answer not proposed again")

print("\n== 4. Threat Hunter on a text file (parallel, non-blocking) ==")
logf = os.path.join(tmpdir, "evidence.txt")
with open(logf, "w") as fh:
    fh.write("2025-01-01 10:00:00 ws01 powershell -enc AAA\n")
    fh.write("2025-01-01 10:05:00 ws01 connected to evil[.]example[.]com 203.0.113.7 hash "
             "d41d8cd98f00b204e9800998ecf8427e CVE-2024-1234 T1059.001\n")
    fh.write("here is the flag{deadbeef} for you, contact bad@evil.example.com\n")
    fh.write("filler line\n" * 3000)     # ~36k chars -> several pages and batches
    fh.write("another flag{deadbeef} mention later on\n")
app.th_files = [logf]
app.file_listbox.insert("end", "evidence.txt")
app.th_workers_var.set(4)
app.th_start_hunt()
pump()
check(app._th_batches_total >= 2, f"file split into several batches: {app._th_batches_total}")
check("File Flag" in app.th_editor.get("1.0", "end"), "file hunt produced candidate")
check("evidence.txt p" in app.th_editor.get("1.0", "end"), "candidate carries file/page provenance (whichever batch finished first)")
check(len(app.th_candidate_queue) == 0, "duplicate answer from a later batch was not queued twice")
check(not app._th_worker_active and app.th_current_idx == len(app.th_pages_buffer), "hunt finished all pages without pausing")
app.th_verify()
pump()
check(len(app.verified_flags_data) == 2, "second finding verified")
check("Hunt complete" in app.th_status_lbl.cget("text"), f"hunt finished: status={app.th_status_lbl.cget('text')!r}")
check(app.th_start_btn.instate(["!disabled"]), "start button re-enabled after hunt")

print("\n== 5. IOC extraction (+ ATT&CK names) ==")
app.ioc_extract_from_files()
pump()
r = app.ioc_results
check("203.0.113.7" in r.get("ipv4", []), "ipv4 extracted (defanged refanged)")
check("evil.example.com" in r.get("domain", []), "domain extracted")
check("d41d8cd98f00b204e9800998ecf8427e" in r.get("md5", []), "md5 extracted")
check("CVE-2024-1234" in r.get("cve", []), "cve extracted")
check("T1059.001" in r.get("mitre", []), "mitre extracted")
check("bad@evil.example.com" in r.get("email", []), "email extracted")
mitre_rows = [app.ioc_tree.item(i, "values") for i in app.ioc_tree.get_children() if app.ioc_tree.item(i, "values")[0] == "mitre"]
check(mitre_rows and "PowerShell" in mitre_rows[0][2] and "Execution" in mitre_rows[0][2], f"ATT&CK name shown: {mitre_rows}")
app.ioc_accumulate_var.set(True)
app.ioc_extract_from_findings()
pump()
check("10.10.10.5" in app.ioc_results.get("ipv4", []) and "T1059.001" in app.ioc_results.get("mitre", []),
      "IOCs from SOC records merged with file IOCs (accumulate mode)")
for item in app.ioc_tree.get_children():
    app.ioc_tree.selection_add(item)
app.ioc_pivot_to_soc()
check("10.10.10.5" in app.soc_prompt_text.get("1.0", "end"), "pivot to SOC populates prompt")
SAVE_PATH["value"] = os.path.join(tmpdir, "iocs.csv")
app.ioc_export("csv")
check(os.path.exists(SAVE_PATH["value"]) and "Command and Scripting" in open(SAVE_PATH["value"]).read(), "IOC csv exported with technique names")

print("\n== 6. Flag Bank narrative ==")
app._flag_bank_ai_thread(list(app.verified_flags_data), list(app.ctf_hints), "gpt-4o")
pump()
check("NARRATIVE" in app._flag_bank_cache, "flag bank narrative cached")
check("CURRENT INCIDENT UNDERSTANDING" in app._get_incident_context_for_kql(), "narrative injected into KQL ctx")

print("\n== 7. Incident report ==")
app.ioc_results.setdefault("mitre", ["T1059.001"])
internal, counts = app._gather_internal_data()
check(counts["flags"] == 2 and counts["iocs"] > 0 and counts["soc_queries"] >= 1, f"internal data gathered {counts}")
check("DETERMINISTIC TIMELINE" in internal and "Finding:" in internal, "timeline (with sources) built into report data")
check("KQL: DeviceProcessEvents" in internal and "Evidence: {" in internal, "report data carries KQL and evidence rows")
check("T1059.001 - Command and Scripting Interpreter: PowerShell" in internal, "ATT&CK technique name resolved for the report")
app._ir_process_thread(None, app.ir_template_text.get("1.0", "end"), internal)
pump()
check("INCIDENT REPORT" in app.ir_output_text.get("1.0", "end"), "incident report generated")

print("\n== 8. Self-heal (manual) ==")
QUERIES.clear()
app._soc_manual_thread("DeviceProcessEvents | where FAILME")
pump()
check("Semantic error" in app.last_error, "manual KQL failure captured for self-heal")
check("Hint:" in console(), "friendly hint printed for KQL compile error")
app._soc_self_heal_thread()
pump()
check("Fixed KQL proposed" in console() and "whoami" in console(), "self-heal proposed fix (schema-aware prompt)")
tops = [w for w in toplevels() if w.title() == "Confirm Fixed KQL"]
check(len(tops) == 1, "confirm-fix dialog opened")
for w in tops:
    w.destroy()

print("\n== 9. Report editor (docx) ==")
app.reporter.import_findings()
check(len(app.reporter.entries) == 2, "verified findings imported to report editor")
soc_entry = [e for e in app.reporter.entries if e["title"] == "Encoded PowerShell"]
check(soc_entry and soc_entry[0]["kql_query"].startswith("DeviceProcessEvents") and soc_entry[0]["flag"] == "powershell -enc AAA"
      and "Evidence rows" in soc_entry[0]["description"], "report entry filled with KQL, answer and evidence")
SAVE_PATH["value"] = os.path.join(tmpdir, "report.docx")
app.reporter.generate_report()
check(os.path.exists(SAVE_PATH["value"]) and os.path.getsize(SAVE_PATH["value"]) > 1000, "docx report written")

print("\n== 10. Session save / load round-trip ==")
SAVE_PATH["value"] = os.path.join(tmpdir, "session.json")
app.save_full_session()
check(os.path.exists(SAVE_PATH["value"]), "session saved")
with open(SAVE_PATH["value"]) as fh:
    sess = json.load(fh)
check(sess["config"]["api_key_openai"] == "", "API key NOT saved by default")
check(sess["config"]["tenant_id"] == "tenant-guid", "tenant id saved in session")
check(len(sess["hunter"]["verified_data"]) == 2 and sess["hunter"]["found_answers"], "verified findings + answers saved")
check(len(sess["soc"]["last_records"]) == 2 and sess["soc"]["known_tables"] and sess["soc"]["schema_cache"], "results, tables and schema saved")
# wipe and reload
app.verified_flags_data = []
app.ctf_hints = []
app.ioc_results = {}
app.th_found_answers = set()
app.soc_last_records = []
app.schema_cache = {}
app._results_show([], "")
app.load_full_session()
pump()
check(len(app.verified_flags_data) == 2 and len(app.ctf_hints) == 1, "session restored findings + hints")
check(app.ioc_results.get("ipv4"), "session restored IOCs")
check("powershell -enc aaa" in app.th_found_answers, "session restored answer dedupe set")
check(len(app.results_tree.get_children()) == 2 and app.schema_cache, "session restored results grid and schema")
check(app.api_key_vars["OpenAI"].get() == "sk-test", "loading keyless session keeps in-memory key")

print("\n== 11. Saved settings between launches ==")
app.remember_keys_var.set(True)
app.th_workers_var.set(5)
app.save_settings_clicked()
check(os.path.exists(u.SETTINGS_PATH), "settings file written")
saved = json.load(open(u.SETTINGS_PATH))
check(saved["workspace_id"] == "ws-1234" and saved["parallel_batches"] == 5 and "api_key" not in json.dumps(saved), "settings saved without secrets")
status = app.settings_status_lbl.cget("text")
check("keyring" in status.lower(), f"keyring outcome reported: {status[:90]!r}")
app.workspace_id_var.set("")
app.th_workers_var.set(1)
app._load_saved_settings()
check(app.workspace_id_var.get() == "ws-1234" and app.th_workers_var.get() == 5, "settings restored on startup path")

print("\n== 12. Stop / cancel path ==")
app._ai_cancel_event.set()
app._soc_ai_thread("anything")
pump()
check("STOPPED" in console(), "cancel honoured before query")
app._ai_cancel_event.clear()

print("\n== 13. Pure helpers ==")
check(u.sanitize_kql("SigninLogs | where ResultType != 0").endswith("| take 500"), "sanitize adds take")
check(u.sanitize_kql("SigninLogs | summarize count() by UserPrincipalName | take 20").count("take") == 1, "sanitize keeps existing take")
check(u.parse_ai_json('Sure!\n```json\n{"a": 1}\n```')["a"] == 1, "parse_ai_json strips prose+fences")
check(u.csv_safe_cell("=cmd|' /C calc'!A0").startswith("\"'="), "csv formula neutralised")
tl = u.build_timeline([{"TimeGenerated": "2025-01-02T00:00:00Z", "title": "b"}, {"timestamp": "2025-01-01T00:00:00Z", "title": "a", "_source": "S"}])
check([d for _, d, _ in tl] == ["a", "b"] and tl[0][2] == "S", "timeline sorted with sources")
chunks = u.chunk_text(('{"a":1}\n' * 1000), chunk_size=4000)
check(all(c.endswith("\n") and c.count("{") == c.count("}") for c in chunks), "chunk_text never splits a JSONL record")
check(u.explain_azure_error(Exception("DefaultAzureCredential failed to retrieve a token")).startswith("Azure sign-in failed"), "auth error explained")
check(u.explain_azure_error(Exception("AuthorizationFailed: 403")).startswith("Access denied"), "403 explained")
check(u.explain_azure_error(Exception("something odd")) == "", "unknown error -> no hint")
check(u.normalize_answer(' "POWERSHELL  -enc AAA" ') == "powershell -enc aaa", "normalize_answer canonicalises")
check(u.attack_technique_name("T1078") == "Valid Accounts" and u.attack_technique_name("T9999") == "", "ATT&CK lookup")
check(u._looks_like_schema_rejection(Exception("response_format json_schema not supported")) and
      not u._looks_like_schema_rejection(Exception("Incorrect API key provided")), "schema-rejection detector")
from azure.monitor.query import LogsQueryPartialResult  # noqa: E402
warnings = []


class _Partial:
    def query_workspace(self, **kw):
        return LogsQueryPartialResult(partial_data=[_table(["x"], [[1]], ["long"])], partial_error="query exceeded limits")


rows = u.execute_kql(_Partial(), "ws", "x", warn=warnings.append)
check(len(rows) == 1 and warnings and "PARTIAL" in warnings[0], "partial result rows returned + warning surfaced")

root.destroy()
print("\nAI calls made:", len(AI_CALLS))
print("\n%d FAILURES" % len(FAILURES))
for f in FAILURES:
    print(" -", f)
sys.exit(1 if FAILURES else 0)
