"""Headless end-to-end exercise of unifiedsoctool with mocked AI + Azure.

Drives every tab the way an analyst would (hint -> KQL -> execute -> hunt ->
verify -> IOCs -> narrative -> incident report -> docx -> session round-trip)
with ai_chat_completion and the Azure LogsQueryClient replaced by fakes, so it
needs no API keys or network. Tk still needs a display:

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
import unifiedsoctool as u  # noqa: E402
import tkinter as tk  # noqa: E402
from azure.monitor.query import LogsQueryResult, LogsTable  # noqa: E402

FAILURES = []


def check(cond, msg):
    print(("  PASS " if cond else "  FAIL ") + msg)
    if not cond:
        FAILURES.append(msg)


# ---------------------------------------------------------------- fake AI
AI_CALLS = []


def fake_ai(provider, api_key, model, messages, json_mode=False, max_tokens=4096, temperature=None):
    joined = "\n".join(m["content"] for m in messages)
    AI_CALLS.append((model, json_mode, joined[:80].replace("\n", " ")))
    if "expert Azure KQL" in joined:
        return json.dumps({
            "table_name": "DeviceProcessEvents",
            "kql_query": "```kql\nDeviceProcessEvents | where ProcessCommandLine has 'powershell'\n```",
            "rationale": "look for powershell",
            "fields": "TimeGenerated, DeviceName",
            "parameters": {"time_range_hours": "720 hours"},
        })
    if "expert CTF Flag Hunter and SOC Analyst" in joined:  # hunt_on_records
        return "Here you go:\n```json\n" + json.dumps({"findings": [{
            "title": "Encoded PowerShell", "description": "base64 launcher",
            "flag_answer": "powershell -enc AAA", "confidence": "High",
            "log_lines": ["powershell -enc AAA"], "notes": ""}]}) + "\n```"
    if "You are a CTF Flag Hunter. Analyze this log excerpt" in joined:
        if "flag{" in joined:
            return json.dumps({"findings": [{
                "title": "File Flag", "description": "flag string in log",
                "flag_answer": "flag{deadbeef}", "severity": "High",
                "evidence": "line with flag{deadbeef}"}]})
        return json.dumps({"findings": []})
    if "Write a very brief (1-sentence) note" in joined:
        return "The flag is flag{deadbeef}"
    if "You are a CTF Assistant" in joined:
        return json.dumps({"clue": "Look at process events", "kql": "DeviceProcessEvents | take 10"})
    if "Lead Incident Responder" in joined:
        return "NARRATIVE: attacker used encoded PowerShell (T1059.001)."
    if "Senior Security Operations Center" in joined:
        return "INCIDENT REPORT\nTimeline...\nMITRE T1059.001"
    if "You are a KQL Expert" in joined:
        return json.dumps({"fixed_kql": "DeviceProcessEvents | take 5", "explanation": "widened"})
    raise AssertionError("Unrecognised prompt: " + joined[:200])


u.ai_chat_completion = fake_ai

# Run worker threads synchronously: without a running mainloop, Tk rejects
# root.after() from a non-main thread ("main thread is not in main loop"),
# which cannot happen in the real app. Semantics of the code under test are
# unchanged; only scheduling is.
import threading as _threading
class _SyncThread:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._t, self._a, self._k = target, args, kwargs or {}
    def start(self):
        self._t(*self._a, **self._k)
    def join(self, *a): pass
    def is_alive(self): return False
class _FakeThreading:
    Thread = _SyncThread
    Event = _threading.Event
    Lock = _threading.Lock
u.threading = _FakeThreading

# ---------------------------------------------------------------- fake Azure
QUERIES = []


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
            t = LogsTable(name="PrimaryResult", columns=["ok"], columns_types=["long"], rows=[[1]])
            return LogsQueryResult(tables=[t])
        if query.startswith("union withsource=TableName"):
            t = LogsTable(name="PrimaryResult", columns=["TableName", "Rows", "Latest"],
                          columns_types=["string", "long", "datetime"],
                          rows=[["DeviceProcessEvents", 1200, "2025-01-01T11:00:00Z"],
                                ["SigninLogs", 40, "2025-01-01T09:00:00Z"]])
            return LogsQueryResult(tables=[t])
        t = LogsTable(name="PrimaryResult",
                      columns=["TimeGenerated", "DeviceName", "ProcessCommandLine", "RemoteIP"],
                      columns_types=["datetime", "string", "string", "string"],
                      rows=[["2025-01-01T10:00:00Z", "ws01", "powershell -enc AAA", "10.10.10.5"],
                            ["2025-01-01T11:00:00Z", "ws02", "cmd /c whoami", "203.0.113[.]7"]])
        return LogsQueryResult(tables=[t])


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

# ---------------------------------------------------------------- build app
os.chdir(tmpdir)
u.CAPTURE_DIR = os.path.join(tmpdir, "soc_captured_logs")
root = tk.Tk()
app = u.UnifiedSOCTool(root)


def pump(n=5):
    for _ in range(n):
        root.update()
        time.sleep(0.02)


app.api_key_vars["OpenAI"].set("sk-test")
app.workspace_id_var.set("ws-1234")

print("\n== 0. Azure connection test + table listing ==")
app.test_azure_connection()
pump()
check("✅" in app.azure_status_lbl.cget("text"), f"connection test green: {app.azure_status_lbl.cget('text')!r}")
check(CRED_KWARGS and CRED_KWARGS[-1].get("exclude_interactive_browser_credential") is False,
      "browser sign-in fallback enabled")
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
check("DeviceProcessEvents" in app.soc_console.get("1.0", "end") and "2 table(s)" in app.soc_console.get("1.0", "end"),
      "list tables printed to console")
QUERIES.clear()

print("\n== 1. Flag Hints ==")
app.hint_input.insert("1.0", "The attacker ran an encoded PowerShell command")
app.new_hint_flag_var.set("Flag 1")
app._hint_thread("The attacker ran an encoded PowerShell command", "Flag 1")
pump()
check(len(app.ctf_hints) == 1 and app.ctf_hints[0]["kql"], "hint stored with KQL")
app.active_flag_var.set("Flag 1")
check(len(app.get_active_hints()) == 1, "active hints filter by focus")

print("\n== 2. SOC Agent: NL -> KQL -> execute -> hunt ==")
app.soc_prompt_text.insert("1.0", "find suspicious powershell")
app._soc_ai_thread("find suspicious powershell")
pump()
console = app.soc_console.get("1.0", "end")
check(len(QUERIES) == 1, "one KQL executed against workspace")
kql_sent = QUERIES[0][1] if QUERIES else ""
check("```" not in kql_sent and "| take 500" in kql_sent, f"KQL sanitised (fences stripped, take added): {kql_sent!r}")
check(QUERIES[0][2].total_seconds() == 720 * 3600, "time_range_hours parsed from '720 hours'")
check("FLAGS / ANSWERS FOUND" in console, "SOC console reports findings")
check(app.last_kql == kql_sent and app.last_error == "", "last_kql captured for self-heal")
caps = os.listdir(u.CAPTURE_DIR) if os.path.isdir(u.CAPTURE_DIR) else []
check(len(caps) == 1 and caps[0].endswith(".jsonl"), f"raw logs captured to jsonl: {caps}")
check(any(f.endswith(".jsonl") for f in app.th_files), "capture file added to Threat Hunter list")
check(len(app.soc_memory) == 1, "query stored in soc_memory")
editor = app.th_editor.get("1.0", "end")
check("Encoded PowerShell" in editor, "SOC finding pushed to Threat Hunter editor for verification")
check(app.soc_run_btn.instate(["!disabled"]), "run button re-enabled after SOC run")

print("\n== 3. Verify finding (AI note) ==")
app.th_verify()
pump()
# note thread runs in background; wait for it
for _ in range(50):
    pump(1)
    if app.verified_flags_data:
        break
check(len(app.verified_flags_data) == 1, "finding verified and stored")
if app.verified_flags_data:
    vf = app.verified_flags_data[0]
    check(vf["source"].startswith("SOC query"), f"provenance kept: {vf['source']}")
    check(vf["focus_id"] == "Flag 1", "focus id recorded")
check("Encoded PowerShell" in app.summary_text.get("1.0", "end"), "summary tab updated")
check(app._th_verifying is False, "verify guard reset")

print("\n== 4. Threat Hunter on a text file ==")
logf = os.path.join(tmpdir, "evidence.txt")
with open(logf, "w") as fh:
    fh.write("2025-01-01 10:00:00 ws01 powershell -enc AAA\n")
    fh.write("2025-01-01 10:05:00 ws01 connected to evil[.]example[.]com 203.0.113.7 hash "
             "d41d8cd98f00b204e9800998ecf8427e CVE-2024-1234 T1059.001\n")
    fh.write("here is the flag{deadbeef} for you, contact bad@evil.example.com\n")
app.th_files = [logf]
app.file_listbox.insert("end", "evidence.txt")
app._ai_cancel_event.clear()
app._set_ai_running(True)
app.th_current_idx = 0
app.th_candidate_queue = []
app.th_pages_buffer = []
app.th_pages_source = []
app._th_read_then_hunt()
pump()
check("File Flag" in app.th_editor.get("1.0", "end"), "file hunt produced candidate")
check("evidence.txt p1" in app.th_editor.get("1.0", "end"), "candidate carries file/page provenance")
app.th_verify()
for _ in range(50):
    pump(1)
    if len(app.verified_flags_data) == 2:
        break
check(len(app.verified_flags_data) == 2, "second finding verified")
check("Hunt complete" in app.th_status_lbl.cget("text") or "Idle" in app.th_status_lbl.cget("text"),
      f"hunt finished: status={app.th_status_lbl.cget('text')!r}")
check(app.th_start_btn.instate(["!disabled"]), "start button re-enabled after hunt")

print("\n== 5. IOC extraction ==")
app.ioc_extract_from_files()
pump()
r = app.ioc_results
check("203.0.113.7" in r.get("ipv4", []), "ipv4 extracted (defanged refanged)")
check("evil.example.com" in r.get("domain", []), "domain extracted")
check("d41d8cd98f00b204e9800998ecf8427e" in r.get("md5", []), "md5 extracted")
check("CVE-2024-1234" in r.get("cve", []), "cve extracted")
check("T1059.001" in r.get("mitre", []), "mitre extracted")
check("bad@evil.example.com" in r.get("email", []), "email extracted")
app.ioc_extract_from_findings()
pump()
check("10.10.10.5" in app.ioc_results.get("ipv4", []), "IOCs from SOC records")
for item in app.ioc_tree.get_children():
    app.ioc_tree.selection_add(item)
app.ioc_pivot_to_soc()
check("10.10.10.5" in app.soc_prompt_text.get("1.0", "end"), "pivot to SOC populates prompt")
SAVE_PATH["value"] = os.path.join(tmpdir, "iocs.csv")
app.ioc_export("csv")
check(os.path.exists(SAVE_PATH["value"]), "IOC csv exported")

print("\n== 6. Flag Bank narrative ==")
app._flag_bank_ai_thread(list(app.verified_flags_data), list(app.ctf_hints), "gpt-4o")
pump()
check("NARRATIVE" in app._flag_bank_cache, "flag bank narrative cached")
check("CURRENT INCIDENT UNDERSTANDING" in app._get_incident_context_for_kql(), "narrative injected into KQL ctx")

print("\n== 7. Incident report ==")
internal, counts = app._gather_internal_data()
check(counts["flags"] == 2 and counts["iocs"] > 0 and counts["soc_queries"] == 1, f"internal data gathered {counts}")
check("DETERMINISTIC TIMELINE" in internal, "timeline built from SOC records")
app._ir_process_thread(None, app.ir_template_text.get("1.0", "end"), internal)
pump()
check("INCIDENT REPORT" in app.ir_output_text.get("1.0", "end"), "incident report generated")

print("\n== 8. Self-heal ==")
QUERIES.clear()
app.last_kql = "DeviceProcessEvents | where FAILME"
app._soc_manual_thread("DeviceProcessEvents | where FAILME")
pump()
check("Semantic error" in app.last_error, "manual KQL failure captured for self-heal")
check("Hint:" in app.soc_console.get("1.0", "end"), "friendly hint printed for KQL compile error")
app._soc_self_heal_thread()
pump()
check("Fixed KQL proposed" in app.soc_console.get("1.0", "end"), "self-heal proposed fix")
# the confirm dialog is a Toplevel; find & run it
tops = [w for w in root.winfo_children() if isinstance(w, tk.Toplevel)]
check(len(tops) == 1, "confirm-fix dialog opened")
for w in tops:
    w.destroy()

print("\n== 9. Report editor (docx) ==")
app.reporter.import_findings()
check(len(app.reporter.entries) == 2, "verified findings imported to report editor")
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
check(len(sess["hunter"]["verified_data"]) == 2, "verified findings saved")
# wipe and reload
app.verified_flags_data = []
app.ctf_hints = []
app.ioc_results = {}
app.load_full_session()
pump()
check(len(app.verified_flags_data) == 2 and len(app.ctf_hints) == 1, "session restored findings + hints")
check(app.ioc_results.get("ipv4"), "session restored IOCs")
check(app.api_key_vars["OpenAI"].get() == "sk-test", "loading keyless session keeps in-memory key")

print("\n== 11. Stop / cancel path ==")
app._ai_cancel_event.set()
app._soc_ai_thread("anything")
pump()
check("STOPPED" in app.soc_console.get("1.0", "end"), "cancel honoured before query")
app._ai_cancel_event.clear()

print("\n== 12. Pure helpers ==")
check(u.sanitize_kql("SigninLogs | where ResultType != 0") .endswith("| take 500"), "sanitize adds take")
check(u.sanitize_kql("SigninLogs | summarize count() by UserPrincipalName | take 20").count("take") == 1, "sanitize keeps existing take")
check(u.parse_ai_json('Sure!\n```json\n{"a": 1}\n```')["a"] == 1, "parse_ai_json strips prose+fences")
check(u.csv_safe_cell("=cmd|' /C calc'!A0").startswith("\"'="), "csv formula neutralised")
tl = u.build_timeline([{"TimeGenerated": "2025-01-02T00:00:00Z", "title": "b"}, {"timestamp": "2025-01-01T00:00:00Z", "title": "a"}])
check([d for _, d in tl] == ["a", "b"], "timeline sorted")
chunks = u.chunk_text(('{"a":1}\n' * 1000), chunk_size=4000)
check(all(c.endswith("\n") and c.count("{") == c.count("}") for c in chunks), "chunk_text never splits a JSONL record")
check(u.explain_azure_error(Exception("DefaultAzureCredential failed to retrieve a token")).startswith("Azure sign-in failed"),
      "auth error explained")
check(u.explain_azure_error(Exception("AuthorizationFailed: 403")).startswith("Access denied"), "403 explained")
check(u.explain_azure_error(Exception("something odd")) == "", "unknown error -> no hint")
# partial results are surfaced
from azure.monitor.query import LogsQueryPartialResult
warnings = []
class _Partial:
    def query_workspace(self, **kw):
        t = LogsTable(name="P", columns=["x"], columns_types=["long"], rows=[[1]])
        return LogsQueryPartialResult(partial_data=[t], partial_error="query exceeded limits")
rows = u.execute_kql(_Partial(), "ws", "x", warn=warnings.append)
check(len(rows) == 1 and warnings and "PARTIAL" in warnings[0], "partial result rows returned + warning surfaced")

root.destroy()
print("\nAI calls made:", len(AI_CALLS))
print("Dialogs shown:", DIALOGS)
print("\n%d FAILURES" % len(FAILURES))
for f in FAILURES:
    print(" -", f)
sys.exit(1 if FAILURES else 0)
