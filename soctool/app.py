# -*- coding: utf-8 -*-
"""Application shell: state, top bar, tab assembly, and the entry point."""
import os
import sys
import threading
from .config import DEFAULT_MODEL
from .deps import HAS_TK, _MISSING_LIBS, init, tk, ttk
from .reporter import ThreatHuntReporterTab

from .tabs.config_tab import ConfigTabMixin
from .tabs.hints_tab import HintsTabMixin
from .tabs.flagbank_tab import FlagBankTabMixin
from .tabs.hunter_tab import HunterTabMixin
from .tabs.soc_tab import SocTabMixin
from .tabs.iocs_tab import IocsTabMixin
from .tabs.results_tab import ResultsTabMixin
from .tabs.timeline_tab import TimelineTabMixin
from .tabs.summary_tab import SummaryTabMixin
from .tabs.incident_tab import IncidentTabMixin
from .tabs.session_tab import SessionTabMixin
from .tabs.guide_tab import GuideTabMixin

class UnifiedSOCTool(ConfigTabMixin, HintsTabMixin, FlagBankTabMixin, HunterTabMixin, SocTabMixin, ResultsTabMixin, TimelineTabMixin, IocsTabMixin, SummaryTabMixin, IncidentTabMixin, SessionTabMixin, GuideTabMixin):
    def __init__(self, root):
        self.root = root
        self.root.title("Unified SOC Analyst & Threat Hunter (CTF Edition)")
        self.root.geometry("1400x900")

        self.provider_var = tk.StringVar(value="OpenAI")
        self.api_key_vars = {
            "OpenAI": tk.StringVar(value=os.environ.get("OPENAI_API_KEY", "")),
            "Gemini": tk.StringVar(value=os.environ.get("GEMINI_API_KEY", "")),
            "Claude": tk.StringVar(value=os.environ.get("ANTHROPIC_API_KEY", "")),
        }
        # Backwards-compatible alias — returns the active provider's key
        self.api_key_var = self.api_key_vars["OpenAI"]
        self.workspace_id_var = tk.StringVar(value="")
        self.tenant_id_var = tk.StringVar(value=os.environ.get("AZURE_TENANT_ID", ""))
        self._model_combos = []  # List of (model_var, combo_widget) for provider switching
        self.custom_models = {"OpenAI": [], "Gemini": [], "Claude": []}  # User-added model names

        self.active_flag_var = tk.StringVar(value="General/All") # GLOBAL FLAG FOCUS

        self.th_files = []
        self.th_found_flags = set()          # titles of verified findings
        self.th_found_answers = set()        # normalized flag answers of verified findings
        self.verified_flags_data = [] # List of {title, description, note, focus_id, flag_answer, kql, evidence, evidence_rows, source}
        self.th_workers_var = tk.IntVar(value=3)   # parallel AI batches (both hunters)
        self._th_worker_active = False       # a hunt is analysing pages in the background
        self._th_candidate_shown = False     # the editor holds a candidate awaiting a decision
        self._th_batches_done = 0
        self._th_batches_total = 0

        self.th_candidate_queue = []
        self.th_pages_buffer = []
        self.th_pages_source = []   # parallel to th_pages_buffer: "<file> p<N>" provenance
        self.th_current_idx = 0
        self.th_model_var = tk.StringVar(value=DEFAULT_MODEL)
        self._th_complete_logged = False   # de-dupe the "Hunt complete" notice
        self._th_verifying = False          # guard re-entrant Verify while drafting a note

        self.soc_memory = []
        self.soc_last_records = []
        self.soc_last_kql = ""
        self.known_tables = []               # [{TableName, Rows, Latest}] from List Tables
        self.schema_cache = {}               # table -> [columns] (getschema)
        self.soc_auto_retry_var = tk.IntVar(value=2)      # agent: auto-fix attempts on error / 0 rows
        self.soc_suggest_var = tk.BooleanVar(value=True)  # agent: propose next pivots after a run
        self.soc_suggestions = []            # [{question, why}] from the last run
        self.soc_next_var = tk.StringVar(value="")
        self.soc_logger = None
        self.soc_model_var = tk.StringVar(value=DEFAULT_MODEL)
        self.last_kql = ""
        self.last_error = ""
        self._ai_cancel_event = threading.Event()
        self._ai_running = False
        self._flag_bank_cache = ""
        self.flag_bank_model_var = tk.StringVar(value=DEFAULT_MODEL)
        # Opt-in: regenerate the Incident Report + Flag Bank narrative every time a
        # flag is verified. Off by default so a normal hunt doesn't fire a storm of
        # slow, costly LLM calls (and overwrite manual report edits).
        self.auto_update_var = tk.BooleanVar(value=False)

        self.ioc_results = {}  # category -> list of indicators (from IOC tab)
        self.ioc_accumulate_var = tk.BooleanVar(value=False)  # merge vs replace on extract

        # Off by default: don't write API keys into saved session files (they are
        # plaintext JSON). The analyst can opt in from the Session Manager tab.
        self.save_keys_var = tk.BooleanVar(value=False)
        # Opt-in: keep API keys in the OS keyring between launches (Configuration tab).
        self.remember_keys_var = tk.BooleanVar(value=False)

        self.ctf_hints = []
        self.hint_model_var = tk.StringVar(value=DEFAULT_MODEL)
        self.new_hint_flag_var = tk.StringVar(value="Flag 1") # Hint Assignment

        self.ir_file_var = tk.StringVar()
        self.ir_model_var = tk.StringVar(value=DEFAULT_MODEL)
        self.ir_template_default = """
Investigation Template

Report Template
Findings (What did you find)
Investigation Summary (What happened)

Who, What, When, Where, Why, How (Answer as much as possible)
Who - Who was involved?
What - What happened?
When - When did this occur and is it still happening? (Include timezone)
Where - Where in the environment did this happen?
Why - Why did this happen? (If known)
How - How did this happen?

Recommendations: (What steps should be taken to reduce risk or stop the activity?)
"""
        self._setup_ui()
        # Restore provider/workspace/model choices (and keyring-held keys, if opted in).
        self._load_saved_settings()

    def _setup_ui(self):
        # --- TOP BAR GLOBAL FOCUS ---
        top_bar = ttk.Frame(self.root, padding=5, relief="raised")
        top_bar.pack(fill="x", side="top")

        ttk.Label(top_bar, text="🚩 Current Investigation Focus:", font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        # Scaled to 100 Flags
        flag_opts = ["General/All"] + [f"Flag {i}" for i in range(1, 101)]
        self.flag_selector = ttk.Combobox(top_bar, textvariable=self.active_flag_var, values=flag_opts, state="readonly", width=15)
        self.flag_selector.pack(side="left", padx=5)

        ttk.Label(top_bar, text="(Selects which hints/context the AI uses)").pack(side="left", padx=5)
        # -----------------------------

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        self.tab_config = ttk.Frame(self.notebook)
        self.tab_hints = ttk.Frame(self.notebook)
        self.tab_hunter = ttk.Frame(self.notebook)
        self.tab_soc = ttk.Frame(self.notebook)
        self.tab_results = ttk.Frame(self.notebook)
        self.tab_timeline = ttk.Frame(self.notebook)
        self.tab_iocs = ttk.Frame(self.notebook) # NEW IOC EXTRACTOR
        self.tab_flag_bank = ttk.Frame(self.notebook) # NEW FLAG BANK
        self.tab_summary = ttk.Frame(self.notebook)
        self.tab_report = ttk.Frame(self.notebook)
        self.tab_incident = ttk.Frame(self.notebook)
        self.tab_session = ttk.Frame(self.notebook)
        self.tab_guide = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_config, text="⚙️ Configuration")
        self.notebook.add(self.tab_hints, text="🧩 Flag Hints")
        self.notebook.add(self.tab_hunter, text="🕵️ Threat Hunter")
        self.notebook.add(self.tab_soc, text="🛡️ Azure SOC Agent")
        self.notebook.add(self.tab_results, text="📊 Query Results")
        self.notebook.add(self.tab_timeline, text="🕒 Timeline")
        self.notebook.add(self.tab_iocs, text="🧬 IOCs") # NEW
        self.notebook.add(self.tab_flag_bank, text="🏦 Flag Bank (Context)") # NEW
        self.notebook.add(self.tab_summary, text="🏆 Flag Summary")
        self.notebook.add(self.tab_report, text="📝 Report Editor")
        self.notebook.add(self.tab_incident, text="📑 Incident Report Generator")
        self.notebook.add(self.tab_session, text="💾 Session Manager")
        self.notebook.add(self.tab_guide, text="📖 How-To Guide")

        self._setup_config_tab()
        self._setup_hints_tab()
        self._setup_hunter_tab()
        self._setup_soc_tab()
        self._setup_results_tab()
        self._setup_timeline_tab()
        self._setup_iocs_tab() # NEW
        self._setup_flag_bank_tab() # NEW
        self._setup_summary_tab()
        self._setup_incident_tab()
        self._setup_session_tab()

        self._setup_guide_tab()
        self.reporter = ThreatHuntReporterTab(self.tab_report, findings_provider=lambda: self.verified_flags_data)


def main():
    if not HAS_TK:
        print("ERROR: tkinter is required to run this GUI application but is not installed.")
        print("  Debian/Ubuntu:      sudo apt-get install python3-tk")
        print("  Fedora/RHEL:        sudo dnf install python3-tkinter")
        print("  macOS (Homebrew):   brew install python-tk")
        print("  Windows:            reinstall Python with the 'tcl/tk' option checked")
        sys.exit(1)

    if _MISSING_LIBS:
        print("WARNING: the following optional libraries are not installed, so some")
        print("features will be unavailable until you install them:")
        print("  " + ", ".join(_MISSING_LIBS))
        print("  Install everything with:  pip install -r requirements.txt")
        print("-" * 60)

    init(autoreset=True)
    root = tk.Tk()
    app = UnifiedSOCTool(root)
    root.mainloop()
    return app
