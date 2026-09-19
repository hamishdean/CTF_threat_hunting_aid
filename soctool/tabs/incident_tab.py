# -*- coding: utf-8 -*-
import os
import json
import threading
from ..ai import ai_chat_completion
from ..deps import filedialog, messagebox, scrolledtext, tk, ttk
from ..prompts import SYSTEM_PROMPT_INCIDENT_REPORT
from ..textutil import IOC_PATTERNS, build_timeline, extract_text_from_file

class IncidentTabMixin:
    def _setup_incident_tab(self):
        input_frame = ttk.LabelFrame(self.tab_incident, text="Input Data", padding=10)
        input_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(input_frame, text="Source Logs (optional - .docx, .txt, .pdf):").grid(row=0, column=0, sticky="w")
        ttk.Entry(input_frame, textvariable=self.ir_file_var, width=60).grid(row=0, column=1, padx=5)
        ttk.Button(input_frame, text="Browse", command=self.ir_browse_file).grid(row=0, column=2, padx=5)

        ttk.Label(input_frame, text="Model:").grid(row=0, column=3, sticky="e")
        ir_model_combo = ttk.Combobox(input_frame, textvariable=self.ir_model_var, values=self._get_models_for_provider(), state="readonly", width=25)
        ir_model_combo.grid(row=0, column=4, padx=5)
        self._model_combos.append((self.ir_model_var, ir_model_combo))

        # Internal data sources panel
        src_frame = ttk.LabelFrame(self.tab_incident, text="Internal Data Sources (auto-included)", padding=10)
        src_frame.pack(fill="x", padx=10, pady=5)

        self.ir_src_flags = tk.BooleanVar(value=True)
        self.ir_src_hints = tk.BooleanVar(value=True)
        self.ir_src_bank = tk.BooleanVar(value=True)
        self.ir_src_soc = tk.BooleanVar(value=True)
        self.ir_src_iocs = tk.BooleanVar(value=True)

        ttk.Checkbutton(src_frame, text="Verified Flags & Answers", variable=self.ir_src_flags).grid(row=0, column=0, sticky="w", padx=10)
        ttk.Checkbutton(src_frame, text="CTF Hints & Clues", variable=self.ir_src_hints).grid(row=0, column=1, sticky="w", padx=10)
        ttk.Checkbutton(src_frame, text="Flag Bank Narrative", variable=self.ir_src_bank).grid(row=0, column=2, sticky="w", padx=10)
        ttk.Checkbutton(src_frame, text="SOC Agent Console & Queries", variable=self.ir_src_soc).grid(row=0, column=3, sticky="w", padx=10)
        ttk.Checkbutton(src_frame, text="Extracted IOCs", variable=self.ir_src_iocs).grid(row=0, column=4, sticky="w", padx=10)

        self.ir_src_status = ttk.Label(src_frame, text="", foreground="gray")
        self.ir_src_status.grid(row=1, column=0, columnspan=5, sticky="w", padx=10, pady=(5,0))

        tpl_frame = ttk.LabelFrame(self.tab_incident, text="Report Template (Editable)", padding=10)
        tpl_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.ir_template_text = scrolledtext.ScrolledText(tpl_frame, height=10, font=("Consolas", 10))
        self.ir_template_text.pack(fill="both", expand=True)
        self.ir_template_text.insert("1.0", self.ir_template_default)

        out_frame = ttk.LabelFrame(self.tab_incident, text="Generated Report", padding=10)
        out_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.ir_output_text = scrolledtext.ScrolledText(out_frame, height=15, font=("Consolas", 10))
        self.ir_output_text.pack(fill="both", expand=True)

        btn_box = ttk.Frame(out_frame)
        btn_box.pack(fill="x", pady=5)
        ttk.Button(btn_box, text="▶ GENERATE REPORT", command=self.ir_generate).pack(side="left", padx=5)
        ttk.Button(btn_box, text="💾 Save Report to .txt", command=self.ir_save).pack(side="right", padx=5)

    def ir_browse_file(self):
        f = filedialog.askopenfilename(filetypes=[("Log Files", "*.docx *.txt *.pdf"), ("All Files", "*.*")])
        if f: self.ir_file_var.set(f)

    def _gather_internal_data(self):
        """Collect all available internal data for the incident report."""
        sections = []
        source_counts = {"flags": 0, "hints": 0, "bank": False, "soc_queries": 0, "soc_logs": 0, "iocs": 0}

        # 1. Verified Flags & Answers
        if self.ir_src_flags.get() and self.verified_flags_data:
            flags_text = "CONFIRMED FINDINGS / FLAG ANSWERS:\n"
            for f in self.verified_flags_data:
                flags_text += f"  - {f.get('title', 'Unknown')}"
                if f.get('note'):
                    flags_text += f" | Answer: {f['note']}"
                if f.get('source'):
                    flags_text += f" | Source: {f['source']}"
                if f.get('focus_id') and f['focus_id'] != 'General/All':
                    flags_text += f" [{f['focus_id']}]"
                flags_text += "\n"
            sections.append(flags_text)
            source_counts["flags"] = len(self.verified_flags_data)

        # 2. CTF Hints & AI-generated Clues
        if self.ir_src_hints.get() and self.ctf_hints:
            hints_text = "INVESTIGATION HINTS & AI CLUES:\n"
            for h in self.ctf_hints:
                hints_text += f"  - [{h.get('id', 'General')}] Hint: {h.get('hint', '')}\n"
                if h.get('clue'):
                    hints_text += f"    Clue: {h['clue']}\n"
                if h.get('kql'):
                    hints_text += f"    Suggested KQL: {h['kql']}\n"
            sections.append(hints_text)
            source_counts["hints"] = len(self.ctf_hints)

        # 3. Flag Bank Narrative
        if self.ir_src_bank.get() and self._flag_bank_cache:
            sections.append(f"CURRENT INCIDENT UNDERSTANDING (Flag Bank Narrative):\n{self._flag_bank_cache}")
            source_counts["bank"] = True

        # 4. SOC Agent - Query History & Console Output
        if self.ir_src_soc.get():
            if self.soc_memory:
                soc_text = "SOC AGENT INVESTIGATION QUERIES:\n"
                for m in self.soc_memory:
                    soc_text += f"  - Question: {m.get('user_input', '')}\n"
                    soc_text += f"    KQL: {m.get('kql_query', '')}\n"
                sections.append(soc_text)
                source_counts["soc_queries"] = len(self.soc_memory)

            # Include last query results (up to 5000 chars)
            if self.soc_last_records:
                try:
                    records_text = json.dumps(self.soc_last_records[:30], default=str, indent=1)
                    if len(records_text) > 5000:
                        records_text = records_text[:5000] + "\n... (truncated)"
                    sections.append(f"LATEST SOC QUERY RESULTS ({len(self.soc_last_records)} total records, showing first 30):\n{records_text}")
                    source_counts["soc_logs"] = len(self.soc_last_records)
                except Exception:
                    pass

        # 5. Extracted Indicators of Compromise (from the IOCs tab).
        if self.ir_src_iocs.get() and self.ioc_results:
            ioc_lines = ["EXTRACTED INDICATORS OF COMPROMISE (IOCs):"]
            ioc_total = 0
            for category in IOC_PATTERNS:  # stable ordering
                vals = self.ioc_results.get(category, [])
                if vals:
                    ioc_lines.append(f"  {category}: " + ", ".join(vals[:50]))
                    ioc_total += len(vals)
            if ioc_total:
                sections.append("\n".join(ioc_lines))
                source_counts["iocs"] = ioc_total

        # 6. Deterministic timeline backbone extracted from real timestamps, so the
        #    AI report is anchored to actual event order rather than a guess.
        timeline_events = []
        if self.ir_src_soc.get() and self.soc_last_records:
            timeline_events.extend(self.soc_last_records)
        if self.ir_src_flags.get() and self.verified_flags_data:
            timeline_events.extend(self.verified_flags_data)
        timeline = build_timeline(timeline_events)
        if timeline:
            tl_text = "DETERMINISTIC TIMELINE (from data timestamps, ascending):\n"
            tl_text += "\n".join(f"  {ts}  |  {desc}" for ts, desc in timeline)
            sections.append(tl_text)

        return "\n\n".join(sections), source_counts

    def ir_generate(self):
        if not self._get_api_key():
            messagebox.showerror("Error", "Missing API Key in Configuration tab.")
            return

        filepath = self.ir_file_var.get()
        internal_data, counts = self._gather_internal_data()

        # Check we have at least some data to work with
        has_file = filepath and os.path.exists(filepath)
        has_internal = bool(internal_data.strip())

        if not has_file and not has_internal:
            messagebox.showerror("Error", "No data available. Either select a source file, or generate some findings using the other tabs first (SOC Agent, Threat Hunter, Flag Hints).")
            return

        # Show what data sources are being used
        source_parts = []
        if has_file:
            source_parts.append(f"File: {os.path.basename(filepath)}")
        if counts["flags"]:
            source_parts.append(f"{counts['flags']} verified flag(s)")
        if counts["hints"]:
            source_parts.append(f"{counts['hints']} hint(s)")
        if counts["bank"]:
            source_parts.append("Flag Bank narrative")
        if counts["soc_queries"]:
            source_parts.append(f"{counts['soc_queries']} SOC query/queries")
        if counts["soc_logs"]:
            source_parts.append(f"{counts['soc_logs']} log record(s)")
        if counts["iocs"]:
            source_parts.append(f"{counts['iocs']} IOC(s)")

        status_msg = "Sources: " + ", ".join(source_parts)
        self.ir_src_status.config(text=status_msg, foreground="blue")

        self.ir_output_text.delete("1.0", "end")
        self.ir_output_text.insert("1.0", f"Generating report using: {', '.join(source_parts)}...\nPlease wait.\n")

        template_content = self.ir_template_text.get("1.0", "end").strip()

        threading.Thread(target=self._ir_process_thread, args=(filepath if has_file else None, template_content, internal_data), daemon=True).start()

    def auto_generate_incident_report(self):
        """Automatically runs the report generation with current data."""
        if not self._get_api_key():
            return

        filepath = self.ir_file_var.get()

        # Fallback to first TH file if IR file not set
        if (not filepath or not os.path.exists(filepath)) and self.th_files:
            filepath = self.th_files[0]
            self.ir_file_var.set(filepath)

        has_file = filepath and os.path.exists(filepath)
        internal_data, counts = self._gather_internal_data()
        has_internal = bool(internal_data.strip())

        if not has_file and not has_internal:
            print("Auto-Report skipped: No data available.")
            return

        self.ir_output_text.delete("1.0", "end")
        self.ir_output_text.insert("1.0", "[AUTO-UPDATE] Generating report from all available data...\n")

        template_content = self.ir_template_text.get("1.0", "end").strip()

        threading.Thread(target=self._ir_process_thread, args=(filepath if has_file else None, template_content, internal_data), daemon=True).start()

    def _ir_process_thread(self, filepath, template_content, internal_data=""):
        try:
            # Extract file content if a file is provided
            file_section = ""
            if filepath:
                chunks = extract_text_from_file(filepath)
                log_content = "\n".join(chunks)
                if log_content.strip():
                    file_section = f"""
=== UPLOADED DOCUMENT (from {os.path.basename(filepath)}) ===
{log_content[:20000]}"""

            # Build the full data payload
            data_payload = ""
            if internal_data.strip():
                data_payload += f"""
=== INVESTIGATION DATA (from program) ===
{internal_data}
"""
            if file_section:
                data_payload += file_section

            if not data_payload.strip():
                self._ir_update_output("Error: No usable data found.")
                return

            user_prompt = f"""Using ALL of the investigation data below, generate a complete incident report.

TASK 1: TIMELINE OF EVENTS
  - Create a chronological timeline (YYYY-MM-DD HH:MM:SS UTC format).
  - Use timestamps from logs, alerts, and findings. A DETERMINISTIC TIMELINE
    block (already sorted) may be provided below — build on it, don't contradict it.
  - If exact timestamps are unavailable, note the sequence of events.

TASK 2: MITRE ATT&CK MAPPING
  - Map the observed activity to MITRE ATT&CK tactics and techniques.
  - Format each as: Tactic - Technique Name (Txxxx[.xxx]) - one line of supporting evidence.
  - Only include techniques the evidence actually supports.

TASK 3: INVESTIGATION REPORT
  - Fill in the template below using ALL available data.
  - Include the specific flag answers/artifacts found.
  - Reference the evidence and KQL queries used.
  - Provide actionable recommendations.

{data_payload}

=== REPORT TEMPLATE ===
{template_content}
"""
            report = ai_chat_completion(
                self._get_provider(), self._get_api_key(), self.ir_model_var.get(),
                [{"role": "system", "content": SYSTEM_PROMPT_INCIDENT_REPORT}, {"role": "user", "content": user_prompt}],
                temperature=0.3
            )
            self._ir_update_output(report, clear=True)
        except Exception as e:
            self._ir_update_output(f"Error during generation: {e}")

    def _ir_update_output(self, text, clear=False):
        def _update():
            if clear: self.ir_output_text.delete("1.0", "end")
            self.ir_output_text.insert("end", text)
        self.root.after(0, _update)

    def ir_save(self):
        content = self.ir_output_text.get("1.0", "end").strip()
        if not content: return
        f = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt")])
        if f:
            try:
                with open(f, "w", encoding="utf-8") as file: file.write(content)
                messagebox.showinfo("Saved", "Report saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
