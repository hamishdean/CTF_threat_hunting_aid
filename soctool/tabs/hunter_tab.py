# -*- coding: utf-8 -*-
import os
import json
import threading
import datetime
from ..ai import ai_chat_completion, parse_ai_json
from ..common import AzureSentinelFormatter
from ..config import DEFAULT_MODEL, PROVIDER_DEFAULTS
from ..deps import filedialog, messagebox, scrolledtext, simpledialog, tk, ttk
from ..textutil import extract_text_from_file

class HunterTabMixin:
    def _setup_hunter_tab(self):
        top_frame = ttk.LabelFrame(self.tab_hunter, text="Input Data & Settings", padding=10)
        top_frame.pack(fill="x", padx=10, pady=5)

        self.file_listbox = tk.Listbox(top_frame, height=4, width=60)
        self.file_listbox.pack(side="left", fill="x", expand=True, padx=5)

        opts_frame = ttk.Frame(top_frame)
        opts_frame.pack(side="right", fill="y")

        ttk.Label(opts_frame, text="AI Model:").pack(anchor="w")
        th_model_combo = ttk.Combobox(opts_frame, textvariable=self.th_model_var, values=self._get_models_for_provider(), state="readonly", width=25)
        th_model_combo.pack(fill="x", pady=2)
        self._model_combos.append((self.th_model_var, th_model_combo))

        ttk.Button(opts_frame, text="Add Files...", command=self.th_add_files).pack(fill="x", pady=2)
        ttk.Button(opts_frame, text="Clear List", command=self.th_clear_files).pack(fill="x", pady=2)
        self.th_start_btn = ttk.Button(opts_frame, text="▶ START HUNT", command=self.th_start_hunt)
        self.th_start_btn.pack(fill="x", pady=(10, 2))
        self.th_stop_btn = ttk.Button(opts_frame, text="■ STOP HUNT", command=self.th_stop_hunt, state="disabled")
        self.th_stop_btn.pack(fill="x", pady=2)

        mid_frame = ttk.LabelFrame(self.tab_hunter, text="Potential Flag / Finding", padding=10)
        mid_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.th_editor = scrolledtext.ScrolledText(mid_frame, height=15, font=("Consolas", 10))
        self.th_editor.pack(fill="both", expand=True)

        action_frame = ttk.Frame(mid_frame)
        action_frame.pack(fill="x", pady=5)
        ttk.Button(action_frame, text="✅ Verify & Save", command=self.th_verify).pack(side="left", padx=5)
        ttk.Button(action_frame, text="❌ Discard", command=self.th_discard).pack(side="left", padx=5)

        # New Manual Flag Button
        ttk.Button(action_frame, text="➕ Manually Add Flag", command=self.th_manual_add).pack(side="left", padx=20)

        self.th_status_lbl = ttk.Label(action_frame, text="Status: Idle", foreground="blue")
        self.th_status_lbl.pack(side="right", padx=10)

        # Off by default: verifying a flag stays fast/free. Turn on to regenerate the
        # Incident Report + Flag Bank narrative automatically after each verify.
        ttk.Checkbutton(action_frame, text="Auto-refresh reports on verify (extra API calls)",
                        variable=self.auto_update_var).pack(side="right", padx=10)

        bot_frame = ttk.LabelFrame(self.tab_hunter, text="Verified Flags History", padding=10)
        bot_frame.pack(fill="x", padx=10, pady=5)
        self.th_history = scrolledtext.ScrolledText(bot_frame, height=6, state="disabled")
        self.th_history.pack(fill="both", expand=True)

    def th_add_files(self):
        files = filedialog.askopenfilenames(filetypes=[
            ("All Supported", "*.pdf *.docx *.txt *.log *.jsonl *.json *.csv"),
            ("PDF", "*.pdf"), ("Word", "*.docx"),
            ("Text / Logs", "*.txt *.log *.jsonl *.json *.csv"),
            ("All Files", "*.*"),
        ])
        for f in files:
            if f not in self.th_files:
                self.th_files.append(f)
                self.file_listbox.insert("end", os.path.basename(f))

    def th_clear_files(self):
        self.th_files = []
        self.file_listbox.delete(0, "end")

    def th_log_history(self, msg):
        self.th_history.config(state="normal")
        self.th_history.insert("end", msg + "\n")
        self.th_history.see("end")
        self.th_history.config(state="disabled")

    def th_start_hunt(self):
        if not self.th_files:
            messagebox.showerror("Error", "No files loaded.")
            return
        if not self._get_api_key():
            messagebox.showerror("Error", "Missing API Key in Configuration tab.")
            return

        self.th_current_idx = 0
        self.th_candidate_queue = []
        self.th_pages_buffer = []
        self.th_pages_source = []
        self._th_complete_logged = False
        self._ai_cancel_event.clear()
        self._set_ai_running(True)
        self.th_status_lbl.config(text="Reading files...")
        # Read files off the UI thread so large PDFs don't freeze the app.
        threading.Thread(target=self._th_read_then_hunt, daemon=True).start()

    def _th_read_then_hunt(self):
        try:
            for f in self.th_files:
                if self._ai_cancelled():
                    self.root.after(0, lambda: self.th_status_lbl.config(text="Hunt stopped by user."))
                    self._set_ai_running(False)
                    return
                base = os.path.basename(f)
                self.root.after(0, lambda n=base: self.th_status_lbl.config(text=f"Reading {n}..."))
                pages = extract_text_from_file(f)
                for i, page in enumerate(pages, 1):
                    self.th_pages_buffer.append(page)
                    self.th_pages_source.append(f"{base} p{i}")

            if not self.th_pages_buffer:
                self.root.after(0, lambda: messagebox.showerror("Error", "No text could be extracted."))
                self.root.after(0, lambda: self.th_status_lbl.config(text="Status: Idle"))
                self._set_ai_running(False)
                return

            self.root.after(0, lambda: self.th_status_lbl.config(
                text=f"Processing {len(self.th_pages_buffer)} pages/chunks..."))
            # Continue processing in this same worker thread.
            self.th_process_batch_thread()
        except Exception as e:
            # Never leave the hunt buttons stuck disabled if reading blows up.
            self.root.after(0, lambda m=f"[!] Hunt could not start: {e}": self.th_log_history(m))
            self.root.after(0, lambda: self.th_status_lbl.config(text="Status: Idle"))
            self._set_ai_running(False)

    def th_process_batch_thread(self):
        # Guard so an unexpected error can never leave the hunt buttons stuck disabled.
        try:
            self._th_process_batch_impl()
        except Exception as e:
            self.root.after(0, lambda m=f"[!] Hunt aborted unexpectedly: {e}": self.th_log_history(m))
            self.root.after(0, lambda: self.th_status_lbl.config(text="Status: Idle"))
            self._set_ai_running(False)

    def _th_process_batch_impl(self):
        PAGE_CAP = 4          # never send more than this many pages at once
        CHAR_BUDGET = 12000   # ...or more than roughly this many characters
        HARD_CAP = 20000      # absolute ceiling for a single oversized page

        while self.th_current_idx < len(self.th_pages_buffer):
            if self._ai_cancelled():
                self.root.after(0, lambda: self.th_status_lbl.config(text="Hunt stopped by user."))
                self._set_ai_running(False)
                return

            # Accumulate pages under a character budget, advancing the index only over
            # pages actually included, so nothing is silently skipped (I5).
            start_idx = self.th_current_idx
            parts = []
            chars = 0
            while self.th_current_idx < len(self.th_pages_buffer):
                page = self.th_pages_buffer[self.th_current_idx]
                if parts and (chars + len(page) > CHAR_BUDGET or len(parts) >= PAGE_CAP):
                    break
                parts.append(page)
                chars += len(page)
                self.th_current_idx += 1
            batch_text = "\n".join(parts)[:HARD_CAP]

            # Provenance label for this batch (E6): a single "<file> p<N>" or a range.
            src_slice = self.th_pages_source[start_idx:self.th_current_idx]
            if not src_slice:
                source_label = ""
            elif src_slice[0] == src_slice[-1]:
                source_label = src_slice[0]
            else:
                source_label = f"{src_slice[0]} … {src_slice[-1]}"

            # Show progress like the SOC batch loop (E-F).
            self.root.after(0, lambda a=start_idx + 1, b=self.th_current_idx, n=len(self.th_pages_buffer):
                            self.th_status_lbl.config(text=f"Analyzing pages {a}-{b} of {n}..."))

            try:
                model = self.th_model_var.get()

                # USE ACTIVE HINTS
                active_hints = self.get_active_hints()
                current_focus = self.active_flag_var.get()

                hints_ctx = ""
                if active_hints:
                    hints_ctx = f"CTF HINTS (FOCUS: {current_focus}):\n" + "\n".join([f"[{h.get('id','?')}] {h['hint']}" for h in active_hints])

                prompt = f"""You are a CTF Flag Hunter. Analyze this log excerpt.
Your goal is to find the EXACT FLAG ANSWER - the specific value, string, artifact, IP, username, hash, or flag{{...}} that answers the CTF challenge or investigation question.

{hints_ctx}
Already found (ignore these): {json.dumps(list(self.th_found_flags))}

IMPORTANT: Do NOT just describe threats generically. Extract the EXACT answer value.
Return JSON: {{ "findings": [ {{ "title": "short name", "description": "why this is the answer", "flag_answer": "THE EXACT VALUE e.g. flag{{abc123}} or 192.168.1.5 or malware.exe", "severity": "High", "evidence": "raw log line proving it" }} ] }}
If no flags found, return: {{ "findings": [] }}

LOGS:
{batch_text}"""
                content = ai_chat_completion(
                    self._get_provider(), self._get_api_key(), model,
                    [{"role": "user", "content": prompt}], json_mode=True
                )
                data = parse_ai_json(content)
                findings = data.get("findings", [])
                for f in findings:
                    if f.get("title") not in self.th_found_flags:
                        f["source"] = source_label
                        self.th_candidate_queue.append(f)
            except Exception as e:
                err = f"[!] Analysis error on pages {start_idx + 1}-{self.th_current_idx}: {e}"
                self.root.after(0, lambda m=err: self.th_log_history(m))

            # Pause for human review as soon as we have something to show (B1).
            if self.th_candidate_queue:
                self.root.after(0, self.th_show_candidate)
                return

        # All pages processed with nothing pending: hand off so completion is reported
        # exactly once (queue is empty here, so th_show_candidate finishes the hunt).
        self._set_ai_running(False)
        self.root.after(0, self.th_show_candidate)

    def th_show_candidate(self):
        # Show the next queued candidate if there is one.
        if self.th_candidate_queue:
            finding = self.th_candidate_queue.pop(0)
            formatted = AzureSentinelFormatter.format_log(finding)
            self.th_editor.delete("1.0", "end")
            self.th_editor.insert("1.0", formatted)
            self.th_status_lbl.config(text="Waiting for Verification...")
            return

        # Queue empty: resume processing only if pages remain and we weren't stopped.
        if self.th_current_idx < len(self.th_pages_buffer) and not self._ai_cancelled():
            self._set_ai_running(True)
            threading.Thread(target=self.th_process_batch_thread, daemon=True).start()
            return

        # Nothing to review and nothing left to process (B1: no restart, no popup spam).
        self._set_ai_running(False)
        if self.th_pages_buffer and self.th_current_idx >= len(self.th_pages_buffer):
            self.th_status_lbl.config(text="Status: Hunt complete.")
            if not self._th_complete_logged:
                self.th_log_history("[DONE] Hunt complete.")
                self._th_complete_logged = True
        else:
            self.th_status_lbl.config(text="Status: Idle")

    def th_manual_add(self):
        """Allows manual entry of a flag."""
        title = simpledialog.askstring("Manual Flag", "Enter Flag Title/Threat Name:")
        if not title: return

        description = simpledialog.askstring("Manual Flag", "Enter brief description (optional):")

        finding = {
            "title": title,
            "description": description if description else "Manually added finding.",
            "timestamp": datetime.datetime.now().isoformat(),
            "evidence": "Manual Entry",
            "source": "Manual entry"
        }

        # Populate editor and let verify logic handle the rest
        formatted = AzureSentinelFormatter.format_log(finding)
        self.th_editor.delete("1.0", "end")
        self.th_editor.insert("1.0", formatted)
        self.th_status_lbl.config(text="Waiting for Verification of Manual Entry...")

    def th_verify(self):
        # Ignore a second click while a note is already being drafted.
        if self._th_verifying:
            return
        try:
            content = self.th_editor.get("1.0", "end").strip()
            if not content:
                return
            data = parse_ai_json(content)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid JSON or Error: {e}")
            return

        title = data.get("AlertName", data.get("title", "Unknown"))
        description = data.get("Description", "")
        flag_answer = data.get("FlagAnswer", data.get("flag_answer", ""))
        focus_id = self.active_flag_var.get()

        # Find the hint linked to the current focus (for note context).
        relevant_hint = "No specific hint linked."
        if focus_id != "General/All":
            for h in self.ctf_hints:
                if h.get('id') == focus_id:
                    relevant_hint = h.get('hint', '')
                    break

        evidence = data.get("Evidence", str(data))
        source = data.get("Source", "")

        # Draft the note off the UI thread so the app stays responsive (B2).
        self._th_verifying = True
        self.th_status_lbl.config(text="Drafting Flag Note (AI)...")
        threading.Thread(
            target=self._th_note_thread,
            args=(title, description, flag_answer, focus_id, relevant_hint, evidence, source),
            daemon=True,
        ).start()

    def _th_note_thread(self, title, description, flag_answer, focus_id, relevant_hint, evidence, source):
        suggested_note = ""
        try:
            if not self._get_api_key():
                raise ValueError("API key not configured")
            prompt = f"""Context: CTF Investigation. Focus: {focus_id}.
Hint provided: "{relevant_hint}"

The analyst found this:
Title: {title}
Flag Answer: {flag_answer}
Description: {description}
Evidence/Data: {evidence}

Task: Write a very brief (1-sentence) note stating the EXACT flag answer or artifact value.
If a flag_answer is provided, include it verbatim in your note.
Example: "The flag is flag{{abc123}}" or "The malicious IP is 192.168.1.5"
"""
            provider = self._get_provider()
            # Use a fast model for note generation.
            fast_models = {"OpenAI": "gpt-4o-mini", "Gemini": "gemini-2.0-flash", "Claude": "claude-haiku-4-5-20251001"}
            fast_model = fast_models.get(provider, PROVIDER_DEFAULTS.get(provider, DEFAULT_MODEL))
            suggested_note = ai_chat_completion(
                provider, self._get_api_key(), fast_model,
                [{"role": "user", "content": prompt}], max_tokens=60
            ).strip()
        except Exception as ai_e:
            print(f"Note Gen Error: {ai_e}")
            suggested_note = f"Flag answer: {flag_answer}" if flag_answer else f"Found {title}. Evidence: {str(evidence)[:120]}"

        # Hand back to the UI thread to show the dialog and save. Guard the handoff so
        # a failure here can't leave the Verify button permanently wedged.
        try:
            self.root.after(0, lambda: self._th_finish_verify(title, description, focus_id, suggested_note, source))
        except Exception as e:
            print(f"Verify handoff error: {e}")
            self._th_verifying = False

    def _th_finish_verify(self, title, description, focus_id, suggested_note, source=""):
        try:
            self.th_status_lbl.config(text="Status: Idle")
            note = simpledialog.askstring(
                "Flag Answer/Note",
                f"Verified '{title}'.\nEdit the generated note below:",
                initialvalue=suggested_note,
            )
            if note is None:
                return  # Cancelled - leave the candidate in the editor to retry.
            if not note:
                note = "No specific note provided."

            self.th_found_flags.add(title)
            self.th_log_history(f"[FLAG] {title}")
            self.verified_flags_data.append({
                "title": title,
                "description": description,
                "note": note,
                "focus_id": focus_id,
                "source": source,
            })
            self._update_summary_display()

            # --- OPTIONAL AUTO-REFRESH (off by default) ---
            # Regenerating the full Incident Report and Flag Bank narrative on every
            # single verify is slow and expensive, and clobbers manual report edits.
            if self.auto_update_var.get():
                self.root.after(500, self.auto_generate_incident_report)
                self.root.after(1000, self.update_flag_bank_ai)

            self.th_editor.delete("1.0", "end")
            self.th_show_candidate()
        finally:
            self._th_verifying = False

    def th_discard(self):
        if self._th_verifying:
            return  # don't discard while a note is drafting for the current candidate
        self.th_editor.delete("1.0", "end")
        self.th_show_candidate()
