# -*- coding: utf-8 -*-
import threading
from ..ai import ai_chat_completion, parse_ai_json
from ..deps import messagebox, scrolledtext, ttk

class HintsTabMixin:
    def _setup_hints_tab(self):
        top_frame = ttk.LabelFrame(self.tab_hints, text="Add New Hint", padding=10)
        top_frame.pack(fill="x", padx=10, pady=5)

        # New Flag ID Selection (Scaled to 100)
        row1 = ttk.Frame(top_frame)
        row1.grid(row=0, column=0, columnspan=3, sticky="ew", pady=5)
        ttk.Label(row1, text="Assign to Flag:").pack(side="left")
        ttk.Combobox(row1, textvariable=self.new_hint_flag_var, values=[f"Flag {i}" for i in range(1, 101)], width=10).pack(side="left", padx=5)

        ttk.Label(top_frame, text="Hint Text (Multiline):").grid(row=1, column=0, sticky="nw")
        self.hint_input = scrolledtext.ScrolledText(top_frame, width=80, height=4, font=("Segoe UI", 10))
        self.hint_input.grid(row=1, column=1, padx=5, pady=5)

        opts_frame = ttk.Frame(top_frame)
        opts_frame.grid(row=1, column=2, sticky="nw", padx=5)

        ttk.Label(opts_frame, text="Model:").pack(anchor="w")
        hint_model_combo = ttk.Combobox(opts_frame, textvariable=self.hint_model_var, values=self._get_models_for_provider(), state="readonly", width=25)
        hint_model_combo.pack(fill="x")
        self._model_combos.append((self.hint_model_var, hint_model_combo))
        ttk.Button(opts_frame, text="Analyze Hint", command=self.hint_analyze).pack(fill="x", pady=5)

        bot_frame = ttk.LabelFrame(self.tab_hints, text="Active Hints & Generated Context", padding=10)
        bot_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.hint_display = scrolledtext.ScrolledText(bot_frame, font=("Consolas", 10), state="disabled")
        self.hint_display.pack(fill="both", expand=True)

        hint_btn_row = ttk.Frame(bot_frame)
        hint_btn_row.pack(fill="x", pady=(5, 0))
        ttk.Button(hint_btn_row, text="▶ Run Hint KQL…", command=self.hints_run_kql).pack(side="left", padx=2)
        ttk.Button(hint_btn_row, text="🗑 Remove Hint…", command=self.hints_remove).pack(side="left", padx=2)
        ttk.Button(hint_btn_row, text="🗑 Clear All Hints", command=self.hints_clear_all).pack(side="left", padx=2)

    def hint_analyze(self):
        hint_text = self.hint_input.get("1.0", "end-1c").strip()
        flag_id = self.new_hint_flag_var.get()
        if not hint_text: return
        self.hint_display.config(state="normal")
        self.hint_display.insert("end", f"\n[*] Analyzing Hint for {flag_id}: '{hint_text[:50]}...'...\n")
        self.hint_display.config(state="disabled")
        threading.Thread(target=self._hint_thread, args=(hint_text, flag_id), daemon=True).start()

    def _hint_thread(self, hint_text, flag_id):
        try:
            model = self.hint_model_var.get()
            prompt = f"""
            You are a CTF Assistant. The user has a hint for {flag_id}: "{hint_text}".
            1. Explain what artifacts or logs to look for based on this hint.
            2. Generate a specific KQL query to find it in Azure Sentinel.
            Return JSON: {{ "clue": "...", "kql": "..." }}
            """
            content = ai_chat_completion(
                self._get_provider(), self._get_api_key(), model,
                [{"role": "user", "content": prompt}], json_mode=True
            )
            data = parse_ai_json(content)
            entry = {"id": flag_id, "hint": hint_text, "clue": data.get("clue"), "kql": data.get("kql")}
            self.ctf_hints.append(entry)
            self.root.after(0, lambda: self._update_hint_ui(entry))
        except Exception as e:
            err = f"\n[!] Hint analysis failed: {e}\n" + "-" * 50 + "\n"
            self.root.after(0, lambda: self._append_hint_display(err))

    def _update_hint_ui(self, entry):
        msg = f"\n✅ HINT ADDED ({entry['id']}):\nHint: {entry['hint']}\nAI Clue: {entry['clue']}\nSuggested KQL: {entry['kql']}\n" + "-"*50 + "\n"
        self.hint_display.config(state="normal")
        self.hint_display.insert("end", msg)
        self.hint_display.see("end")
        self.hint_display.config(state="disabled")
        self.hint_input.delete("1.0", "end")
        messagebox.showinfo("Success", "Hint added to AI Memory.")

    def _append_hint_display(self, msg):
        """Append a message to the hints panel (thread-safe when called via root.after)."""
        self.hint_display.config(state="normal")
        self.hint_display.insert("end", msg)
        self.hint_display.see("end")
        self.hint_display.config(state="disabled")

    def _render_hints(self):
        """Rebuild the hints panel from self.ctf_hints (authoritative after edits)."""
        self.hint_display.config(state="normal")
        self.hint_display.delete("1.0", "end")
        for h in self.ctf_hints:
            self.hint_display.insert(
                "end",
                f"✅ HINT ({h.get('id', '?')}):\nHint: {h.get('hint', '')}\n"
                f"AI Clue: {h.get('clue', '')}\nSuggested KQL: {h.get('kql', '')}\n" + "-" * 50 + "\n"
            )
        self.hint_display.config(state="disabled")

    def hints_clear_all(self):
        """Remove every hint (with confirmation)."""
        if not self.ctf_hints:
            return
        if not messagebox.askyesno("Clear All Hints", f"Remove all {len(self.ctf_hints)} hint(s)?"):
            return
        self.ctf_hints = []
        self._render_hints()

    def hints_remove(self):
        """Remove one or more selected hints."""
        if not self.ctf_hints:
            messagebox.showinfo("No Hints", "There are no hints to remove.")
            return
        snapshot = list(self.ctf_hints)
        labels = [f"[{h.get('id', '?')}] {h.get('hint', '')[:70]}" for h in snapshot]

        def remove(idxs):
            remove_ids = {id(snapshot[i]) for i in idxs}
            self.ctf_hints = [h for h in self.ctf_hints if id(h) not in remove_ids]
            self._render_hints()

        self._open_remove_dialog("Remove Hint", "Select hint(s) to remove:", labels, remove)

    def get_active_hints(self):
        focus = self.active_flag_var.get()
        if focus == "General/All":
            return self.ctf_hints
        return [h for h in self.ctf_hints if h.get("id") == focus]

    def _get_incident_context_for_kql(self):
        """Generates context from verified flags AND FLAG BANK for AI."""
        ctx = ""
        # 1. Verified Flags
        if self.verified_flags_data:
            ctx += "CONFIRMED FINDINGS/FLAGS (Use these to correlate/pivot):\n"
            for f in self.verified_flags_data:
                ctx += f"- Found: {f.get('title', 'Unknown')} | Note: {f.get('note', '')}\n"

        # 2. Flag Bank (Current Understanding) - use cached copy for thread safety
        bank_text = self._flag_bank_cache
        if bank_text:
            ctx += f"\nCURRENT INCIDENT UNDERSTANDING (Narrative):\n{bank_text}\n"

        return ctx

    def hints_run_kql(self):
        """Pick a hint and open its suggested KQL in the Manual KQL Editor, ready to run
        against the workspace (results flow through the normal SOC pipeline)."""
        with_kql = [h for h in self.ctf_hints if (h.get("kql") or "").strip()]
        if not with_kql:
            messagebox.showinfo("No KQL", "No hint has a suggested KQL yet. Analyze a hint first.")
            return
        labels = [f"[{h.get('id', '?')}] {h.get('hint', '')[:60]}  ->  {h['kql'][:70]}" for h in with_kql]

        def run(idxs):
            h = with_kql[idxs[0]]
            if h.get("id"):
                self.active_flag_var.set(h["id"])   # focus the investigation on that flag
            self.notebook.select(self.tab_soc)
            self.soc_open_manual_kql(prefill=h["kql"])

        self._open_remove_dialog("Run Hint KQL", "Select the hint whose KQL you want to run:", labels, run)
