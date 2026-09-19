# -*- coding: utf-8 -*-
import os
import json
from ..config import DEFAULT_MODEL
from ..deps import filedialog, messagebox, ttk
from ..textutil import normalize_answer

class SessionTabMixin:
    def _setup_session_tab(self):
        frame = ttk.LabelFrame(self.tab_session, text="Session Management", padding=20)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        lbl = ttk.Label(frame, text="Save or Load the entire application state (hints, flags, queries, reports).", font=("Segoe UI", 12))
        lbl.pack(pady=10)

        ttk.Checkbutton(frame, text="Include API keys in the saved file",
                        variable=self.save_keys_var).pack(anchor="w", pady=(0, 2))
        ttk.Label(frame,
                  text="⚠️  Session files are plaintext JSON. Leave this off unless the file stays private —\n"
                       "otherwise anyone with the file gets your API keys. Keys load from env vars regardless.",
                  foreground="#b5651d", font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 10))

        btn_save = ttk.Button(frame, text="💾 Save Full Session", command=self.save_full_session)
        btn_save.pack(fill="x", pady=5)

        btn_load = ttk.Button(frame, text="📂 Load Full Session", command=self.load_full_session)
        btn_load.pack(fill="x", pady=5)

        self.session_status = ttk.Label(frame, text="Ready", foreground="gray")
        self.session_status.pack(pady=20)

    def save_full_session(self):
        # Only persist API keys when the analyst explicitly opts in (they are stored
        # in plaintext). Otherwise write empty strings; keys still load from env vars.
        include_keys = self.save_keys_var.get()
        data = {
            "config": {
                "provider": self.provider_var.get(),
                "api_key_openai": self.api_key_vars["OpenAI"].get() if include_keys else "",
                "api_key_gemini": self.api_key_vars["Gemini"].get() if include_keys else "",
                "api_key_claude": self.api_key_vars["Claude"].get() if include_keys else "",
                "workspace_id": self.workspace_id_var.get(),
                "tenant_id": self.tenant_id_var.get(),
                "custom_models": self.custom_models,
                "active_flag": self.active_flag_var.get()
            },
            "hints": {
                "ctf_hints": self.ctf_hints,
                "model": self.hint_model_var.get(),
                "display_text": self.hint_display.get("1.0", "end")
            },
            "hunter": {
                "files": self.th_files,
                "found_flags": list(self.th_found_flags),
                "found_answers": sorted(self.th_found_answers),
                "model": self.th_model_var.get(),
                "history_text": self.th_history.get("1.0", "end"),
                "verified_data": self.verified_flags_data # Save verified data
            },
            "soc": {
                "memory": self.soc_memory,
                "model": self.soc_model_var.get(),
                "console_text": self.soc_console.get("1.0", "end"),
                # Latest result set (capped) so the Results/Timeline tabs and the
                # report have data straight after a reload.
                "last_kql": self.soc_last_kql,
                "last_records": json.loads(json.dumps(self.soc_last_records[:2000], default=str)),
                "known_tables": self.known_tables,
                "schema_cache": self.schema_cache,
                "suggestions": self.soc_suggestions,
            },
            "reporter": self.reporter.get_state(),
            "incident": {
                "file": self.ir_file_var.get(),
                "model": self.ir_model_var.get(),
                "template": self.ir_template_text.get("1.0", "end"),
                "output": self.ir_output_text.get("1.0", "end")
            },
            "flag_bank": {
                "text": self.flag_bank_text.get("1.0", "end"),
                "model": self.flag_bank_model_var.get()
            },
            "iocs": self.ioc_results
        }
        f = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Session", "*.json")])
        if f:
            try:
                with open(f, 'w') as file: json.dump(data, file, indent=4)
                self.session_status.config(text=f"Saved to {os.path.basename(f)}", foreground="green")
            except Exception as e:
                messagebox.showerror("Save Error", str(e))

    def load_full_session(self):
        f = filedialog.askopenfilename(filetypes=[("JSON Session", "*.json")])
        if not f: return
        try:
            with open(f, 'r') as file: data = json.load(file)

            if "config" in data:
                cfg = data["config"]
                self.provider_var.set(cfg.get("provider", "OpenAI"))
                # Only overwrite a key when the session actually carries one, so
                # loading a key-less session (I3) doesn't wipe keys already entered
                # or supplied via environment variables.
                if "api_key_openai" in cfg:
                    for prov, key in (("OpenAI", "api_key_openai"),
                                      ("Gemini", "api_key_gemini"),
                                      ("Claude", "api_key_claude")):
                        val = cfg.get(key, "")
                        if val:
                            self.api_key_vars[prov].set(val)
                elif cfg.get("api_key"):
                    # Legacy format: single OpenAI key
                    self.api_key_vars["OpenAI"].set(cfg.get("api_key", ""))
                self.workspace_id_var.set(cfg.get("workspace_id", ""))
                if cfg.get("tenant_id"):
                    self.tenant_id_var.set(cfg["tenant_id"])
                self.active_flag_var.set(cfg.get("active_flag", "General/All"))
                # Restore custom models before triggering provider change
                saved_custom = cfg.get("custom_models", {})
                for provider in self.custom_models:
                    self.custom_models[provider] = saved_custom.get(provider, [])
                self._on_provider_changed()

            if "hints" in data:
                self.ctf_hints = data["hints"].get("ctf_hints", [])
                self.hint_model_var.set(data["hints"].get("model", DEFAULT_MODEL))
                self.hint_display.config(state="normal")
                self.hint_display.delete("1.0", "end")
                self.hint_display.insert("1.0", data["hints"].get("display_text", ""))
                self.hint_display.config(state="disabled")

            if "hunter" in data:
                self.th_files = data["hunter"].get("files", [])
                self.file_listbox.delete(0, "end")
                for file_path in self.th_files: self.file_listbox.insert("end", os.path.basename(file_path))
                self.th_found_flags = set(data["hunter"].get("found_flags", []))
                self.verified_flags_data = data["hunter"].get("verified_data", []) # Load verified data
                # Rebuild the answer set from the findings (older sessions lack it).
                self.th_found_answers = set(data["hunter"].get("found_answers", [])) | {
                    normalize_answer(f.get("flag_answer", "")) for f in self.verified_flags_data
                    if normalize_answer(f.get("flag_answer", ""))}
                self.th_model_var.set(data["hunter"].get("model", DEFAULT_MODEL))
                self.th_history.config(state="normal")
                self.th_history.delete("1.0", "end")
                self.th_history.insert("1.0", data["hunter"].get("history_text", ""))
                self.th_history.config(state="disabled")
                self._update_summary_display() # Update Summary Tab

            if "soc" in data:
                self.soc_memory = data["soc"].get("memory", [])
                self.soc_model_var.set(data["soc"].get("model", DEFAULT_MODEL))
                self.soc_console.config(state="normal")
                self.soc_console.delete("1.0", "end")
                self.soc_console.insert("1.0", data["soc"].get("console_text", ""))
                self.soc_console.config(state="disabled")
                self.soc_last_kql = data["soc"].get("last_kql", "")
                self.soc_last_records = [r for r in data["soc"].get("last_records", []) if isinstance(r, dict)]
                self.known_tables = [t for t in data["soc"].get("known_tables", []) if isinstance(t, dict)]
                self.schema_cache = {k: v for k, v in (data["soc"].get("schema_cache") or {}).items() if isinstance(v, list)}
                self.soc_suggestions = [s for s in data["soc"].get("suggestions", []) if isinstance(s, dict)]
                self.soc_next_combo["values"] = [s.get("question", "") for s in self.soc_suggestions]
                self.soc_next_var.set(self.soc_next_combo["values"][0] if self.soc_suggestions else "")
                if self.soc_last_records:
                    self._results_show(self.soc_last_records, self.soc_last_kql)

            if "reporter" in data: self.reporter.set_state(data["reporter"])

            if "incident" in data:
                self.ir_file_var.set(data["incident"].get("file", ""))
                self.ir_model_var.set(data["incident"].get("model", DEFAULT_MODEL))
                self.ir_template_text.delete("1.0", "end")
                self.ir_template_text.insert("1.0", data["incident"].get("template", ""))
                self.ir_output_text.delete("1.0", "end")
                self.ir_output_text.insert("1.0", data["incident"].get("output", ""))

            if "flag_bank" in data:
                bank_text = data["flag_bank"].get("text", "")
                self.flag_bank_text.delete("1.0", "end")
                self.flag_bank_text.insert("1.0", bank_text)
                self._flag_bank_cache = bank_text
                self.flag_bank_model_var.set(data["flag_bank"].get("model", DEFAULT_MODEL))

            if "iocs" in data and isinstance(data["iocs"], dict):
                self.ioc_results = data["iocs"]
                self._ioc_populate_tree(source="session")

            self.timeline_refresh()
            self.session_status.config(text=f"Loaded {os.path.basename(f)}", foreground="green")
            messagebox.showinfo("Session Loaded", "Full session state restored.")
        except Exception as e:
            messagebox.showerror("Load Error", str(e))
