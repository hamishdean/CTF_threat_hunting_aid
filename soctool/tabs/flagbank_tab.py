# -*- coding: utf-8 -*-
import threading
from ..ai import ai_chat_completion
from ..deps import messagebox, scrolledtext, ttk

class FlagBankTabMixin:
    def _setup_flag_bank_tab(self):
        frame = ttk.LabelFrame(self.tab_flag_bank, text="Current Incident Understanding (AI Generated)", padding=10)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.flag_bank_text = scrolledtext.ScrolledText(frame, font=("Segoe UI", 11), state="normal")
        self.flag_bank_text.pack(fill="both", expand=True)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=5)

        ttk.Label(btn_frame, text="Model:").pack(side="left")
        flag_bank_model_combo = ttk.Combobox(btn_frame, textvariable=self.flag_bank_model_var,
                                              values=self._get_models_for_provider(), state="readonly", width=25)
        flag_bank_model_combo.pack(side="left", padx=5)
        self._model_combos.append((self.flag_bank_model_var, flag_bank_model_combo))

        ttk.Button(btn_frame, text="🔄 Update Understanding with AI", command=self.update_flag_bank_ai).pack(side="right")
        ttk.Button(btn_frame, text="📤 Export Narrative to Incident Report", command=self.export_flag_bank_to_ir).pack(side="right", padx=10)

    def update_flag_bank_ai(self):
        if not self.verified_flags_data and not self.ctf_hints:
            return
        if not self._get_api_key():
            return

        # Get data on main thread
        flags_data = list(self.verified_flags_data)
        hints_data = list(self.ctf_hints)
        model = self.flag_bank_model_var.get()

        self.flag_bank_text.insert("end", "\n[System] Updating narrative...\n")
        self.flag_bank_text.see("end")

        threading.Thread(target=self._flag_bank_ai_thread, args=(flags_data, hints_data, model), daemon=True).start()

    def _flag_bank_ai_thread(self, flags, hints, model):
        try:
            context_str = "VERIFIED FACTS:\n" + "\n".join([f"- {f['title']}: {f['note']}" for f in flags])
            context_str += "\n\nKNOWN HINTS:\n" + "\n".join([f"- {h['hint']}" for h in hints])

            prompt = f"""
            You are a Lead Incident Responder.
            Based on the following Verified Facts and Known Hints, write a cohesive "Current Understanding of the Incident" narrative.

            - Connect the dots between flags.
            - Highlight what is confirmed vs what is suspected (hints).
            - Map the activity to MITRE ATT&CK tactics and techniques (include technique
              IDs such as T1059) wherever the evidence supports it.
            - Keep it professional and chronological if possible.

            DATA:
            {context_str}
            """

            narrative = ai_chat_completion(
                self._get_provider(), self._get_api_key(), model,
                [{"role": "user", "content": prompt}]
            )

            self.root.after(0, lambda: self._update_flag_bank_ui(narrative))

        except Exception as e:
            self.root.after(0, lambda e=e: self._flag_bank_text_append(f"\n[!] Narrative update failed: {e}\n"))

    def _flag_bank_text_append(self, msg):
        """Append a message to the Flag Bank panel without wiping existing narrative."""
        self.flag_bank_text.insert("end", msg)
        self.flag_bank_text.see("end")

    def _update_flag_bank_ui(self, text):
        self.flag_bank_text.delete("1.0", "end")
        self.flag_bank_text.insert("1.0", text)
        self._flag_bank_cache = text

    def export_flag_bank_to_ir(self):
        """Export Flag Bank content to Incident Report template."""
        narrative = self.flag_bank_text.get("1.0", "end").strip()
        if not narrative:
            messagebox.showwarning("Empty", "Flag Bank is empty.")
            return

        # Switch to IR tab
        self.notebook.select(self.tab_incident)

        # Append to template
        current_template = self.ir_template_text.get("1.0", "end")
        if "CONTEXT FROM FLAG BANK" not in current_template:
            self.ir_template_text.insert("end", f"\n\n=== CONTEXT FROM FLAG BANK ===\n{narrative}\n")
            messagebox.showinfo("Exported", "Flag Bank narrative appended to Report Template.")
        else:
            # Maybe replace? For now just append or warn.
            messagebox.showinfo("Info", "Flag Bank context appears to be already present in the template.")
