# -*- coding: utf-8 -*-
import os
import json
import time
import math
import threading
from ..ai import ai_chat_completion, get_query_context, hunt_on_records, parse_ai_json
from ..azure_la import build_azure_credential, execute_kql, explain_azure_error
from ..common import SessionLogger
from ..config import CAPTURE_DIR
from ..deps import Fore, LogsQueryClient, filedialog, messagebox, scrolledtext, tk, ttk

class SocTabMixin:
    def _setup_soc_tab(self):
        console_frame = ttk.LabelFrame(self.tab_soc, text="Agent Console", padding=5)
        console_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.soc_console = scrolledtext.ScrolledText(console_frame, state="disabled", height=25, font=("Consolas", 9), bg="black", fg="lime")
        self.soc_console.pack(fill="both", expand=True)
        self.logger = SessionLogger(self.soc_console)

        ctrl_frame = ttk.Frame(self.tab_soc)
        ctrl_frame.pack(fill="x", padx=10, pady=10)

        top_ctrl = ttk.Frame(ctrl_frame)
        top_ctrl.pack(fill="x", pady=2)
        ttk.Label(top_ctrl, text="Instruction / Query:").pack(side="left")
        # Pack the combobox first so it sits at the far right with its label to its left.
        soc_model_combo = ttk.Combobox(top_ctrl, textvariable=self.soc_model_var, values=self._get_models_for_provider(), state="readonly", width=25)
        soc_model_combo.pack(side="right")
        ttk.Label(top_ctrl, text="Model:").pack(side="right")
        self._model_combos.append((self.soc_model_var, soc_model_combo))

        self.soc_prompt_text = tk.Text(ctrl_frame, height=3, font=("Consolas", 10), wrap="word")
        self.soc_prompt_text.pack(fill="x", pady=2)

        btn_box = ttk.Frame(ctrl_frame)
        btn_box.pack(fill="x", pady=5)
        self.soc_run_btn = ttk.Button(btn_box, text="Run AI Investigation", command=self.soc_run_ai)
        self.soc_run_btn.pack(side="left", padx=2)
        self.soc_stop_btn = ttk.Button(btn_box, text="Stop AI", command=self.soc_stop_ai, state="disabled")
        self.soc_stop_btn.pack(side="left", padx=2)
        ttk.Button(btn_box, text="Generate KQL Only", command=self.soc_gen_kql).pack(side="left", padx=2)
        ttk.Button(btn_box, text="Open Manual KQL Editor", command=self.soc_open_manual_kql).pack(side="left", padx=2)
        ttk.Button(btn_box, text="📋 List Tables", command=self.soc_list_tables).pack(side="left", padx=2)
        ttk.Button(btn_box, text="💾 Export Log to File", command=self.soc_export_log).pack(side="right", padx=2)
        ttk.Button(btn_box, text="🩹 Self-Heal Last KQL", command=self.soc_self_heal).pack(side="right", padx=2)
        ttk.Button(btn_box, text="🧹 Clear Console", command=self.soc_clear_console).pack(side="right", padx=2)

    def _soc_precheck(self):
        # Every SOC Agent path that runs a query also hands the rows to the AI,
        # so it needs both Azure config and an API key.
        return self._azure_precheck(need_api_key=True)

    def soc_list_tables(self):
        """Show which tables actually hold data, so hunts (and the AI) target real tables."""
        if not self._azure_precheck():
            return
        threading.Thread(target=self._soc_list_tables_thread,
                         args=(self._get_workspace_id(), self._get_tenant_id()), daemon=True).start()

    def _soc_list_tables_thread(self, ws, tenant_id):
        kql = ("union withsource=TableName * "
               "| summarize Rows=count(), Latest=max(TimeGenerated) by TableName "
               "| sort by Rows desc")
        self.soc_print(f"{Fore.CYAN}--- TABLES WITH DATA (last 365 days) ---{Fore.RESET}")
        try:
            client = LogsQueryClient(credential=build_azure_credential(tenant_id))
            rows = execute_kql(client, ws, kql, hours=8760, warn=self.soc_print)
            if not rows:
                self.soc_print("No tables contain data in the last 365 days.")
                return
            self.soc_print(f"{'TableName':<42}{'Rows':>10}   Latest record")
            for r in rows:
                self.soc_print(f"{str(r.get('TableName', '')):<42}{str(r.get('Rows', '')):>10}   {r.get('Latest', '')}")
            self.soc_print(f"{len(rows)} table(s). Tip: name one of these in your prompt to steer the AI's KQL.")
        except Exception as e:
            self.last_kql = kql
            self.last_error = str(e)
            self.soc_print(f"{Fore.RED}Could not list tables: {e}{Fore.RESET}")
            hint = explain_azure_error(e, ws)
            if hint:
                self.soc_print(f"{Fore.YELLOW}Hint: {hint}{Fore.RESET}")

    def _set_ai_running(self, running):
        """Toggle AI running state and update button availability."""
        self._ai_running = running
        def _update():
            if running:
                self.soc_run_btn.config(state="disabled")
                self.soc_stop_btn.config(state="normal")
                self.th_start_btn.config(state="disabled")
                self.th_stop_btn.config(state="normal")
            else:
                self.soc_run_btn.config(state="normal")
                self.soc_stop_btn.config(state="disabled")
                self.th_start_btn.config(state="normal")
                self.th_stop_btn.config(state="disabled")
        self.root.after(0, _update)

    def soc_stop_ai(self):
        """Signal all running AI threads to stop."""
        if self._ai_running:
            self._ai_cancel_event.set()
            self.soc_print("Stopping AI processing... (will halt after current API call completes)")

    def th_stop_hunt(self):
        """Stop the Threat Hunter AI processing."""
        if self._ai_running:
            self._ai_cancel_event.set()
            self.th_status_lbl.config(text="Status: Stopping...")
            self.th_log_history("[STOPPED] Hunt stopped by user.")

    def _ai_cancelled(self):
        """Check if cancellation has been requested."""
        return self._ai_cancel_event.is_set()

    def soc_print(self, msg):
        # FIX: Ensure thread safety by using root.after
        self.root.after(0, lambda: self.logger.write(msg + "\n"))

    def _process_results_in_batches(self, results, table_name, model):
        """Unified logic to process records in batches with detailed feedback."""
        if not results:
            self.soc_print("No records to process.")
            return

        # --- AUTO-SAVE LOGIC ---
        try:
            ts = int(time.time())
            # Keep captures tidy in a dedicated folder, and use the ABSOLUTE path so
            # the Threat Hunter can still read it regardless of the working directory.
            os.makedirs(CAPTURE_DIR, exist_ok=True)
            filename = os.path.join(CAPTURE_DIR, f"azure_raw_logs_{ts}.jsonl")

            with open(filename, "w", encoding="utf-8") as f:
                for r in results:
                    f.write(json.dumps(r, default=str) + "\n")

            self.soc_print(f"{Fore.CYAN}Saved {len(results)} raw logs to {filename} and added to Threat Hunter.{Fore.RESET}")

            # Update file listbox safely on the UI thread.
            if filename not in self.th_files:
                def _add_file():
                    self.th_files.append(filename)
                    self.file_listbox.insert("end", os.path.basename(filename))
                self.root.after(0, _add_file)

        except Exception as e:
            self.soc_print(f"{Fore.RED}Auto-save error: {e}{Fore.RESET}")

        # --- BATCH PROCESSING ---
        total_records = len(results)
        self.soc_print(f"{total_records} records found.")

        batch_size = 50
        total_batches = math.ceil(total_records / batch_size)

        self.soc_print(f"Processing in batches of {batch_size}...")

        provider = self._get_provider()
        api_key = self._get_api_key()
        all_findings = []

        # Use Active Focus Hints
        active_hints = self.get_active_hints()
        focus = self.active_flag_var.get()

        for i in range(total_batches):
            if self._ai_cancelled():
                self.soc_print(f"{Fore.YELLOW}--- AI PROCESSING STOPPED (completed {i}/{total_batches} batches) ---{Fore.RESET}")
                break

            start_idx = i * batch_size
            end_idx = min((i + 1) * batch_size, total_records)
            batch_records = results[start_idx:end_idx]

            self.soc_print(f"Batch {i+1} of {total_batches}...")

            current_ignore_list = set(self.th_found_flags)
            for f in all_findings:
                current_ignore_list.add(f.get('title'))

            try:
                batch_findings = hunt_on_records(provider, api_key, batch_records, table_name, model, active_hints, current_ignore_list, focus)

                new_count = 0
                if batch_findings:
                    for f in batch_findings:
                        if f.get('title') not in current_ignore_list:
                            all_findings.append(f)
                            new_count += 1

                self.soc_print(f"  + {new_count} flag(s)/answer(s) found.")

            except Exception as e:
                self.soc_print(f"{Fore.RED}  [!] Error processing batch: {e}{Fore.RESET}")

        self.soc_print("End of Batches.")

        if all_findings:
            self.soc_print(f"{Fore.RED}!!! FLAGS / ANSWERS FOUND ({len(all_findings)}) !!!{Fore.RESET}")
            for f in all_findings:
                answer = f.get('flag_answer', '')
                title = f.get('title', 'Unknown')
                if answer:
                    self.soc_print(f"  FLAG: {title} -> {Fore.CYAN}{answer}{Fore.RESET}")
                else:
                    self.soc_print(f"  - {title}: {f.get('description', '')[:100]}")

            # Auto-push findings to Threat Hunter candidate queue
            def _push_to_hunter():
                for f in all_findings:
                    if f.get('title') not in self.th_found_flags:
                        f["source"] = f"SOC query: {table_name}"
                        self.th_candidate_queue.append(f)
                self.th_show_candidate()
            self.root.after(0, _push_to_hunter)
            self.soc_print("Findings sent to Threat Hunter tab for verification.")
        else:
            self.soc_print("No flags or answers found in logs.")

    def soc_run_ai(self):
        if not self._soc_precheck(): return
        if self._ai_running:
            messagebox.showinfo("Busy", "AI is already running. Stop it first before starting a new investigation.")
            return
        user_input = self.soc_prompt_text.get("1.0", "end").strip()
        if not user_input:
            messagebox.showinfo("Input", "Please enter instructions above.")
            return
        self._ai_cancel_event.clear()
        self._set_ai_running(True)
        threading.Thread(target=self._soc_ai_thread, args=(user_input,), daemon=True).start()

    def _soc_ai_thread(self, user_input):
        self.soc_print(f"{Fore.CYAN}--- STARTING AI INVESTIGATION ---{Fore.RESET}")
        self.soc_print(f"Goal: {user_input}")

        try:
            provider = self._get_provider()
            api_key = self._get_api_key()
            law_client = LogsQueryClient(credential=build_azure_credential(self._get_tenant_id()))
            model = self.soc_model_var.get()

            # Use active hints
            active_hints = self.get_active_hints()
            focus = self.active_flag_var.get()

            # Get Accumulated Report Context
            incident_ctx = self._get_incident_context_for_kql()

            if self._ai_cancelled():
                self.soc_print(f"{Fore.YELLOW}--- AI INVESTIGATION STOPPED ---{Fore.RESET}")
                return

            # --- SMART MODE vs SAFE MODE LOGIC ---
            # 1. Ask AI for query
            ctx = get_query_context(provider, api_key, user_input, model, self.soc_memory, active_hints, focus, incident_ctx)

            if self._ai_cancelled():
                self.soc_print(f"{Fore.YELLOW}--- AI INVESTIGATION STOPPED ---{Fore.RESET}")
                return

            # 2. Check if query is valid
            kql = ctx.get('kql_query', '')
            table_name = ctx.get('table_name', 'Unknown')

            if not kql or len(kql) < 10:
                self.soc_print(f"{Fore.YELLOW}AI failed to generate a complex query. Using fallback.{Fore.RESET}")
                # Fallback: Simple search
                clean_input = user_input.replace('"', '').replace("'", "")
                kql = f"search \"{clean_input}\" | take 100"
                table_name = "Search"
            else:
                self.soc_print(f"{Fore.YELLOW}AI Generated KQL:{Fore.RESET}")

            self.soc_print(f"{kql}")
            # Capture for Self-Heal regardless of outcome (B5): if execute_kql raises
            # below, the except still knows which query failed and why.
            self.last_kql = kql
            self.last_error = ""

            # 3. Execute
            self.soc_print("Executing query...")

            # Default to 1 year (8760h) for AI queries
            time_range = ctx.get('time_range_hours', 8760)

            results = execute_kql(law_client, self._get_workspace_id(), kql, time_range, warn=self.soc_print)

            if self._ai_cancelled():
                self.soc_print(f"{Fore.YELLOW}--- AI INVESTIGATION STOPPED ---{Fore.RESET}")
                return

            if results:
                self.soc_memory.append({"user_input": user_input, "kql_query": kql})
                self.soc_last_records = results
                self._process_results_in_batches(results, table_name, model)
            else:
                self.last_error = "0 records found."
                self.soc_print(f"{Fore.GREEN}0 records found.{Fore.RESET}")

        except Exception as e:
            self.last_error = str(e)
            self.soc_print(f"{Fore.RED}Error: {e}{Fore.RESET}")
            hint = explain_azure_error(e, self._get_workspace_id())
            if hint:
                self.soc_print(f"{Fore.YELLOW}Hint: {hint}{Fore.RESET}")
        finally:
            self._set_ai_running(False)

    def soc_gen_kql(self):
        # Generating KQL doesn't touch Azure, so it only needs an API key (not a
        # Workspace ID). Full _soc_precheck is reserved for paths that run queries.
        if not self._get_api_key():
            messagebox.showerror("Config Error", "Please set an API Key in the Configuration tab.")
            return
        user_input = self.soc_prompt_text.get("1.0", "end").strip()
        if not user_input:
            messagebox.showinfo("Input", "Please enter instructions above.")
            return
        threading.Thread(target=self._soc_kql_only_thread, args=(user_input,), daemon=True).start()

    def _soc_kql_only_thread(self, user_input):
        try:
            provider = self._get_provider()
            api_key = self._get_api_key()
            model = self.soc_model_var.get()
            active_hints = self.get_active_hints()
            focus = self.active_flag_var.get()

            # Get Accumulated Report Context
            incident_ctx = self._get_incident_context_for_kql()

            ctx = get_query_context(provider, api_key, user_input, model, self.soc_memory, active_hints, focus, incident_ctx)
            kql = ctx.get('kql_query') or ""
            if not kql:
                err = ctx.get('error', 'the AI did not return a query.')
                self.soc_print(f"{Fore.RED}Could not generate KQL: {err}{Fore.RESET}")
                return
            # Update last KQL for self-healing / manual runs.
            self.last_kql = kql
            self.last_error = ""
            self.soc_print(f"\n{Fore.YELLOW}KQL Preview:\n{kql}{Fore.RESET}")
        except Exception as e:
            self.soc_print(str(e))

    def soc_open_manual_kql(self):
        if not self._soc_precheck(): return
        win = tk.Toplevel(self.root)
        win.title("Manual KQL Editor")
        win.geometry("800x600")
        lbl = ttk.Label(win, text="Enter your KQL Query below (Press Run to execute):")
        lbl.pack(padx=10, pady=5, anchor="w")
        text_area = scrolledtext.ScrolledText(win, font=("Consolas", 12))
        text_area.pack(fill="both", expand=True, padx=10, pady=5)
        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill="x", padx=10, pady=10)

        def run_manual():
            query = text_area.get("1.0", "end").strip()
            if not query: return
            win.destroy()
            self._ai_cancel_event.clear()
            self._set_ai_running(True)
            threading.Thread(target=self._soc_manual_thread, args=(query,), daemon=True).start()

        ttk.Button(btn_frame, text="RUN QUERY", command=run_manual).pack(side="right")

    def _soc_manual_thread(self, kql):
        self.soc_print(f"Running Manual KQL: {kql}")
        self.last_kql = kql
        self.last_error = ""   # don't let a stale error from an earlier query leak into Self-Heal
        try:
            law_client = LogsQueryClient(credential=build_azure_credential(self._get_tenant_id()))
            results = execute_kql(law_client, self._get_workspace_id(), kql, hours=8760, warn=self.soc_print)
            self.soc_last_records = results

            if self._ai_cancelled():
                self.soc_print(f"{Fore.YELLOW}--- MANUAL KQL STOPPED ---{Fore.RESET}")
                return

            if not results:
                self.last_error = "0 records found."
                self.soc_print(f"{Fore.GREEN}0 records found.{Fore.RESET}")
                return

            # FIX: Infer table name correctly to avoid split error on empty string
            table_name = "Unknown"
            if kql:
                # If starts with let, try to find the real table name after last semicolon
                if kql.strip().lower().startswith("let"):
                    parts = kql.strip().split(";")
                    if parts:
                        table_name = parts[-1].strip().split()[0]
                else:
                    table_name = kql.split()[0]

            model = self.soc_model_var.get()
            self._process_results_in_batches(results, table_name, model)

        except Exception as e:
            self.last_error = str(e)
            self.soc_print(f"{Fore.RED}Query Failed: {e}{Fore.RESET}")
            hint = explain_azure_error(e, self._get_workspace_id())
            if hint:
                self.soc_print(f"{Fore.YELLOW}Hint: {hint}{Fore.RESET}")
        finally:
            self._set_ai_running(False)

    def soc_self_heal(self):
        if not self._soc_precheck(): return
        if not self.last_kql:
            messagebox.showinfo("Info", "No recent KQL query to fix.")
            return

        self.soc_print(f"{Fore.CYAN}--- STARTING SELF-HEAL ---{Fore.RESET}")
        self.soc_print(f"Attempting to fix: {self.last_kql}")
        self.soc_print(f"Last Error: {self.last_error}")

        threading.Thread(target=self._soc_self_heal_thread, daemon=True).start()

    def _soc_self_heal_thread(self):
        try:
            prompt = f"""
            You are a KQL Expert. The following query failed or returned no results.

            Failed Query:
            {self.last_kql}

            Error Message / Issue:
            {self.last_error}

            Task: Fix the KQL syntax, table names, or logic.
            - If "0 records found", maybe the time range is too short (default to 30d) or the 'where' clause is too strict.
            - If syntax error, correct it.

            Return JSON: {{ "fixed_kql": "...", "explanation": "..." }}
            """

            content = ai_chat_completion(
                self._get_provider(), self._get_api_key(), self.soc_model_var.get(),
                [{"role": "user", "content": prompt}], json_mode=True
            )
            data = parse_ai_json(content)
            fixed_kql = data.get("fixed_kql", "")
            explanation = data.get("explanation", "")

            self.soc_print(f"{Fore.YELLOW}Fixed KQL proposed:\n{fixed_kql}{Fore.RESET}")
            self.soc_print(f"Reason: {explanation}")

            # Interactive Confirmation Step (Main Thread)
            self.soc_print("Prompting user to review fix...")
            self.root.after(0, lambda: self._confirm_and_run_fix(fixed_kql))

        except Exception as e:
            self.soc_print(f"{Fore.RED}Self-Heal Failed: {e}{Fore.RESET}")

    def _confirm_and_run_fix(self, fixed_kql):
        # Open a dialog to confirm/edit
        win = tk.Toplevel(self.root)
        win.title("Confirm Fixed KQL")
        win.geometry("800x600")

        lbl = ttk.Label(win, text="The AI suggested the following fix. Review/Edit and Run:")
        lbl.pack(padx=10, pady=5, anchor="w")

        text_area = scrolledtext.ScrolledText(win, font=("Consolas", 12))
        text_area.pack(fill="both", expand=True, padx=10, pady=5)
        text_area.insert("1.0", fixed_kql)

        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill="x", padx=10, pady=10)

        def run():
            query = text_area.get("1.0", "end").strip()
            win.destroy()
            if query:
                self._ai_cancel_event.clear()
                self._set_ai_running(True)
                threading.Thread(target=self._soc_manual_thread, args=(query,), daemon=True).start()

        ttk.Button(btn_frame, text="RUN FIXED QUERY", command=run).pack(side="right")
        ttk.Button(btn_frame, text="Cancel", command=win.destroy).pack(side="right", padx=5)

    def soc_export_log(self):
        f = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt")])
        if f:
            if self.logger.save_to_file(f):
                self.soc_print(f"Session saved to {f}")
                if messagebox.askyesno("Integration", "Load this log into Threat Hunter Tab?"):
                    self.th_files.append(f)
                    self.file_listbox.insert("end", os.path.basename(f))
                    self.notebook.select(self.tab_hunter)
            else:
                messagebox.showerror("Error", "Failed to save file.")

    def soc_clear_console(self):
        """Empty the SOC Agent console output."""
        self.soc_console.config(state="normal")
        self.soc_console.delete("1.0", "end")
        self.soc_console.config(state="disabled")
