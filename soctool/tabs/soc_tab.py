# -*- coding: utf-8 -*-
import os
import json
import time
import math
import threading
from ..ai import get_query_context, hunt_on_records, fix_kql, suggest_next_steps
from ..azure_la import execute_kql, explain_azure_error, make_logs_client, fetch_schema, format_schema, LIST_TABLES_KQL
from ..common import SessionLogger
from ..config import CAPTURE_DIR
from ..deps import Fore, filedialog, messagebox, scrolledtext, tk, ttk
from concurrent.futures import ThreadPoolExecutor, as_completed
from ..textutil import normalize_answer, rows_mentioning

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

        # Agent controls: automatic retry of failed / empty queries and pivot suggestions.
        agent_row = ttk.Frame(ctrl_frame)
        agent_row.pack(fill="x", pady=2)
        ttk.Label(agent_row, text="Agent:").pack(side="left")
        ttk.Label(agent_row, text="auto-fix failed/empty queries up to").pack(side="left", padx=(6, 2))
        ttk.Spinbox(agent_row, from_=0, to=5, width=2, textvariable=self.soc_auto_retry_var).pack(side="left")
        ttk.Label(agent_row, text="times").pack(side="left", padx=(2, 10))
        ttk.Checkbutton(agent_row, text="suggest next pivots after each run", variable=self.soc_suggest_var).pack(side="left")
        ttk.Label(agent_row, text="Next:").pack(side="left", padx=(20, 2))
        self.soc_next_combo = ttk.Combobox(agent_row, textvariable=self.soc_next_var, values=[], state="readonly", width=60)
        self.soc_next_combo.pack(side="left", fill="x", expand=True)
        ttk.Button(agent_row, text="▶ Run Suggested", command=self.soc_run_suggested).pack(side="left", padx=4)

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
        kql = LIST_TABLES_KQL
        self.soc_print(f"{Fore.CYAN}--- TABLES WITH DATA (last 365 days) ---{Fore.RESET}")
        try:
            client = make_logs_client(tenant_id)
            rows = execute_kql(client, ws, kql, hours=8760, warn=self.soc_print)
            if not rows:
                self.soc_print("No tables contain data in the last 365 days.")
                return
            self.known_tables = [{"TableName": str(r.get("TableName", "")), "Rows": r.get("Rows", ""),
                                  "Latest": str(r.get("Latest", ""))} for r in rows]
            self.soc_print(f"{'TableName':<42}{'Rows':>10}   Latest record")
            for r in self.known_tables:
                self.soc_print(f"{r['TableName']:<42}{str(r['Rows']):>10}   {r['Latest']}")
            self.soc_print(f"{len(rows)} table(s). Fetching column names so the AI uses real schema...")
            names = [r["TableName"] for r in self.known_tables]
            schema = fetch_schema(client, ws, names, max_tables=40, warn=self.soc_print, should_stop=self._ai_cancelled)
            self.schema_cache.update(schema)
            self.soc_print(f"{Fore.GREEN}Schema cached for {len(schema)} table(s). "
                           f"KQL generation and Self-Heal will now use these tables and columns.{Fore.RESET}")
            self.root.after(0, lambda: self._results_show(rows, kql, title="Tables with data"))
        except Exception as e:
            self.last_kql = kql
            self.last_error = str(e)
            self.soc_print(f"{Fore.RED}Could not list tables: {e}{Fore.RESET}")
            hint = explain_azure_error(e, ws)
            if hint:
                self.soc_print(f"{Fore.YELLOW}Hint: {hint}{Fore.RESET}")

    def _schema_text(self):
        """Schema block for prompts, or "" if List Tables hasn't been run."""
        return format_schema(self.known_tables, self.schema_cache) if self.known_tables else ""

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

    def _process_results_in_batches(self, results, table_name, model, kql="", goal=""):
        """Hunt through query results in parallel batches, attach provenance to each
        finding, push new ones to the Threat Hunter, then (agent mode) ask what to
        query next."""
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

        # --- BATCH PROCESSING (parallel) ---
        total_records = len(results)
        self.soc_print(f"{total_records} records found.")

        batch_size = 50
        total_batches = math.ceil(total_records / batch_size)
        try:
            workers = max(1, min(8, int(self.th_workers_var.get())))
        except Exception:
            workers = 3
        self.soc_print(f"Processing in {total_batches} batch(es) of {batch_size}, {workers} at a time...")

        provider = self._get_provider()
        api_key = self._get_api_key()
        active_hints = self.get_active_hints()
        focus = self.active_flag_var.get()
        ignore_titles = set(self.th_found_flags)
        ignore_answers = set(self.th_found_answers)

        def run_batch(i):
            if self._ai_cancelled():
                return i, None, None
            batch_records = results[i * batch_size:min((i + 1) * batch_size, total_records)]
            try:
                found = hunt_on_records(provider, api_key, batch_records, table_name, model,
                                        active_hints, ignore_titles, focus, found_answers=ignore_answers)
                for f in found:
                    f["kql"] = kql
                    f["source"] = f"SOC query: {table_name}"
                    f["evidence_rows"] = rows_mentioning(batch_records, f.get("flag_answer", ""))
                return i, found, None
            except Exception as e:
                return i, None, e

        all_findings = []
        seen_answers = set()
        done = 0
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(run_batch, i) for i in range(total_batches)]
            for fut in as_completed(futures):
                i, found, err = fut.result()
                done += 1
                if err is not None:
                    self.soc_print(f"{Fore.RED}  [!] Batch {i + 1}: {err}{Fore.RESET}")
                    continue
                if found is None:
                    continue
                new = []
                for f in found:
                    ans = normalize_answer(f.get("flag_answer", ""))
                    if f.get("title") in ignore_titles or (ans and (ans in ignore_answers or ans in seen_answers)):
                        continue
                    seen_answers.add(ans)
                    new.append(f)
                all_findings.extend(new)
                self.soc_print(f"  Batch {i + 1}/{total_batches} done: +{len(new)} flag(s)/answer(s) ({done}/{total_batches} complete)")

        if self._ai_cancelled():
            self.soc_print(f"{Fore.YELLOW}--- AI PROCESSING STOPPED ({done}/{total_batches} batches) ---{Fore.RESET}")
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
            # Queue for verification (dedupes against verified + queued answers).
            self._th_offer_candidates(all_findings)
            self.soc_print("Findings sent to Threat Hunter tab for verification.")
        else:
            self.soc_print("No flags or answers found in logs.")

        # --- AGENT: what next? ---
        if self.soc_suggest_var.get() and not self._ai_cancelled():
            self._soc_suggest_next(goal or self.soc_prompt_text_snapshot(), kql, results, all_findings)

    def soc_prompt_text_snapshot(self):
        """Read the prompt box from a worker thread without touching Tk: use the
        last goal we recorded instead."""
        return getattr(self, "_soc_last_goal", "")

    def _soc_suggest_next(self, goal, kql, records, findings):
        try:
            assessment, suggestions = suggest_next_steps(
                self._get_provider(), self._get_api_key(), self.soc_model_var.get(),
                goal, kql, records, findings, self._get_incident_context_for_kql(), self.get_active_hints())
        except Exception as e:
            self.soc_print(f"{Fore.YELLOW}(Next-step suggestions unavailable: {e}){Fore.RESET}")
            return
        if assessment:
            self.soc_print(f"{Fore.CYAN}Agent assessment: {assessment}{Fore.RESET}")
        if suggestions:
            self.soc_print(f"{Fore.CYAN}Suggested next pivots (pick one in the 'Next' box and press Run Suggested):{Fore.RESET}")
            for n, s in enumerate(suggestions, 1):
                self.soc_print(f"  {n}. {s['question']}  — {s.get('why', '')}")
        self.soc_suggestions = suggestions

        def _fill():
            values = [s["question"] for s in suggestions]
            self.soc_next_combo["values"] = values
            self.soc_next_var.set(values[0] if values else "")
        self.root.after(0, _fill)

    def soc_run_suggested(self):
        """Run the pivot selected in the 'Next' box as a new AI investigation."""
        q = self.soc_next_var.get().strip()
        if not q:
            messagebox.showinfo("No Suggestion", "Run an investigation first; the agent will propose next pivots here.")
            return
        self.soc_prompt_text.delete("1.0", "end")
        self.soc_prompt_text.insert("1.0", q)
        self.soc_run_ai()

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
        self._soc_last_goal = user_input

        try:
            provider = self._get_provider()
            api_key = self._get_api_key()
            law_client = make_logs_client(self._get_tenant_id())
            model = self.soc_model_var.get()

            # Use active hints
            active_hints = self.get_active_hints()
            focus = self.active_flag_var.get()

            # Get Accumulated Report Context
            incident_ctx = self._get_incident_context_for_kql()
            schema_text = self._schema_text()

            if self._ai_cancelled():
                self.soc_print(f"{Fore.YELLOW}--- AI INVESTIGATION STOPPED ---{Fore.RESET}")
                return

            # 1. Ask AI for query
            ctx = get_query_context(provider, api_key, user_input, model, self.soc_memory, active_hints,
                                    focus, incident_ctx, schema_text=schema_text)

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

            # Default to 1 year (8760h) for AI queries
            time_range = ctx.get('time_range_hours', 8760)

            # 3. Execute, with the agent retrying failed / empty queries by itself.
            results, kql = self._soc_execute_with_retry(law_client, kql, time_range, schema_text)
            if results is None:
                return  # error already reported

            if self._ai_cancelled():
                self.soc_print(f"{Fore.YELLOW}--- AI INVESTIGATION STOPPED ---{Fore.RESET}")
                return

            self.soc_last_records = results
            self.soc_last_kql = kql
            self.root.after(0, lambda r=results, k=kql: self._results_show(r, k))

            if results:
                self.soc_memory.append({"user_input": user_input, "kql_query": kql})
                self._process_results_in_batches(results, table_name, model, kql=kql, goal=user_input)
            else:
                self.last_error = "0 records found."
                self.soc_print(f"{Fore.GREEN}0 records found.{Fore.RESET}")
                if self.soc_suggest_var.get():
                    self._soc_suggest_next(user_input, kql, [], [])

        except Exception as e:
            self.last_error = str(e)
            self.soc_print(f"{Fore.RED}Error: {e}{Fore.RESET}")
            hint = explain_azure_error(e, self._get_workspace_id())
            if hint:
                self.soc_print(f"{Fore.YELLOW}Hint: {hint}{Fore.RESET}")
        finally:
            self._set_ai_running(False)

    def _soc_execute_with_retry(self, law_client, kql, time_range, schema_text=""):
        """Run `kql`; on an error or an empty result ask the AI to fix it and re-run,
        up to the configured number of attempts. Returns (results, final_kql), or
        (None, kql) if it ultimately failed with an error."""
        try:
            max_fixes = max(0, int(self.soc_auto_retry_var.get()))
        except Exception:
            max_fixes = 0
        attempt = 0
        while True:
            self.soc_print("Executing query...")
            problem = None
            results = []
            try:
                results = execute_kql(law_client, self._get_workspace_id(), kql, time_range, warn=self.soc_print)
                if not results:
                    problem = "0 records found."
            except Exception as e:
                problem = str(e)
                self.last_error = problem
                self.soc_print(f"{Fore.RED}Query failed: {e}{Fore.RESET}")
                hint = explain_azure_error(e, self._get_workspace_id())
                if hint:
                    self.soc_print(f"{Fore.YELLOW}Hint: {hint}{Fore.RESET}")

            if problem is None:
                self.last_error = ""
                return results, kql
            if attempt >= max_fixes or self._ai_cancelled():
                if problem == "0 records found.":
                    return [], kql
                return None, kql

            attempt += 1
            self.soc_print(f"{Fore.CYAN}Agent: {problem} -> asking the AI for a fix (attempt {attempt}/{max_fixes})...{Fore.RESET}")
            try:
                fixed, why = fix_kql(self._get_provider(), self._get_api_key(), self.soc_model_var.get(),
                                     kql, problem, schema_text)
            except Exception as e:
                self.soc_print(f"{Fore.YELLOW}Agent: could not get a fix ({e}).{Fore.RESET}")
                return ([] if problem == "0 records found." else None), kql
            if not fixed or fixed.strip() == kql.strip():
                self.soc_print(f"{Fore.YELLOW}Agent: no different query proposed; stopping retries.{Fore.RESET}")
                return ([] if problem == "0 records found." else None), kql
            self.soc_print(f"{Fore.YELLOW}Agent-fixed KQL ({why}):\n{fixed}{Fore.RESET}")
            kql = fixed
            self.last_kql = kql
            time_range = 8760

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

    def soc_open_manual_kql(self, prefill=""):
        if not self._soc_precheck(): return
        win = tk.Toplevel(self.root)
        win.title("Manual KQL Editor")
        win.geometry("800x600")
        lbl = ttk.Label(win, text="Enter your KQL Query below (Press Run to execute):")
        lbl.pack(padx=10, pady=5, anchor="w")
        text_area = scrolledtext.ScrolledText(win, font=("Consolas", 12))
        text_area.pack(fill="both", expand=True, padx=10, pady=5)
        if prefill:
            text_area.insert("1.0", prefill)
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
        self._soc_last_goal = f"Manual KQL: {kql[:120]}"
        try:
            law_client = make_logs_client(self._get_tenant_id())
            results = execute_kql(law_client, self._get_workspace_id(), kql, hours=8760, warn=self.soc_print)
            self.soc_last_records = results
            self.soc_last_kql = kql
            self.root.after(0, lambda r=results, k=kql: self._results_show(r, k))

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
            self.soc_memory.append({"user_input": f"(manual) {kql[:80]}", "kql_query": kql})
            self._process_results_in_batches(results, table_name, model, kql=kql, goal=self._soc_last_goal)

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
            fixed_kql, explanation = fix_kql(
                self._get_provider(), self._get_api_key(), self.soc_model_var.get(),
                self.last_kql, self.last_error, self._schema_text())

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
