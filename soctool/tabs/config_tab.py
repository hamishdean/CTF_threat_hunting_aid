# -*- coding: utf-8 -*-
import threading
from ..azure_la import execute_kql, explain_azure_error, make_logs_client
from ..config import MODEL_OPTIONS, PROVIDER_DEFAULTS, PROVIDER_MODELS, PROVIDER_OPTIONS
from ..deps import HAS_AZURE, messagebox, ttk
from ..config import SETTINGS_PATH, load_settings, save_settings, keyring_available, keyring_get_key, keyring_set_key

class ConfigTabMixin:
    def _setup_config_tab(self):
        # AI Provider Selection
        provider_frame = ttk.LabelFrame(self.tab_config, text="AI Provider", padding=20)
        provider_frame.pack(fill="x", padx=20, pady=10)

        ttk.Label(provider_frame, text="Active Provider:").grid(row=0, column=0, sticky="w", pady=10)
        provider_combo = ttk.Combobox(provider_frame, textvariable=self.provider_var, values=PROVIDER_OPTIONS, state="readonly", width=20)
        provider_combo.grid(row=0, column=1, padx=10, sticky="w")
        provider_combo.bind("<<ComboboxSelected>>", lambda e: self._on_provider_changed())

        # Custom Model Entry
        model_frame = ttk.LabelFrame(self.tab_config, text="Custom AI Models", padding=20)
        model_frame.pack(fill="x", padx=20, pady=10)

        ttk.Label(model_frame, text="Add a model ID not yet in the built-in list (e.g. gpt-6, claude-opus-5):").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 5))

        ttk.Label(model_frame, text="Model ID:").grid(row=1, column=0, sticky="w", pady=5)
        self.custom_model_entry = ttk.Entry(model_frame, width=40)
        self.custom_model_entry.grid(row=1, column=1, padx=10, sticky="w")
        ttk.Button(model_frame, text="Add to Current Provider", command=self._add_custom_model).grid(row=1, column=2, padx=10)

        ttk.Label(model_frame, text="Custom models for current provider:").grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.custom_models_label = ttk.Label(model_frame, text="(none)", foreground="gray")
        self.custom_models_label.grid(row=2, column=1, columnspan=2, sticky="w", padx=10, pady=(10, 0))

        ttk.Button(model_frame, text="Remove Selected Custom Model", command=self._remove_custom_model).grid(row=3, column=2, padx=10, pady=5)
        self.remove_model_entry = ttk.Entry(model_frame, width=40)
        self.remove_model_entry.grid(row=3, column=1, padx=10, sticky="w")
        ttk.Label(model_frame, text="Model to remove:").grid(row=3, column=0, sticky="w", pady=5)

        # API Keys for all providers
        keys_frame = ttk.LabelFrame(self.tab_config, text="API Keys", padding=20)
        keys_frame.pack(fill="x", padx=20, pady=10)

        ttk.Label(keys_frame, text="OpenAI API Key:").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Entry(keys_frame, textvariable=self.api_key_vars["OpenAI"], width=60, show="*").grid(row=0, column=1, padx=10)

        ttk.Label(keys_frame, text="Gemini API Key:").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(keys_frame, textvariable=self.api_key_vars["Gemini"], width=60, show="*").grid(row=1, column=1, padx=10)
        ttk.Label(keys_frame, text="(pip install google-genai)").grid(row=1, column=2, sticky="w")

        ttk.Label(keys_frame, text="Claude API Key:").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Entry(keys_frame, textvariable=self.api_key_vars["Claude"], width=60, show="*").grid(row=2, column=1, padx=10)
        ttk.Label(keys_frame, text="(pip install anthropic)").grid(row=2, column=2, sticky="w")

        # Azure settings
        frame = ttk.LabelFrame(self.tab_config, text="Azure Settings", padding=20)
        frame.pack(fill="x", padx=20, pady=10)

        ttk.Label(frame, text="Log Analytics Workspace ID:").grid(row=0, column=0, sticky="w", pady=10)
        ttk.Entry(frame, textvariable=self.workspace_id_var, width=60).grid(row=0, column=1, padx=10)

        ttk.Label(frame, text="(Required for SOC Agent tab only)").grid(row=0, column=2, sticky="w")

        ttk.Label(frame, text="Azure Tenant ID (optional):").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(frame, textvariable=self.tenant_id_var, width=60).grid(row=1, column=1, padx=10)
        ttk.Label(frame, text="(Set if the workspace is in a tenant where you are a guest)").grid(row=1, column=2, sticky="w")

        az_btns = ttk.Frame(frame)
        az_btns.grid(row=2, column=1, pady=15, sticky="w", padx=10)
        ttk.Button(az_btns, text="Save / Validate",
                   command=lambda: messagebox.showinfo("Info", "Settings ready in memory.")).pack(side="left")
        ttk.Button(az_btns, text="🔌 Test Azure Connection", command=self.test_azure_connection).pack(side="left", padx=10)

        self.azure_status_lbl = ttk.Label(frame, text="Azure: not tested yet", foreground="gray", wraplength=1000, justify="left")
        self.azure_status_lbl.grid(row=3, column=0, columnspan=3, sticky="w")

        # Persist settings between launches
        persist = ttk.LabelFrame(self.tab_config, text="Remember Settings", padding=12)
        persist.pack(fill="x", padx=20, pady=10)
        ttk.Label(persist, text=f"Provider, models, workspace, tenant and agent options are saved to {SETTINGS_PATH} "
                                "and restored on the next launch. API keys are only stored in the OS keyring "
                                "(never in that file) when the box below is ticked.",
                  wraplength=1000, justify="left").grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 6))
        ttk.Checkbutton(persist, text="Remember API keys in the OS keyring", variable=self.remember_keys_var).grid(row=1, column=0, sticky="w")
        ttk.Button(persist, text="💾 Save Settings", command=self.save_settings_clicked).grid(row=1, column=1, padx=10)
        ttk.Button(persist, text="🗑 Forget Saved Keys", command=self.forget_saved_keys).grid(row=1, column=2, padx=4)
        self.settings_status_lbl = ttk.Label(persist, text="", foreground="gray", wraplength=1000, justify="left")
        self.settings_status_lbl.grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))

    def _get_tenant_id(self):
        """Return the optional Azure tenant ID, whitespace trimmed."""
        return self.tenant_id_var.get().strip()

    def _azure_precheck(self, need_api_key=False):
        """Shared guard for anything that talks to Azure. Returns True when OK."""
        if not HAS_AZURE:
            messagebox.showerror(
                "Missing Library",
                "This feature needs the Azure libraries, which are not installed.\n\n"
                "pip install azure-identity azure-monitor-query"
            )
            return False
        if not self._get_workspace_id():
            messagebox.showerror("Config Error", "Please set the Log Analytics Workspace ID in the Configuration tab.")
            return False
        if need_api_key and not self._get_api_key():
            messagebox.showerror("Config Error", "Please set an API Key in the Configuration tab.")
            return False
        return True

    def test_azure_connection(self):
        """Run a trivial query so the analyst can confirm auth + workspace before hunting."""
        if not self._azure_precheck():
            return
        ws = self._get_workspace_id()
        self.azure_status_lbl.config(
            text="Azure: connecting... (if you are not signed in with `az login`, a browser sign-in window will open)",
            foreground="blue")
        threading.Thread(target=self._test_azure_thread, args=(ws, self._get_tenant_id()), daemon=True).start()

    def _test_azure_thread(self, ws, tenant_id):
        try:
            client = make_logs_client(tenant_id)
            rows = execute_kql(client, ws, "print ok=1", hours=1)
            ok = bool(rows) and str(rows[0].get("ok", "")) == "1"
            text = (f"Azure: ✅ connected. Workspace {ws} accepted a query." if ok
                    else "Azure: ⚠️ the workspace answered, but the test query returned nothing.")
            self.root.after(0, lambda: self.azure_status_lbl.config(text=text, foreground="green" if ok else "#b5651d"))
        except Exception as e:
            hint = explain_azure_error(e, ws) or f"{type(e).__name__}: {str(e)[:300]}"
            self.root.after(0, lambda: self.azure_status_lbl.config(text=f"Azure: ❌ {hint}", foreground="red"))

    def _get_provider(self):
        """Return the currently selected AI provider name."""
        return self.provider_var.get()

    def _get_api_key(self):
        """Return the API key for the currently selected provider (whitespace trimmed
        so a pasted key with a trailing space/newline doesn't fail auth cryptically)."""
        return self.api_key_vars[self.provider_var.get()].get().strip()

    def _get_workspace_id(self):
        """Return the Azure Log Analytics workspace ID, whitespace trimmed."""
        return self.workspace_id_var.get().strip()

    def _get_models_for_provider(self, provider=None):
        """Return built-in + custom models for the given provider."""
        if provider is None:
            provider = self.provider_var.get()
        built_in = list(PROVIDER_MODELS.get(provider, MODEL_OPTIONS))
        custom = self.custom_models.get(provider, [])
        return built_in + custom

    def _on_provider_changed(self):
        """Called when the user changes the AI provider dropdown."""
        provider = self.provider_var.get()
        default_model = PROVIDER_DEFAULTS.get(provider, "gpt-4o")
        models = self._get_models_for_provider(provider)

        # Update all model dropdowns
        for model_var, combo in self._model_combos:
            model_var.set(default_model)
            combo['values'] = models

        self._update_custom_models_label()

    def _add_custom_model(self):
        """Add a user-entered model ID to the current provider's model list."""
        model_id = self.custom_model_entry.get().strip()
        if not model_id:
            messagebox.showwarning("No Model ID", "Please enter a model ID.")
            return

        provider = self.provider_var.get()
        all_models = self._get_models_for_provider(provider)

        if model_id in all_models:
            messagebox.showinfo("Already Exists", f"'{model_id}' is already available for {provider}.")
            return

        self.custom_models[provider].append(model_id)
        updated_models = self._get_models_for_provider(provider)

        # Update all model dropdowns to include the new model
        for model_var, combo in self._model_combos:
            combo['values'] = updated_models

        self.custom_model_entry.delete(0, "end")
        self._update_custom_models_label()
        messagebox.showinfo("Model Added", f"'{model_id}' added to {provider}. You can now select it in any tab's model dropdown.")

    def _remove_custom_model(self):
        """Remove a custom model from the current provider's list."""
        model_id = self.remove_model_entry.get().strip()
        if not model_id:
            messagebox.showwarning("No Model ID", "Please enter the model ID to remove.")
            return

        provider = self.provider_var.get()
        if model_id not in self.custom_models.get(provider, []):
            messagebox.showwarning("Not Found", f"'{model_id}' is not a custom model for {provider}.")
            return

        self.custom_models[provider].remove(model_id)
        updated_models = self._get_models_for_provider(provider)

        for model_var, combo in self._model_combos:
            combo['values'] = updated_models
            # If the removed model was selected, reset to default
            if model_var.get() == model_id:
                model_var.set(PROVIDER_DEFAULTS.get(provider, "gpt-4o"))

        self.remove_model_entry.delete(0, "end")
        self._update_custom_models_label()
        messagebox.showinfo("Model Removed", f"'{model_id}' removed from {provider}.")

    def _update_custom_models_label(self):
        """Update the label showing custom models for the current provider."""
        provider = self.provider_var.get()
        custom = self.custom_models.get(provider, [])
        if custom:
            self.custom_models_label.config(text=", ".join(custom), foreground="black")
        else:
            self.custom_models_label.config(text="(none)", foreground="gray")

    # ------------------------------------------------------------------ saved settings
    def _settings_snapshot(self):
        return {
            "provider": self.provider_var.get(),
            "workspace_id": self.workspace_id_var.get(),
            "tenant_id": self.tenant_id_var.get(),
            "custom_models": self.custom_models,
            "models": {
                "hint": self.hint_model_var.get(), "hunter": self.th_model_var.get(),
                "soc": self.soc_model_var.get(), "flag_bank": self.flag_bank_model_var.get(),
                "incident": self.ir_model_var.get(),
            },
            "parallel_batches": self.th_workers_var.get(),
            "soc_auto_retry": self.soc_auto_retry_var.get(),
            "soc_suggest": bool(self.soc_suggest_var.get()),
            "remember_keys": bool(self.remember_keys_var.get()),
        }

    def _apply_settings(self, data):
        if not data:
            return
        try:
            if data.get("provider") in PROVIDER_OPTIONS:
                self.provider_var.set(data["provider"])
            if data.get("workspace_id") and not self.workspace_id_var.get():
                self.workspace_id_var.set(data["workspace_id"])
            if data.get("tenant_id") and not self.tenant_id_var.get():
                self.tenant_id_var.set(data["tenant_id"])
            for prov, models in (data.get("custom_models") or {}).items():
                if prov in self.custom_models and isinstance(models, list):
                    self.custom_models[prov] = [m for m in models if isinstance(m, str)]
            self._on_provider_changed()
            models = data.get("models") or {}
            for key, var in (("hint", self.hint_model_var), ("hunter", self.th_model_var), ("soc", self.soc_model_var),
                             ("flag_bank", self.flag_bank_model_var), ("incident", self.ir_model_var)):
                if models.get(key):
                    var.set(models[key])
            if data.get("parallel_batches"):
                self.th_workers_var.set(int(data["parallel_batches"]))
            if "soc_auto_retry" in data:
                self.soc_auto_retry_var.set(int(data["soc_auto_retry"]))
            if "soc_suggest" in data:
                self.soc_suggest_var.set(bool(data["soc_suggest"]))
            self.remember_keys_var.set(bool(data.get("remember_keys")))
        except Exception as e:
            print(f"Saved settings partially applied: {e}")

    def _load_saved_settings(self):
        """Called once at startup: restore non-secret settings and, if opted in,
        pull API keys from the OS keyring (env vars still win when set)."""
        data = load_settings()
        self._apply_settings(data)
        loaded_keys = []
        if data.get("remember_keys"):
            for prov, var in self.api_key_vars.items():
                if not var.get():
                    key = keyring_get_key(prov)
                    if key:
                        var.set(key)
                        loaded_keys.append(prov)
        if hasattr(self, "settings_status_lbl"):
            if data:
                msg = "Settings restored from last session."
                if loaded_keys:
                    msg += f" API keys loaded from the OS keyring for: {', '.join(loaded_keys)}."
                self.settings_status_lbl.config(text=msg, foreground="green")

    def save_settings_clicked(self):
        try:
            save_settings(self._settings_snapshot())
        except Exception as e:
            messagebox.showerror("Save Failed", f"Could not write {SETTINGS_PATH}:\n{e}")
            return
        msg = f"Settings saved to {SETTINGS_PATH}."
        if self.remember_keys_var.get():
            if not keyring_available():
                msg += (" API keys were NOT stored: no usable OS keyring found "
                        "(pip install keyring, and on Linux a Secret Service backend).")
                self.settings_status_lbl.config(text=msg, foreground="#b5651d")
                return
            stored = []
            for prov, var in self.api_key_vars.items():
                try:
                    keyring_set_key(prov, var.get().strip())
                    if var.get().strip():
                        stored.append(prov)
                except Exception as e:
                    msg += f" ({prov} key not stored: {e})"
            if stored:
                msg += f" API keys stored in the OS keyring for: {', '.join(stored)}."
        self.settings_status_lbl.config(text=msg, foreground="green")

    def forget_saved_keys(self):
        removed = 0
        for prov in self.api_key_vars:
            try:
                keyring_set_key(prov, "")
                removed += 1
            except Exception:
                pass
        self.remember_keys_var.set(False)
        try:
            save_settings(self._settings_snapshot())
        except Exception:
            pass
        self.settings_status_lbl.config(text="Saved API keys removed from the OS keyring; 'remember keys' turned off.",
                                        foreground="green")
