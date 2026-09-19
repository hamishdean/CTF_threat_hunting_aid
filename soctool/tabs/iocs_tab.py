# -*- coding: utf-8 -*-
import os
import json
from ..deps import filedialog, messagebox, ttk
from ..textutil import IOC_PATTERNS, csv_safe_cell, extract_iocs, extract_text_from_file, merge_iocs

class IocsTabMixin:
    def _setup_iocs_tab(self):
        top = ttk.LabelFrame(self.tab_iocs, text="Indicator of Compromise (IOC) Extractor", padding=10)
        top.pack(fill="x", padx=10, pady=5)

        ttk.Label(top, text="Pull IOCs (IPs, domains, URLs, hashes, emails, CVEs, MITRE T-codes) "
                            "from your data. Deterministic — no API key or Azure needed.",
                  font=("Segoe UI", 9, "italic")).pack(anchor="w", pady=(0, 8))

        btn_row = ttk.Frame(top)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="📄 Extract from Loaded Files", command=self.ioc_extract_from_files).pack(side="left", padx=2)
        ttk.Button(btn_row, text="🏁 Extract from Findings & Logs", command=self.ioc_extract_from_findings).pack(side="left", padx=2)
        ttk.Button(btn_row, text="🧹 Clear", command=self.ioc_clear).pack(side="left", padx=2)
        ttk.Checkbutton(btn_row, text="Add to existing", variable=self.ioc_accumulate_var).pack(side="left", padx=10)
        self.ioc_count_lbl = ttk.Label(btn_row, text="0 indicators", foreground="gray")
        self.ioc_count_lbl.pack(side="right", padx=5)

        mid = ttk.LabelFrame(self.tab_iocs, text="Extracted Indicators", padding=10)
        mid.pack(fill="both", expand=True, padx=10, pady=5)

        self.ioc_tree = ttk.Treeview(mid, columns=("type", "indicator"), show="headings", selectmode="extended")
        self.ioc_tree.heading("type", text="Type")
        self.ioc_tree.heading("indicator", text="Indicator")
        self.ioc_tree.column("type", width=120, stretch=False)
        self.ioc_tree.column("indicator", width=760)
        ioc_scroll = ttk.Scrollbar(mid, orient="vertical", command=self.ioc_tree.yview)
        self.ioc_tree.configure(yscrollcommand=ioc_scroll.set)
        self.ioc_tree.pack(side="left", fill="both", expand=True)
        ioc_scroll.pack(side="right", fill="y")

        bot = ttk.Frame(self.tab_iocs)
        bot.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(bot, text="🎯 Pivot Selected → SOC Agent", command=self.ioc_pivot_to_soc).pack(side="left", padx=2)
        ttk.Button(bot, text="📋 Copy Selected", command=self.ioc_copy_selected).pack(side="left", padx=2)
        ttk.Button(bot, text="💾 Export JSON", command=lambda: self.ioc_export("json")).pack(side="right", padx=2)
        ttk.Button(bot, text="💾 Export CSV", command=lambda: self.ioc_export("csv")).pack(side="right", padx=2)

    def _ioc_gather_files_text(self):
        """Read all loaded Threat Hunter files into one text blob."""
        blobs = []
        for f in self.th_files:
            if os.path.exists(f):
                blobs.extend(extract_text_from_file(f))
        return "\n".join(blobs)

    def _ioc_gather_findings_text(self):
        """Collect text from verified findings, hints, and the latest SOC records."""
        parts = []
        for f in self.verified_flags_data:
            parts.extend([f.get("title", ""), f.get("description", ""), f.get("note", "")])
        for h in self.ctf_hints:
            parts.extend([h.get("hint", ""), h.get("clue", "") or "", h.get("kql", "") or ""])
        if self.soc_last_records:
            try:
                parts.append(json.dumps(self.soc_last_records, default=str))
            except Exception:
                parts.append(str(self.soc_last_records))
        return "\n".join(p for p in parts if p)

    def ioc_extract_from_files(self):
        if not self.th_files:
            messagebox.showinfo("No Files", "Add files in the Threat Hunter tab first.")
            return
        text = self._ioc_gather_files_text()
        if not text.strip():
            messagebox.showinfo("No Text", "No readable text found in the loaded files.")
            return
        new = extract_iocs(text)
        merged = merge_iocs(self.ioc_results, new) if self.ioc_accumulate_var.get() else new
        self._ioc_set_results(merged, source="loaded files")

    def ioc_extract_from_findings(self):
        text = self._ioc_gather_findings_text()
        if not text.strip():
            messagebox.showinfo("No Data", "No findings, hints, or SOC results available yet.")
            return
        new = extract_iocs(text)
        merged = merge_iocs(self.ioc_results, new) if self.ioc_accumulate_var.get() else new
        self._ioc_set_results(merged, source="findings & logs")

    def _ioc_populate_tree(self, source=""):
        """Refresh the IOC table from self.ioc_results and update the count label.

        Returns the number of indicators shown. No dialogs, so it is safe to call
        on session load (see _ioc_set_results for the interactive extract path)."""
        for item in self.ioc_tree.get_children():
            self.ioc_tree.delete(item)
        total = 0
        for category in IOC_PATTERNS:  # stable, sensible ordering
            for value in self.ioc_results.get(category, []):
                self.ioc_tree.insert("", "end", values=(category, value))
                total += 1
        suffix = f" (from {source})" if source else ""
        self.ioc_count_lbl.config(text=f"{total} indicators{suffix}",
                                  foreground="black" if total else "gray")
        return total

    def _ioc_set_results(self, results, source=""):
        self.ioc_results = results
        total = self._ioc_populate_tree(source)
        if total == 0:
            messagebox.showinfo("No IOCs", "No indicators of compromise were found in that data.")

    def ioc_clear(self):
        self.ioc_results = {}
        for item in self.ioc_tree.get_children():
            self.ioc_tree.delete(item)
        self.ioc_count_lbl.config(text="0 indicators", foreground="gray")

    def _ioc_selected_values(self):
        return [self.ioc_tree.item(i, "values")[1] for i in self.ioc_tree.selection()]

    def ioc_pivot_to_soc(self):
        selected = self._ioc_selected_values()
        if not selected:
            messagebox.showinfo("No Selection", "Select one or more indicators to pivot on.")
            return
        joined = ", ".join(selected[:10])
        query = (f"Search all tables for any activity involving these indicators: {joined}. "
                 f"Return matching records with timestamps, devices, and accounts.")
        self.soc_prompt_text.delete("1.0", "end")
        self.soc_prompt_text.insert("1.0", query)
        self.notebook.select(self.tab_soc)

    def ioc_copy_selected(self):
        selected = self._ioc_selected_values()
        if not selected:
            messagebox.showinfo("No Selection", "Select one or more indicators to copy.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(selected))

    def ioc_export(self, fmt):
        if not self.ioc_results:
            messagebox.showinfo("Nothing to Export", "Extract some IOCs first.")
            return
        if fmt == "json":
            f = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
            if not f:
                return
            try:
                with open(f, "w", encoding="utf-8") as fh:
                    json.dump(self.ioc_results, fh, indent=2)
                messagebox.showinfo("Exported", f"IOCs saved to {os.path.basename(f)}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))
        else:
            f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
            if not f:
                return
            try:
                with open(f, "w", encoding="utf-8", newline="") as fh:
                    fh.write("type,indicator\n")
                    for category in IOC_PATTERNS:
                        for value in self.ioc_results.get(category, []):
                            fh.write(f"{csv_safe_cell(category)},{csv_safe_cell(value)}\n")
                messagebox.showinfo("Exported", f"IOCs saved to {os.path.basename(f)}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))
