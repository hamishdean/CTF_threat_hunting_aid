# -*- coding: utf-8 -*-
"""Query Results tab: a sortable, filterable grid of the rows the last KQL returned."""
import json
import os
import time

from ..config import CAPTURE_DIR
from ..deps import tk, ttk, messagebox, filedialog
from ..textutil import csv_safe_cell

MAX_GRID_ROWS = 2000      # keep Tk responsive on huge result sets
MAX_CELL_CHARS = 300


class ResultsTabMixin:
    def _setup_results_tab(self):
        self.results_rows = []          # full row dicts currently loaded
        self.results_columns = []
        self._results_sort_col = None
        self._results_sort_desc = False

        top = ttk.Frame(self.tab_results, padding=(10, 8, 10, 0))
        top.pack(fill="x")
        self.results_title_lbl = ttk.Label(top, text="No query results yet. Run a query in the Azure SOC Agent tab.",
                                           font=("Segoe UI", 9, "italic"))
        self.results_title_lbl.pack(side="left")
        ttk.Label(top, text="Filter:").pack(side="left", padx=(20, 2))
        self.results_filter_var = tk.StringVar()
        filt = ttk.Entry(top, textvariable=self.results_filter_var, width=40)
        filt.pack(side="left")
        filt.bind("<Return>", lambda e: self._results_render())
        ttk.Button(top, text="Apply", command=self._results_render).pack(side="left", padx=2)
        ttk.Button(top, text="Clear", command=self._results_clear_filter).pack(side="left", padx=2)
        self.results_count_lbl = ttk.Label(top, text="", foreground="gray")
        self.results_count_lbl.pack(side="right")

        kql_frame = ttk.LabelFrame(self.tab_results, text="KQL that produced these rows", padding=5)
        kql_frame.pack(fill="x", padx=10, pady=5)
        self.results_kql_text = tk.Text(kql_frame, height=3, font=("Consolas", 9), wrap="word")
        self.results_kql_text.pack(fill="x")

        mid = ttk.Frame(self.tab_results)
        mid.pack(fill="both", expand=True, padx=10, pady=5)
        self.results_tree = ttk.Treeview(mid, columns=(), show="headings", selectmode="extended")
        ysb = ttk.Scrollbar(mid, orient="vertical", command=self.results_tree.yview)
        xsb = ttk.Scrollbar(mid, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        mid.rowconfigure(0, weight=1)
        mid.columnconfigure(0, weight=1)
        self.results_tree.bind("<Double-1>", lambda e: self.results_show_row())

        bot = ttk.Frame(self.tab_results)
        bot.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Button(bot, text="🔍 View Row", command=self.results_show_row).pack(side="left", padx=2)
        ttk.Button(bot, text="📋 Copy Selected", command=self.results_copy_selected).pack(side="left", padx=2)
        ttk.Button(bot, text="🕵️ Send Selected to Threat Hunter", command=self.results_send_to_hunter).pack(side="left", padx=2)
        ttk.Button(bot, text="🎯 Pivot on Cell Value…", command=self.results_pivot).pack(side="left", padx=2)
        ttk.Button(bot, text="💾 Export CSV", command=self.results_export_csv).pack(side="right", padx=2)
        ttk.Button(bot, text="💾 Export JSON", command=self.results_export_json).pack(side="right", padx=2)

    # ------------------------------------------------------------------ loading
    def _results_show(self, rows, kql="", title=None):
        """Load a result set into the grid (UI thread)."""
        self.results_rows = list(rows or [])
        cols = []
        for r in self.results_rows[:200]:
            for k in r.keys():
                if k not in cols:
                    cols.append(k)
        self.results_columns = cols
        self.results_kql_text.delete("1.0", "end")
        self.results_kql_text.insert("1.0", kql or "")
        n = len(self.results_rows)
        self.results_title_lbl.config(text=title or f"Latest query returned {n} row(s)"
                                      + (f" (showing first {MAX_GRID_ROWS})" if n > MAX_GRID_ROWS else ""))
        self._results_sort_col = None
        self._results_render()

    def _results_visible_rows(self):
        needle = self.results_filter_var.get().strip().lower()
        rows = self.results_rows
        if needle:
            rows = [r for r in rows if needle in json.dumps(r, default=str).lower()]
        if self._results_sort_col:
            col = self._results_sort_col
            rows = sorted(rows, key=lambda r: str(r.get(col, "")), reverse=self._results_sort_desc)
        return rows

    def _results_render(self):
        tree = self.results_tree
        tree.delete(*tree.get_children())
        tree["columns"] = self.results_columns
        for c in self.results_columns:
            arrow = ""
            if c == self._results_sort_col:
                arrow = " ▼" if self._results_sort_desc else " ▲"
            tree.heading(c, text=c + arrow, command=lambda col=c: self._results_sort_by(col))
            tree.column(c, width=160, minwidth=60, stretch=False)
        visible = self._results_visible_rows()
        for r in visible[:MAX_GRID_ROWS]:
            vals = [self._cell(r.get(c, "")) for c in self.results_columns]
            tree.insert("", "end", values=vals)
        self.results_count_lbl.config(text=f"{min(len(visible), MAX_GRID_ROWS)} of {len(self.results_rows)} rows")

    @staticmethod
    def _cell(v):
        s = v if isinstance(v, str) else json.dumps(v, default=str) if isinstance(v, (dict, list)) else str(v)
        s = s.replace("\n", " ")
        return s[:MAX_CELL_CHARS] + ("…" if len(s) > MAX_CELL_CHARS else "")

    def _results_sort_by(self, col):
        if self._results_sort_col == col:
            self._results_sort_desc = not self._results_sort_desc
        else:
            self._results_sort_col, self._results_sort_desc = col, False
        self._results_render()

    def _results_clear_filter(self):
        self.results_filter_var.set("")
        self._results_render()

    # ------------------------------------------------------------------ selection helpers
    def _results_selected_rows(self):
        """Map selected tree items back to their row dicts (by position in the
        currently visible ordering)."""
        visible = self._results_visible_rows()[:MAX_GRID_ROWS]
        out = []
        for item in self.results_tree.selection():
            idx = self.results_tree.index(item)
            if 0 <= idx < len(visible):
                out.append(visible[idx])
        return out

    def results_show_row(self):
        rows = self._results_selected_rows()
        if not rows:
            messagebox.showinfo("No Selection", "Select a row first.")
            return
        win = tk.Toplevel(self.root)
        win.title("Row detail")
        win.geometry("760x520")
        txt = tk.Text(win, font=("Consolas", 10), wrap="word")
        txt.pack(fill="both", expand=True, padx=8, pady=8)
        txt.insert("1.0", "\n\n".join(json.dumps(r, indent=2, default=str) for r in rows[:5]))
        txt.config(state="disabled")

    def results_copy_selected(self):
        rows = self._results_selected_rows()
        if not rows:
            messagebox.showinfo("No Selection", "Select one or more rows first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(json.dumps(r, default=str) for r in rows))

    def results_send_to_hunter(self):
        """Write the selected rows to a JSONL capture and add it to the Threat Hunter."""
        rows = self._results_selected_rows()
        if not rows:
            messagebox.showinfo("No Selection", "Select one or more rows first.")
            return
        try:
            os.makedirs(CAPTURE_DIR, exist_ok=True)
            path = os.path.join(CAPTURE_DIR, f"selected_rows_{int(time.time())}.jsonl")
            with open(path, "w", encoding="utf-8") as fh:
                for r in rows:
                    fh.write(json.dumps(r, default=str) + "\n")
        except Exception as e:
            messagebox.showerror("Error", f"Could not write capture file: {e}")
            return
        if path not in self.th_files:
            self.th_files.append(path)
            self.file_listbox.insert("end", os.path.basename(path))
        self.notebook.select(self.tab_hunter)
        messagebox.showinfo("Sent", f"{len(rows)} row(s) saved to {os.path.basename(path)} and added to the Threat Hunter file list.")

    def results_pivot(self):
        """Pick a column of the selected row and turn its value into a SOC Agent pivot."""
        rows = self._results_selected_rows()
        if not rows:
            messagebox.showinfo("No Selection", "Select a row first.")
            return
        row = rows[0]
        labels = [f"{k} = {self._cell(v)[:80]}" for k, v in row.items() if v not in ("", None)]
        keys = [k for k, v in row.items() if v not in ("", None)]

        def pivot(idxs):
            vals = [f"{keys[i]} '{self._cell(row[keys[i]])[:120]}'" for i in idxs]
            query = ("Search all tables for any other activity involving " + " and ".join(vals)
                     + ". Return matching records with timestamps, devices, and accounts.")
            self.soc_prompt_text.delete("1.0", "end")
            self.soc_prompt_text.insert("1.0", query)
            self.notebook.select(self.tab_soc)

        self._open_remove_dialog("Pivot on value", "Select the value(s) to pivot on:", labels, pivot)

    # ------------------------------------------------------------------ export
    def results_export_csv(self):
        if not self.results_rows:
            messagebox.showinfo("Nothing to Export", "No query results loaded.")
            return
        f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not f:
            return
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write(",".join(csv_safe_cell(c) for c in self.results_columns) + "\n")
                for r in self._results_visible_rows():
                    fh.write(",".join(csv_safe_cell(self._cell(r.get(c, ""))) for c in self.results_columns) + "\n")
            messagebox.showinfo("Exported", f"Results saved to {os.path.basename(f)}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def results_export_json(self):
        if not self.results_rows:
            messagebox.showinfo("Nothing to Export", "No query results loaded.")
            return
        f = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not f:
            return
        try:
            with open(f, "w", encoding="utf-8") as fh:
                json.dump(self._results_visible_rows(), fh, indent=1, default=str)
            messagebox.showinfo("Exported", f"Results saved to {os.path.basename(f)}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))
