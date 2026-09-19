# -*- coding: utf-8 -*-
import os
from ..deps import filedialog, messagebox, scrolledtext, tk, ttk

class SummaryTabMixin:
    def _setup_summary_tab(self):
        frame = ttk.LabelFrame(self.tab_summary, text="Confirmed Flags & Notes", padding=10)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.summary_text = scrolledtext.ScrolledText(frame, font=("Consolas", 11), state="disabled")
        self.summary_text.pack(fill="both", expand=True)

        btn_box = ttk.Frame(frame)
        btn_box.pack(fill="x", pady=5)
        ttk.Button(btn_box, text="Refresh Display", command=self._update_summary_display).pack(side="right")
        ttk.Button(btn_box, text="💾 Export to .txt", command=self.summary_export).pack(side="right", padx=5)
        ttk.Button(btn_box, text="📋 Copy", command=self.summary_copy).pack(side="right")
        ttk.Button(btn_box, text="🗑 Remove Finding…", command=self.summary_remove_finding).pack(side="left")

    def summary_copy(self):
        """Copy the findings summary to the clipboard."""
        content = self.summary_text.get("1.0", "end").strip()
        if not content:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("Copied", "Findings summary copied to clipboard.")

    def summary_export(self):
        """Save the findings summary to a text file."""
        content = self.summary_text.get("1.0", "end").strip()
        if not content:
            messagebox.showinfo("Nothing to Export", "No findings to export yet.")
            return
        f = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text File", "*.txt")])
        if not f:
            return
        try:
            with open(f, "w", encoding="utf-8") as fh:
                fh.write(content)
            messagebox.showinfo("Exported", f"Summary saved to {os.path.basename(f)}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def _open_remove_dialog(self, title, prompt, labels, on_remove_indices):
        """Generic modal picker: an extended-select listbox of `labels`; calls
        on_remove_indices(sorted_selected_indices) on confirm. Shared by the
        finding and hint removers."""
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("640x400")
        ttk.Label(win, text=prompt).pack(anchor="w", padx=10, pady=(10, 5))

        list_frame = ttk.Frame(win)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        scroll = ttk.Scrollbar(list_frame, orient="vertical")
        lb = tk.Listbox(list_frame, selectmode="extended", yscrollcommand=scroll.set)
        scroll.config(command=lb.yview)
        scroll.pack(side="right", fill="y")
        lb.pack(side="left", fill="both", expand=True)
        for text in labels:
            lb.insert("end", text)

        def do_remove():
            idxs = sorted(lb.curselection())
            win.destroy()
            if idxs:
                on_remove_indices(idxs)

        btn_frame = ttk.Frame(win)
        btn_frame.pack(fill="x", padx=10, pady=10)
        ttk.Button(btn_frame, text="Remove Selected", command=do_remove).pack(side="right")
        ttk.Button(btn_frame, text="Cancel", command=win.destroy).pack(side="right", padx=5)

    def summary_remove_finding(self):
        """Remove one or more verified findings (e.g. false positives)."""
        if not self.verified_flags_data:
            messagebox.showinfo("Nothing to Remove", "No verified findings yet.")
            return
        # Same sorted order as the Summary display, so the list lines up visually.
        ordered = sorted(self.verified_flags_data, key=lambda x: x.get('title', ''))
        labels = [f"{it.get('title', '?')} — {(it.get('note') or '')[:70]}" for it in ordered]

        def remove(idxs):
            remove_ids = {id(ordered[i]) for i in idxs}
            removed_titles = {ordered[i].get('title') for i in idxs}
            self.verified_flags_data = [f for f in self.verified_flags_data if id(f) not in remove_ids]
            self.th_found_flags -= {t for t in removed_titles if t}
            for t in removed_titles:
                if t:
                    self.th_log_history(f"[REMOVED] {t}")
            self._update_summary_display()

        self._open_remove_dialog("Remove Finding",
                                 "Select finding(s) to remove (this is permanent):",
                                 labels, remove)

    def _update_summary_display(self):
        self.summary_text.config(state="normal")
        self.summary_text.delete("1.0", "end")

        txt = "=== INVESTIGATION FINDINGS SUMMARY ===\n\n"

        # Sort by Title to keep tidy
        sorted_flags = sorted(self.verified_flags_data, key=lambda x: x.get('title', ''))

        for idx, item in enumerate(sorted_flags, 1):
            txt += f"{idx}. FLAG: {item['title']}\n"
            txt += f"   FOCUS: {item.get('focus_id', 'General')}\n"
            if item.get('source'):
                txt += f"   SOURCE: {item['source']}\n"
            txt += f"   NOTE:  {item['note']}\n"
            txt += "-"*50 + "\n"

        self.summary_text.insert("1.0", txt)
        self.summary_text.config(state="disabled")
