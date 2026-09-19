# -*- coding: utf-8 -*-
"""Timeline tab: verified findings and query results in chronological order."""
import os

from ..deps import tk, ttk, messagebox, filedialog
from ..textutil import build_timeline, csv_safe_cell


class TimelineTabMixin:
    def _setup_timeline_tab(self):
        top = ttk.Frame(self.tab_timeline, padding=(10, 8, 10, 0))
        top.pack(fill="x")
        ttk.Label(top, text="Events from verified findings and the latest query results, sorted by timestamp. "
                            "The same list anchors the Incident Report's timeline.",
                  font=("Segoe UI", 9, "italic")).pack(side="left")
        self.timeline_include_records = tk.BooleanVar(value=True)
        ttk.Checkbutton(top, text="include query results", variable=self.timeline_include_records,
                        command=self.timeline_refresh).pack(side="right")
        ttk.Button(top, text="🔄 Refresh", command=self.timeline_refresh).pack(side="right", padx=6)

        mid = ttk.Frame(self.tab_timeline)
        mid.pack(fill="both", expand=True, padx=10, pady=5)
        self.timeline_tree = ttk.Treeview(mid, columns=("time", "source", "event"), show="headings", selectmode="extended")
        self.timeline_tree.heading("time", text="Time (UTC)")
        self.timeline_tree.heading("source", text="Source")
        self.timeline_tree.heading("event", text="Event")
        self.timeline_tree.column("time", width=200, stretch=False)
        self.timeline_tree.column("source", width=200, stretch=False)
        self.timeline_tree.column("event", width=800)
        ysb = ttk.Scrollbar(mid, orient="vertical", command=self.timeline_tree.yview)
        self.timeline_tree.configure(yscrollcommand=ysb.set)
        self.timeline_tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")
        self.timeline_tree.tag_configure("finding", foreground="#b00020")

        bot = ttk.Frame(self.tab_timeline)
        bot.pack(fill="x", padx=10, pady=(0, 10))
        self.timeline_count_lbl = ttk.Label(bot, text="0 events", foreground="gray")
        self.timeline_count_lbl.pack(side="left")
        ttk.Button(bot, text="📋 Copy", command=self.timeline_copy).pack(side="right", padx=2)
        ttk.Button(bot, text="💾 Export CSV", command=self.timeline_export).pack(side="right", padx=2)

    def timeline_events(self, max_events=500):
        """(time, description, source) rows for the tab and the incident report."""
        events = []
        for f in self.verified_flags_data:
            ev = dict(f)
            ev["_source"] = f"Finding: {f.get('source') or 'verified'}"
            # Prefer an evidence-row timestamp (when the flag was seen) over verification time.
            for row in f.get("evidence_rows") or []:
                if isinstance(row, dict):
                    for k in ("TimeGenerated", "timestamp", "Timestamp", "time"):
                        if row.get(k):
                            ev["TimeGenerated"] = row[k]
                            break
                    if ev.get("TimeGenerated"):
                        break
            if not ev.get("TimeGenerated") and not any(ev.get(k) for k in ("timestamp", "Timestamp")):
                ev["timestamp"] = f.get("timestamp", "")
            ev["title"] = f"{f.get('title', '')}" + (f" -> {f['flag_answer']}" if f.get("flag_answer") else "")
            events.append(ev)
        if self.timeline_include_records.get() and self.soc_last_records:
            for r in self.soc_last_records[:2000]:
                if isinstance(r, dict):
                    ev = dict(r)
                    ev["_source"] = "Query result"
                    events.append(ev)
        return build_timeline(events, max_events=max_events)

    def timeline_refresh(self):
        if not hasattr(self, "timeline_tree"):
            return
        rows = self.timeline_events()
        self.timeline_tree.delete(*self.timeline_tree.get_children())
        for ts, desc, src in rows:
            tag = "finding" if str(src).startswith("Finding") else ""
            self.timeline_tree.insert("", "end", values=(ts, src, desc), tags=(tag,))
        self.timeline_count_lbl.config(text=f"{len(rows)} events", foreground="black" if rows else "gray")

    def timeline_copy(self):
        rows = self.timeline_events()
        if not rows:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append("\n".join(f"{ts}\t{src}\t{desc}" for ts, desc, src in rows))
        messagebox.showinfo("Copied", "Timeline copied to clipboard.")

    def timeline_export(self):
        rows = self.timeline_events()
        if not rows:
            messagebox.showinfo("Nothing to Export", "The timeline is empty.")
            return
        f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not f:
            return
        try:
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.write("time,source,event\n")
                for ts, desc, src in rows:
                    fh.write(f"{csv_safe_cell(ts)},{csv_safe_cell(src)},{csv_safe_cell(desc)}\n")
            messagebox.showinfo("Exported", f"Timeline saved to {os.path.basename(f)}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))
