# -*- coding: utf-8 -*-
"""The Report Editor tab: per-finding write-ups exported to a Word document."""
import os
import datetime
from .deps import Document, HAS_DOCX, Inches, Pt, RGBColor, WD_ALIGN_PARAGRAPH, filedialog, messagebox, scrolledtext, simpledialog, tk, ttk

class ThreatHuntReporterTab:
    """Encapsulates the HuntLogApp logic within a Frame."""
    def __init__(self, parent_frame, findings_provider=None):
        self.parent = parent_frame
        self.entries = []
        self.current_images = []
        # Optional callable returning the app's verified findings (for one-click import).
        self.findings_provider = findings_provider
        self._init_ui()

    def _init_ui(self):
        toolbar = ttk.Frame(self.parent, padding=5)
        toolbar.pack(fill=tk.X)
        ttk.Label(toolbar, text="HuntLog Reporter Module", font=("Segoe UI", 9, "italic")).pack(side=tk.RIGHT)
        if self.findings_provider:
            ttk.Button(toolbar, text="⬇ Import Verified Findings", command=self.import_findings).pack(side=tk.LEFT)

        self.notebook = ttk.Notebook(self.parent)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.input_tab = ttk.Frame(self.notebook, padding="15")
        self.help_tab = ttk.Frame(self.notebook, padding="15")

        self.notebook.add(self.input_tab, text="Entry Form")
        self.notebook.add(self.help_tab, text="Help & Instructions")

        self._init_input_tab()
        self._init_help_tab()

    def _init_input_tab(self):
        # Scrollable wrapper for the entire input tab
        canvas = tk.Canvas(self.input_tab, highlightthickness=0)
        v_scroll = ttk.Scrollbar(self.input_tab, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)

        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=v_scroll.set)

        canvas.pack(side="left", fill="both", expand=True)
        v_scroll.pack(side="right", fill="y")

        # Enable mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        def _on_linux_scroll_up(event):
            canvas.yview_scroll(-3, "units")
        def _on_linux_scroll_down(event):
            canvas.yview_scroll(3, "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)
        canvas.bind_all("<Button-4>", _on_linux_scroll_up)
        canvas.bind_all("<Button-5>", _on_linux_scroll_down)

        # Resize inner frame width to match canvas
        def _on_canvas_configure(event):
            canvas.itemconfig(canvas.find_all()[0], width=event.width)
        canvas.bind("<Configure>", _on_canvas_configure)

        # --- All content goes into scroll_frame instead of self.input_tab ---
        meta_frame = ttk.LabelFrame(scroll_frame, text="Report Details", padding="10")
        meta_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(meta_frame, text="Author Name:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.author_entry = ttk.Entry(meta_frame, width=30)
        self.author_entry.grid(row=0, column=1, sticky=tk.W, padx=5)

        ttk.Label(meta_frame, text="Event/Engagement:").grid(row=0, column=2, sticky=tk.W, padx=5)
        self.event_entry = ttk.Entry(meta_frame, width=30)
        self.event_entry.grid(row=0, column=3, sticky=tk.W, padx=5)

        input_frame = ttk.LabelFrame(scroll_frame, text="Add New Finding / Challenge", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 10))
        input_frame.columnconfigure(1, weight=1)

        ttk.Label(input_frame, text="Challenge/Title:").grid(row=0, column=0, sticky=tk.NW, pady=5)
        self.title_entry = ttk.Entry(input_frame)
        self.title_entry.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)

        ttk.Label(input_frame, text="Category:").grid(row=0, column=2, sticky=tk.NW, pady=5)
        self.cat_combo = ttk.Combobox(input_frame, values=["Network Forensics", "Endpoint Security", "Malware Analysis", "OSINT", "Log Analysis", "Web Exploitation", "Cryptography", "Cloud Security", "Other"])
        self.cat_combo.current(0)
        self.cat_combo.grid(row=0, column=3, sticky=tk.EW, padx=5, pady=5)

        ttk.Label(input_frame, text="Description:").grid(row=1, column=0, sticky=tk.NW, pady=5)
        self.desc_text_frame, self.desc_text = self.create_scrollable_text(input_frame, height=3)
        self.desc_text_frame.grid(row=1, column=1, columnspan=3, sticky=tk.EW, padx=5, pady=5)

        ttk.Label(input_frame, text="Methodology:").grid(row=2, column=0, sticky=tk.NW, pady=5)
        self.method_text_frame, self.method_text = self.create_scrollable_text(input_frame, height=4)
        self.method_text_frame.grid(row=2, column=1, columnspan=3, sticky=tk.EW, padx=5, pady=5)

        ttk.Label(input_frame, text="KQL / Query:").grid(row=3, column=0, sticky=tk.NW, pady=5)
        self.kql_text_frame, self.kql_text = self.create_scrollable_text(input_frame, height=3, font=("Courier New", 10))
        self.kql_text_frame.grid(row=3, column=1, columnspan=3, sticky=tk.EW, padx=5, pady=5)

        ttk.Label(input_frame, text="Flag / Artifact:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.flag_entry = ttk.Entry(input_frame)
        self.flag_entry.grid(row=4, column=1, columnspan=3, sticky=tk.EW, padx=5, pady=5)

        ttk.Label(input_frame, text="Screenshots:").grid(row=5, column=0, sticky=tk.NW, pady=5)
        img_control_frame = ttk.Frame(input_frame)
        img_control_frame.grid(row=5, column=1, columnspan=3, sticky=tk.EW, padx=5, pady=5)

        btn_box = ttk.Frame(img_control_frame)
        btn_box.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        self.add_img_btn = ttk.Button(btn_box, text="Add Image + Caption", command=self.add_image_with_caption)
        self.add_img_btn.pack(fill=tk.X, pady=(0, 5))
        self.remove_img_btn = ttk.Button(btn_box, text="Remove Selected", command=self.remove_selected_image)
        self.remove_img_btn.pack(fill=tk.X)

        self.img_listbox = tk.Listbox(img_control_frame, height=4, width=60, font=("Segoe UI", 9))
        self.img_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=6, column=0, columnspan=4, pady=10)
        ttk.Button(btn_frame, text="Add Entry to Report", command=self.add_entry).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Clear Form", command=self.clear_form).pack(side=tk.LEFT, padx=10)

        list_frame = ttk.LabelFrame(scroll_frame, text="Entries Queued for Export", padding="10")
        list_frame.pack(fill=tk.X, pady=(0, 10))

        self.tree = ttk.Treeview(list_frame, columns=("Title", "Category", "Images"), show="headings", height=5)
        self.tree.heading("Title", text="Title")
        self.tree.heading("Category", text="Category")
        self.tree.heading("Images", text="Image Count")
        self.tree.column("Title", width=300)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        del_btn = ttk.Button(list_frame, text="Delete Selected Entry", command=self.delete_entry)
        del_btn.pack(side=tk.BOTTOM, pady=5, anchor=tk.E)

        ttk.Button(scroll_frame, text="GENERATE WORD DOC REPORT", command=self.generate_report).pack(fill=tk.X, pady=10)

    def _init_help_tab(self):
        help_text_content = """
        REPORT GENERATOR HELP
        =====================
        1. SAVING & LOADING: Use the SESSION MANAGER TAB to save/load your full work.
        2. ADD FINDINGS: Fill out the form. Paste KQL queries in the KQL box.
        3. SCREENSHOTS: Click 'Add Image' to attach evidence.
        4. GENERATE: Click the bottom button to create a .docx file.
        """
        help_text = scrolledtext.ScrolledText(self.help_tab, font=("Courier New", 11))
        help_text.pack(fill=tk.BOTH, expand=True)
        help_text.insert(tk.END, help_text_content)
        help_text.config(state=tk.DISABLED)

    def create_scrollable_text(self, parent, height=5, font=("Segoe UI", 10)):
        frame = ttk.Frame(parent)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL)
        text_widget = tk.Text(frame, height=height, font=font, yscrollcommand=scrollbar.set)
        scrollbar.config(command=text_widget.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        return frame, text_widget

    def add_image_with_caption(self):
        file_path = filedialog.askopenfilename()
        if not file_path: return
        caption = simpledialog.askstring("Image Caption", f"Enter description for:\n{os.path.basename(file_path)}")
        if caption is None: return
        self.current_images.append({'path': file_path, 'caption': caption or "Evidence"})
        self.img_listbox.insert(tk.END, f"{os.path.basename(file_path)} - {caption}")

    def remove_selected_image(self):
        selection = self.img_listbox.curselection()
        if selection:
            idx = selection[0]
            self.img_listbox.delete(idx)
            del self.current_images[idx]

    def add_entry(self):
        title = self.title_entry.get().strip()
        if not title:
            messagebox.showwarning("Validation Error", "Please provide a Challenge Title.")
            return

        entry = {
            "title": title,
            "category": self.cat_combo.get(),
            "description": self.desc_text.get("1.0", tk.END).strip(),
            "methodology": self.method_text.get("1.0", tk.END).strip(),
            "kql_query": self.kql_text.get("1.0", tk.END).strip(),
            "flag": self.flag_entry.get().strip(),
            "images": list(self.current_images)
        }
        self.entries.append(entry)
        self.tree.insert("", tk.END, values=(entry['title'], entry['category'], str(len(entry['images']))))
        self.clear_form()

    def import_findings(self):
        """Pull the app's verified findings into the report as entries (dedup by title)."""
        findings = self.findings_provider() if self.findings_provider else []
        if not findings:
            messagebox.showinfo("No Findings", "No verified findings to import yet.")
            return
        existing = {en.get('title') for en in self.entries}
        added = 0
        for f in findings:
            title = f.get('title') or "Untitled Finding"
            if title in existing:
                continue
            methodology = ""
            if f.get('focus_id') and f['focus_id'] != 'General/All':
                methodology += f"Investigation focus: {f['focus_id']}\n"
            if f.get('source'):
                methodology += f"Source: {f['source']}"
            entry = {
                "title": title,
                "category": "Log Analysis",
                "description": f.get('description') or f.get('note', ''),
                "methodology": methodology.strip(),
                "kql_query": "",
                "flag": f.get('note', ''),
                "images": []
            }
            self.entries.append(entry)
            self.tree.insert("", tk.END, values=(entry['title'], entry['category'], "0"))
            existing.add(title)
            added += 1
        if added:
            messagebox.showinfo("Imported", f"Imported {added} finding(s) into the report.")
        else:
            messagebox.showinfo("Nothing New", "All verified findings are already in the report.")

    def delete_entry(self):
        selected = self.tree.selection()
        if selected:
            item = selected[0]
            idx = self.tree.index(item)
            self.tree.delete(item)
            del self.entries[idx]

    def clear_form(self):
        self.title_entry.delete(0, tk.END)
        self.desc_text.delete("1.0", tk.END)
        self.method_text.delete("1.0", tk.END)
        self.kql_text.delete("1.0", tk.END)
        self.flag_entry.delete(0, tk.END)
        self.current_images = []
        self.img_listbox.delete(0, tk.END)

    def generate_report(self):
        if not self.entries: return
        if not HAS_DOCX:
            messagebox.showerror(
                "Missing Library",
                "Generating a Word report needs python-docx, which is not installed.\n\n"
                "pip install python-docx"
            )
            return
        f = filedialog.asksaveasfilename(defaultextension=".docx")
        if not f: return
        try:
            doc = Document()
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run("Threat Hunt Report")
            run.bold = True; run.font.size = Pt(24); run.font.color.rgb = RGBColor(0x2E, 0x74, 0xB5)

            p2 = doc.add_paragraph()
            p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p2.add_run(f"\nEvent: {self.event_entry.get()}\nAuthor: {self.author_entry.get()}\nDate: {datetime.datetime.now().strftime('%Y-%m-%d')}")
            doc.add_page_break()

            for i, e in enumerate(self.entries, 1):
                doc.add_heading(f"{i}. {e['title']}", level=1)
                doc.add_paragraph(f"Category: {e['category']}")
                doc.add_heading('Description', level=2)
                doc.add_paragraph(e['description'])
                doc.add_heading('Methodology', level=2)
                doc.add_paragraph(e['methodology'])

                if e.get('kql_query'):
                    doc.add_heading('KQL Query', level=3)
                    run = doc.add_paragraph().add_run(e['kql_query'])
                    run.font.name = 'Courier New'

                if e.get('images'):
                    doc.add_heading('Evidence', level=3)
                    for img in e['images']:
                        if os.path.exists(img['path']):
                            # Skip a single bad/unsupported image instead of aborting the whole report.
                            try:
                                doc.add_picture(img['path'], width=Inches(6))
                                doc.add_paragraph(f"Caption: {img['caption']}", style="Caption")
                            except Exception as img_err:
                                doc.add_paragraph(f"[Image could not be embedded: {os.path.basename(img['path'])} — {img_err}]")
                        else:
                            doc.add_paragraph(f"[Image not found: {os.path.basename(img['path'])}]")

                doc.add_heading('Flag', level=2)
                run = doc.add_paragraph().add_run(e['flag'])
                run.font.color.rgb = RGBColor(255, 0, 0); run.bold = True
                doc.add_page_break()

            doc.save(f)
            messagebox.showinfo("Success", f"Report saved to {f}")
        except Exception as ex:
            messagebox.showerror("Error", str(ex))

    def get_state(self):
        return {
            "entries": self.entries,
            "author": self.author_entry.get(),
            "event": self.event_entry.get()
        }

    def set_state(self, data):
        self.entries = data.get("entries", [])
        self.author_entry.delete(0, tk.END)
        self.author_entry.insert(0, data.get("author", ""))
        self.event_entry.delete(0, tk.END)
        self.event_entry.insert(0, data.get("event", ""))
        for item in self.tree.get_children():
            self.tree.delete(item)
        for e in self.entries:
            self.tree.insert("", tk.END, values=(e['title'], e['category'], str(len(e.get('images', [])))))
