# -*- coding: utf-8 -*-
from ..deps import scrolledtext
from ..guide import GUIDE_TEXT

class GuideTabMixin:
    def _setup_guide_tab(self):
        guide_text = scrolledtext.ScrolledText(self.tab_guide, font=("Consolas", 11), wrap="word")
        guide_text.pack(fill="both", expand=True, padx=10, pady=10)
        guide_text.insert("1.0", GUIDE_TEXT)
        guide_text.config(state="disabled")
