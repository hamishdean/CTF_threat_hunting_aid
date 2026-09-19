# -*- coding: utf-8 -*-
"""Small UI-adjacent helpers shared by several tabs."""
import json
import re

class SessionLogger:
    """Redirects print statements to a tkinter ScrolledText widget."""
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

    def write(self, message):
        # Clean ANSI color codes for GUI display
        clean_msg = self.ansi_escape.sub('', message)

        if self.text_widget:
            self.text_widget.config(state="normal")
            self.text_widget.insert("end", clean_msg)
            self.text_widget.see("end")
            self.text_widget.config(state="disabled")

    def flush(self):
        pass

    def save_to_file(self, filename):
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(self.text_widget.get("1.0", "end"))
            return True
        except Exception:
            return False

class AzureSentinelFormatter:
    """Formats output to look like Azure Log Analytics / Sentinel results."""
    @staticmethod
    def format_log(finding: dict) -> str:
        formatted = {
            "TimeGenerated": finding.get("timestamp", ""),
            "AlertName": finding.get("title", "Unknown Alert"),
            "FlagAnswer": finding.get("flag_answer", ""),
            "Description": finding.get("description", ""),
            "Severity": finding.get("severity", "Medium"),
            "Evidence": finding.get("evidence", ""),
            "Source": finding.get("source", "")
        }
        return json.dumps(formatted, indent=2)
