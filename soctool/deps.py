# -*- coding: utf-8 -*-
"""Optional third-party imports. Each library is imported independently so a
missing package degrades one feature with a clear message instead of crashing
the program. Every other module imports the names it needs from here."""

# --- GUI toolkit (required to run the app, but guarded so the module can still be
#     imported headlessly for testing / tooling on machines without tkinter) ---
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, simpledialog
    from tkinter import scrolledtext
    HAS_TK = True
except ImportError:
    HAS_TK = False
    tk = ttk = messagebox = filedialog = simpledialog = scrolledtext = None

# --- Third Party Imports ---
# Each library is imported independently so that one missing package degrades a
# single feature with a clear message instead of crashing the whole program.
_MISSING_LIBS = []

try:
    from pypdf import PdfReader
    HAS_PYPDF = True
except ImportError:
    HAS_PYPDF = False
    PdfReader = None
    _MISSING_LIBS.append("pypdf")

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    pd = None
    _MISSING_LIBS.append("pandas")

try:
    from colorama import Fore, init, Style
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    _MISSING_LIBS.append("colorama")

    # Fallback shims so the many Fore.<COLOR> references never raise.
    class _NoColor:
        def __getattr__(self, name):
            return ""
    Fore = Style = _NoColor()

    def init(*args, **kwargs):
        pass

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False
    OpenAI = None
    _MISSING_LIBS.append("openai")

try:
    from azure.identity import DefaultAzureCredential
    from azure.monitor.query import LogsQueryClient
    from azure.core.exceptions import HttpResponseError, ClientAuthenticationError
    HAS_AZURE = True
except ImportError:
    HAS_AZURE = False
    DefaultAzureCredential = LogsQueryClient = HttpResponseError = ClientAuthenticationError = None
    _MISSING_LIBS.append("azure-identity + azure-monitor-query")

try:
    # Imports for Report Generator & Docx Reading
    from docx import Document
    from docx.shared import Inches, Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    HAS_DOCX = True
except ImportError:
    HAS_DOCX = False
    Document = Inches = Pt = RGBColor = WD_ALIGN_PARAGRAPH = None
    _MISSING_LIBS.append("python-docx")

# Optional AI Provider imports
HAS_ANTHROPIC = False
try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    pass

# Gemini: prefer the current google-genai SDK. The older google-generativeai
# package is deprecated and no longer updated, but keep it working as a fallback
# for machines that still have it installed.
HAS_GEMINI = False
GEMINI_SDK = None   # "google-genai" | "legacy" | None
genai = google_genai = google_genai_types = None
try:
    from google import genai as google_genai
    from google.genai import types as google_genai_types
    HAS_GEMINI = True
    GEMINI_SDK = "google-genai"
except ImportError:
    try:
        import google.generativeai as genai
        HAS_GEMINI = True
        GEMINI_SDK = "legacy"
    except ImportError:
        pass

__all__ = ['tk', 'ttk', 'messagebox', 'filedialog', 'simpledialog', 'scrolledtext', 'HAS_TK', 'PdfReader', 'HAS_PYPDF', 'pd', 'HAS_PANDAS', 'Fore', 'Style', 'init', 'HAS_COLORAMA', 'OpenAI', 'HAS_OPENAI', 'DefaultAzureCredential', 'LogsQueryClient', 'HttpResponseError', 'ClientAuthenticationError', 'HAS_AZURE', 'Document', 'Inches', 'Pt', 'RGBColor', 'WD_ALIGN_PARAGRAPH', 'HAS_DOCX', 'anthropic', 'HAS_ANTHROPIC', 'genai', 'google_genai', 'google_genai_types', 'HAS_GEMINI', 'GEMINI_SDK', '_MISSING_LIBS']

try:
    import keyring
    HAS_KEYRING = True
except ImportError:
    keyring = None
    HAS_KEYRING = False
__all__ += ["keyring", "HAS_KEYRING"]
