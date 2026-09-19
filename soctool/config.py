# -*- coding: utf-8 -*-
"""Model / provider tables and paths."""
import os

MODEL_OPTIONS = ["gpt-4o", "gpt-4o-mini", "gpt-5.2", "gpt-5-mini"]
DEFAULT_MODEL = "gpt-4o"

PROVIDER_OPTIONS = ["OpenAI", "Gemini", "Claude"]
PROVIDER_MODELS = {
    "OpenAI": ["gpt-4o", "gpt-4o-mini", "gpt-5.2", "gpt-5-mini"],
    "Gemini": ["gemini-2.5-pro", "gemini-2.5-flash", "gemini-2.0-flash", "gemini-3.1-pro", "gemini-3.1-flash"],
    "Claude": ["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5-20251001"],
}
PROVIDER_DEFAULTS = {
    "OpenAI": "gpt-4o",
    "Gemini": "gemini-2.5-pro",
    "Claude": "claude-sonnet-4-6",
}
PROVIDER_ENV_KEYS = {
    "OpenAI": "OPENAI_API_KEY",
    "Gemini": "GEMINI_API_KEY",
    "Claude": "ANTHROPIC_API_KEY",
}

# Folder for auto-captured SOC query results. Absolute so the paths added to the
# Threat Hunter keep working even if the process's working directory changes.
CAPTURE_DIR = os.path.abspath("soc_captured_logs")
