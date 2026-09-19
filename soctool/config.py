# -*- coding: utf-8 -*-
"""Model / provider tables and paths."""
import os
from .deps import keyring, HAS_KEYRING
import json

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

# ------------------------------------------
# SAVED SETTINGS (between launches)
# ------------------------------------------
# Non-secret settings live in a small JSON file in the user's home directory.
# API keys are never written there; with the analyst's opt-in they go to the OS
# keyring (Windows Credential Manager, macOS Keychain, Secret Service on Linux).

SETTINGS_DIR = os.path.join(os.path.expanduser("~"), ".unifiedsoctool")
SETTINGS_PATH = os.path.join(SETTINGS_DIR, "config.json")
KEYRING_SERVICE = "unifiedsoctool"

def load_settings():
    """Return the saved settings dict, or {} if none / unreadable."""
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def save_settings(data):
    """Write the settings dict. Raises on failure so the UI can say why."""
    os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)

def keyring_available():
    if not HAS_KEYRING:
        return False
    try:
        # A missing backend raises only on use; probe with a harmless read.
        keyring.get_password(KEYRING_SERVICE, "__probe__")
        return True
    except Exception:
        return False

def keyring_get_key(provider):
    try:
        return keyring.get_password(KEYRING_SERVICE, provider) or "" if HAS_KEYRING else ""
    except Exception:
        return ""

def keyring_set_key(provider, value):
    """Store (or, for an empty value, delete) a provider's API key. Raises on failure."""
    if not HAS_KEYRING:
        raise RuntimeError("The 'keyring' package is not installed (pip install keyring).")
    if value:
        keyring.set_password(KEYRING_SERVICE, provider, value)
    else:
        try:
            keyring.delete_password(KEYRING_SERVICE, provider)
        except Exception:
            pass
