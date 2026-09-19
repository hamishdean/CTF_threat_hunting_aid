# -*- coding: utf-8 -*-
"""Unified SOC Analyst & Threat Hunter (CTF Edition) - launcher.

The application lives in the `soctool` package next to this file:

    soctool/deps.py       optional third-party imports and HAS_* flags
    soctool/config.py     model / provider tables, paths, saved settings
    soctool/ai.py         provider-agnostic AI calls, KQL generation, record hunting
    soctool/azure_la.py   Azure Log Analytics credentials, query execution, schema
    soctool/textutil.py   file extraction, chunking, IOCs, timeline, ATT&CK lookup
    soctool/prompts.py    system prompts
    soctool/reporter.py   Report Editor tab (Word export)
    soctool/tabs/*.py     one mixin per notebook tab
    soctool/app.py        UnifiedSOCTool shell and main()

Run:  python unifiedsoctool.py
"""
import os
import sys

# Make the package importable when the script is launched from another directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from soctool.app import main  # noqa: E402

if __name__ == "__main__":
    main()
