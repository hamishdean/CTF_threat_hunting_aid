# -*- coding: utf-8 -*-
"""Deterministic text helpers: file extraction, chunking, IOC extraction,
timeline building, CSV safety. No AI, no Azure."""
import os
import re
from typing import List
from .deps import Document, HAS_DOCX, HAS_PYPDF, PdfReader
import json

def extract_text_from_file(filepath: str) -> List[str]:
    """Reads PDF, DOCX, or TXT files and returns a list of page strings (or chunks)."""
    text_chunks = []
    try:
        ext = filepath.lower()
        if ext.endswith('.pdf'):
            if not HAS_PYPDF:
                print(f"Cannot read {os.path.basename(filepath)}: pypdf is not installed (pip install pypdf).")
                return text_chunks
            reader = PdfReader(filepath)
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    text_chunks.append(text)
        elif ext.endswith('.docx'):
            if not HAS_DOCX:
                print(f"Cannot read {os.path.basename(filepath)}: python-docx is not installed (pip install python-docx).")
                return text_chunks
            doc = Document(filepath)
            full_text = []
            for para in doc.paragraphs:
                if para.text.strip():
                    full_text.append(para.text)
            text_chunks.append('\n'.join(full_text))
        else:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()
            text_chunks.extend(chunk_text(content))
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    return text_chunks

def chunk_text(content, chunk_size=4000):
    """Split text into ~chunk_size pieces on line boundaries.

    Cutting at a fixed byte offset split log records (one JSONL line from the SOC
    Agent capture, a syslog line, a CSV row) across two AI batches, so neither
    batch saw the whole record. A single line longer than chunk_size is emitted
    on its own rather than truncated."""
    chunks, buf, size = [], [], 0
    for line in (content or "").splitlines(keepends=True):
        if buf and size + len(line) > chunk_size:
            chunks.append("".join(buf))
            buf, size = [], 0
        buf.append(line)
        size += len(line)
    if buf:
        chunks.append("".join(buf))
    return chunks

# ------------------------------------------
# IOC EXTRACTION (deterministic - no AI/Azure)
# ------------------------------------------

# Reports and logs frequently "defang" indicators so they aren't clickable.
# Convert them back so the regexes below can match.
_DEFANG_REPLACEMENTS = [
    ("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."),
    ("[:]", ":"), ("[//]", "//"), ("[/]", "/"), ("[@]", "@"), ("[at]", "@"),
    ("hxxps", "https"), ("hxxp", "http"), ("hXXps", "https"), ("hXXp", "http"),
]

# TLD-looking tokens that are really file extensions; used to drop filename noise
# (e.g. "report.pdf", "payload.exe") from the domain category.
_COMMON_FILE_EXTS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "scr",
    "txt", "log", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf",
    "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico", "zip", "rar", "7z", "tar",
    "gz", "csv", "json", "xml", "html", "htm", "php", "asp", "aspx", "py", "sh",
    "bin", "dat", "tmp", "conf", "ini", "md", "yml", "yaml", "sql", "db", "lnk",
}

# Ordered so more specific / longer patterns are reported first.
IOC_PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "ipv6": r"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b",
    "sha256": r"\b[A-Fa-f0-9]{64}\b",
    "sha1": r"\b[A-Fa-f0-9]{40}\b",
    "md5": r"\b[A-Fa-f0-9]{32}\b",
    "url": r"\bhttps?://[^\s<>\"'\)\]]+",
    "email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "domain": r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b",
    "cve": r"\bCVE-\d{4}-\d{4,7}\b",
    "mitre": r"\bT\d{4}(?:\.\d{3})?\b",
}

def refang(text):
    """Convert defanged IOCs (hxxp://, 1.2.3[.]4) back to normal form."""
    if not text:
        return ""
    out = text
    for a, b in _DEFANG_REPLACEMENTS:
        out = out.replace(a, b)
    return out

def extract_iocs(text):
    """Extract common indicators of compromise from raw text (deterministic).

    Returns a dict of {category: sorted unique list} for any category that had
    hits. Categories: ipv4, ipv6, domain, url, email, md5, sha1, sha256, cve,
    mitre. Handles defanged indicators and filters obvious filename / timestamp
    false positives.
    """
    if not text:
        return {}
    clean = refang(text)
    results = {}

    for category, pattern in IOC_PATTERNS.items():
        flags = re.IGNORECASE if category in ("url", "email", "domain", "cve") else 0
        matches = re.findall(pattern, clean, flags)

        # Dedupe case-insensitively while preserving first-seen casing.
        seen_lower = set()
        unique = []
        for m in matches:
            key = m.lower()
            if key not in seen_lower:
                seen_lower.add(key)
                unique.append(m)
        if unique:
            results[category] = unique

    # ipv6: drop pure-decimal colon strings (timestamps like 10:30:45) - keep only
    # matches that contain a hex letter or the "::" compression marker.
    if "ipv6" in results:
        kept = [v for v in results["ipv6"] if "::" in v or re.search(r"[A-Fa-f]", v)]
        if kept:
            results["ipv6"] = kept
        else:
            results.pop("ipv6")

    # domain: drop filename noise (report.pdf, payload.exe). Domains that also
    # appear inside a URL or email are kept on purpose - the bare host is a
    # distinct, pivotable indicator for hunting.
    if "domain" in results:
        kept = [d for d in results["domain"]
                if d.rsplit(".", 1)[-1].lower() not in _COMMON_FILE_EXTS]
        if kept:
            results["domain"] = kept
        else:
            results.pop("domain")

    return {k: sorted(v) for k, v in results.items()}

def merge_iocs(a, b):
    """Merge two IOC dicts: per-category union, case-insensitive dedupe (first-seen
    casing wins), sorted. Used by the IOC tab's 'Add to existing' mode."""
    out = {}
    for category in set(a) | set(b):
        seen = set()
        values = []
        for v in list(a.get(category, [])) + list(b.get(category, [])):
            key = v.lower()
            if key not in seen:
                seen.add(key)
                values.append(v)
        if values:
            out[category] = sorted(values)
    return out

# ------------------------------------------
# TIMELINE BUILDER (deterministic - no AI)
# ------------------------------------------

# Common timestamp field names in Azure/Sentinel records and finding dicts.
_TIMESTAMP_KEYS = ("TimeGenerated", "timestamp", "Timestamp", "time", "Time",
                   "createdDateTime", "eventTime", "StartTime", "EndTime", "Date")

# ISO-8601-ish timestamp anywhere in a stringified value (fallback).
_TIMESTAMP_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?Z?\b")

# Fields that make a good one-line description for a timeline row, best first.
_TIMELINE_DESC_KEYS = ("title", "AlertName", "description", "Description", "message",
                       "flag_answer", "FlagAnswer", "ProcessCommandLine", "AccountName",
                       "DeviceName", "RemoteIP", "note")

def build_timeline(events, max_events=100, source=""):
    """Build a chronological timeline from records/findings (deterministic).

    `events` is an iterable of dicts (Azure log records, finding dicts, etc.).
    For each dict, use the first recognizable timestamp field (or any ISO-8601-ish
    timestamp found in its values) plus a short description. Returns a list of
    (timestamp_string, description, source) tuples sorted ascending; rows with no
    parseable timestamp are skipped. `source` labels every row unless the event
    carries its own "_source" key. Gives the AI report a factual backbone instead
    of relying on it to invent the order.
    """
    rows = []
    for ev in events or []:
        if not isinstance(ev, dict):
            continue

        ts = None
        for key in _TIMESTAMP_KEYS:
            if ev.get(key):
                ts = str(ev[key])
                break
        if not ts:
            match = _TIMESTAMP_RE.search(" ".join(str(v) for k, v in ev.items() if k != "_source"))
            if match:
                ts = match.group(0)
        if not ts:
            continue

        desc = ""
        for key in _TIMELINE_DESC_KEYS:
            if ev.get(key):
                desc = str(ev[key])
                break
        if not desc:
            desc = "; ".join(f"{k}={v}" for k, v in list(ev.items()) if k != "_source")[:200]

        rows.append((ts.strip(), desc.strip()[:200], str(ev.get("_source") or source)))

    # ISO-8601 strings sort chronologically as plain text.
    rows.sort(key=lambda r: r[0])
    return rows[:max_events]

def csv_safe_cell(value):
    """Quote a value for CSV and neutralize spreadsheet formula injection.

    IOCs and findings are attacker-controlled, so a cell beginning with = + - @
    (or a tab/CR) is prefixed with a single quote to stop Excel/Sheets executing
    it as a formula when the export is opened."""
    s = str(value)
    if s[:1] in ("=", "+", "-", "@", "\t", "\r"):
        s = "'" + s
    return '"' + s.replace('"', '""') + '"'

# ------------------------------------------
# FINDING DEDUPE
# ------------------------------------------

def normalize_answer(value):
    """Canonical form of a flag answer for duplicate detection: refanged, trimmed,
    unquoted, whitespace-collapsed, lower-cased. Two findings with the same
    normalized answer are the same answer even if the AI titled them differently."""
    if value is None:
        return ""
    s = refang(str(value)).strip().strip("\"'`").strip()
    s = re.sub(r"\s+", " ", s)
    return s.lower()

def rows_mentioning(records, value, limit=3):
    """Return up to `limit` records whose stringified values contain `value`
    (case-insensitive). Used to attach raw evidence rows to an AI finding."""
    needle = normalize_answer(value)
    if not needle or len(needle) < 2:
        return []
    hits = []
    for r in records or []:
        try:
            blob = json.dumps(r, default=str).lower()
        except Exception:
            blob = str(r).lower()
        if needle in blob:
            hits.append(r)
            if len(hits) >= limit:
                break
    return hits

# ------------------------------------------
# MITRE ATT&CK TECHNIQUE LOOKUP (bundled data, no network)
# ------------------------------------------

ATTACK_DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                "data", "attack_techniques.json")
_ATTACK_CACHE = None

def load_attack_techniques():
    """Return {technique_id: {"name": ..., "tactics": [...]}} from the bundled
    data/attack_techniques.json (MITRE ATT&CK Enterprise). Empty dict if missing."""
    global _ATTACK_CACHE
    if _ATTACK_CACHE is None:
        try:
            with open(ATTACK_DATA_PATH, "r", encoding="utf-8") as fh:
                _ATTACK_CACHE = json.load(fh).get("techniques", {})
        except Exception:
            _ATTACK_CACHE = {}
    return _ATTACK_CACHE

def attack_technique_name(technique_id):
    """'T1059.001' -> 'Command and Scripting Interpreter: PowerShell' ('' if unknown)."""
    info = load_attack_techniques().get(str(technique_id).upper().strip())
    return info["name"] if info else ""

def attack_label(technique_id, with_tactics=True):
    """Human label for a technique id, e.g.
    'T1059.001 - Command and Scripting Interpreter: PowerShell (Execution)'."""
    tid = str(technique_id).upper().strip()
    info = load_attack_techniques().get(tid)
    if not info:
        return tid
    label = f"{tid} - {info['name']}"
    if with_tactics and info.get("tactics"):
        label += f" ({', '.join(info['tactics'])})"
    return label
