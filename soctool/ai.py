# -*- coding: utf-8 -*-
"""Provider-agnostic AI calls plus the KQL-generation and record-hunting helpers."""
import json
import time
from .deps import GEMINI_SDK, HAS_ANTHROPIC, HAS_GEMINI, HAS_OPENAI, OpenAI, anthropic, genai, google_genai, google_genai_types, pd
from .prompts import SYSTEM_PROMPT_KQL_GENERATOR, SYSTEM_PROMPT_THREAT_HUNT, THREAT_HUNT_PROMPTS, THREAT_HUNT_PROMPT_DEFAULT

def _is_transient_error(exc):
    """True if an AI API error looks worth retrying (rate limit, 5xx, connection)."""
    status = getattr(exc, "status_code", None) or getattr(exc, "status", None)
    if status in (429, 500, 502, 503, 504):
        return True
    msg = str(exc).lower()
    markers = ("rate limit", "ratelimit", "429", "overloaded", "timeout", "timed out",
               "temporarily unavailable", "503", "502", "504", "connection", "reset by peer")
    return any(m in msg for m in markers)

def call_with_retry(fn, attempts=3, base_delay=1.0):
    """Call fn(), retrying transient failures with exponential backoff.

    Non-transient errors (auth, bad request) are re-raised immediately so real
    problems still surface fast."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:
            last = e
            if i == attempts - 1 or not _is_transient_error(e):
                raise
            time.sleep(base_delay * (2 ** i))
    raise last

def ai_chat_completion(provider, api_key, model, messages, json_mode=False, max_tokens=4096, temperature=None):
    """Unified AI completion wrapper supporting OpenAI, Gemini, and Claude.

    Args:
        provider: "OpenAI", "Gemini", or "Claude"
        api_key: API key string for the chosen provider
        model: Model name string
        messages: List of {"role": ..., "content": ...} dicts (OpenAI format)
        json_mode: If True, request JSON output
        max_tokens: Maximum tokens in response
        temperature: Optional temperature override

    Returns:
        Response content as a string
    """
    if provider == "OpenAI":
        if not HAS_OPENAI:
            raise ImportError("openai package not installed. Run: pip install openai")
        client = OpenAI(api_key=api_key)
        kwargs = {"model": model, "messages": messages}
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        # Newer OpenAI reasoning models (o-series, gpt-5) require
        # max_completion_tokens and only accept the default temperature.
        needs_completion_tokens = model.startswith(("o1", "o3", "o4", "gpt-5"))
        if max_tokens:
            token_param = "max_completion_tokens" if needs_completion_tokens else "max_tokens"
            kwargs[token_param] = max_tokens
        if temperature is not None and not needs_completion_tokens:
            kwargs["temperature"] = temperature
        response = call_with_retry(lambda: client.chat.completions.create(**kwargs))
        # content is None when a reasoning model hits the token cap before
        # emitting text; return "" so callers/parse_ai_json fail cleanly.
        return response.choices[0].message.content or ""

    elif provider == "Claude":
        if not HAS_ANTHROPIC:
            raise ImportError("anthropic package not installed. Run: pip install anthropic")
        client = anthropic.Anthropic(api_key=api_key)
        # Extract system message from messages list
        system_text = ""
        user_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_text += msg["content"] + "\n"
            else:
                user_messages.append(msg)
        if json_mode:
            system_text += "\nYou MUST return valid JSON only. No extra text outside the JSON object."
        if not user_messages:
            user_messages = [{"role": "user", "content": "Please proceed."}]
        kwargs = {
            "model": model,
            "max_tokens": max_tokens or 4096,
            "messages": user_messages,
        }
        if system_text.strip():
            kwargs["system"] = system_text.strip()
        if temperature is not None:
            kwargs["temperature"] = temperature
        response = call_with_retry(lambda: client.messages.create(**kwargs))
        # Return the first text block; guard against empty or non-text content.
        for block in response.content:
            if getattr(block, "type", None) == "text":
                return block.text
        return ""

    elif provider == "Gemini":
        if not HAS_GEMINI:
            raise ImportError("google-genai package not installed. Run: pip install google-genai")

        # Split the system text from the conversation turns (shared by both SDKs).
        system_text = ""
        turns = []   # (role, text) with role in {"user", "model"}
        for msg in messages:
            if msg["role"] == "system":
                system_text += msg["content"] + "\n"
            elif msg["role"] == "assistant":
                turns.append(("model", msg["content"]))
            else:
                turns.append(("user", msg["content"]))
        if not turns:
            turns = [("user", "Please proceed.")]
        system_text = system_text.strip()

        if GEMINI_SDK == "google-genai":
            client = google_genai.Client(api_key=api_key)
            cfg = {}
            if system_text:
                cfg["system_instruction"] = system_text
            if json_mode:
                cfg["response_mime_type"] = "application/json"
            if temperature is not None:
                cfg["temperature"] = temperature
            if max_tokens:
                cfg["max_output_tokens"] = max_tokens
            contents = [
                google_genai_types.Content(role=role, parts=[google_genai_types.Part.from_text(text=text)])
                for role, text in turns
            ]
            response = call_with_retry(lambda: client.models.generate_content(
                model=model, contents=contents,
                config=google_genai_types.GenerateContentConfig(**cfg) if cfg else None))
            # .text is None (with a warning) when the reply had no text part.
            try:
                return response.text or ""
            except Exception:
                return ""

        # Legacy google-generativeai path.
        genai.configure(api_key=api_key)
        gen_config = {}
        if json_mode:
            gen_config["response_mime_type"] = "application/json"
        if temperature is not None:
            gen_config["temperature"] = temperature
        if max_tokens:
            gen_config["max_output_tokens"] = max_tokens
        contents = [{"role": role, "parts": [text]} for role, text in turns]
        # The legacy SDK has no system slot here; prepend it to the first user turn.
        if system_text:
            contents[0]["parts"][0] = system_text + "\n\n" + contents[0]["parts"][0]
        model_obj = genai.GenerativeModel(model, generation_config=gen_config if gen_config else None)
        response = call_with_retry(lambda: model_obj.generate_content(contents))
        # response.text raises when the model returned no text part (blocked or
        # empty); fall back to assembling text from the candidate parts.
        try:
            return response.text
        except Exception:
            try:
                parts = response.candidates[0].content.parts
                return "".join(getattr(p, "text", "") for p in parts)
            except Exception:
                return ""

    else:
        raise ValueError(f"Unsupported AI provider: {provider}")


def sanitize_kql(kql):
    """Clean up AI-generated KQL to fix common problems."""
    if not kql:
        return kql
    # Strip markdown code fences the AI sometimes wraps queries in
    kql = kql.strip()
    if kql.startswith("```"):
        kql = kql.split("\n", 1)[-1] if "\n" in kql else kql[3:]
    if kql.endswith("```"):
        kql = kql[:-3]
    kql = kql.strip()

    # Ensure a take limit exists to prevent runaway queries
    kql_lower = kql.lower()
    if "| take " not in kql_lower and "| limit " not in kql_lower and "| count" not in kql_lower:
        kql = kql.rstrip().rstrip(";") + "\n| take 500"

    return kql

def clean_json_string(json_str):
    if not json_str: return "{}"
    start = json_str.find('{')
    end = json_str.rfind('}')
    if start != -1 and end != -1 and end > start:
        return json_str[start : end + 1]
    return json_str.replace("```json", "").replace("```", "").strip()

def parse_ai_json(content):
    """Robustly parse a JSON object from raw AI output.

    Handles None, markdown ```json code fences, and leading/trailing prose that
    some providers (notably Claude and Gemini) wrap around the JSON even when a
    JSON response was requested. Raises ValueError with a short snippet if no
    valid JSON object can be recovered, so callers can surface a clear message
    instead of silently dropping results (the historic bug where every finding
    vanished on non-OpenAI providers).
    """
    if content is None:
        raise ValueError("AI returned an empty response (no content).")

    # First attempt: extract the outermost {...} block (strips fences + prose).
    try:
        return json.loads(clean_json_string(content))
    except (json.JSONDecodeError, TypeError):
        pass

    # Second attempt: strip code fences explicitly and parse the whole string.
    stripped = content.replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, TypeError):
        snippet = " ".join(content.split())[:200]
        raise ValueError(f"AI did not return valid JSON. Response was: {snippet}")

def get_query_context(provider, api_key, user_input, model, history=None, hints=None, active_focus="General/All", incident_context=""):
    # Keep context concise to avoid confusing the KQL generator
    hist_str = ""
    if history:
        # Only include the last 2 queries, KQL only (no bloated context)
        hist_str = "Previous queries:\n" + "\n".join([f"- {h['kql_query']}" for h in history[-2:]])

    hints_str = ""
    if hints:
        # Only include short hint text, not full clue analysis
        hint_lines = [h['hint'][:100] for h in hints[:5]]
        hints_str = f"Context clues ({active_focus}): " + "; ".join(hint_lines)

    inc_str = ""
    if incident_context:
        # Truncate incident context to avoid overwhelming the KQL prompt
        inc_str = incident_context[:500]

    user_msg = f"User Request: {user_input}"
    if hints_str:
        user_msg = f"{hints_str}\n{user_msg}"
    if inc_str:
        user_msg = f"{inc_str}\n{user_msg}"
    if hist_str:
        user_msg = f"{hist_str}\n{user_msg}"

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT_KQL_GENERATOR},
        {"role": "user", "content": user_msg}
    ]
    try:
        content = ai_chat_completion(provider, api_key, model, messages, json_mode=True)
        query_context = parse_ai_json(content)

        # UPDATED: Clean parameters like EXECUTOR.py
        if "kql_query" not in query_context:
            query_context["kql_query"] = ""
        else:
            query_context["kql_query"] = sanitize_kql(query_context["kql_query"])
        if "parameters" not in query_context:
            query_context["parameters"] = {}

        params = query_context.get("parameters", {})
        try:
            # Flatten time range
            raw_hours = params.get("time_range_hours", 8760)
            query_context["time_range_hours"] = int(str(raw_hours).lower().replace("hours","").replace("hour","").strip())
        except (ValueError, AttributeError):
            query_context["time_range_hours"] = 8760

        # Flatten specific keys
        query_context["device_name"] = params.get("device_name", "")
        query_context["caller"] = params.get("caller", "")
        query_context["user_principal_name"] = params.get("user_principal_name", "")

        return query_context

    except Exception as e:
        return {"table_name": "Error", "kql_query": "", "error": str(e)}

def hunt_on_records(provider, api_key, records, table_name, model, hints=None, found_flags=None, active_focus="General/All"):
    try:
        df = pd.DataFrame(records)
        csv_data = df.to_csv(index=False)
    except Exception:
        csv_data = str(records)

    # Bound payload size to keep token cost/latency sane (matches the file-hunter cap).
    MAX_CSV_CHARS = 15000
    if len(csv_data) > MAX_CSV_CHARS:
        csv_data = csv_data[:MAX_CSV_CHARS] + "\n... (truncated for length)"

    context_str = ""
    if hints:
        context_str += f"CTF HINTS (FOCUS: {active_focus}):\n" + "\n".join([f"- [{h.get('id', 'General')}] {h['hint']}" for h in hints]) + "\n"
    if found_flags:
        context_str += "ALREADY FOUND FLAGS (Ignore these):\n" + json.dumps(list(found_flags)) + "\n"

    specific_instructions = THREAT_HUNT_PROMPTS.get(table_name, THREAT_HUNT_PROMPT_DEFAULT)

    prompt = f"""{context_str}
Instructions: {specific_instructions}
Analyze these {table_name} logs. Find the EXACT flag answer or specific artifact value that solves the question.
Do NOT just say "suspicious activity detected". Instead, extract the exact value (IP, username, hash, command, flag string, etc.) and put it in "flag_answer".
LOG DATA:
{csv_data}"""

    try:
        messages = [SYSTEM_PROMPT_THREAT_HUNT, {"role": "user", "content": prompt}]
        content = ai_chat_completion(provider, api_key, model, messages, json_mode=True)
        return parse_ai_json(content).get("findings", [])
    except Exception as e:
        raise e
