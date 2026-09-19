# -*- coding: utf-8 -*-
"""Azure Log Analytics access: credentials, query execution, error explanation."""
import os
from datetime import timedelta
from .deps import ClientAuthenticationError, DefaultAzureCredential, HAS_AZURE, LogsQueryClient
import re

def build_azure_credential(tenant_id=""):
    """DefaultAzureCredential tuned for an analyst workstation.

    - Honors an explicit tenant. CTF / client workspaces often live in a tenant
      where you are a guest, and the default chain otherwise picks your home
      tenant and fails with a confusing 403/404.
    - Enables the interactive-browser fallback, so someone without the Azure CLI
      installed gets a sign-in window instead of a wall of credential errors.
    The Azure CLI credential still comes first, so `az login` keeps working as
    before. The tenant also falls back to the AZURE_TENANT_ID environment variable.
    """
    if not HAS_AZURE:
        raise ImportError("Azure libraries not installed. Run: pip install azure-identity azure-monitor-query")
    kwargs = {"exclude_interactive_browser_credential": False}
    tenant_id = (tenant_id or os.environ.get("AZURE_TENANT_ID", "")).strip()
    if tenant_id:
        kwargs.update({
            "interactive_browser_tenant_id": tenant_id,
            "shared_cache_tenant_id": tenant_id,
            "visual_studio_code_tenant_id": tenant_id,
        })
    return DefaultAzureCredential(**kwargs)

def explain_azure_error(exc, workspace_id=""):
    """Translate the common Azure SDK failures into one actionable sentence.

    Returns "" when the error isn't one we recognise, so callers can fall back
    to printing the raw exception."""
    low = str(exc).lower()
    if (ClientAuthenticationError is not None and isinstance(exc, ClientAuthenticationError)) \
            or "defaultazurecredential failed" in low or "az login" in low \
            or "authentication failed" in low or "credential" in low and "unavailable" in low:
        return ("Azure sign-in failed. Run `az login` (add `--tenant <tenant-id>` if the workspace is in "
                "a tenant where you are a guest), or set the Tenant ID in Configuration and click "
                "'Test Azure Connection' to get a browser sign-in window.")
    if "pathnotfounderror" in low or "not found" in low or "404" in low or "does not exist" in low:
        return (f"Workspace '{workspace_id}' was not found. Check the Workspace ID (Azure Portal > Log "
                "Analytics workspace > Overview) and that you are signed in to the tenant that owns it.")
    if "403" in low or "forbidden" in low or "authorizationfailed" in low or "insufficient" in low:
        return "Access denied. Your account needs at least the 'Log Analytics Reader' role on the workspace."
    if "semanticerror" in low or "semantic error" in low or "syntaxerror" in low or "syntax error" in low \
            or "badargumenterror" in low or "failed to resolve" in low:
        return "The KQL did not compile (unknown table/column or syntax). Use 'List Tables' to see real table names, then 'Self-Heal Last KQL'."
    if "timeout" in low or "timed out" in low or "gatewaytimeout" in low:
        return "The query timed out. Narrow the time range or add a tighter 'where' filter."
    return ""

def execute_kql(law_client, workspace_id, kql, hours=8760, warn=None):
    """Run KQL against a workspace and return rows as a list of dicts.

    `warn(msg)` (optional) is called when Azure returns a PARTIAL result, so the
    analyst knows the row set was truncated instead of silently trusting it."""
    try:
        # Increase limit for manual/custom queries like EXECUTOR.py suggests
        if hours > 8800: hours = 8800

        response = law_client.query_workspace(
            workspace_id=workspace_id,
            query=kql,
            timespan=timedelta(hours=hours)
        )
        if hasattr(response, 'tables'):
            tables = response.tables
        elif hasattr(response, 'partial_data'):
            tables = response.partial_data
            partial_error = getattr(response, "partial_error", None)
            if warn and partial_error:
                warn(f"Warning: Azure returned PARTIAL results (row set may be truncated): {partial_error}")
        else:
            tables = []

        if not tables:
            return []

        table = tables[0]
        columns = [col.name if hasattr(col, 'name') else str(col) for col in table.columns]
        results = [{col: val for col, val in zip(columns, row)} for row in table.rows]
        return results
    except Exception as e:
        raise e

def make_logs_client(tenant_id=""):
    """LogsQueryClient wired to build_azure_credential (one place to change auth)."""
    if not HAS_AZURE:
        raise ImportError("Azure libraries not installed. Run: pip install azure-identity azure-monitor-query")
    return LogsQueryClient(credential=build_azure_credential(tenant_id))

# Tables that hold data in the last year, largest first.
LIST_TABLES_KQL = ("union withsource=TableName * "
                   "| summarize Rows=count(), Latest=max(TimeGenerated) by TableName "
                   "| sort by Rows desc")

def fetch_schema(law_client, workspace_id, tables, max_tables=40, warn=None, should_stop=None):
    """Return {table: [column, ...]} for up to `max_tables` tables using `getschema`
    (a metadata call, so it is cheap even on big tables). Failures on one table are
    reported through `warn` and skipped so one odd table can't sink the whole map."""
    schema = {}
    for name in list(tables)[:max_tables]:
        if should_stop and should_stop():
            break
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", str(name)):
            continue
        try:
            rows = execute_kql(law_client, workspace_id, f"{name} | getschema | project ColumnName, ColumnType", hours=1)
            cols = [str(r.get("ColumnName", "")) for r in rows if r.get("ColumnName")]
            if cols:
                schema[name] = cols
        except Exception as e:
            if warn:
                warn(f"  (schema for {name} skipped: {str(e)[:120]})")
    return schema

def format_schema(known_tables, schema_cache, max_cols=40):
    """Compact text block for the KQL prompt: one line per table that has data,
    with its row count and real column names (truncated)."""
    lines = []
    for t in known_tables or []:
        name = t.get("TableName") if isinstance(t, dict) else str(t)
        rows = t.get("Rows", "") if isinstance(t, dict) else ""
        cols = schema_cache.get(name, [])
        col_txt = ", ".join(cols[:max_cols]) + (", ..." if len(cols) > max_cols else "")
        lines.append(f"- {name} ({rows} rows): {col_txt}" if cols else f"- {name} ({rows} rows)")
    return "\n".join(lines)
