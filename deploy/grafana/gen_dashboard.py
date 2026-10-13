"""Generates deploy/grafana/dashboards/guardrails.json.

The dashboard is generated rather than hand-edited for the same reason the tool
matrix is: a 1,500-line JSON file edited by hand drifts from the metrics it
claims to show, and nobody notices until an incident. Run:

    python deploy/grafana/gen_dashboard.py
"""
import json
import os

PROM = {"type": "prometheus", "uid": "prometheus"}
LOKI = {"type": "loki", "uid": "loki"}

panels = []
_id = [0]
y = [0]


def nid():
    _id[0] += 1
    return _id[0]


def row(title):
    panels.append({"type": "row", "title": title, "id": nid(), "collapsed": False,
                   "gridPos": {"h": 1, "w": 24, "x": 0, "y": y[0]}, "panels": []})
    y[0] += 1


def ts(title, targets, x, w, h=8, unit="short", desc="", stack=False, min0=True):
    p = {
        "type": "timeseries", "title": title, "id": nid(), "datasource": PROM, "description": desc,
        "gridPos": {"h": h, "w": w, "x": x, "y": y[0]},
        "fieldConfig": {"defaults": {"unit": unit, "custom": {"lineWidth": 2, "fillOpacity": 8 if not stack else 60,
                                                                  "stacking": {"mode": "normal" if stack else "none"},
                                                                  "showPoints": "never"},
                                     **({"min": 0} if min0 else {})}, "overrides": []},
        "options": {"legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
        "targets": [{"datasource": PROM, "expr": e, "legendFormat": l, "refId": chr(65 + i)} for i, (e, l) in enumerate(targets)],
    }
    panels.append(p)


def stat(title, expr, x, w, unit="short", desc="", decimals=None, thresholds=None):
    steps = thresholds or [{"color": "text", "value": None}]
    p = {
        "type": "stat", "title": title, "id": nid(), "datasource": PROM, "description": desc,
        "gridPos": {"h": 4, "w": w, "x": x, "y": y[0]},
        "fieldConfig": {"defaults": {"unit": unit, "thresholds": {"mode": "absolute", "steps": steps},
                                     **({"decimals": decimals} if decimals is not None else {})}, "overrides": []},
        "options": {"reduceOptions": {"calcs": ["lastNotNull"]}, "colorMode": "value", "graphMode": "area", "textMode": "auto"},
        "targets": [{"datasource": PROM, "expr": expr, "refId": "A", "instant": False}],
    }
    panels.append(p)


R = "$__rate_interval"

# --- headline -------------------------------------------------------------------
row("Overview")
stat("Requests / s (inbound)", f'sum(rate(guardrails_requests_total{{stage="inbound"}}[{R}]))', 0, 4, "reqps")
stat("Inbound block rate", f'sum(rate(guardrails_requests_total{{stage="inbound",action="block"}}[{R}])) / clamp_min(sum(rate(guardrails_requests_total{{stage="inbound"}}[{R}])), 1e-9)', 4, 4, "percentunit", decimals=1)
stat("Semantic-tier blocks / min", f'sum(rate(guardrails_semantic_tier_decisions_total{{outcome="unsafe"}}[{R}])) * 60', 8, 4, "short", decimals=2)
stat("Model spend / hour", f'sum(rate(guardrails_cost_usd_total[{R}])) * 3600', 12, 4, "currencyUSD", decimals=4)
stat("Cache hit ratio", f'sum(rate(guardrails_cache_lookups_total{{result="hit"}}[{R}])) / clamp_min(sum(rate(guardrails_cache_lookups_total{{kind="exact",result=~"hit|miss"}}[{R}])), 1e-9)', 16, 4, "percentunit", decimals=1)
stat("Guard p99 (inbound)", f'histogram_quantile(0.99, sum by (le) (rate(guardrails_stage_duration_seconds_bucket{{stage="inbound"}}[{R}])))', 20, 4, "s",
     thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 0.025}, {"color": "red", "value": 0.05}],
     desc="Against the 50 ms stage budget.")
y[0] += 4

# --- enforcement -----------------------------------------------------------------
row("Enforcement")
ts("Decisions by stage and action", [(f'sum by (stage, action) (rate(guardrails_requests_total[{R}]))', "{{stage}} · {{action}}")], 0, 12, unit="reqps")
ts("Findings by category", [(f'topk(10, sum by (category, severity) (rate(guardrails_findings_total[{R}])))', "{{category}} ({{severity}})")], 12, 12, unit="reqps")
y[0] += 8
ts("Proxy outcomes", [(f'sum by (outcome) (rate(guardrails_proxy_duration_seconds_count[{R}]))', "{{outcome}}")], 0, 12, unit="reqps", stack=True,
   desc="served, cached, blocked_inbound, blocked_semantic, blocked_outbound, error")
ts("Payload rewrites (redaction, restore)", [(f'sum by (guard, reason) (rate(guardrails_mutations_total[{R}]))', "{{guard}} · {{reason}}")], 12, 12, unit="reqps")
y[0] += 8

# --- latency ------------------------------------------------------------------------
row("Latency: guards vs model")
ts("Guard overhead per stage (p50 / p99)", [
    (f'histogram_quantile(0.5, sum by (le, stage) (rate(guardrails_stage_duration_seconds_bucket[{R}])))', "p50 {{stage}}"),
    (f'histogram_quantile(0.99, sum by (le, stage) (rate(guardrails_stage_duration_seconds_bucket[{R}])))', "p99 {{stage}}"),
], 0, 8, unit="s")
ts("Slowest guards (p99)", [(f'topk(6, histogram_quantile(0.99, sum by (le, guard) (rate(guardrails_guard_duration_seconds_bucket[{R}]))))', "{{guard}}")], 8, 8, unit="s")
ts("Upstream latency by route (p50 / p95)", [
    (f'histogram_quantile(0.5, sum by (le, route) (rate(guardrails_upstream_duration_seconds_bucket[{R}])))', "p50 {{route}}"),
    (f'histogram_quantile(0.95, sum by (le, route) (rate(guardrails_upstream_duration_seconds_bucket[{R}])))', "p95 {{route}}"),
], 16, 8, unit="s")
y[0] += 8
ts("End-to-end proxy latency by outcome (p50 / p95)", [
    (f'histogram_quantile(0.5, sum by (le, outcome) (rate(guardrails_proxy_duration_seconds_bucket[{R}])))', "p50 {{outcome}}"),
    (f'histogram_quantile(0.95, sum by (le, outcome) (rate(guardrails_proxy_duration_seconds_bucket[{R}])))', "p95 {{outcome}}"),
], 0, 12, unit="s")
ts("Semantic classifier latency (p50 / p95)", [
    (f'histogram_quantile(0.5, sum by (le, classifier) (rate(guardrails_judge_duration_seconds_bucket[{R}])))', "p50 {{classifier}}"),
    (f'histogram_quantile(0.95, sum by (le, classifier) (rate(guardrails_judge_duration_seconds_bucket[{R}])))', "p95 {{classifier}}"),
], 12, 12, unit="s")
y[0] += 8

# --- providers -----------------------------------------------------------------------
row("Providers and resilience")
ts("Upstream calls by provider and outcome", [(f'sum by (provider, outcome) (rate(guardrails_upstream_requests_total[{R}]))', "{{provider}} · {{outcome}}")], 0, 8, unit="reqps")
ts("Fallback attempts", [(f'sum by (route, outcome) (rate(guardrails_upstream_fallbacks_total[{R}]))', "{{route}} · {{outcome}}")], 8, 8, unit="reqps")
ts("Circuit breakers open", [('max by (upstream) (guardrails_circuit_open)', "{{upstream}}")], 16, 8, unit="bool", desc="1 = open or half-open")
y[0] += 8

# --- cost --------------------------------------------------------------------------------
row("Cost and efficiency")
ts("Spend per hour by model", [(f'sum by (model) (rate(guardrails_cost_usd_total[{R}])) * 3600', "{{model}}")], 0, 8, unit="currencyUSD", stack=True)
ts("Tokens / s by model", [(f'sum by (model, kind) (rate(guardrails_tokens_total[{R}]))', "{{model}} · {{kind}}")], 8, 8)
ts("Cache lookups and savings", [
    (f'sum by (kind, result) (rate(guardrails_cache_lookups_total[{R}]))', "{{kind}} · {{result}}"),
    (f'sum(rate(guardrails_cache_saved_usd_total[{R}])) * 3600', "saved $/h"),
], 16, 8)
y[0] += 8

# --- semantic tier ------------------------------------------------------------------------
row("Semantic tier")
ts("Classifier calls by verdict", [(f'sum by (classifier, verdict) (rate(guardrails_judge_calls_total[{R}]))', "{{classifier}} · {{verdict}}")], 0, 8, unit="reqps")
ts("Escalation decisions", [(f'sum by (reason, outcome) (rate(guardrails_semantic_tier_decisions_total[{R}]))', "{{reason}} → {{outcome}}")], 8, 8, unit="reqps",
   desc="Why the tier did or did not call a classifier, and what it decided.")
ts("Tier disagreements", [(f'sum by (direction) (rate(guardrails_semantic_tier_disagreements_total[{R}]))', "{{direction}}")], 16, 8, unit="reqps",
   desc="judge_only: coverage the rules lack. heuristic_only: candidate false positives of the rules.")
y[0] += 8

# --- tool calls / MCP ---------------------------------------------------------------------
row("Tool calls and MCP")
ts("Tool calls by outcome", [(f'sum by (status) (rate(guardrails_tool_calls_total[{R}]))', "{{status}}")], 0, 8, unit="reqps", stack=True,
   desc="Every brokered call: executed, refused, held for approval, quarantined, or result withheld.")
ts("Tool calls by risk tier", [(f'sum by (tier) (rate(guardrails_tool_calls_total[{R}]))', "{{tier}}")], 8, 8, unit="reqps")
ts("MCP tools quarantined", [('sum by (server, reason) (guardrails_mcp_quarantined_total)', "{{server}} · {{reason}}")], 16, 8,
   desc="Poisoned definitions, shadowing and rug pulls withheld from agents.")
y[0] += 8

# --- health ------------------------------------------------------------------------------------
row("Health")
ts("Guard errors (coverage lost)", [(f'sum by (guard, kind, fail_mode) (rate(guardrails_guard_errors_total[{R}]))', "{{guard}} {{kind}} ({{fail_mode}})")], 0, 8, unit="reqps")
ts("Degraded decisions", [(f'sum by (stage) (rate(guardrails_degraded_decisions_total[{R}]))', "{{stage}}")], 8, 8, unit="reqps")
ts("Budget breaches", [(f'rate(guardrails_budget_breaches_total[{R}])', "breaches")], 16, 8, unit="reqps")
y[0] += 8

# --- logs ----------------------------------------------------------------------------------------
row("Audit log")
panels.append({
    "type": "logs", "title": "Blocked and redacted decisions (click a trace_id to open the trace)", "id": nid(), "datasource": LOKI,
    "gridPos": {"h": 12, "w": 24, "x": 0, "y": y[0]},
    "options": {"showTime": True, "wrapLogMessage": True, "prettifyLogMessage": False, "enableLogDetails": True, "sortOrder": "Descending"},
    "targets": [{"datasource": LOKI, "refId": "A",
                 "expr": '{job="guardrails"} | json | event=~"guardrail.decision|guardrail.semantic|guardrail.tool_execution|guardrail.tool_call" '}],
})
y[0] += 12

dash = {
    "uid": "guardrails-overview", "title": "Guardrails Gateway", "tags": ["guardrails", "llm"],
    "timezone": "browser", "schemaVersion": 39, "version": 1, "refresh": "10s",
    "time": {"from": "now-30m", "to": "now"}, "panels": panels,
    "annotations": {"list": []}, "templating": {"list": []},
}
out = os.path.join(os.path.dirname(__file__), "dashboards", "guardrails.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(dash, f, indent=2)
print("wrote", out, len(panels), "panels")
