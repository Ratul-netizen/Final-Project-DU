#!/usr/bin/env python3
"""
Reporting utilities for generating colorful, detailed vulnerability reports

Design goals:
- NEVER break runtime if optional deps are missing
- Prefer PDF via pdfkit (wkhtmltopdf) or WeasyPrint when available
- Fallback to HTML download when PDF generation is unavailable
"""
from __future__ import annotations

import io
import os
import base64
import logging
from datetime import datetime
from typing import Any, Dict, List, Tuple

from flask import render_template

# Import dashboard at runtime (same module used by c2_server)
from vulnerability_dashboard import dashboard


def _safe_import_matplotlib():
    try:
        import matplotlib
        matplotlib.use("Agg")  # Headless backend
        import matplotlib.pyplot as plt
        return plt
    except Exception as e:
        logging.warning(f"Matplotlib not available for charts: {e}")
        return None


def _b64_png(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=170)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()


def build_context(filters: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Assemble data for the vulnerability report from the processed dashboard store."""
    filters = filters or {}

    dash = dashboard.get_dashboard_data() or {}
    vulns: List[Dict[str, Any]] = dashboard.get_vulnerabilities() or []
    scans = list(getattr(dashboard, "scans", {}).values())

    # Filter by agent_id(s)
    agent_filter = set()
    if filters.get("agent_id"):
        # comma-separated list allowed
        agent_filter = {a.strip() for a in str(filters["agent_id"]).split(",") if a.strip()}
        if agent_filter:
            vulns = [v for v in vulns if v.get("agent_id") in agent_filter]
            scans = [s for s in scans if s.get("agent_id") in agent_filter]

    # Compute severity counts
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for v in vulns:
        sev = v.get("severity", "Low")
        if sev in sev_counts:
            sev_counts[sev] += 1

    # Top findings (critical/high first)
    priority_order = {"Critical": 3, "High": 2, "Medium": 1, "Low": 0}
    top_findings = sorted(
        vulns,
        key=lambda v: (priority_order.get(v.get("severity", "Low"), 0), v.get("cve", "")),
        reverse=True,
    )[:15]

    # Per-agent summary
    per_agent: Dict[str, Dict[str, Any]] = {}
    for v in vulns:
        aid = v.get("agent_id")
        if not aid:
            continue
        per_agent.setdefault(aid, {"id": aid, "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}, "vulns": 0})
        per_agent[aid]["vulns"] += 1
        sev = v.get("severity", "Low")
        if sev in per_agent[aid]["counts"]:
            per_agent[aid]["counts"][sev] += 1

    # Risk score trend (from scans)
    trend: List[Tuple[str, float]] = []
    for s in sorted(scans, key=lambda x: x.get("timestamp", ""))[-30:]:
        ts = s.get("timestamp")
        trend.append((ts, float(s.get("risk_score", 0))))

    ctx: Dict[str, Any] = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "filters": filters,
        "summary": dash.get("summary", {}),
        "vuln_counts": sev_counts,
        "top_findings": top_findings,
        "per_agent": list(per_agent.values()),
        "findings": vulns,
        "scan_history": scans,
        "trend": trend,
    }
    return ctx


def add_charts_to_context(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Generate PNG charts (base64) and attach to context. Safe to skip if deps missing."""
    plt = _safe_import_matplotlib()
    if not plt:
        return ctx

    # Severity distribution
    labels = ["Critical", "High", "Medium", "Low"]
    values = [ctx["vuln_counts"].get(k, 0) for k in labels]
    if sum(values) > 0:
        fig, ax = plt.subplots(figsize=(4.2, 4.2))
        colors = ["#ef4444", "#ff6b35", "#f59e0b", "#06b6d4"]
        ax.pie(values, labels=labels, colors=colors, autopct="%1.0f%%", startangle=140, textprops={"color": "#1e293b"})
        ax.axis("equal")
        ctx["chart_severity"] = _b64_png(fig)
        plt.close(fig)

    # CVE by year
    year_counts: Dict[str, int] = {}
    for v in ctx.get("findings", []):
        cve = v.get("cve", "")
        if cve.startswith("CVE-"):
            y = cve.split("-")[1]
            if len(y) == 4 and y.isdigit():
                year_counts[y] = year_counts.get(y, 0) + 1
    if year_counts:
        years = sorted(year_counts.keys())[-6:]
        values = [year_counts[y] for y in years]
        fig, ax = plt.subplots(figsize=(5.5, 3.2))
        ax.bar(years, values, color="#2563eb")
        ax.set_title("CVEs by Year")
        ax.set_ylabel("Count")
        for i, v in enumerate(values):
            ax.text(i, v + 0.05, str(v), ha="center", color="#e5e7eb")
        ctx["chart_cve_year"] = _b64_png(fig)
        plt.close(fig)

    # Risk trend
    if ctx.get("trend"):
        xs = [t[0] for t in ctx["trend"]]
        ys = [t[1] for t in ctx["trend"]]
        fig, ax = plt.subplots(figsize=(6.0, 3.0))
        ax.plot(xs, ys, color="#f59e0b")
        ax.fill_between(range(len(ys)), ys, color="#f59e0b", alpha=0.15)
        ax.set_ylim(0, 100)
        ax.set_title("Risk Score Trend")
        ax.set_ylabel("Risk Score")
        ax.tick_params(axis='x', labelrotation=45)
        ctx["chart_risk_trend"] = _b64_png(fig)
        plt.close(fig)

    return ctx


def render_report_html(ctx: Dict[str, Any]) -> str:
    """Render the HTML report using the Jinja2 template."""
    # Ensure charts present when possible
    ctx = add_charts_to_context(ctx)
    html = render_template("report_vulnerabilities.html", **ctx)
    return html


def _try_pdfkit(html: str) -> bytes | None:
    try:
        import pdfkit  # type: ignore
        config = None
        bin_path = os.environ.get("WKHTMLTOPDF_BIN")
        if bin_path and os.path.isfile(bin_path):
            config = pdfkit.configuration(wkhtmltopdf=bin_path)
        pdf_bytes = pdfkit.from_string(html, False, configuration=config)
        return pdf_bytes
    except Exception as e:
        logging.warning(f"pdfkit generation failed: {e}")
        return None


def _try_weasyprint(html: str) -> bytes | None:
    try:
        from weasyprint import HTML  # type: ignore
        pdf_bytes = HTML(string=html).write_pdf()
        return pdf_bytes
    except Exception as e:
        logging.warning(f"WeasyPrint generation failed: {e}")
        return None


def generate_pdf_or_html(filters: Dict[str, Any] | None = None) -> Tuple[str, bytes, str]:
    """
    Returns a tuple: (filename, data, mimetype)
    - Prefer PDF (application/pdf). Fallback: HTML (text/html; charset=utf-8)
    """
    ctx = build_context(filters)
    html = render_report_html(ctx)

    # Attempt PDF generation via pdfkit, then WeasyPrint
    for producer in (_try_pdfkit, _try_weasyprint):
        pdf = producer(html)
        if pdf:
            fname = f"Vulnerability_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
            return fname, pdf, "application/pdf"

    # Fallback to HTML
    fname = f"Vulnerability_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.html"
    return fname, html.encode("utf-8"), "text/html; charset=utf-8"


