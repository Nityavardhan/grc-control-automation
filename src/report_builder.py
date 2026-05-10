"""
HTML executive report builder.
Produces a polished, printable HTML report suitable for management review
or direct submission to auditors.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd


def build_html_report(
    findings: pd.DataFrame,
    summary: dict,
    output_path: str | Path,
) -> Path:
    """Build and save the HTML executive report. Returns the output path."""
    html = _render(findings, summary)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    return out


def _severity_badge(severity: str) -> str:
    colors = {
        "CRITICAL": ("#fff0f0", "#d32f2f"),
        "HIGH":     ("#fff8e1", "#f57c00"),
        "MEDIUM":   ("#fffde7", "#f9a825"),
        "LOW":      ("#f1f8e9", "#388e3c"),
    }
    bg, fg = colors.get(severity, ("#f5f5f5", "#666"))
    return f'<span style="background:{bg};color:{fg};padding:3px 10px;border-radius:12px;font-size:0.8em;font-weight:600">{severity}</span>'


def _render(findings: pd.DataFrame, summary: dict) -> str:
    now = datetime.now().strftime("%B %d, %Y at %H:%M")
    total = summary.get("total_findings", 0)
    critical = summary.get("critical_findings", 0)
    high = summary.get("high_findings", 0)
    medium = summary.get("medium_findings", 0)
    low = summary.get("low_findings", 0)
    avg_risk = summary.get("avg_risk_score", 0)
    compliance_rate = summary.get("compliance_rate", 0)
    affected_employees = summary.get("affected_employees", 0)
    active_employees = summary.get("active_employees", 0)
    affected_systems = summary.get("affected_systems", 0)

    # Finding type summary rows
    type_rows = ""
    for finding_type, count in summary.get("by_type", {}).items():
        type_rows += f"<tr><td>{finding_type.replace('_', ' ')}</td><td>{count}</td></tr>"

    # Department rows
    dept_rows = ""
    for dept, count in list(summary.get("by_department", {}).items())[:8]:
        dept_rows += f"<tr><td>{dept}</td><td>{count}</td></tr>"

    # Findings table
    finding_rows = ""
    if not findings.empty:
        for _, r in findings.iterrows():
            finding_rows += f"""
            <tr>
              <td style="font-family:monospace;font-size:0.85em">{r['finding_id']}</td>
              <td>{_severity_badge(r['severity'])}</td>
              <td style="font-size:0.85em">{r['finding_type'].replace('_', ' ')}</td>
              <td>{r['employee_name']}</td>
              <td>{r['department']}</td>
              <td>{r['system_name']}</td>
              <td style="font-weight:600;color:#1e3a5f">{r['risk_score']}</td>
              <td style="font-size:0.82em;color:#6b7280;max-width:280px">{r['detail'][:120]}{'…' if len(str(r['detail'])) > 120 else ''}</td>
            </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Privileged Access Review — Executive Report</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f4f6f8; color: #1a1a2e; font-size: 14px; line-height: 1.6; }}

    /* Header */
    .report-header {{
      background: linear-gradient(135deg, #1e3a5f 0%, #1565c0 60%, #2196f3 100%);
      color: white; padding: 48px 56px;
    }}
    .report-header .company {{ font-size: 0.9em; opacity: 0.75; letter-spacing: .08em;
                               text-transform: uppercase; margin-bottom: 12px; }}
    .report-header h1 {{ font-size: 2em; font-weight: 700; margin-bottom: 8px; }}
    .report-header .subtitle {{ opacity: 0.85; font-size: 1em; }}
    .report-header .meta {{ margin-top: 24px; display: flex; gap: 32px; }}
    .report-header .meta span {{ background: rgba(255,255,255,0.15);
                                  border-radius: 20px; padding: 5px 16px; font-size: 0.82em; }}

    /* Layout */
    .page {{ max-width: 1200px; margin: 0 auto; padding: 40px 48px; }}

    /* KPI row */
    .kpi-grid {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 16px;
                 margin-bottom: 36px; }}
    .kpi {{ background: white; border-radius: 12px; padding: 20px;
             box-shadow: 0 2px 10px rgba(0,0,0,0.07); text-align: center;
             border-top: 3px solid #e8edf5; }}
    .kpi.critical {{ border-top-color: #d32f2f; }}
    .kpi.high {{ border-top-color: #f57c00; }}
    .kpi.medium {{ border-top-color: #f9a825; }}
    .kpi.low {{ border-top-color: #388e3c; }}
    .kpi.neutral {{ border-top-color: #2196f3; }}
    .kpi .label {{ font-size: 0.72em; color: #6b7280; text-transform: uppercase;
                   letter-spacing: .06em; margin-bottom: 8px; }}
    .kpi .value {{ font-size: 2em; font-weight: 700; color: #1e3a5f; }}
    .kpi.critical .value {{ color: #d32f2f; }}
    .kpi.high .value {{ color: #f57c00; }}
    .kpi.medium .value {{ color: #b45309; }}

    /* Sections */
    .section {{ background: white; border-radius: 12px; padding: 28px 32px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.07); margin-bottom: 28px; }}
    .section h2 {{ font-size: 1.1em; color: #1e3a5f; font-weight: 600;
                   border-bottom: 2px solid #e8edf5; padding-bottom: 14px; margin-bottom: 20px; }}
    .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}

    /* Tables */
    table {{ width: 100%; border-collapse: collapse; }}
    th {{ background: #f0f4ff; color: #1e3a5f; text-align: left;
          padding: 10px 14px; font-size: 0.78em; text-transform: uppercase; letter-spacing:.05em;
          border-bottom: 2px solid #d0dcf5; }}
    td {{ padding: 10px 14px; border-bottom: 1px solid #f0f2f5; vertical-align: top; }}
    tr:hover td {{ background: #fafbff; }}

    /* Risk bar */
    .risk-bar {{ display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }}
    .risk-bar .label {{ min-width: 80px; font-size: 0.85em; color: #6b7280; }}
    .risk-bar .bar-track {{ flex: 1; background: #e8edf5; border-radius: 6px; height: 8px; }}
    .risk-bar .bar-fill {{ border-radius: 6px; height: 8px; }}
    .risk-bar .count {{ min-width: 30px; text-align: right; font-size: 0.85em;
                        font-weight: 600; color: #1e3a5f; }}

    /* Footer */
    footer {{ text-align: center; padding: 32px; font-size: 0.8em; color: #9ca3af; }}

    @media print {{
      body {{ background: white; }}
      .kpi-grid {{ grid-template-columns: repeat(3, 1fr); }}
      .two-col {{ grid-template-columns: 1fr; }}
    }}
  </style>
</head>
<body>

<div class="report-header">
  <div class="company">DataStream Technologies — GRC Control Automation Platform</div>
  <h1>Privileged Access Review</h1>
  <div class="subtitle">Automated Control Assessment — SOC 2 | PCI DSS | ISO 27001</div>
  <div class="meta">
    <span>📅 {now}</span>
    <span>🔒 Control ID: CTRL-IAM-001</span>
    <span>🔄 Continuous Monitoring</span>
  </div>
</div>

<div class="page">

  <!-- KPIs -->
  <div class="kpi-grid" style="margin-top:36px">
    <div class="kpi critical">
      <div class="label">Critical</div>
      <div class="value">{critical}</div>
    </div>
    <div class="kpi high">
      <div class="label">High</div>
      <div class="value">{high}</div>
    </div>
    <div class="kpi medium">
      <div class="label">Medium</div>
      <div class="value">{medium}</div>
    </div>
    <div class="kpi low">
      <div class="label">Low</div>
      <div class="value">{low}</div>
    </div>
    <div class="kpi neutral">
      <div class="label">Avg Risk</div>
      <div class="value">{avg_risk}</div>
    </div>
    <div class="kpi neutral">
      <div class="label">Compliance %</div>
      <div class="value">{compliance_rate}%</div>
    </div>
  </div>

  <!-- Coverage -->
  <div class="section">
    <h2>Review Coverage</h2>
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:20px;text-align:center">
      <div>
        <div style="font-size:2em;font-weight:700;color:#1e3a5f">{active_employees}</div>
        <div style="font-size:0.82em;color:#6b7280">Active Employees</div>
      </div>
      <div>
        <div style="font-size:2em;font-weight:700;color:#1e3a5f">{summary.get('total_access_records', 0)}</div>
        <div style="font-size:0.82em;color:#6b7280">Access Records Reviewed</div>
      </div>
      <div>
        <div style="font-size:2em;font-weight:700;color:#d32f2f">{affected_employees}</div>
        <div style="font-size:0.82em;color:#6b7280">Employees with Findings</div>
      </div>
      <div>
        <div style="font-size:2em;font-weight:700;color:#f57c00">{affected_systems}</div>
        <div style="font-size:0.82em;color:#6b7280">Systems with Findings</div>
      </div>
    </div>
  </div>

  <!-- Breakdown tables -->
  <div class="two-col">
    <div class="section">
      <h2>Findings by Type</h2>
      <table>
        <thead><tr><th>Finding Type</th><th>Count</th></tr></thead>
        <tbody>{type_rows}</tbody>
      </table>
    </div>
    <div class="section">
      <h2>Findings by Department</h2>
      <table>
        <thead><tr><th>Department</th><th>Count</th></tr></thead>
        <tbody>{dept_rows}</tbody>
      </table>
    </div>
  </div>

  <!-- Findings table -->
  <div class="section">
    <h2>All Findings — Sorted by Risk Score</h2>
    <div style="overflow-x:auto">
      <table>
        <thead>
          <tr>
            <th>Finding ID</th><th>Severity</th><th>Type</th><th>Employee</th>
            <th>Department</th><th>System</th><th>Risk</th><th>Detail</th>
          </tr>
        </thead>
        <tbody>{finding_rows}</tbody>
      </table>
    </div>
  </div>

</div>

<footer>
  GRC Control Automation Platform v1.0 &nbsp;·&nbsp; DataStream Technologies &nbsp;·&nbsp;
  Frameworks: SOC 2 Type II · PCI DSS v4.0 · ISO 27001:2022 &nbsp;·&nbsp;
  This report is confidential and intended for authorized personnel only.
</footer>
</body>
</html>"""
