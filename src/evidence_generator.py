"""
Evidence package generator.
Produces audit-ready evidence bundles (JSON + CSV + HTML manifest)
that can be provided directly to auditors for SOC 2, PCI DSS, or ISO 27001 reviews.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pandas as pd
import yaml


def _load_config() -> dict:
    path = Path(__file__).parent.parent / "config" / "controls.yaml"
    with open(path) as f:
        return yaml.safe_load(f)


def _ts() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def generate_evidence_package(
    findings: pd.DataFrame,
    employees: pd.DataFrame,
    access: pd.DataFrame,
    summary: dict,
    output_dir: str | Path,
) -> Path:
    """
    Create a timestamped evidence package directory containing:
      - findings.json / findings.csv
      - access_snapshot.csv
      - employee_snapshot.csv
      - summary.json
      - manifest.html (human-readable index)
    Returns the path to the package directory.
    """
    config = _load_config()
    ts = _ts()
    pkg_dir = Path(output_dir) / f"evidence_package_{ts}"
    pkg_dir.mkdir(parents=True, exist_ok=True)

    # 1. Findings
    findings.to_csv(pkg_dir / "findings.csv", index=False)
    findings.to_json(pkg_dir / "findings.json", orient="records", indent=2, default_handler=str)

    # 2. Access snapshot (active only, no sensitive fields)
    access_snap = access[access["is_active"]].copy()
    access_snap.to_csv(pkg_dir / "access_snapshot.csv", index=False)

    # 3. Employee snapshot (status fields only — no PII beyond name/dept)
    emp_snap = employees[["employee_id", "full_name", "department", "title", "status", "hire_date", "termination_date"]].copy()
    emp_snap.to_csv(pkg_dir / "employee_snapshot.csv", index=False)

    # 4. Summary JSON
    meta = {
        "package_id":       f"EVD-{ts}",
        "generated_at":     datetime.now().isoformat(),
        "generated_by":     "GRC Control Automation Platform v1.0",
        "control_id":       config["control"]["id"],
        "control_name":     config["control"]["name"],
        "review_period":    "Continuous — Snapshot as of " + datetime.now().strftime("%Y-%m-%d"),
        "frameworks":       config["company"]["compliance_frameworks"],
        "summary":          summary,
    }
    with open(pkg_dir / "summary.json", "w") as f:
        json.dump(meta, f, indent=2, default=str)

    # 5. HTML manifest
    manifest_html = _build_manifest_html(meta, findings)
    (pkg_dir / "manifest.html").write_text(manifest_html, encoding="utf-8")

    return pkg_dir


def _build_manifest_html(meta: dict, findings: pd.DataFrame) -> str:
    summary = meta["summary"]
    now_str = meta["generated_at"]
    findings_html = ""
    if not findings.empty:
        top = findings.head(20)
        rows = ""
        for _, r in top.iterrows():
            band_colors = {"CRITICAL": "#d32f2f", "HIGH": "#f57c00", "MEDIUM": "#f9a825", "LOW": "#388e3c"}
            color = band_colors.get(r["severity"], "#666")
            rows += f"""
            <tr>
              <td>{r['finding_id']}</td>
              <td><span style="color:{color};font-weight:600">{r['severity']}</span></td>
              <td>{r['finding_type'].replace('_', ' ')}</td>
              <td>{r['employee_name']}</td>
              <td>{r['department']}</td>
              <td>{r['system_name']}</td>
              <td>{r['risk_score']}</td>
              <td style="font-size:0.85em;max-width:320px">{r['detail']}</td>
            </tr>"""
        findings_html = f"""
        <table>
          <thead>
            <tr>
              <th>Finding ID</th><th>Severity</th><th>Type</th><th>Employee</th>
              <th>Department</th><th>System</th><th>Risk Score</th><th>Detail</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Evidence Package — {meta['package_id']}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            margin: 0; background: #f4f6f8; color: #1a1a2e; }}
    .header {{ background: linear-gradient(135deg, #1e3a5f 0%, #2563eb 100%);
               color: white; padding: 40px 48px; }}
    .header h1 {{ margin: 0 0 8px; font-size: 1.8em; font-weight: 700; }}
    .header p {{ margin: 0; opacity: 0.85; font-size: 0.95em; }}
    .badge {{ display:inline-block; background:rgba(255,255,255,0.2);
              border-radius:20px; padding:4px 14px; font-size:0.8em; margin-top:12px; }}
    .content {{ padding: 40px 48px; }}
    .meta-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 36px; }}
    .meta-card {{ background: white; border-radius: 10px; padding: 20px 24px;
                  box-shadow: 0 2px 8px rgba(0,0,0,0.07); }}
    .meta-card .label {{ font-size: 0.78em; color: #6b7280; text-transform: uppercase;
                          letter-spacing: .06em; margin-bottom: 6px; }}
    .meta-card .value {{ font-size: 1.4em; font-weight: 700; color: #1e3a5f; }}
    .meta-card .sub {{ font-size: 0.82em; color: #6b7280; margin-top: 2px; }}
    .critical .value {{ color: #d32f2f; }}
    .high .value {{ color: #f57c00; }}
    .section {{ background: white; border-radius: 10px; padding: 28px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.07); margin-bottom: 28px; }}
    .section h2 {{ margin: 0 0 20px; font-size: 1.1em; color: #1e3a5f;
                   border-bottom: 2px solid #e8edf5; padding-bottom: 12px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.88em; }}
    th {{ background: #f0f4ff; color: #1e3a5f; text-align: left;
          padding: 10px 12px; font-size: 0.8em; text-transform: uppercase; letter-spacing:.04em; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }}
    tr:hover td {{ background: #fafbff; }}
    .files-list {{ list-style: none; padding: 0; margin: 0; }}
    .files-list li {{ padding: 10px 0; border-bottom: 1px solid #f0f0f0;
                      display: flex; align-items: center; gap: 10px; }}
    .files-list li:last-child {{ border-bottom: none; }}
    .file-icon {{ font-size: 1.2em; }}
    .footer {{ text-align: center; padding: 24px; font-size: 0.82em; color: #9ca3af; }}
    .framework-badge {{ display:inline-block; background:#e8f0fe; color:#1e3a5f;
                         border-radius:4px; padding:3px 10px; font-size:0.8em; margin:3px; }}
  </style>
</head>
<body>
<div class="header">
  <h1>📋 Audit Evidence Package</h1>
  <p>GRC Control Automation Platform — DataStream Technologies</p>
  <div class="badge">Package ID: {meta['package_id']}</div>
  <div class="badge" style="margin-left:8px">Generated: {now_str[:19]}</div>
</div>

<div class="content">

  <div class="meta-grid">
    <div class="meta-card">
      <div class="label">Control</div>
      <div class="value" style="font-size:1em">{meta['control_name']}</div>
      <div class="sub">{meta['control_id']}</div>
    </div>
    <div class="meta-card">
      <div class="label">Review Period</div>
      <div class="value" style="font-size:1em">{meta['review_period']}</div>
    </div>
    <div class="meta-card">
      <div class="label">Total Findings</div>
      <div class="value">{summary.get('total_findings', 0)}</div>
      <div class="sub">across {summary.get('affected_systems', 0)} systems</div>
    </div>
    <div class="meta-card critical">
      <div class="label">Critical Findings</div>
      <div class="value">{summary.get('critical_findings', 0)}</div>
      <div class="sub">SLA: 24–48 hours</div>
    </div>
    <div class="meta-card high">
      <div class="label">High Findings</div>
      <div class="value">{summary.get('high_findings', 0)}</div>
      <div class="sub">SLA: 72 hours</div>
    </div>
    <div class="meta-card">
      <div class="label">Affected Employees</div>
      <div class="value">{summary.get('affected_employees', 0)}</div>
      <div class="sub">of {summary.get('active_employees', 0)} active</div>
    </div>
  </div>

  <div class="section">
    <h2>Compliance Frameworks</h2>
    {"".join(f'<span class="framework-badge">{fw}</span>' for fw in meta['frameworks'])}
  </div>

  <div class="section">
    <h2>Top 20 Findings (by Risk Score)</h2>
    {findings_html if findings_html else "<p style='color:#6b7280'>No findings.</p>"}
  </div>

  <div class="section">
    <h2>Package Contents</h2>
    <ul class="files-list">
      <li><span class="file-icon">📄</span> <strong>findings.json</strong> — Machine-readable findings in JSON format</li>
      <li><span class="file-icon">📊</span> <strong>findings.csv</strong> — Findings export for spreadsheet review</li>
      <li><span class="file-icon">👥</span> <strong>employee_snapshot.csv</strong> — Employee status at time of review</li>
      <li><span class="file-icon">🔐</span> <strong>access_snapshot.csv</strong> — All active access rights at time of review</li>
      <li><span class="file-icon">📋</span> <strong>summary.json</strong> — Aggregated metrics and package metadata</li>
      <li><span class="file-icon">🌐</span> <strong>manifest.html</strong> — This human-readable index</li>
    </ul>
  </div>

</div>
<div class="footer">
  Generated by GRC Control Automation Platform v1.0 &nbsp;·&nbsp; DataStream Technologies &nbsp;·&nbsp; {now_str[:10]}
</div>
</body>
</html>"""
