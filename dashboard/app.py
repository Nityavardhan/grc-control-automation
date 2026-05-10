"""
GRC Control Automation — Streamlit Dashboard
DataStream Technologies · Privileged Access Review
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow imports from project root
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.control_engine import compute_summary, run_all_rules
from src.data_generator import generate_all
from src.evidence_generator import generate_evidence_package
from src.report_builder import build_html_report
from src.risk_scorer import BAND_COLORS, BAND_ORDER

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="GRC Control Automation | DataStream Technologies",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────

st.markdown("""
<style>
  /* Global */
  [data-testid="stAppViewContainer"] { background: #f0f4f8; }
  [data-testid="stSidebar"] {
    background: linear-gradient(180deg, #1e3a5f 0%, #1a2d4e 100%);
  }
  [data-testid="stSidebar"] * { color: #e2e8f0 !important; }
  [data-testid="stSidebar"] .stSelectbox label,
  [data-testid="stSidebar"] .stMultiSelect label { color: #94a3b8 !important; font-size:0.8em; }

  /* Hide default Streamlit chrome */
  #MainMenu { visibility: hidden; }
  footer { visibility: hidden; }
  header { visibility: hidden; }

  /* Metric cards */
  [data-testid="metric-container"] {
    background: white;
    border-radius: 12px;
    padding: 18px 22px !important;
    box-shadow: 0 2px 12px rgba(0,0,0,0.06);
    border-left: 4px solid #2196f3;
  }
  [data-testid="stMetricLabel"] { font-size: 0.78em !important; color: #6b7280 !important; text-transform: uppercase; letter-spacing: .05em; }
  [data-testid="stMetricValue"] { font-size: 2em !important; font-weight: 700 !important; color: #1e3a5f !important; }
  [data-testid="stMetricDelta"] { font-size: 0.82em !important; }

  /* Section headers */
  .section-header {
    font-size: 1.05em; font-weight: 600; color: #1e3a5f;
    border-bottom: 2px solid #e2e8f0; padding-bottom: 10px;
    margin: 28px 0 18px; letter-spacing: .01em;
  }

  /* Severity pills */
  .pill {
    display: inline-block; border-radius: 20px;
    padding: 3px 12px; font-size: 0.78em; font-weight: 700;
    letter-spacing: .04em;
  }
  .pill-CRITICAL { background:#fff0f0; color:#d32f2f; }
  .pill-HIGH     { background:#fff8e1; color:#f57c00; }
  .pill-MEDIUM   { background:#fffde7; color:#b45309; }
  .pill-LOW      { background:#f1f8e9; color:#388e3c; }

  /* Dataframe */
  [data-testid="stDataFrame"] { border-radius: 10px; overflow: hidden; }

  /* Tabs */
  [data-testid="stTabs"] [role="tab"] {
    font-size: 0.9em; font-weight: 600; color: #6b7280;
  }
  [data-testid="stTabs"] [role="tab"][aria-selected="true"] {
    color: #1e3a5f; border-bottom: 3px solid #2196f3;
  }

  /* Info box */
  .info-box {
    background: #e8f4fd; border-left: 4px solid #2196f3;
    border-radius: 0 8px 8px 0; padding: 14px 18px;
    font-size: 0.9em; color: #1565c0; margin-bottom: 16px;
  }
  .warn-box {
    background: #fff8e1; border-left: 4px solid #f9a825;
    border-radius: 0 8px 8px 0; padding: 14px 18px;
    font-size: 0.9em; color: #7c5500; margin-bottom: 16px;
  }
  .danger-box {
    background: #fff0f0; border-left: 4px solid #d32f2f;
    border-radius: 0 8px 8px 0; padding: 14px 18px;
    font-size: 0.9em; color: #b71c1c; margin-bottom: 16px;
  }
</style>
""", unsafe_allow_html=True)


# ── Data loading (cached) ─────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def load_data() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame, dict]:
    datasets = generate_all(seed=42)
    employees = datasets["employees"]
    access    = datasets["access_rights"]
    systems   = datasets["systems"]
    findings  = run_all_rules(employees, access)
    summary   = compute_summary(findings, employees, access)
    return employees, access, systems, findings, summary


# ── Sidebar ───────────────────────────────────────────────────────────────────

def render_sidebar(findings: pd.DataFrame) -> dict:
    with st.sidebar:
        st.markdown("""
        <div style="padding:20px 0 24px; text-align:center">
          <div style="font-size:2em">🔒</div>
          <div style="font-size:1.05em;font-weight:700;color:#e2e8f0;margin-top:6px">
            GRC Automation
          </div>
          <div style="font-size:0.78em;color:#94a3b8;margin-top:2px">
            DataStream Technologies
          </div>
        </div>
        <hr style="border-color:#334155;margin-bottom:20px">
        """, unsafe_allow_html=True)

        page = st.radio(
            "Navigation",
            ["Executive Dashboard", "Findings Explorer", "Access Inventory", "Control Configuration", "Evidence Packages"],
            label_visibility="collapsed",
        )

        st.markdown("<hr style='border-color:#334155;margin:20px 0'>", unsafe_allow_html=True)

        # Filters (only relevant for findings pages)
        filters: dict = {}
        if not findings.empty:
            st.markdown("<div style='font-size:0.78em;color:#94a3b8;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px'>Filters</div>", unsafe_allow_html=True)

            severity_opts = ["All"] + sorted(findings["severity"].unique().tolist(), key=lambda x: BAND_ORDER.index(x) if x in BAND_ORDER else 99)
            filters["severity"] = st.selectbox("Severity", severity_opts)

            dept_opts = ["All"] + sorted(findings["department"].unique().tolist())
            filters["department"] = st.selectbox("Department", dept_opts)

            type_opts = ["All"] + sorted(findings["finding_type"].unique().tolist())
            filters["finding_type"] = st.selectbox("Finding Type", type_opts)

        st.markdown("""
        <hr style='border-color:#334155;margin:20px 0'>
        <div style='font-size:0.72em;color:#475569;text-align:center;padding-bottom:16px'>
          SOC 2 · PCI DSS · ISO 27001<br>
          <span style='color:#64748b'>Control: CTRL-IAM-001</span>
        </div>
        """, unsafe_allow_html=True)

    return {"page": page, "filters": filters}


# ── Helper: apply filters ─────────────────────────────────────────────────────

def apply_filters(findings: pd.DataFrame, filters: dict) -> pd.DataFrame:
    df = findings.copy()
    if filters.get("severity", "All") != "All":
        df = df[df["severity"] == filters["severity"]]
    if filters.get("department", "All") != "All":
        df = df[df["department"] == filters["department"]]
    if filters.get("finding_type", "All") != "All":
        df = df[df["finding_type"] == filters["finding_type"]]
    return df


# ── Page: Executive Dashboard ─────────────────────────────────────────────────

def page_executive(findings: pd.DataFrame, summary: dict, employees: pd.DataFrame, access: pd.DataFrame):
    st.markdown("""
    <div style="background:linear-gradient(135deg,#1e3a5f 0%,#1565c0 60%,#2196f3 100%);
                border-radius:14px;padding:32px 36px;margin-bottom:28px;color:white">
      <div style="font-size:0.82em;opacity:.7;letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px">
        DataStream Technologies · GRC Control Automation Platform
      </div>
      <h1 style="margin:0;font-size:1.9em;font-weight:700">Privileged Access Review</h1>
      <div style="margin-top:8px;opacity:.85">Continuous monitoring · SOC 2 Type II · PCI DSS v4.0 · ISO 27001:2022</div>
    </div>
    """, unsafe_allow_html=True)

    if summary.get("critical_findings", 0) > 0:
        st.markdown(f"""
        <div class="danger-box">
          🚨 <strong>{summary['critical_findings']} CRITICAL finding(s)</strong> require immediate attention —
          SLA is 24–48 hours. Review the Findings Explorer tab for details.
        </div>""", unsafe_allow_html=True)

    # KPI row
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("🚨 Critical", summary.get("critical_findings", 0), help="Findings requiring action within 24-48h")
    c2.metric("⚠️ High", summary.get("high_findings", 0), help="Findings requiring action within 72h")
    c3.metric("📋 Total Findings", summary.get("total_findings", 0))
    c4.metric("👥 Affected Employees", summary.get("affected_employees", 0))
    c5.metric("💻 Affected Systems", summary.get("affected_systems", 0))
    c6.metric("✅ Compliance Rate", f"{summary.get('compliance_rate', 0)}%", help="% of access records with no findings")

    st.markdown("<div class='section-header'>Finding Distribution</div>", unsafe_allow_html=True)

    col_left, col_right = st.columns([1.2, 1])

    with col_left:
        # Severity bar chart
        sev_data = pd.DataFrame([
            {"Severity": k, "Count": v, "Color": BAND_COLORS.get(k, "#888")}
            for k, v in summary.get("by_severity", {}).items()
        ]).sort_values("Severity", key=lambda s: s.map({b: i for i, b in enumerate(BAND_ORDER)}))

        fig_sev = px.bar(
            sev_data, x="Severity", y="Count",
            color="Severity",
            color_discrete_map={k: BAND_COLORS[k] for k in BAND_COLORS},
            title="Findings by Severity",
            text="Count",
        )
        fig_sev.update_traces(textposition="outside", marker_line_width=0)
        fig_sev.update_layout(
            showlegend=False, plot_bgcolor="white", paper_bgcolor="white",
            title_font_size=14, title_font_color="#1e3a5f",
            xaxis_title="", yaxis_title="Count",
            margin=dict(t=48, b=20, l=20, r=20),
            font_family="Segoe UI",
        )
        st.plotly_chart(fig_sev, use_container_width=True)

    with col_right:
        # Finding type donut
        type_data = pd.DataFrame([
            {"Type": k.replace("_", " ").title(), "Count": v}
            for k, v in summary.get("by_type", {}).items()
        ])
        fig_type = px.pie(
            type_data, names="Type", values="Count",
            title="Findings by Type",
            hole=0.55,
            color_discrete_sequence=px.colors.qualitative.Set2,
        )
        fig_type.update_traces(textposition="inside", textinfo="percent+label")
        fig_type.update_layout(
            showlegend=False, paper_bgcolor="white",
            title_font_size=14, title_font_color="#1e3a5f",
            margin=dict(t=48, b=20, l=20, r=20),
            font_family="Segoe UI",
        )
        st.plotly_chart(fig_type, use_container_width=True)

    # Department heatmap + system bar
    col_a, col_b = st.columns([1, 1.2])

    with col_a:
        dept_data = pd.DataFrame([
            {"Department": k, "Findings": v}
            for k, v in summary.get("by_department", {}).items()
        ]).sort_values("Findings", ascending=True)

        fig_dept = px.bar(
            dept_data, x="Findings", y="Department",
            orientation="h", title="Findings by Department",
            color="Findings",
            color_continuous_scale=["#e8f4fd", "#1565c0"],
            text="Findings",
        )
        fig_dept.update_traces(textposition="outside")
        fig_dept.update_layout(
            showlegend=False, plot_bgcolor="white", paper_bgcolor="white",
            title_font_size=14, title_font_color="#1e3a5f",
            coloraxis_showscale=False,
            xaxis_title="Findings", yaxis_title="",
            margin=dict(t=48, b=20, l=20, r=20),
            font_family="Segoe UI",
        )
        st.plotly_chart(fig_dept, use_container_width=True)

    with col_b:
        sys_data = pd.DataFrame([
            {"System": k, "Findings": v}
            for k, v in list(summary.get("by_system", {}).items())[:10]
        ]).sort_values("Findings", ascending=True)

        fig_sys = px.bar(
            sys_data, x="Findings", y="System",
            orientation="h", title="Top Systems by Finding Count",
            color="Findings",
            color_continuous_scale=["#fff8e1", "#e65100"],
            text="Findings",
        )
        fig_sys.update_traces(textposition="outside")
        fig_sys.update_layout(
            showlegend=False, plot_bgcolor="white", paper_bgcolor="white",
            title_font_size=14, title_font_color="#1e3a5f",
            coloraxis_showscale=False,
            xaxis_title="Findings", yaxis_title="",
            margin=dict(t=48, b=20, l=20, r=20),
            font_family="Segoe UI",
        )
        st.plotly_chart(fig_sys, use_container_width=True)

    # Risk score distribution
    st.markdown("<div class='section-header'>Risk Score Distribution</div>", unsafe_allow_html=True)
    if not findings.empty:
        fig_hist = px.histogram(
            findings, x="risk_score", nbins=20,
            title="Risk Score Distribution Across All Findings",
            color_discrete_sequence=["#2196f3"],
            labels={"risk_score": "Risk Score (0–100)"},
        )
        fig_hist.update_layout(
            plot_bgcolor="white", paper_bgcolor="white",
            title_font_size=14, title_font_color="#1e3a5f",
            yaxis_title="# of Findings", bargap=0.05,
            margin=dict(t=48, b=20, l=20, r=20),
            font_family="Segoe UI",
        )
        fig_hist.add_vline(x=findings["risk_score"].mean(), line_dash="dash",
                           line_color="#f57c00", annotation_text=f"Avg: {findings['risk_score'].mean():.1f}")
        st.plotly_chart(fig_hist, use_container_width=True)


# ── Page: Findings Explorer ───────────────────────────────────────────────────

def page_findings(findings: pd.DataFrame, filters: dict):
    st.markdown("## 🔍 Findings Explorer")

    filtered = apply_filters(findings, filters)

    col1, col2, col3 = st.columns(3)
    col1.metric("Filtered Results", len(filtered))
    col2.metric("Avg Risk Score", f"{filtered['risk_score'].mean():.1f}" if not filtered.empty else "—")
    col3.metric("Max Risk Score", f"{filtered['risk_score'].max():.0f}" if not filtered.empty else "—")

    if filtered.empty:
        st.info("No findings match the current filters.")
        return

    # Search
    search = st.text_input("🔎 Search findings (employee, system, type, detail…)", placeholder="e.g. terminated, AWS, SoD…")
    if search:
        mask = filtered.apply(lambda row: row.astype(str).str.contains(search, case=False).any(), axis=1)
        filtered = filtered[mask]

    st.markdown(f"<div class='section-header'>Showing {len(filtered)} findings</div>", unsafe_allow_html=True)

    # Color-code severity in display table
    display_cols = [
        "finding_id", "severity", "risk_score", "finding_type",
        "employee_name", "department", "system_name",
        "system_criticality", "access_level", "sla_deadline", "detail"
    ]
    display = filtered[display_cols].copy()
    display.columns = [
        "Finding ID", "Severity", "Risk", "Type",
        "Employee", "Department", "System",
        "Criticality", "Access Level", "SLA Deadline", "Detail"
    ]

    st.dataframe(
        display,
        use_container_width=True,
        height=480,
        column_config={
            "Risk":      st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%.0f"),
            "Severity":  st.column_config.TextColumn("Severity"),
            "Finding ID": st.column_config.TextColumn("Finding ID", width="small"),
            "Detail":    st.column_config.TextColumn("Detail", width="large"),
        },
    )

    # Download
    st.download_button(
        label="📥 Download Filtered Findings (CSV)",
        data=filtered.to_csv(index=False).encode("utf-8"),
        file_name="grc_findings_filtered.csv",
        mime="text/csv",
    )

    # Detail card for selected finding
    st.markdown("<div class='section-header'>Finding Detail View</div>", unsafe_allow_html=True)
    finding_ids = filtered["finding_id"].tolist()
    selected_id = st.selectbox("Select a finding to inspect", finding_ids)
    if selected_id:
        row = filtered[filtered["finding_id"] == selected_id].iloc[0]
        col_a, col_b = st.columns(2)
        with col_a:
            sev_color = BAND_COLORS.get(row["severity"], "#666")
            st.markdown(f"""
            <div style="background:white;border-radius:12px;padding:24px;box-shadow:0 2px 10px rgba(0,0,0,.07);
                        border-left:5px solid {sev_color}">
              <div style="font-size:0.78em;color:#6b7280;margin-bottom:4px">{row['finding_id']} · {row['rule_id']}</div>
              <div style="font-size:1.3em;font-weight:700;color:#1e3a5f;margin-bottom:12px">{row['rule_name']}</div>
              <div style="margin-bottom:8px"><span style="color:{sev_color};font-weight:700">{row['severity']}</span>
                &nbsp;·&nbsp; Risk Score: <strong>{row['risk_score']}</strong></div>
              <div style="font-size:0.9em;color:#374151;margin-top:12px;line-height:1.7">{row['detail']}</div>
            </div>
            """, unsafe_allow_html=True)
        with col_b:
            st.markdown(f"""
            <div style="background:white;border-radius:12px;padding:24px;box-shadow:0 2px 10px rgba(0,0,0,.07)">
              <div style="font-size:0.78em;color:#6b7280;font-weight:600;text-transform:uppercase;letter-spacing:.05em;margin-bottom:16px">Metadata</div>
              <table style="width:100%;font-size:0.88em">
                <tr><td style="color:#6b7280;padding:5px 0">Employee</td><td style="font-weight:600">{row['employee_name']}</td></tr>
                <tr><td style="color:#6b7280;padding:5px 0">Department</td><td>{row['department']}</td></tr>
                <tr><td style="color:#6b7280;padding:5px 0">System</td><td>{row['system_name']}</td></tr>
                <tr><td style="color:#6b7280;padding:5px 0">Access Level</td><td>{row['access_level'].upper()}</td></tr>
                <tr><td style="color:#6b7280;padding:5px 0">System Criticality</td><td>{row['system_criticality'].upper()}</td></tr>
                <tr><td style="color:#6b7280;padding:5px 0">SLA Deadline</td><td style="color:#d32f2f;font-weight:600">{row['sla_deadline']}</td></tr>
                <tr><td style="color:#6b7280;padding:5px 0">Frameworks</td><td style="font-size:0.85em">{row['frameworks']}</td></tr>
                <tr><td style="color:#6b7280;padding:5px 0">Detected At</td><td>{row['detected_at']}</td></tr>
              </table>
            </div>
            """, unsafe_allow_html=True)


# ── Page: Access Inventory ────────────────────────────────────────────────────

def page_access(access: pd.DataFrame, employees: pd.DataFrame, systems: pd.DataFrame):
    st.markdown("## 🗝️ Access Inventory")

    merged = access.merge(
        employees[["employee_id", "full_name", "department", "status", "title"]],
        on="employee_id", how="left"
    )

    # Filters
    col_f1, col_f2, col_f3, col_f4 = st.columns(4)
    with col_f1:
        emp_status_filter = st.selectbox("Employee Status", ["All", "active", "terminated", "on_leave"])
    with col_f2:
        access_level_filter = st.selectbox("Access Level", ["All", "admin", "elevated", "standard"])
    with col_f3:
        crit_filter = st.selectbox("System Criticality", ["All", "critical", "high", "medium", "low"])
    with col_f4:
        active_only = st.checkbox("Active Access Only", value=True)

    df = merged.copy()
    if active_only:
        df = df[df["is_active"]]
    if emp_status_filter != "All":
        df = df[df["status"] == emp_status_filter]
    if access_level_filter != "All":
        df = df[df["access_level"] == access_level_filter]
    if crit_filter != "All":
        df = df[df["system_criticality"] == crit_filter]

    # Summary cards
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Records", len(df))
    c2.metric("Unique Employees", df["employee_id"].nunique())
    c3.metric("Unique Systems", df["system_id"].nunique())
    admin_count = len(df[df["access_level"] == "admin"])
    c4.metric("Admin Access Grants", admin_count)

    st.markdown("<div class='section-header'>Access Records</div>", unsafe_allow_html=True)

    display_cols = ["access_id", "full_name", "department", "status", "system_name",
                    "system_criticality", "access_level", "granted_date", "last_used_date",
                    "is_active", "business_justification"]
    display = df[display_cols].rename(columns={
        "access_id": "Access ID", "full_name": "Employee", "department": "Department",
        "status": "Emp Status", "system_name": "System", "system_criticality": "Criticality",
        "access_level": "Level", "granted_date": "Granted", "last_used_date": "Last Used",
        "is_active": "Active", "business_justification": "Justification",
    })

    st.dataframe(
        display,
        use_container_width=True,
        height=480,
        column_config={
            "Active": st.column_config.CheckboxColumn("Active"),
            "Justification": st.column_config.TextColumn("Justification", width="large"),
        },
    )

    st.download_button(
        "📥 Download Access Records (CSV)",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="access_inventory.csv",
        mime="text/csv",
    )

    # Access level breakdown
    st.markdown("<div class='section-header'>Access Level Breakdown</div>", unsafe_allow_html=True)
    col_p1, col_p2 = st.columns(2)
    with col_p1:
        level_counts = df["access_level"].value_counts().reset_index()
        level_counts.columns = ["Level", "Count"]
        fig = px.pie(level_counts, names="Level", values="Count",
                     title="Distribution of Access Levels",
                     color_discrete_sequence=["#d32f2f", "#f57c00", "#388e3c"],
                     hole=0.5)
        fig.update_layout(paper_bgcolor="white", title_font_size=13, title_font_color="#1e3a5f",
                          margin=dict(t=48, b=0, l=0, r=0), font_family="Segoe UI")
        st.plotly_chart(fig, use_container_width=True)
    with col_p2:
        dept_access = df.groupby(["department", "access_level"]).size().reset_index(name="Count")
        fig2 = px.bar(dept_access, x="department", y="Count", color="access_level",
                      title="Access by Department & Level",
                      color_discrete_map={"admin": "#d32f2f", "elevated": "#f57c00", "standard": "#388e3c"},
                      barmode="stack")
        fig2.update_layout(plot_bgcolor="white", paper_bgcolor="white",
                           title_font_size=13, title_font_color="#1e3a5f",
                           xaxis_title="", legend_title="Level",
                           margin=dict(t=48, b=20, l=20, r=20), font_family="Segoe UI")
        st.plotly_chart(fig2, use_container_width=True)


# ── Page: Control Configuration ───────────────────────────────────────────────

def page_config():
    import yaml
    st.markdown("## ⚙️ Control Configuration")

    config_path = ROOT / "config" / "controls.yaml"
    with open(config_path) as f:
        config = yaml.safe_load(f)

    company = config["company"]
    control = config["control"]
    rules = config["detection_rules"]

    st.markdown(f"""
    <div class="info-box">
      <strong>Control:</strong> {control['id']} — {control['name']}<br>
      <strong>Owner:</strong> {control['owner']} &nbsp;·&nbsp;
      <strong>Frequency:</strong> {control['frequency']}
    </div>
    """, unsafe_allow_html=True)

    # Framework coverage
    st.markdown("<div class='section-header'>Compliance Framework Coverage</div>", unsafe_allow_html=True)
    fw_cols = st.columns(len(control["frameworks"]))
    for col, fw in zip(fw_cols, control["frameworks"]):
        col.markdown(f"""
        <div style="background:white;border-radius:10px;padding:16px;text-align:center;
                    box-shadow:0 2px 8px rgba(0,0,0,.06);border-top:3px solid #2196f3">
          <div style="font-weight:700;color:#1e3a5f;font-size:0.95em">{fw['ref']}</div>
          <div style="font-size:0.78em;color:#6b7280;margin-top:4px">{fw['description']}</div>
        </div>
        """, unsafe_allow_html=True)

    # Detection rules
    st.markdown("<div class='section-header'>Detection Rules</div>", unsafe_allow_html=True)
    for rule in rules:
        sev_color = BAND_COLORS.get(rule["severity"], "#666")
        with st.expander(f"{rule['id']} — {rule['name']}", expanded=False):
            col_a, col_b = st.columns([2, 1])
            with col_a:
                st.markdown(f"""
                <div style="font-size:0.9em;color:#374151;margin-bottom:12px">{rule['description']}</div>
                <div style="font-size:0.82em;color:#6b7280">
                  <strong>Type:</strong> {rule['type']}<br>
                  <strong>Auto-Remediate:</strong> {'Yes' if rule.get('auto_remediate') else 'No — human review required'}<br>
                  <strong>SLA:</strong> {rule['sla_hours']} hours<br>
                  <strong>Frameworks:</strong> {', '.join(rule.get('frameworks', []))}
                </div>
                """, unsafe_allow_html=True)
            with col_b:
                st.markdown(f"""
                <div style="background:{sev_color}18;border:1px solid {sev_color}40;border-radius:8px;
                            padding:16px;text-align:center">
                  <div style="font-size:0.75em;color:#6b7280;margin-bottom:4px">Severity</div>
                  <div style="font-size:1.4em;font-weight:700;color:{sev_color}">{rule['severity']}</div>
                </div>
                """, unsafe_allow_html=True)
                st.markdown(f"""
                <div style="margin-top:12px">
                  <div style="font-size:0.78em;color:#6b7280;margin-bottom:6px"><strong>Evidence Required:</strong></div>
                  {"".join(f'<div style="font-size:0.8em;padding:3px 0;color:#374151">• {e.replace("_", " ").title()}</div>' for e in rule.get('evidence_required', []))}
                </div>
                """, unsafe_allow_html=True)

    # Raw YAML viewer
    with st.expander("🔧 Raw Configuration (YAML)", expanded=False):
        st.code(open(config_path).read(), language="yaml")


# ── Page: Evidence Packages ───────────────────────────────────────────────────

def page_evidence(findings: pd.DataFrame, employees: pd.DataFrame, access: pd.DataFrame, summary: dict):
    st.markdown("## 📦 Evidence Packages")

    st.markdown("""
    <div class="info-box">
      Evidence packages are audit-ready bundles containing findings, access snapshots,
      employee records, and a signed manifest — suitable for direct submission to SOC 2,
      PCI DSS, or ISO 27001 auditors.
    </div>
    """, unsafe_allow_html=True)

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 📥 Generate Evidence Package")
        st.markdown("""
        Creates a timestamped directory with:
        - `findings.json` / `findings.csv`
        - `access_snapshot.csv`
        - `employee_snapshot.csv`
        - `summary.json`
        - `manifest.html` (human-readable index)
        """)
        if st.button("🔒 Generate Evidence Package", type="primary", use_container_width=True):
            with st.spinner("Generating evidence package…"):
                pkg_path = generate_evidence_package(
                    findings, employees, access, summary,
                    output_dir=ROOT / "outputs" / "evidence"
                )
            st.success(f"Evidence package created:\n`{pkg_path}`")
            manifest = (pkg_path / "manifest.html").read_text(encoding="utf-8")
            st.download_button(
                "📋 Download Manifest (HTML)",
                data=manifest.encode("utf-8"),
                file_name="evidence_manifest.html",
                mime="text/html",
            )

    with col2:
        st.markdown("### 📄 Generate Executive Report")
        st.markdown("""
        Produces a printable HTML report for management review, containing:
        - Executive KPI summary
        - Finding breakdown by type, severity, department
        - Full findings table with risk scores
        """)
        if st.button("📊 Generate Executive Report", type="primary", use_container_width=True):
            with st.spinner("Building report…"):
                import time
                ts = time.strftime("%Y%m%d_%H%M%S")
                report_path = ROOT / "outputs" / "reports" / f"par_report_{ts}.html"
                build_html_report(findings, summary, report_path)
            st.success(f"Report created:\n`{report_path}`")
            report_html = report_path.read_text(encoding="utf-8")
            st.download_button(
                "📋 Download Executive Report (HTML)",
                data=report_html.encode("utf-8"),
                file_name="par_executive_report.html",
                mime="text/html",
            )

    # Preview findings download directly
    st.markdown("---")
    st.markdown("### ⚡ Quick Exports")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.download_button(
            "📊 All Findings (CSV)",
            data=findings.to_csv(index=False).encode("utf-8"),
            file_name="all_findings.csv", mime="text/csv",
            use_container_width=True,
        )
    with c2:
        st.download_button(
            "👥 Employee Snapshot (CSV)",
            data=employees.to_csv(index=False).encode("utf-8"),
            file_name="employee_snapshot.csv", mime="text/csv",
            use_container_width=True,
        )
    with c3:
        st.download_button(
            "🔐 Access Inventory (CSV)",
            data=access[access["is_active"]].to_csv(index=False).encode("utf-8"),
            file_name="active_access.csv", mime="text/csv",
            use_container_width=True,
        )


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    with st.spinner("Loading GRC automation data…"):
        employees, access, systems, findings, summary = load_data()

    nav = render_sidebar(findings)
    page = nav["page"]
    filters = nav["filters"]

    if page == "Executive Dashboard":
        page_executive(findings, summary, employees, access)
    elif page == "Findings Explorer":
        page_findings(findings, filters)
    elif page == "Access Inventory":
        page_access(access, employees, systems)
    elif page == "Control Configuration":
        page_config()
    elif page == "Evidence Packages":
        page_evidence(findings, employees, access, summary)


if __name__ == "__main__":
    main()
