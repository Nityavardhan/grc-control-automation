"""
GRC Control Automation — Streamlit Dashboard
DataStream Technologies · Privileged Access Review

Clean, minimalist, interview-ready enterprise design.
"""

from __future__ import annotations

import sys
from pathlib import Path

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
from src.risk_scorer import BAND_ORDER

# ── Page config ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="GRC Platform · DataStream",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Design tokens ─────────────────────────────────────────────────────────────

SEV_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#f59e0b",
    "LOW":      "#10b981",
}
SEV_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#f0fdf4",
}
NAV_ICONS = {
    "Executive Dashboard":   "📊",
    "Findings Explorer":     "🔍",
    "Access Inventory":      "🗝️",
    "Control Configuration": "⚙️",
    "Evidence Packages":     "📦",
}
CHART_FONT = dict(family="Inter, -apple-system, sans-serif", color="#1e293b")
CHART_BASE = dict(
    paper_bgcolor="white",
    plot_bgcolor="white",
    font=CHART_FONT,
    margin=dict(l=16, r=16, t=40, b=16),
)

# ── CSS ───────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

/* ── Base ── */
html, body, [class*="css"] { font-family: 'Inter', -apple-system, sans-serif !important; }
[data-testid="stAppViewContainer"] { background: #f1f5f9; }
[data-testid="block-container"]    { padding: 28px 32px 48px; max-width: 1400px; }

/* ── Hide chrome ── */
#MainMenu, footer, header, [data-testid="stDecoration"],
[data-testid="stStatusWidget"] { display: none !important; visibility: hidden !important; }

/* ── Sidebar ── */
[data-testid="stSidebar"] > div:first-child {
    background: #0f172a;
    padding: 0;
    border-right: 1px solid rgba(255,255,255,0.05);
}
/* Radio nav items */
[data-testid="stSidebar"] .stRadio > label { display: none; }
[data-testid="stSidebar"] .stRadio > div   { gap: 2px; padding: 0 12px; }
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] { gap: 2px; }
[data-testid="stSidebar"] .stRadio label {
    display: flex !important;
    align-items: center !important;
    padding: 10px 12px !important;
    border-radius: 8px !important;
    color: #64748b !important;
    font-size: 0.85em !important;
    font-weight: 500 !important;
    cursor: pointer !important;
    transition: all 0.15s !important;
    margin: 1px 0 !important;
}
[data-testid="stSidebar"] .stRadio label:hover {
    background: rgba(255,255,255,0.07) !important;
    color: #e2e8f0 !important;
}
/* Sidebar filter labels */
[data-testid="stSidebar"] .stSelectbox > label {
    color: #334155 !important;
    font-size: 0.68em !important;
    font-weight: 700 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.08em !important;
}
[data-testid="stSidebar"] [data-baseweb="select"] > div {
    background: rgba(255,255,255,0.05) !important;
    border: 1px solid rgba(255,255,255,0.08) !important;
    border-radius: 8px !important;
    color: #cbd5e1 !important;
}
[data-testid="stSidebar"] [data-baseweb="select"] span { color: #cbd5e1 !important; }
[data-testid="stSidebar"] .stSelectbox svg { fill: #64748b !important; }

/* Sidebar checkbox */
[data-testid="stSidebar"] .stCheckbox > label {
    color: #94a3b8 !important;
    font-size: 0.82em !important;
}

/* ── Section divider ── */
.divider {
    height: 1px; background: #e2e8f0;
    margin: 28px 0 20px; border: none;
}

/* ── Page header ── */
.page-hdr { margin-bottom: 24px; }
.page-hdr h2 {
    font-size: 1.45em; font-weight: 800; color: #0f172a;
    margin: 0 0 4px; letter-spacing: -0.025em;
}
.page-hdr p { font-size: 0.84em; color: #64748b; margin: 0; }

/* ── KPI cards ── */
.kpi-row {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 14px;
    margin-bottom: 24px;
}
.kpi {
    background: white;
    border-radius: 12px;
    padding: 18px 20px 16px;
    border-top: 3px solid var(--a);
    box-shadow: 0 1px 2px rgba(0,0,0,0.04), 0 4px 12px rgba(0,0,0,0.03);
    position: relative;
}
.kpi-ico {
    position: absolute; right: 16px; top: 16px;
    font-size: 1.3em; opacity: 0.2;
}
.kpi-lbl {
    font-size: 0.65em; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.08em;
    color: #94a3b8; margin-bottom: 10px;
}
.kpi-val {
    font-size: 2.1em; font-weight: 800;
    color: var(--a); line-height: 1; margin-bottom: 5px;
}
.kpi-sub { font-size: 0.7em; color: #cbd5e1; font-weight: 500; }

/* ── Chart card wrapper ── */
.chart-card {
    background: white;
    border-radius: 12px;
    padding: 20px 20px 12px;
    box-shadow: 0 1px 2px rgba(0,0,0,0.04), 0 4px 12px rgba(0,0,0,0.03);
    margin-bottom: 16px;
}
.chart-title {
    font-size: 0.72em; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.07em;
    color: #64748b; margin-bottom: 4px;
}

/* ── Alert ── */
.alert {
    display: flex; align-items: center; gap: 12px;
    padding: 12px 16px; border-radius: 8px;
    border-left: 4px solid var(--ac);
    background: var(--abg);
    margin-bottom: 8px;
    font-size: 0.85em; color: var(--atx);
    font-weight: 500;
}

/* ── Finding list items ── */
.frow {
    display: grid;
    grid-template-columns: 90px 1fr auto;
    align-items: start; gap: 16px;
    background: white;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 8px;
    border-left: 4px solid var(--sev);
    box-shadow: 0 1px 2px rgba(0,0,0,0.04);
    transition: box-shadow 0.15s;
}
.frow:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.08); }
.frow-id   { font-family: monospace; font-size: 0.72em; color: #94a3b8; padding-top: 2px; }
.frow-name { font-size: 0.88em; font-weight: 600; color: #1e293b; margin-bottom: 4px; }
.frow-meta { font-size: 0.78em; color: #64748b; }
.frow-score {
    font-size: 1.6em; font-weight: 800; color: var(--sev);
    text-align: right; line-height: 1;
}
.frow-sev {
    font-size: 0.65em; text-align: right;
    color: var(--sev); font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.05em;
}

/* ── Severity badge ── */
.badge {
    display: inline-block;
    padding: 2px 9px; border-radius: 20px;
    font-size: 0.72em; font-weight: 700;
    letter-spacing: 0.04em;
}

/* ── Stat row (access page) ── */
.stat-row {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 14px; margin-bottom: 20px;
}
.stat {
    background: white; border-radius: 12px;
    padding: 20px; text-align: center;
    box-shadow: 0 1px 2px rgba(0,0,0,0.04), 0 4px 12px rgba(0,0,0,0.03);
}
.stat-val { font-size: 2em; font-weight: 800; color: #0f172a; line-height: 1; margin-bottom: 6px; }
.stat-lbl { font-size: 0.72em; color: #94a3b8; font-weight: 600;
            text-transform: uppercase; letter-spacing: 0.06em; }

/* ── Rule card ── */
.rule-hdr {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 8px;
}
.rule-id { font-size: 0.72em; font-family: monospace; color: #94a3b8; }
.rule-desc { font-size: 0.85em; color: #475569; line-height: 1.6; margin-bottom: 12px; }
.rule-pill {
    display: inline-block; padding: 3px 10px; border-radius: 5px;
    font-size: 0.7em; font-weight: 600; margin: 2px;
    background: #f1f5f9; color: #475569;
}

/* ── Dataframe overrides ── */
[data-testid="stDataFrame"] > div { border-radius: 10px !important; overflow: hidden; }
[data-testid="stDataFrame"] thead th {
    background: #f8fafc !important; color: #64748b !important;
    font-size: 0.72em !important; text-transform: uppercase;
    letter-spacing: 0.06em !important; font-weight: 700 !important;
}

/* ── Download button ── */
[data-testid="stDownloadButton"] > button {
    border-radius: 8px !important; border: 1px solid #e2e8f0 !important;
    background: white !important; color: #1e293b !important;
    font-size: 0.84em !important; font-weight: 600 !important;
    padding: 8px 16px !important;
    box-shadow: 0 1px 2px rgba(0,0,0,0.04) !important;
    transition: all 0.15s !important;
}
[data-testid="stDownloadButton"] > button:hover {
    border-color: #3b82f6 !important; color: #3b82f6 !important;
    box-shadow: 0 4px 12px rgba(59,130,246,0.15) !important;
}

/* ── Primary button ── */
[data-testid="stButton"] > button[kind="primary"] {
    background: #1e293b !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-size: 0.84em !important;
    font-weight: 600 !important;
    padding: 10px 20px !important;
    transition: all 0.15s !important;
}
[data-testid="stButton"] > button[kind="primary"]:hover {
    background: #3b82f6 !important;
    box-shadow: 0 4px 16px rgba(59,130,246,0.3) !important;
}

/* ── Text input ── */
[data-testid="stTextInput"] input {
    border-radius: 8px !important;
    border: 1px solid #e2e8f0 !important;
    font-size: 0.88em !important;
    padding: 10px 14px !important;
}
[data-testid="stTextInput"] input:focus {
    border-color: #3b82f6 !important;
    box-shadow: 0 0 0 3px rgba(59,130,246,0.1) !important;
}

/* ── Expander ── */
[data-testid="stExpander"] {
    background: white !important;
    border: 1px solid #e2e8f0 !important;
    border-radius: 10px !important;
    margin-bottom: 8px !important;
    overflow: hidden !important;
}
[data-testid="stExpander"] summary {
    padding: 14px 18px !important;
    font-weight: 600 !important;
    font-size: 0.88em !important;
    color: #1e293b !important;
}
[data-testid="stExpander"] summary:hover { background: #f8fafc !important; }

/* ── Code block ── */
.stCode { border-radius: 8px !important; }
</style>
""", unsafe_allow_html=True)


# ── Data loading ──────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def load_data():
    datasets = generate_all(seed=42)
    emp  = datasets["employees"]
    acc  = datasets["access_rights"]
    sys_ = datasets["systems"]
    fnd  = run_all_rules(emp, acc)
    smry = compute_summary(fnd, emp, acc)
    return emp, acc, sys_, fnd, smry


# ── Chart helpers ─────────────────────────────────────────────────────────────

def _clean(fig, height=280, title_size=11):
    fig.update_layout(
        **CHART_BASE,
        height=height,
        title_font=dict(size=title_size, color="#64748b", family="Inter"),
        title_x=0,
    )
    fig.update_xaxes(showgrid=False, zeroline=False, showline=False, tickfont=dict(size=10, color="#94a3b8"))
    fig.update_yaxes(showgrid=False, zeroline=False, showline=False, tickfont=dict(size=10, color="#94a3b8"))
    return fig


def gauge_chart(value: float) -> go.Figure:
    color = "#ef4444" if value >= 70 else "#f97316" if value >= 45 else "#f59e0b" if value >= 25 else "#10b981"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        number={"font": {"size": 52, "color": "#0f172a", "family": "Inter"}, "suffix": "/100"},
        gauge={
            "axis":      {"range": [0, 100], "tickwidth": 0, "tickcolor": "white", "tickvals": [0, 25, 50, 75, 100]},
            "bar":       {"color": color, "thickness": 0.28},
            "bgcolor":   "white",
            "borderwidth": 0,
            "steps": [
                {"range": [0,  30], "color": "#f0fdf4"},
                {"range": [30, 55], "color": "#fffbeb"},
                {"range": [55, 80], "color": "#fff7ed"},
                {"range": [80,100], "color": "#fef2f2"},
            ],
        },
    ))
    fig.update_layout(
        **CHART_BASE,
        height=240,
        margin=dict(l=20, r=20, t=10, b=10),
    )
    return fig


def treemap_chart(by_type: dict) -> go.Figure:
    data = pd.DataFrame([
        {"Type": k.replace("_", " ").title(), "Count": v}
        for k, v in by_type.items()
    ])
    fig = px.treemap(
        data, path=["Type"], values="Count",
        color="Count",
        color_continuous_scale=["#dbeafe", "#3b82f6", "#1e3a8a"],
    )
    fig.update_traces(
        textinfo="label+value",
        textfont=dict(size=13, family="Inter"),
        marker_line_width=2,
        marker_line_color="white",
    )
    fig.update_layout(
        **CHART_BASE,
        height=240,
        margin=dict(l=0, r=0, t=0, b=0),
        coloraxis_showscale=False,
    )
    return fig


def hbar_chart(data: dict, title: str, color: str = "#3b82f6", n: int = 8) -> go.Figure:
    df = pd.DataFrame(list(data.items()), columns=["Label", "Count"]).sort_values("Count").tail(n)
    fig = px.bar(
        df, x="Count", y="Label", orientation="h",
        text="Count",
        title=title,
    )
    fig.update_traces(
        marker_color=color,
        marker_line_width=0,
        textposition="outside",
        textfont=dict(size=10, color="#64748b"),
    )
    fig.update_layout(**CHART_BASE, height=max(220, n * 32 + 60))
    fig.update_xaxes(visible=False)
    fig.update_yaxes(tickfont=dict(size=10))
    return fig


def severity_bar(by_sev: dict) -> go.Figure:
    order = [s for s in BAND_ORDER if s in by_sev]
    counts = [by_sev[s] for s in order]
    colors = [SEV_COLOR[s] for s in order]
    fig = go.Figure(go.Bar(
        x=order, y=counts,
        marker_color=colors,
        marker_line_width=0,
        text=counts,
        textposition="outside",
        textfont=dict(size=12, color="#1e293b"),
    ))
    fig.update_layout(**CHART_BASE, height=240, title="Findings by Severity")
    fig.update_xaxes(showgrid=False, showline=False)
    fig.update_yaxes(visible=False)
    return fig


def histogram_chart(findings: pd.DataFrame) -> go.Figure:
    fig = px.histogram(
        findings, x="risk_score", nbins=25,
        title="Risk Score Distribution",
        color_discrete_sequence=["#3b82f6"],
    )
    fig.update_traces(marker_line_width=0, opacity=0.85)
    avg = findings["risk_score"].mean()
    fig.add_vline(
        x=avg, line_dash="dash", line_color="#ef4444", line_width=1.5,
        annotation_text=f"  avg {avg:.0f}",
        annotation_font=dict(size=11, color="#ef4444"),
        annotation_position="top right",
    )
    fig.update_layout(**CHART_BASE, height=220, bargap=0.06)
    fig.update_xaxes(title_text="Risk Score", title_font=dict(size=10, color="#94a3b8"))
    fig.update_yaxes(title_text="Findings", title_font=dict(size=10, color="#94a3b8"), showgrid=True, gridcolor="#f1f5f9")
    return fig


# ── HTML components ───────────────────────────────────────────────────────────

def kpi_row(summary: dict) -> str:
    def card(label, value, sub, accent, icon):
        return f"""
        <div class="kpi" style="--a:{accent}">
          <div class="kpi-ico">{icon}</div>
          <div class="kpi-lbl">{label}</div>
          <div class="kpi-val">{value}</div>
          <div class="kpi-sub">{sub}</div>
        </div>"""

    c = summary.get("critical_findings", 0)
    h = summary.get("high_findings", 0)
    m = summary.get("medium_findings", 0)
    t = summary.get("total_findings", 0)
    e = summary.get("affected_employees", 0)
    r = summary.get("compliance_rate", 0)

    cards = (
        card("Critical", c, "24h SLA",            "#ef4444", "🚨") +
        card("High",     h, "72h SLA",            "#f97316", "⚠️") +
        card("Medium",   m, "5-day SLA",          "#f59e0b", "📋") +
        card("Total",    t, "all findings",       "#3b82f6", "🔍") +
        card("Employees", e, "with findings",     "#8b5cf6", "👤") +
        card("Compliant", f"{r}%", "access records", "#10b981", "✅")
    )
    return f'<div class="kpi-row">{cards}</div>'


def sev_badge(sev: str) -> str:
    c = SEV_COLOR.get(sev, "#64748b")
    bg = SEV_BG.get(sev, "#f1f5f9")
    return f'<span class="badge" style="background:{bg};color:{c}">{sev}</span>'


def finding_cards(findings: pd.DataFrame, n: int = 8) -> str:
    html = ""
    for _, r in findings.head(n).iterrows():
        sev = r["severity"]
        c = SEV_COLOR.get(sev, "#64748b")
        html += f"""
        <div class="frow" style="--sev:{c}">
          <div>
            <div class="frow-id">{r['finding_id']}</div>
            <div style="margin-top:8px">{sev_badge(sev)}</div>
          </div>
          <div>
            <div class="frow-name">{r['finding_type'].replace('_',' ').title()}</div>
            <div class="frow-meta">
              {r['employee_name']} &nbsp;·&nbsp; {r['department']}
              &nbsp;·&nbsp; {r['system_name']}
            </div>
            <div style="font-size:0.78em;color:#94a3b8;margin-top:6px;line-height:1.5">
              {str(r['detail'])[:130]}{'…' if len(str(r['detail']))>130 else ''}
            </div>
          </div>
          <div style="text-align:right">
            <div class="frow-score">{r['risk_score']:.0f}</div>
            <div class="frow-sev">risk</div>
          </div>
        </div>"""
    return html


def alert_html(n_critical: int) -> str:
    if n_critical == 0:
        return ""
    return f"""
    <div class="alert" style="
      --ac:#ef4444; --abg:#fef2f2; --atx:#991b1b;
      margin-bottom:20px">
      🚨&nbsp; <strong>{n_critical} CRITICAL finding(s)</strong> detected —
      remediation required within <strong>24 hours</strong> per SLA.
      Review the Findings Explorer for details.
    </div>"""


def page_header(title: str, sub: str) -> None:
    st.markdown(
        f'<div class="page-hdr"><h2>{title}</h2><p>{sub}</p></div>',
        unsafe_allow_html=True,
    )


def chart_card(title: str, fig) -> None:
    st.markdown(f'<div class="chart-title">{title}</div>', unsafe_allow_html=True)
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


# ── Sidebar ───────────────────────────────────────────────────────────────────

def render_sidebar(findings: pd.DataFrame) -> dict:
    with st.sidebar:
        # Brand
        st.markdown("""
        <div style="padding:28px 20px 20px;border-bottom:1px solid rgba(255,255,255,0.06)">
          <div style="font-size:1.3em;font-weight:800;color:#f8fafc;letter-spacing:-0.02em">
            🔒 GRC Platform
          </div>
          <div style="font-size:0.72em;color:#475569;margin-top:4px;font-weight:500">
            DataStream Technologies
          </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

        page = st.radio(
            "nav",
            list(NAV_ICONS.keys()),
            label_visibility="collapsed",
            format_func=lambda x: f"{NAV_ICONS[x]}  {x}",
        )

        # Filters
        filters: dict = {}
        if not findings.empty:
            st.markdown("""
            <div style="padding:20px 20px 8px;border-top:1px solid rgba(255,255,255,0.06);
                        margin-top:16px">
              <div style="font-size:0.65em;font-weight:700;text-transform:uppercase;
                          letter-spacing:0.1em;color:#334155;margin-bottom:12px">
                Filters
              </div>
            </div>
            """, unsafe_allow_html=True)

            sev_opts = ["All"] + [s for s in BAND_ORDER if s in findings["severity"].unique()]
            filters["severity"] = st.selectbox("Severity", sev_opts, key="f_sev")

            dept_opts = ["All"] + sorted(findings["department"].unique().tolist())
            filters["department"] = st.selectbox("Department", dept_opts, key="f_dept")

            type_opts = ["All"] + sorted(findings["finding_type"].unique().tolist())
            filters["finding_type"] = st.selectbox("Finding Type", type_opts, key="f_type")

        # Footer
        st.markdown("""
        <div style="position:fixed;bottom:0;left:0;width:250px;
                    padding:16px 20px;border-top:1px solid rgba(255,255,255,0.05);
                    background:#0f172a">
          <div style="font-size:0.62em;color:#1e3a5f;font-weight:600;
                      text-transform:uppercase;letter-spacing:0.06em;margin-bottom:6px">
            Frameworks
          </div>
          <div style="font-size:0.68em;color:#334155">
            SOC 2 Type II &nbsp;·&nbsp; PCI DSS v4.0 &nbsp;·&nbsp; ISO 27001:2022
          </div>
        </div>
        """, unsafe_allow_html=True)

    return {"page": page, "filters": filters}


# ── Filter helper ─────────────────────────────────────────────────────────────

def apply_filters(findings: pd.DataFrame, filters: dict) -> pd.DataFrame:
    df = findings.copy()
    if filters.get("severity",     "All") != "All": df = df[df["severity"]     == filters["severity"]]
    if filters.get("department",   "All") != "All": df = df[df["department"]   == filters["department"]]
    if filters.get("finding_type", "All") != "All": df = df[df["finding_type"] == filters["finding_type"]]
    return df


# ── Page: Executive Dashboard ─────────────────────────────────────────────────

def page_executive(findings, summary, employees, access):
    page_header(
        "Privileged Access Review",
        f"Continuous monitoring · {len(employees)} employees · {len(access[access['is_active']])} active access records · {summary.get('affected_systems',0)} systems with findings",
    )

    # Alert
    if summary.get("critical_findings", 0):
        st.markdown(alert_html(summary["critical_findings"]), unsafe_allow_html=True)

    # KPI cards
    st.markdown(kpi_row(summary), unsafe_allow_html=True)

    # Row 1: gauge + treemap + severity bar
    c1, c2, c3 = st.columns([1, 1.1, 1.1])
    with c1:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Average Risk Score</div>', unsafe_allow_html=True)
        st.plotly_chart(gauge_chart(summary.get("avg_risk_score", 0)),
                        use_container_width=True, config={"displayModeBar": False})
        st.markdown('</div>', unsafe_allow_html=True)

    with c2:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.markdown('<div class="chart-title">Finding Types</div>', unsafe_allow_html=True)
        st.plotly_chart(treemap_chart(summary.get("by_type", {})),
                        use_container_width=True, config={"displayModeBar": False})
        st.markdown('</div>', unsafe_allow_html=True)

    with c3:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.plotly_chart(severity_bar(summary.get("by_severity", {})),
                        use_container_width=True, config={"displayModeBar": False})
        st.markdown('</div>', unsafe_allow_html=True)

    # Row 2: top departments + top systems
    c4, c5 = st.columns(2)
    with c4:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.plotly_chart(
            _clean(hbar_chart(summary.get("by_department", {}), "Findings by Department", "#8b5cf6"), 280),
            use_container_width=True, config={"displayModeBar": False},
        )
        st.markdown('</div>', unsafe_allow_html=True)

    with c5:
        st.markdown('<div class="chart-card">', unsafe_allow_html=True)
        st.plotly_chart(
            _clean(hbar_chart(summary.get("by_system", {}), "Top Systems by Findings", "#f97316"), 280),
            use_container_width=True, config={"displayModeBar": False},
        )
        st.markdown('</div>', unsafe_allow_html=True)

    # Row 3: risk histogram
    st.markdown('<div class="chart-card">', unsafe_allow_html=True)
    st.plotly_chart(histogram_chart(findings), use_container_width=True,
                    config={"displayModeBar": False})
    st.markdown('</div>', unsafe_allow_html=True)

    # Row 4: top findings
    st.markdown("""
    <div style="font-size:0.72em;font-weight:700;text-transform:uppercase;
                letter-spacing:0.08em;color:#64748b;margin:24px 0 12px">
      Top Findings by Risk Score
    </div>""", unsafe_allow_html=True)
    st.markdown(finding_cards(findings, n=8), unsafe_allow_html=True)


# ── Page: Findings Explorer ───────────────────────────────────────────────────

def page_findings(findings, filters):
    page_header("Findings Explorer", "Search, filter, and drill into individual findings")

    filtered = apply_filters(findings, filters)

    # Search
    search = st.text_input("", placeholder="🔎  Search by employee, system, type, or keyword…", label_visibility="collapsed")
    if search:
        mask = filtered.apply(lambda row: row.astype(str).str.contains(search, case=False).any(), axis=1)
        filtered = filtered[mask]

    # Stats
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Results",        len(filtered))
    c2.metric("Critical",       int((filtered["severity"] == "CRITICAL").sum()) if not filtered.empty else 0)
    c3.metric("Avg Risk Score", f"{filtered['risk_score'].mean():.1f}" if not filtered.empty else "—")
    c4.metric("Unique Systems", filtered["system_name"].nunique() if not filtered.empty else 0)

    if filtered.empty:
        st.markdown("""
        <div style="text-align:center;padding:60px 0;color:#94a3b8">
          <div style="font-size:2em;margin-bottom:12px">🎉</div>
          <div style="font-weight:600">No findings match the current filters</div>
        </div>""", unsafe_allow_html=True)
        return

    st.markdown(f"""
    <div style="font-size:0.72em;font-weight:700;text-transform:uppercase;
                letter-spacing:0.08em;color:#64748b;margin:20px 0 12px">
      {len(filtered)} findings
    </div>""", unsafe_allow_html=True)

    # Table
    display = filtered[[
        "finding_id", "severity", "risk_score", "finding_type",
        "employee_name", "department", "system_name",
        "system_criticality", "access_level", "sla_deadline"
    ]].copy()
    display.columns = [
        "ID", "Severity", "Risk", "Type",
        "Employee", "Department", "System",
        "Criticality", "Access", "SLA Deadline"
    ]
    st.dataframe(
        display, use_container_width=True, height=380,
        column_config={
            "Risk": st.column_config.ProgressColumn("Risk", min_value=0, max_value=100, format="%.0f"),
            "ID":   st.column_config.TextColumn("ID", width="small"),
            "Type": st.column_config.TextColumn("Type", width="medium"),
        },
        hide_index=True,
    )

    st.download_button(
        "📥 Export CSV", data=filtered.to_csv(index=False).encode(),
        file_name="findings_filtered.csv", mime="text/csv",
    )

    # Detail card
    st.markdown('<hr class="divider">', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-size:0.72em;font-weight:700;text-transform:uppercase;
                letter-spacing:0.08em;color:#64748b;margin-bottom:12px">
      Finding Detail
    </div>""", unsafe_allow_html=True)

    sel = st.selectbox("Select finding", filtered["finding_id"].tolist(), label_visibility="collapsed")
    if sel:
        r = filtered[filtered["finding_id"] == sel].iloc[0]
        sev = r["severity"]
        sev_c = SEV_COLOR.get(sev, "#64748b")
        sev_bg = SEV_BG.get(sev, "#f1f5f9")

        ca, cb = st.columns([1.4, 1])
        with ca:
            st.markdown(f"""
            <div style="background:white;border-radius:12px;padding:24px;
                        border-left:5px solid {sev_c};
                        box-shadow:0 1px 2px rgba(0,0,0,0.04),0 4px 12px rgba(0,0,0,0.03)">
              <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:14px">
                <div>
                  <div style="font-family:monospace;font-size:0.72em;color:#94a3b8">{r['finding_id']} · {r['rule_id']}</div>
                  <div style="font-size:1.1em;font-weight:700;color:#0f172a;margin-top:4px">{r['rule_name']}</div>
                </div>
                <span class="badge" style="background:{sev_bg};color:{sev_c};font-size:0.75em">{sev}</span>
              </div>
              <div style="font-size:0.88em;color:#475569;line-height:1.7">{r['detail']}</div>
            </div>
            """, unsafe_allow_html=True)

        with cb:
            st.markdown(f"""
            <div style="background:white;border-radius:12px;padding:24px;
                        box-shadow:0 1px 2px rgba(0,0,0,0.04),0 4px 12px rgba(0,0,0,0.03)">
              <div style="font-size:0.65em;font-weight:700;text-transform:uppercase;
                          letter-spacing:0.08em;color:#94a3b8;margin-bottom:14px">Metadata</div>
              {''.join(f'''
              <div style="display:flex;justify-content:space-between;
                          padding:7px 0;border-bottom:1px solid #f1f5f9;font-size:0.84em">
                <span style="color:#94a3b8">{k}</span>
                <span style="font-weight:600;color:#1e293b">{v}</span>
              </div>''' for k, v in [
                  ("Employee",    r["employee_name"]),
                  ("Department",  r["department"]),
                  ("System",      r["system_name"]),
                  ("Access",      r["access_level"].upper()),
                  ("Criticality", r["system_criticality"].upper()),
                  ("Risk Score",  f"{r['risk_score']} / 100"),
                  ("SLA Deadline",r["sla_deadline"][:16]),
              ])}
            </div>
            """, unsafe_allow_html=True)


# ── Page: Access Inventory ────────────────────────────────────────────────────

def page_access(access, employees, systems):
    page_header("Access Inventory", "All active access rights across employees and systems")

    # Filters
    ca, cb, cc, cd = st.columns(4)
    emp_f  = ca.selectbox("Employee Status",    ["All", "active", "terminated", "on_leave"])
    acc_f  = cb.selectbox("Access Level",       ["All", "admin", "elevated", "standard"])
    crit_f = cc.selectbox("System Criticality", ["All", "critical", "high", "medium", "low"])
    active_only = cd.checkbox("Active only", value=True)

    merged = access.merge(
        employees[["employee_id", "full_name", "department", "status", "title"]],
        on="employee_id", how="left",
    )
    df = merged.copy()
    if active_only:       df = df[df["is_active"]]
    if emp_f  != "All":   df = df[df["status"]           == emp_f]
    if acc_f  != "All":   df = df[df["access_level"]     == acc_f]
    if crit_f != "All":   df = df[df["system_criticality"] == crit_f]

    # Stats
    admin_count = int((df["access_level"] == "admin").sum())
    st.markdown(f"""
    <div class="stat-row">
      <div class="stat">
        <div class="stat-val">{len(df)}</div>
        <div class="stat-lbl">Access Records</div>
      </div>
      <div class="stat">
        <div class="stat-val">{df['employee_id'].nunique()}</div>
        <div class="stat-lbl">Unique Employees</div>
      </div>
      <div class="stat">
        <div class="stat-val">{df['system_id'].nunique()}</div>
        <div class="stat-lbl">Systems</div>
      </div>
      <div class="stat" style="border-top:3px solid #ef4444">
        <div class="stat-val" style="color:#ef4444">{admin_count}</div>
        <div class="stat-lbl">Admin Grants</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Charts
    cc1, cc2 = st.columns(2)
    with cc1:
        level_counts = df["access_level"].value_counts().reset_index()
        level_counts.columns = ["Level", "Count"]
        fig1 = px.pie(
            level_counts, names="Level", values="Count",
            hole=0.6,
            color="Level",
            color_discrete_map={"admin": "#ef4444", "elevated": "#f97316", "standard": "#10b981"},
        )
        fig1.update_traces(textinfo="percent+label", textfont_size=11, marker_line_width=2, marker_line_color="white")
        fig1.update_layout(**CHART_BASE, height=260, showlegend=False, title="Access Level Mix")
        st.plotly_chart(fig1, use_container_width=True, config={"displayModeBar": False})

    with cc2:
        dept_acc = df.groupby(["department", "access_level"]).size().reset_index(name="n")
        fig2 = px.bar(
            dept_acc, x="department", y="n", color="access_level",
            color_discrete_map={"admin": "#ef4444", "elevated": "#f97316", "standard": "#10b981"},
            barmode="stack", title="Access by Department & Level",
        )
        fig2.update_traces(marker_line_width=0)
        fig2.update_layout(**CHART_BASE, height=260, legend_title="", xaxis_title="", yaxis_title="")
        fig2.update_xaxes(tickangle=-35)
        st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})

    # Table
    st.markdown("""
    <div style="font-size:0.72em;font-weight:700;text-transform:uppercase;
                letter-spacing:0.08em;color:#64748b;margin:20px 0 10px">
      Access Records
    </div>""", unsafe_allow_html=True)

    show = df[["access_id", "full_name", "department", "status", "system_name",
               "system_criticality", "access_level", "granted_date", "last_used_date",
               "is_active", "business_justification"]].rename(columns={
        "access_id": "ID", "full_name": "Employee", "department": "Dept",
        "status": "Status", "system_name": "System",
        "system_criticality": "Criticality", "access_level": "Level",
        "granted_date": "Granted", "last_used_date": "Last Used",
        "is_active": "Active", "business_justification": "Justification",
    })
    st.dataframe(show, use_container_width=True, height=380,
                 column_config={"Active": st.column_config.CheckboxColumn("Active")},
                 hide_index=True)

    st.download_button(
        "📥 Export Access Records (CSV)",
        data=df.to_csv(index=False).encode(),
        file_name="access_inventory.csv", mime="text/csv",
    )


# ── Page: Control Configuration ──────────────────────────────────────────────

def page_config():
    import yaml
    page_header("Control Configuration", "Detection rules, scoring weights, and compliance framework mapping")

    cfg_path = ROOT / "config" / "controls.yaml"
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)

    ctrl    = cfg["control"]
    rules   = cfg["detection_rules"]
    scoring = cfg["scoring"]

    # Control overview
    st.markdown(f"""
    <div style="background:white;border-radius:12px;padding:24px 28px;
                box-shadow:0 1px 2px rgba(0,0,0,0.04),0 4px 12px rgba(0,0,0,0.03);
                border-left:4px solid #3b82f6;margin-bottom:20px">
      <div style="display:flex;justify-content:space-between;align-items:start">
        <div>
          <div style="font-family:monospace;font-size:0.72em;color:#94a3b8">{ctrl['id']}</div>
          <div style="font-size:1.15em;font-weight:700;color:#0f172a;margin:4px 0 8px">
            {ctrl['name']}
          </div>
          <div style="font-size:0.85em;color:#64748b;line-height:1.6;max-width:600px">
            {ctrl['description'].strip()}
          </div>
        </div>
        <div style="text-align:right">
          <span style="background:#f0fdf4;color:#10b981;padding:4px 12px;
                       border-radius:20px;font-size:0.75em;font-weight:700">
            ACTIVE
          </span>
          <div style="font-size:0.78em;color:#94a3b8;margin-top:8px">
            Owner: {ctrl['owner']}<br>Cadence: {ctrl['frequency']}
          </div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Frameworks
    fw_html = "".join(f"""
    <div style="background:white;border-radius:10px;padding:16px 18px;
                box-shadow:0 1px 2px rgba(0,0,0,0.04);border-top:3px solid #3b82f6">
      <div style="font-weight:700;color:#1e293b;font-size:0.88em">{fw['ref']}</div>
      <div style="font-size:0.75em;color:#64748b;margin-top:4px;line-height:1.5">{fw['description']}</div>
    </div>""" for fw in ctrl["frameworks"])

    st.markdown(f"""
    <div style="font-size:0.72em;font-weight:700;text-transform:uppercase;
                letter-spacing:0.08em;color:#64748b;margin:24px 0 12px">
      Compliance Framework Coverage
    </div>
    <div style="display:grid;grid-template-columns:repeat({len(ctrl['frameworks'])},1fr);gap:12px;margin-bottom:24px">
      {fw_html}
    </div>
    """, unsafe_allow_html=True)

    # Rules
    st.markdown("""
    <div style="font-size:0.72em;font-weight:700;text-transform:uppercase;
                letter-spacing:0.08em;color:#64748b;margin-bottom:12px">
      Detection Rules
    </div>""", unsafe_allow_html=True)

    for rule in rules:
        sev = rule["severity"]
        sev_c = SEV_COLOR.get(sev, "#666")
        sev_bg = SEV_BG.get(sev, "#f5f5f5")
        with st.expander(f"{rule['id']}  ·  {rule['name']}", expanded=False):
            c1, c2 = st.columns([2, 1])
            with c1:
                st.markdown(f"""
                <div class="rule-desc">{rule['description'].strip()}</div>
                <div>
                  {"".join(f'<span class="rule-pill">{fw}</span>' for fw in rule.get("frameworks", []))}
                </div>
                """, unsafe_allow_html=True)
            with c2:
                st.markdown(f"""
                <div style="text-align:center;background:{sev_bg};border-radius:10px;
                            padding:16px;border:1px solid {sev_c}22">
                  <div style="font-size:0.68em;color:#94a3b8;margin-bottom:6px;font-weight:700;
                              text-transform:uppercase;letter-spacing:.06em">Severity</div>
                  <div style="font-size:1.5em;font-weight:800;color:{sev_c}">{sev}</div>
                  <div style="font-size:0.72em;color:#94a3b8;margin-top:6px">SLA: {rule['sla_hours']}h</div>
                </div>
                """, unsafe_allow_html=True)

    # YAML
    with st.expander("🔧  Raw YAML Configuration", expanded=False):
        st.code(open(cfg_path).read(), language="yaml")


# ── Page: Evidence Packages ───────────────────────────────────────────────────

def page_evidence(findings, employees, access, summary):
    page_header("Evidence Packages", "One-click audit-ready exports for SOC 2, PCI DSS, and ISO 27001 auditors")

    st.markdown("""
    <div class="alert" style="--ac:#3b82f6;--abg:#eff6ff;--atx:#1d4ed8;margin-bottom:24px">
      ℹ️  Each package is timestamped and includes findings, access snapshot, employee
      status, and an HTML manifest — suitable for direct submission to auditors.
    </div>
    """, unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("""
        <div style="background:white;border-radius:12px;padding:24px;
                    box-shadow:0 1px 2px rgba(0,0,0,0.04),0 4px 12px rgba(0,0,0,0.03);
                    margin-bottom:16px">
          <div style="font-weight:700;color:#1e293b;margin-bottom:8px">📦 Evidence Package</div>
          <div style="font-size:0.82em;color:#64748b;line-height:1.7;margin-bottom:16px">
            Generates a timestamped directory containing:<br>
            <code>findings.json</code> / <code>findings.csv</code><br>
            <code>access_snapshot.csv</code><br>
            <code>employee_snapshot.csv</code><br>
            <code>summary.json</code><br>
            <code>manifest.html</code>
          </div>
        """, unsafe_allow_html=True)

        if st.button("Generate Evidence Package", type="primary", use_container_width=True):
            with st.spinner("Generating…"):
                pkg = generate_evidence_package(
                    findings, employees, access, summary,
                    output_dir=ROOT / "outputs" / "evidence",
                )
            st.success(f"Saved to `{pkg.name}`")
            manifest = (pkg / "manifest.html").read_text(encoding="utf-8")
            st.download_button("📋 Download Manifest",
                               data=manifest.encode(), file_name="evidence_manifest.html",
                               mime="text/html", use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    with c2:
        st.markdown("""
        <div style="background:white;border-radius:12px;padding:24px;
                    box-shadow:0 1px 2px rgba(0,0,0,0.04),0 4px 12px rgba(0,0,0,0.03);
                    margin-bottom:16px">
          <div style="font-weight:700;color:#1e293b;margin-bottom:8px">📄 Executive Report</div>
          <div style="font-size:0.82em;color:#64748b;line-height:1.7;margin-bottom:16px">
            Produces a printable HTML report containing:<br>
            Executive KPI summary<br>
            Findings by type, severity, department<br>
            Full findings table with risk scores<br>
            Suitable for board / management review
          </div>
        """, unsafe_allow_html=True)

        if st.button("Generate Executive Report", type="primary", use_container_width=True):
            import time
            with st.spinner("Building…"):
                ts = time.strftime("%Y%m%d_%H%M%S")
                rpt = ROOT / "outputs" / "reports" / f"par_report_{ts}.html"
                build_html_report(findings, summary, rpt)
            st.success(f"Saved to `{rpt.name}`")
            html = rpt.read_text(encoding="utf-8")
            st.download_button("📋 Download Report",
                               data=html.encode(), file_name="par_executive_report.html",
                               mime="text/html", use_container_width=True)
        st.markdown("</div>", unsafe_allow_html=True)

    # Quick exports
    st.markdown("""
    <div style="font-size:0.72em;font-weight:700;text-transform:uppercase;
                letter-spacing:0.08em;color:#64748b;margin:8px 0 12px">
      Quick Exports
    </div>""", unsafe_allow_html=True)

    e1, e2, e3 = st.columns(3)
    with e1:
        st.download_button("📊 All Findings (CSV)",
                           data=findings.to_csv(index=False).encode(),
                           file_name="all_findings.csv", mime="text/csv",
                           use_container_width=True)
    with e2:
        st.download_button("👥 Employee Snapshot (CSV)",
                           data=employees.to_csv(index=False).encode(),
                           file_name="employees.csv", mime="text/csv",
                           use_container_width=True)
    with e3:
        st.download_button("🔐 Active Access (CSV)",
                           data=access[access["is_active"]].to_csv(index=False).encode(),
                           file_name="active_access.csv", mime="text/csv",
                           use_container_width=True)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    with st.spinner("Loading GRC data…"):
        employees, access, systems, findings, summary = load_data()

    nav     = render_sidebar(findings)
    page    = nav["page"]
    filters = nav["filters"]

    if   page == "Executive Dashboard":   page_executive(findings, summary, employees, access)
    elif page == "Findings Explorer":     page_findings(findings, filters)
    elif page == "Access Inventory":      page_access(access, employees, systems)
    elif page == "Control Configuration": page_config()
    elif page == "Evidence Packages":     page_evidence(findings, employees, access, summary)


if __name__ == "__main__":
    main()
