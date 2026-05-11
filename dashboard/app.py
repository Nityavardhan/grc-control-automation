"""
GRC Control Automation — Enterprise Dashboard
DataStream Technologies · Privileged Access Review
SOC 2 Type II | PCI DSS v4.0 | ISO 27001:2022

Minimalist, interactive, interview-ready design.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.control_engine     import compute_summary, run_all_rules
from src.data_generator     import generate_all
from src.evidence_generator import generate_evidence_package
from src.report_builder     import build_html_report
from src.risk_scorer        import BAND_ORDER

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="GRC Platform · DataStream",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Design tokens ─────────────────────────────────────────────────────────────
SEV_COLOR = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b", "LOW": "#10b981"}
SEV_BG    = {"CRITICAL": "#fef2f2", "HIGH": "#fff7ed", "MEDIUM": "#fffbeb", "LOW": "#f0fdf4"}
BLUE  = "#3b82f6"
NAVY  = "#0f172a"
_FONT = dict(family="Inter, -apple-system, sans-serif", color="#1e293b")
_BASE = dict(paper_bgcolor="white", plot_bgcolor="white", font=_FONT,
             margin=dict(l=16, r=16, t=44, b=16))

def _lay(**kw):
    """Merge CHART_BASE with per-chart overrides, avoiding duplicate-kwarg errors."""
    return {**_BASE, **kw}

# ── CSS ───────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

/* ── Base ── */
html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif !important;
}
[data-testid="stAppViewContainer"] { background: #f8fafc; }
[data-testid="block-container"] {
    padding: 24px 32px 56px !important;
    max-width: 1460px !important;
}
#MainMenu, footer, header,
[data-testid="stDecoration"],
[data-testid="stStatusWidget"] { display: none !important; }

/* ── Sidebar ── */
[data-testid="stSidebar"] > div:first-child {
    background: linear-gradient(180deg, #0f172a 0%, #1a2744 100%);
    border-right: 1px solid rgba(255,255,255,0.06);
}
/* Make all sidebar text readable on dark bg */
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] span,
[data-testid="stSidebar"] div,
[data-testid="stSidebar"] label { color: #94a3b8 !important; }
[data-testid="stSidebar"] [data-baseweb="select"] > div {
    background: rgba(255,255,255,0.06) !important;
    border: 1px solid rgba(255,255,255,0.1) !important;
    border-radius: 8px !important;
}
[data-testid="stSidebar"] [data-baseweb="select"] span { color: #cbd5e1 !important; }
[data-testid="stSidebar"] .stSelectbox label {
    font-size: 0.65em !important;
    font-weight: 700 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.1em !important;
    color: #334155 !important;
}

/* ── Top-level tabs (primary nav) ── */
button[data-baseweb="tab"] {
    background: transparent !important;
    border: none !important;
    border-bottom: 3px solid transparent !important;
    border-radius: 0 !important;
    padding: 12px 18px !important;
    font-size: 0.88em !important;
    font-weight: 600 !important;
    color: #64748b !important;
    margin-bottom: -2px !important;
    transition: color 0.15s, border-color 0.15s !important;
}
button[data-baseweb="tab"]:hover {
    color: #1e293b !important;
    background: rgba(59,130,246,0.05) !important;
}
button[data-baseweb="tab"][aria-selected="true"] {
    color: #3b82f6 !important;
    border-bottom-color: #3b82f6 !important;
}
[data-baseweb="tab-list"] {
    border-bottom: 2px solid #e2e8f0 !important;
    background: transparent !important;
    margin-bottom: 20px !important;
    gap: 2px !important;
}
[data-baseweb="tab-panel"] { padding: 0 !important; }

/* ── White card wrapper ── */
.card {
    background: white;
    border-radius: 14px;
    padding: 20px 22px 16px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05), 0 4px 18px rgba(0,0,0,0.04);
    margin-bottom: 16px;
}
.card-title {
    font-size: 0.68em; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.09em;
    color: #94a3b8; margin-bottom: 6px;
}

/* ── KPI row ── */
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 14px;
    margin-bottom: 22px;
}
@media (max-width: 1200px) {
    .kpi-grid { grid-template-columns: repeat(3, 1fr); }
}
.kpi {
    background: white;
    border-radius: 14px;
    padding: 18px 20px 15px;
    border-top: 3px solid var(--a, #3b82f6);
    box-shadow: 0 1px 3px rgba(0,0,0,0.05), 0 4px 18px rgba(0,0,0,0.04);
    transition: transform 0.15s, box-shadow 0.15s;
}
.kpi:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 24px rgba(0,0,0,0.08);
}
.kpi-icon { font-size: 1.4em; margin-bottom: 10px; opacity: 0.8; }
.kpi-lbl {
    font-size: 0.62em; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.09em; color: #94a3b8; margin-bottom: 8px;
}
.kpi-val {
    font-size: 2.3em; font-weight: 800;
    color: var(--a, #0f172a); line-height: 1; margin-bottom: 5px;
}
.kpi-sub { font-size: 0.68em; color: #cbd5e1; font-weight: 500; }

/* ── Finding row (cards) ── */
.frow {
    display: grid;
    grid-template-columns: 108px 1fr 72px;
    align-items: start; gap: 16px;
    background: white; border-radius: 12px;
    padding: 14px 18px; margin-bottom: 8px;
    border-left: 4px solid var(--sev, #64748b);
    box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    transition: box-shadow 0.15s, transform 0.12s;
}
.frow:hover {
    box-shadow: 0 4px 20px rgba(0,0,0,0.09);
    transform: translateX(2px);
}

/* ── Alert banner ── */
.alert-crit {
    display: flex; align-items: center; gap: 12px;
    padding: 14px 18px; border-radius: 10px;
    border-left: 4px solid #ef4444;
    background: linear-gradient(135deg, #fef2f2 0%, #fff8f8 100%);
    margin-bottom: 20px;
    font-size: 0.88em; font-weight: 600; color: #991b1b;
}

/* ── Stat grid (access page) ── */
.stat-grid {
    display: grid; grid-template-columns: repeat(4, 1fr);
    gap: 14px; margin-bottom: 20px;
}
.stat {
    background: white; border-radius: 14px; padding: 20px 16px;
    text-align: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05), 0 4px 18px rgba(0,0,0,0.04);
}
.stat-val { font-size: 2.1em; font-weight: 800; color: #0f172a; line-height: 1; margin-bottom: 5px; }
.stat-lbl { font-size: 0.68em; color: #94a3b8; font-weight: 700; text-transform: uppercase; letter-spacing: 0.07em; }

/* ── Section header ── */
.sec-hdr {
    font-size: 0.68em; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.1em; color: #94a3b8; margin: 22px 0 10px;
}

/* ── Expander ── */
[data-testid="stExpander"] {
    background: white !important;
    border: 1px solid #f1f5f9 !important;
    border-radius: 12px !important;
    margin-bottom: 8px !important;
    overflow: hidden !important;
    box-shadow: 0 1px 3px rgba(0,0,0,0.04) !important;
}
[data-testid="stExpander"] summary {
    padding: 13px 18px !important;
    font-size: 0.9em !important;
    font-weight: 600 !important;
    color: #1e293b !important;
}
[data-testid="stExpander"] summary:hover { background: #f8fafc !important; }

/* ── Dataframe ── */
[data-testid="stDataFrame"] > div { border-radius: 12px !important; overflow: hidden; }
[data-testid="stDataFrame"] thead th {
    background: #f8fafc !important; color: #64748b !important;
    font-size: 0.7em !important; text-transform: uppercase !important;
    letter-spacing: 0.06em !important; font-weight: 700 !important;
}

/* ── Buttons ── */
[data-testid="stDownloadButton"] button {
    border-radius: 8px !important;
    border: 1.5px solid #e2e8f0 !important;
    background: white !important;
    font-size: 0.84em !important;
    font-weight: 600 !important;
    transition: all 0.15s !important;
}
[data-testid="stDownloadButton"] button:hover {
    border-color: #3b82f6 !important;
    color: #3b82f6 !important;
    box-shadow: 0 4px 12px rgba(59,130,246,0.15) !important;
}
button[kind="primary"] {
    background: #1e293b !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    transition: background 0.15s !important;
}
button[kind="primary"]:hover { background: #3b82f6 !important; }

/* ── Text input / search ── */
[data-testid="stTextInput"] input {
    border-radius: 8px !important;
    border: 1.5px solid #e2e8f0 !important;
    font-size: 0.9em !important;
    padding: 10px 14px !important;
    background: white !important;
}
[data-testid="stTextInput"] input:focus {
    border-color: #3b82f6 !important;
    box-shadow: 0 0 0 3px rgba(59,130,246,0.1) !important;
    outline: none !important;
}

/* ── Divider ── */
hr { border: none; border-top: 1px solid #e2e8f0; margin: 24px 0; }

/* ── st.metric ── */
[data-testid="stMetric"] {
    background: white; border-radius: 12px; padding: 16px 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.05) !important;
}
[data-testid="stMetricLabel"] { font-size: 0.7em !important; color: #94a3b8 !important; font-weight: 700 !important; }
[data-testid="stMetricValue"] { font-size: 1.8em !important; font-weight: 800 !important; color: #0f172a !important; }

/* ── Code block ── */
.stCode { border-radius: 10px !important; }

/* ── Select slider ── */
[data-testid="stSlider"] { padding-top: 4px; }
</style>
""", unsafe_allow_html=True)


# ── Data loading ──────────────────────────────────────────────────────────────

@st.cache_data(show_spinner=False)
def load_data():
    d    = generate_all(seed=42)
    emp  = d["employees"]
    acc  = d["access_rights"]
    sys_ = d["systems"]
    fnd  = run_all_rules(emp, acc)
    smry = compute_summary(fnd, emp, acc)
    return emp, acc, sys_, fnd, smry


@st.cache_data(show_spinner=False)
def load_config_yaml():
    import yaml
    cfg_path = ROOT / "config" / "controls.yaml"
    raw = cfg_path.read_text(encoding="utf-8")
    return yaml.safe_load(raw), raw


# ── Chart helpers ─────────────────────────────────────────────────────────────

_CFG = {"displayModeBar": False}   # Plotly toolbar off


def gauge_chart(value: float) -> go.Figure:
    color = (
        "#ef4444" if value >= 70 else
        "#f97316" if value >= 45 else
        "#f59e0b" if value >= 25 else
        "#10b981"
    )
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        number={"font": {"size": 52, "color": "#0f172a", "family": "Inter"}, "suffix": ""},
        title={"text": "Avg Risk Score", "font": {"size": 11, "color": "#94a3b8", "family": "Inter"}},
        gauge={
            "axis": {
                "range": [0, 100], "tickwidth": 0, "tickcolor": "white",
                "tickvals": [0, 25, 50, 75, 100],
                "tickfont": {"color": "#94a3b8", "size": 9},
            },
            "bar":       {"color": color, "thickness": 0.3},
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
    fig.update_layout(**_lay(height=220, margin=dict(l=20, r=20, t=30, b=10)))
    return fig


def donut_severity(by_sev: dict) -> go.Figure:
    order  = [s for s in BAND_ORDER if s in by_sev]
    values = [by_sev[s] for s in order]
    colors = [SEV_COLOR[s] for s in order]
    fig = go.Figure(go.Pie(
        labels=order, values=values,
        marker=dict(colors=colors, line=dict(color="white", width=2)),
        hole=0.60,
        textinfo="percent",
        textfont=dict(size=11, family="Inter"),
        hovertemplate="<b>%{label}</b>: %{value} findings (%{percent})<extra></extra>",
    ))
    fig.update_layout(**_lay(
        height=220,
        margin=dict(l=10, r=10, t=30, b=10),
        showlegend=True,
        legend=dict(orientation="v", x=1.02, y=0.5,
                    font=dict(size=11, color="#64748b")),
        title="Severity Breakdown",
    ))
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
        textfont=dict(size=12, family="Inter"),
        marker_line_width=2,
        marker_line_color="white",
        hovertemplate="<b>%{label}</b><br>%{value} findings<extra></extra>",
    )
    fig.update_layout(**_lay(
        height=280,
        margin=dict(l=0, r=0, t=4, b=0),
        coloraxis_showscale=False,
        title="Violations by Type",
    ))
    return fig


def hbar_chart(data: dict, title: str, color: str = BLUE, n: int = 8) -> go.Figure:
    df = (pd.DataFrame(list(data.items()), columns=["Label", "Count"])
            .sort_values("Count")
            .tail(n))
    fig = px.bar(df, x="Count", y="Label", orientation="h",
                 text="Count", title=title)
    fig.update_traces(
        marker_color=color,
        marker_line_width=0,
        textposition="outside",
        textfont=dict(size=10, color="#64748b"),
    )
    fig.update_layout(**_lay(height=max(200, n * 30 + 60)))
    fig.update_xaxes(visible=False)
    fig.update_yaxes(tickfont=dict(size=10, color="#475569"), showgrid=False, showline=False)
    return fig


def histogram_chart(findings: pd.DataFrame) -> go.Figure:
    fig = px.histogram(
        findings, x="risk_score", nbins=25,
        title="Risk Score Distribution",
        color_discrete_sequence=[BLUE],
    )
    fig.update_traces(marker_line_width=0, opacity=0.82)
    avg = findings["risk_score"].mean()
    fig.add_vline(
        x=avg, line_dash="dash", line_color="#ef4444", line_width=1.5,
        annotation_text=f"  avg {avg:.0f}",
        annotation_font=dict(size=11, color="#ef4444"),
        annotation_position="top right",
    )
    fig.update_layout(**_lay(height=260, bargap=0.06))
    fig.update_xaxes(title_text="Risk Score", title_font=dict(size=10, color="#94a3b8"))
    fig.update_yaxes(
        title_text="Findings", title_font=dict(size=10, color="#94a3b8"),
        showgrid=True, gridcolor="#f1f5f9",
    )
    return fig


def risk_scatter(findings: pd.DataFrame) -> go.Figure:
    """Bubble: access_level vs risk_score, coloured by severity."""
    df = findings.copy()
    df["bubble_size"] = df["risk_score"] * 0.45 + 3
    fig = px.scatter(
        df,
        x="access_level",
        y="risk_score",
        color="severity",
        size="bubble_size",
        size_max=18,
        color_discrete_map=SEV_COLOR,
        title="Risk by Access Level",
        labels={"access_level": "Access Level", "risk_score": "Risk Score"},
        hover_data={"employee_name": True, "system_name": True,
                    "finding_type": True, "bubble_size": False},
    )
    fig.update_layout(**_lay(height=260, legend_title="Severity"))
    fig.update_xaxes(showgrid=False, showline=True, linecolor="#e2e8f0")
    fig.update_yaxes(showgrid=True, gridcolor="#f1f5f9", zeroline=False)
    return fig


def dept_type_heatmap(findings: pd.DataFrame) -> go.Figure:
    """Heatmap of department × finding_type finding count."""
    pivot = (
        findings
        .groupby(["department", "finding_type"])
        .size()
        .reset_index(name="count")
        .pivot(index="department", columns="finding_type", values="count")
        .fillna(0)
    )
    pivot.columns = [c.replace("_", " ").title() for c in pivot.columns]

    fig = px.imshow(
        pivot.values,
        x=list(pivot.columns),
        y=list(pivot.index),
        color_continuous_scale=["#f0f9ff", "#93c5fd", "#2563eb", "#1e3a8a"],
        title="Finding Density: Department × Violation Type",
        labels={"x": "Violation Type", "y": "Department", "color": "Findings"},
        text_auto=True,
    )
    fig.update_traces(textfont=dict(size=10, family="Inter"))
    fig.update_layout(**_lay(height=320, margin=dict(l=16, r=16, t=48, b=16)))
    fig.update_xaxes(tickangle=-30, tickfont=dict(size=10))
    fig.update_yaxes(tickfont=dict(size=10))
    fig.update_coloraxes(showscale=False)
    return fig


def access_donut(df: pd.DataFrame) -> go.Figure:
    vc = df["access_level"].value_counts()
    _colors = {"admin": "#ef4444", "elevated": "#f97316", "standard": "#10b981"}
    fig = go.Figure(go.Pie(
        labels=vc.index.tolist(),
        values=vc.values.tolist(),
        marker=dict(
            colors=[_colors.get(x, "#94a3b8") for x in vc.index],
            line=dict(color="white", width=2),
        ),
        hole=0.60,
        textinfo="percent+label",
        textfont=dict(size=11, family="Inter"),
        hovertemplate="<b>%{label}</b>: %{value:,} grants (%{percent})<extra></extra>",
    ))
    fig.update_layout(**_lay(
        height=260,
        margin=dict(l=10, r=10, t=44, b=10),
        showlegend=False,
        title="Access Level Mix",
    ))
    return fig


def dept_access_bar(df: pd.DataFrame) -> go.Figure:
    grp = df.groupby(["department", "access_level"]).size().reset_index(name="n")
    _colors = {"admin": "#ef4444", "elevated": "#f97316", "standard": "#10b981"}
    fig = px.bar(
        grp, x="department", y="n", color="access_level",
        color_discrete_map=_colors,
        barmode="stack",
        title="Access by Department & Level",
    )
    fig.update_traces(marker_line_width=0)
    fig.update_layout(**_lay(height=280, legend_title="", xaxis_title="", yaxis_title=""))
    fig.update_xaxes(tickangle=-30, tickfont=dict(size=10))
    return fig


# ── HTML helpers ──────────────────────────────────────────────────────────────

def kpi_row_html(s: dict) -> str:
    def _card(icon, lbl, val, sub, accent):
        return (
            f'<div class="kpi" style="--a:{accent}">'
            f'  <div class="kpi-icon">{icon}</div>'
            f'  <div class="kpi-lbl">{lbl}</div>'
            f'  <div class="kpi-val">{val}</div>'
            f'  <div class="kpi-sub">{sub}</div>'
            f'</div>'
        )
    c = s.get("critical_findings",  0)
    h = s.get("high_findings",       0)
    m = s.get("medium_findings",     0)
    t = s.get("total_findings",      0)
    e = s.get("affected_employees",  0)
    r = s.get("compliance_rate",     0)
    cards = (
        _card("🚨", "Critical",  c,        "24h SLA",         "#ef4444") +
        _card("⚠️", "High",      h,        "72h SLA",         "#f97316") +
        _card("📋", "Medium",    m,        "5-day SLA",       "#f59e0b") +
        _card("🔍", "Total",     t,        "all findings",    BLUE)      +
        _card("👤", "Affected",  e,        "employees",       "#8b5cf6") +
        _card("✅", "Compliant", f"{r}%",  "access records",  "#10b981")
    )
    return f'<div class="kpi-grid">{cards}</div>'


def sev_badge(sev: str) -> str:
    c  = SEV_COLOR.get(sev, "#64748b")
    bg = SEV_BG.get(sev, "#f1f5f9")
    return (
        f'<span style="display:inline-block;padding:3px 10px;border-radius:20px;'
        f'font-size:0.72em;font-weight:700;letter-spacing:0.04em;'
        f'background:{bg};color:{c}">{sev}</span>'
    )


def finding_rows_html(findings: pd.DataFrame, n: int = 10) -> str:
    html = ""
    for _, r in findings.head(n).iterrows():
        sev = r["severity"]
        sc  = SEV_COLOR.get(sev, "#64748b")
        html += f"""
        <div class="frow" style="--sev:{sc}">
          <div>
            <div style="font-family:monospace;font-size:0.68em;color:#94a3b8;
                        margin-bottom:7px;word-break:break-all">{r['finding_id']}</div>
            {sev_badge(sev)}
          </div>
          <div>
            <div style="font-size:0.9em;font-weight:700;color:#0f172a;margin-bottom:4px">
              {r['finding_type'].replace('_', ' ').title()}
            </div>
            <div style="font-size:0.8em;color:#64748b;margin-bottom:5px">
              {r['employee_name']}
              &nbsp;<span style="color:#cbd5e1">·</span>&nbsp;
              {r['department']}
              &nbsp;<span style="color:#cbd5e1">·</span>&nbsp;
              {r['system_name']}
            </div>
            <div style="font-size:0.76em;color:#94a3b8;line-height:1.55">
              {str(r['detail'])[:150]}{'…' if len(str(r['detail'])) > 150 else ''}
            </div>
          </div>
          <div style="text-align:right;flex-shrink:0">
            <div style="font-size:1.85em;font-weight:800;color:{sc};line-height:1">
              {r['risk_score']:.0f}
            </div>
            <div style="font-size:0.62em;font-weight:700;text-transform:uppercase;
                        letter-spacing:0.06em;color:#94a3b8;margin-top:2px">risk</div>
          </div>
        </div>"""
    return html


def sec_hdr(text: str) -> None:
    st.markdown(f'<div class="sec-hdr">{text}</div>', unsafe_allow_html=True)


def page_title(h2: str, sub: str) -> None:
    st.markdown(
        f'<div style="margin-bottom:22px">'
        f'  <h2 style="font-size:1.5em;font-weight:800;color:#0f172a;'
        f'             margin:0 0 5px;letter-spacing:-0.025em">{h2}</h2>'
        f'  <p style="font-size:0.84em;color:#64748b;margin:0">{sub}</p>'
        f'</div>',
        unsafe_allow_html=True,
    )


# ── Sidebar (filters only) ────────────────────────────────────────────────────

def render_sidebar(findings: pd.DataFrame) -> dict:
    with st.sidebar:
        # Brand header
        st.markdown("""
        <div style="padding:28px 20px 22px;
                    border-bottom:1px solid rgba(255,255,255,0.07)">
          <div style="font-size:1.25em;font-weight:800;color:#f8fafc;
                      letter-spacing:-0.02em;margin-bottom:5px">
            🔒 GRC Platform
          </div>
          <div style="font-size:0.72em;color:#334155;font-weight:500">
            DataStream Technologies
          </div>
          <div style="margin-top:14px;display:flex;gap:6px;flex-wrap:wrap">
            <span style="background:#1e3a5f;color:#60a5fa;font-size:0.6em;
                         font-weight:700;padding:3px 8px;border-radius:4px;
                         letter-spacing:0.04em">SOC 2</span>
            <span style="background:#14301a;color:#4ade80;font-size:0.6em;
                         font-weight:700;padding:3px 8px;border-radius:4px;
                         letter-spacing:0.04em">PCI DSS</span>
            <span style="background:#2e1a3a;color:#c084fc;font-size:0.6em;
                         font-weight:700;padding:3px 8px;border-radius:4px;
                         letter-spacing:0.04em">ISO 27001</span>
          </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)

        # Filters
        filters: dict = {}
        if not findings.empty:
            sev_opts  = ["All"] + [s for s in BAND_ORDER if s in findings["severity"].unique()]
            dept_opts = ["All"] + sorted(findings["department"].unique().tolist())
            type_opts = ["All"] + sorted(findings["finding_type"].unique().tolist())

            filters["severity"]     = st.selectbox("Severity",     sev_opts,  key="f_sev")
            filters["department"]   = st.selectbox("Department",   dept_opts, key="f_dept")
            filters["finding_type"] = st.selectbox("Finding Type", type_opts, key="f_type")

        # Footer
        st.markdown("""
        <div style="position:fixed;bottom:0;left:0;width:248px;
                    padding:14px 20px;
                    border-top:1px solid rgba(255,255,255,0.06);
                    background:linear-gradient(180deg,transparent,#0f172a 60%)">
          <div style="font-size:0.6em;color:#1e3a5f;letter-spacing:0.04em;line-height:1.8">
            Control CTRL-IAM-001<br>Privileged Access Review<br>
            <span style="color:#263550">© 2025 DataStream Technologies</span>
          </div>
        </div>
        """, unsafe_allow_html=True)

    return filters


def apply_filters(findings: pd.DataFrame, filters: dict) -> pd.DataFrame:
    df = findings.copy()
    if filters.get("severity",     "All") != "All":
        df = df[df["severity"]     == filters["severity"]]
    if filters.get("department",   "All") != "All":
        df = df[df["department"]   == filters["department"]]
    if filters.get("finding_type", "All") != "All":
        df = df[df["finding_type"] == filters["finding_type"]]
    return df


# ── Page: Executive Dashboard ─────────────────────────────────────────────────

def page_executive(
    findings: pd.DataFrame,
    summary:  dict,
    employees: pd.DataFrame,
    access:    pd.DataFrame,
) -> None:
    page_title(
        "Privileged Access Review — Executive Dashboard",
        f"Control CTRL-IAM-001 · {len(employees):,} employees · "
        f"{int(access['is_active'].sum()):,} active grants · "
        f"{summary.get('affected_systems', 0)} systems with findings",
    )

    # Critical alert
    n_crit = summary.get("critical_findings", 0)
    if n_crit:
        st.markdown(
            f'<div class="alert-crit">🚨 <strong>{n_crit} CRITICAL finding(s)</strong> '
            f'require remediation within <strong>24 hours</strong> per SLA.</div>',
            unsafe_allow_html=True,
        )

    # KPI row
    st.markdown(kpi_row_html(summary), unsafe_allow_html=True)

    # Sub-tabs within executive page
    ov_tab, risk_tab, top_tab = st.tabs(
        ["📈  Overview", "🔬  Risk Analysis", "🏆  Top Findings"]
    )

    # ── Overview ──────────────────────────────────────────────────────────────
    with ov_tab:
        # Row 1: gauge · severity donut · treemap
        c1, c2, c3 = st.columns([1, 1, 1.35])

        with c1:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.plotly_chart(
                gauge_chart(summary.get("avg_risk_score", 0)),
                width="stretch", config=_CFG,
            )
            st.markdown("</div>", unsafe_allow_html=True)

        with c2:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.plotly_chart(
                donut_severity(summary.get("by_severity", {})),
                width="stretch", config=_CFG,
            )
            st.markdown("</div>", unsafe_allow_html=True)

        with c3:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.plotly_chart(
                treemap_chart(summary.get("by_type", {})),
                width="stretch", config=_CFG,
            )
            st.markdown("</div>", unsafe_allow_html=True)

        # Row 2: department bar · systems bar
        c4, c5 = st.columns(2)

        with c4:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.plotly_chart(
                hbar_chart(summary.get("by_department", {}),
                           "Findings by Department", "#8b5cf6"),
                width="stretch", config=_CFG,
            )
            st.markdown("</div>", unsafe_allow_html=True)

        with c5:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.plotly_chart(
                hbar_chart(summary.get("by_system", {}),
                           "Top Systems at Risk", "#f97316"),
                width="stretch", config=_CFG,
            )
            st.markdown("</div>", unsafe_allow_html=True)

    # ── Risk Analysis ─────────────────────────────────────────────────────────
    with risk_tab:
        # Row 1: histogram · scatter
        r1c1, r1c2 = st.columns(2)

        with r1c1:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.plotly_chart(histogram_chart(findings), width="stretch", config=_CFG)
            st.markdown("</div>", unsafe_allow_html=True)

        with r1c2:
            st.markdown('<div class="card">', unsafe_allow_html=True)
            st.plotly_chart(risk_scatter(findings), width="stretch", config=_CFG)
            st.markdown("</div>", unsafe_allow_html=True)

        # Row 2: heatmap (full width)
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.plotly_chart(dept_type_heatmap(findings), width="stretch", config=_CFG)
        st.markdown("</div>", unsafe_allow_html=True)

        # Row 3: finding type breakdown table
        sec_hdr("Finding Type Summary")
        breakdown = (
            findings
            .groupby(["finding_type", "severity"])
            .agg(count=("finding_id", "count"), avg_risk=("risk_score", "mean"))
            .reset_index()
            .rename(columns={
                "finding_type": "Type", "severity": "Severity",
                "count": "Count",       "avg_risk": "Avg Risk",
            })
            .sort_values("Avg Risk", ascending=False)
        )
        breakdown["Avg Risk"] = breakdown["Avg Risk"].round(1)
        breakdown["Type"] = breakdown["Type"].str.replace("_", " ").str.title()
        st.dataframe(
            breakdown, width="stretch", height=280,
            column_config={
                "Avg Risk": st.column_config.ProgressColumn(
                    "Avg Risk", min_value=0, max_value=100, format="%.1f"
                ),
            },
            hide_index=True,
        )

    # ── Top Findings ──────────────────────────────────────────────────────────
    with top_tab:
        c_left, c_right = st.columns([3, 1])
        with c_right:
            n_show = st.select_slider(
                "Show top N", options=[5, 8, 10, 15, 20], value=10, key="exec_topn"
            )
        sec_hdr(f"Top {n_show} findings ranked by risk score")
        st.markdown(finding_rows_html(findings, n=n_show), unsafe_allow_html=True)


# ── Page: Findings Explorer ───────────────────────────────────────────────────

def page_findings(findings: pd.DataFrame, filters: dict) -> None:
    page_title(
        "Findings Explorer",
        "Search, filter and drill into every individual compliance finding",
    )

    filtered = apply_filters(findings, filters)

    # Search bar
    search = st.text_input(
        "", placeholder="🔎  Search employee, system, type, department…",
        label_visibility="collapsed",
        key="search_box",
    )
    if search:
        mask = filtered.apply(
            lambda row: row.astype(str).str.contains(search, case=False).any(), axis=1
        )
        filtered = filtered[mask]

    # Quick metrics
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Findings",         len(filtered))
    m2.metric("Critical",         int((filtered["severity"] == "CRITICAL").sum()) if not filtered.empty else 0)
    m3.metric("Avg Risk Score",   f"{filtered['risk_score'].mean():.0f}" if not filtered.empty else "—")
    m4.metric("Systems Affected", filtered["system_name"].nunique() if not filtered.empty else 0)

    if filtered.empty:
        st.markdown("""
        <div style="text-align:center;padding:80px 0;color:#94a3b8">
          <div style="font-size:2.8em;margin-bottom:16px">🎉</div>
          <div style="font-size:1.1em;font-weight:700;color:#475569">No findings match the current filters</div>
          <div style="font-size:0.84em;margin-top:6px">Adjust the sidebar filters or clear the search above</div>
        </div>""", unsafe_allow_html=True)
        return

    # Two view modes
    tv, cv = st.tabs(["📋  Table View", "🗂️  Card View"])

    with tv:
        display = filtered[[
            "finding_id", "severity", "risk_score", "finding_type",
            "employee_name", "department", "system_name",
            "system_criticality", "access_level", "sla_deadline",
        ]].copy()
        display.columns = [
            "ID", "Severity", "Risk", "Type",
            "Employee", "Department", "System",
            "Criticality", "Access", "SLA Deadline",
        ]
        st.dataframe(
            display,
            width="stretch",
            height=440,
            column_config={
                "Risk": st.column_config.ProgressColumn(
                    "Risk", min_value=0, max_value=100, format="%.0f"
                ),
                "ID":   st.column_config.TextColumn("ID", width="small"),
            },
            hide_index=True,
        )
        st.download_button(
            "📥  Export Filtered CSV",
            data=filtered.to_csv(index=False).encode(),
            file_name="findings_filtered.csv",
            mime="text/csv",
        )

    with cv:
        per_page = 12
        n_pages  = max(1, -(-len(filtered) // per_page))
        if n_pages > 1:
            pg = st.number_input(
                "Page", min_value=1, max_value=n_pages, value=1, step=1, key="cv_pg"
            )
        else:
            pg = 1
        chunk = filtered.iloc[(pg - 1) * per_page : pg * per_page]
        st.markdown(finding_rows_html(chunk, n=per_page), unsafe_allow_html=True)
        if n_pages > 1:
            st.caption(f"Page {pg} of {n_pages}  ·  {len(filtered):,} total findings")

    # ── Detail panel ──────────────────────────────────────────────────────────
    st.markdown("<hr>", unsafe_allow_html=True)
    sec_hdr("Finding Detail — drill into a single finding")

    sel = st.selectbox(
        "Select finding ID",
        filtered["finding_id"].tolist(),
        label_visibility="collapsed",
        key="detail_sel",
    )
    if sel:
        r   = filtered[filtered["finding_id"] == sel].iloc[0]
        sev = r["severity"]
        sc  = SEV_COLOR.get(sev, "#64748b")
        sbg = SEV_BG.get(sev,   "#f1f5f9")

        ca, cb = st.columns([1.5, 1])

        with ca:
            st.markdown(f"""
            <div style="background:white;border-radius:14px;padding:26px;
                        border-left:5px solid {sc};
                        box-shadow:0 1px 3px rgba(0,0,0,0.05),0 6px 20px rgba(0,0,0,0.05)">
              <div style="display:flex;justify-content:space-between;
                          align-items:flex-start;margin-bottom:16px">
                <div>
                  <div style="font-family:monospace;font-size:0.7em;color:#94a3b8;
                              margin-bottom:6px">{r['finding_id']}  ·  {r['rule_id']}</div>
                  <div style="font-size:1.12em;font-weight:700;color:#0f172a">{r['rule_name']}</div>
                </div>
                {sev_badge(sev)}
              </div>
              <div style="font-size:0.88em;color:#475569;line-height:1.75;
                          border-top:1px solid #f1f5f9;padding-top:16px">
                {r['detail']}
              </div>
              <div style="margin-top:16px;padding-top:14px;border-top:1px solid #f8fafc;
                          font-size:0.76em;color:#94a3b8">
                <strong>Frameworks:</strong> {r['frameworks']}
              </div>
            </div>
            """, unsafe_allow_html=True)

        with cb:
            meta_rows = "".join(
                f'<div style="display:flex;justify-content:space-between;'
                f'padding:9px 0;border-bottom:1px solid #f8fafc;font-size:0.85em">'
                f'<span style="color:#94a3b8">{k}</span>'
                f'<span style="font-weight:600;color:#1e293b">{v}</span></div>'
                for k, v in [
                    ("Employee",    r["employee_name"]),
                    ("Department",  r["department"]),
                    ("System",      r["system_name"]),
                    ("Access",      r["access_level"].upper()),
                    ("Criticality", r["system_criticality"].upper()),
                    ("Risk Score",  f"{r['risk_score']} / 100"),
                    ("Risk Band",   r["risk_band"]),
                    ("SLA",         str(r["sla_deadline"])[:16]),
                    ("Status",      r.get("status", "OPEN")),
                ]
            )
            st.markdown(f"""
            <div style="background:white;border-radius:14px;padding:22px;
                        box-shadow:0 1px 3px rgba(0,0,0,0.05),0 6px 20px rgba(0,0,0,0.05)">
              <div style="font-size:0.65em;font-weight:700;text-transform:uppercase;
                          letter-spacing:0.09em;color:#94a3b8;margin-bottom:14px">Metadata</div>
              {meta_rows}
            </div>
            """, unsafe_allow_html=True)


# ── Page: Access Inventory ────────────────────────────────────────────────────

def page_access(
    access: pd.DataFrame,
    employees: pd.DataFrame,
    systems,
) -> None:
    page_title(
        "Access Inventory",
        "All access grants across employees and systems — with live filtering",
    )

    # Inline filters
    fc1, fc2, fc3, fc4 = st.columns(4)
    emp_f    = fc1.selectbox("Employee Status",    ["All", "active", "terminated", "on_leave"])
    acc_f    = fc2.selectbox("Access Level",       ["All", "admin", "elevated", "standard"])
    crit_f   = fc3.selectbox("System Criticality", ["All", "critical", "high", "medium", "low"])
    act_only = fc4.checkbox("Active grants only", value=True)

    merged = access.merge(
        employees[["employee_id", "full_name", "department", "status", "title"]],
        on="employee_id", how="left",
    )
    df = merged.copy()
    if act_only:        df = df[df["is_active"]]
    if emp_f  != "All": df = df[df["status"]             == emp_f]
    if acc_f  != "All": df = df[df["access_level"]       == acc_f]
    if crit_f != "All": df = df[df["system_criticality"] == crit_f]

    admin_n = int((df["access_level"] == "admin").sum())

    # Stats row
    st.markdown(f"""
    <div class="stat-grid">
      <div class="stat">
        <div class="stat-val">{len(df):,}</div>
        <div class="stat-lbl">Access Records</div>
      </div>
      <div class="stat">
        <div class="stat-val">{df['employee_id'].nunique():,}</div>
        <div class="stat-lbl">Unique Employees</div>
      </div>
      <div class="stat">
        <div class="stat-val">{df['system_id'].nunique()}</div>
        <div class="stat-lbl">Systems</div>
      </div>
      <div class="stat" style="border-top:3px solid #ef4444">
        <div class="stat-val" style="color:#ef4444">{admin_n}</div>
        <div class="stat-lbl">Admin Grants</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Sub-tabs
    t_charts, t_table, t_admin = st.tabs(
        ["📊  Charts", "📋  Access Table", "🔐  Admin Analysis"]
    )

    with t_charts:
        c1, c2 = st.columns(2)
        with c1:
            st.plotly_chart(access_donut(df), width="stretch", config=_CFG)
        with c2:
            st.plotly_chart(dept_access_bar(df), width="stretch", config=_CFG)

        # Critical systems without justification
        no_just = df[
            (df["system_criticality"] == "critical") &
            (df["business_justification"].isna() | (df["business_justification"].str.strip() == ""))
        ]
        if not no_just.empty:
            st.markdown(f"""
            <div style="background:#fef2f2;border-left:4px solid #ef4444;border-radius:10px;
                        padding:14px 18px;margin-top:4px;font-size:0.88em;color:#991b1b;font-weight:600">
              ⚠️ <strong>{len(no_just)} critical-system grants</strong> have no business
              justification on record — review recommended.
            </div>""", unsafe_allow_html=True)

    with t_table:
        show = df[[
            "access_id", "full_name", "department", "status",
            "system_name", "system_criticality", "access_level",
            "granted_date", "last_used_date", "is_active", "business_justification",
        ]].rename(columns={
            "access_id": "ID", "full_name": "Employee", "department": "Dept",
            "status": "Emp Status", "system_name": "System",
            "system_criticality": "Criticality", "access_level": "Level",
            "granted_date": "Granted", "last_used_date": "Last Used",
            "is_active": "Active", "business_justification": "Justification",
        })
        st.dataframe(
            show,
            width="stretch",
            height=440,
            column_config={"Active": st.column_config.CheckboxColumn("Active")},
            hide_index=True,
        )
        st.download_button(
            "📥  Export Access Records (CSV)",
            data=df.to_csv(index=False).encode(),
            file_name="access_inventory.csv",
            mime="text/csv",
        )

    with t_admin:
        admins = df[df["access_level"] == "admin"].copy()
        if admins.empty:
            st.info("No admin grants match the current filters.")
        else:
            sec_hdr(
                f"{len(admins)} admin grant(s) — sorted by Last Used (oldest = highest risk)"
            )
            admins_show = admins[[
                "full_name", "department", "system_name", "system_criticality",
                "granted_date", "last_used_date", "business_justification",
            ]].rename(columns={
                "full_name": "Employee", "department": "Dept",
                "system_name": "System", "system_criticality": "Criticality",
                "granted_date": "Granted", "last_used_date": "Last Used",
                "business_justification": "Justification",
            }).sort_values("Last Used", na_position="first")

            st.dataframe(admins_show, width="stretch", height=420, hide_index=True)
            st.download_button(
                "📥  Export Admin Grants (CSV)",
                data=admins.to_csv(index=False).encode(),
                file_name="admin_grants.csv",
                mime="text/csv",
            )


# ── Page: Control Configuration ──────────────────────────────────────────────

def page_config() -> None:
    page_title(
        "Control Configuration",
        "Detection rules, scoring weights and compliance framework mapping",
    )

    cfg, raw_yaml = load_config_yaml()
    ctrl    = cfg["control"]
    rules   = cfg["detection_rules"]
    scoring = cfg["scoring"]

    # Control overview banner
    st.markdown(f"""
    <div style="background:white;border-radius:14px;padding:24px 28px;
                box-shadow:0 1px 3px rgba(0,0,0,0.05),0 4px 18px rgba(0,0,0,0.04);
                border-left:5px solid {BLUE};margin-bottom:24px">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:24px">
        <div style="flex:1">
          <div style="font-family:monospace;font-size:0.7em;color:#94a3b8;margin-bottom:6px">
            {ctrl['id']}
          </div>
          <div style="font-size:1.2em;font-weight:800;color:#0f172a;margin-bottom:10px">
            {ctrl['name']}
          </div>
          <div style="font-size:0.86em;color:#64748b;line-height:1.75">
            {ctrl['description'].strip()}
          </div>
        </div>
        <div style="text-align:right;flex-shrink:0">
          <span style="background:#f0fdf4;color:#10b981;padding:5px 14px;
                       border-radius:20px;font-size:0.76em;font-weight:700;
                       letter-spacing:0.04em">● ACTIVE</span>
          <div style="font-size:0.78em;color:#94a3b8;margin-top:12px;line-height:1.8">
            Owner: {ctrl['owner']}<br>Cadence: {ctrl['frequency']}
          </div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    t_rules, t_fw, t_yaml = st.tabs(
        ["🛡️  Detection Rules", "📋  Framework Coverage", "🔧  Raw YAML"]
    )

    # ── Detection Rules ───────────────────────────────────────────────────────
    with t_rules:
        for rule in rules:
            sev = rule["severity"]
            sc  = SEV_COLOR.get(sev, "#666")
            sbg = SEV_BG.get(sev,   "#f5f5f5")
            with st.expander(
                f"**{rule['name']}**  ·  `{rule['id']}`",
                expanded=False,
            ):
                ca, cb = st.columns([2, 1])
                with ca:
                    fw_pills = "".join(
                        f'<span style="display:inline-block;padding:3px 10px;'
                        f'border-radius:5px;font-size:0.72em;font-weight:600;'
                        f'margin:2px;background:#f1f5f9;color:#475569">{fw}</span>'
                        for fw in rule.get("frameworks", [])
                    )
                    st.markdown(f"""
                    <div style="font-size:0.87em;color:#475569;line-height:1.75;
                                margin-bottom:12px">
                      {rule['description'].strip()}
                    </div>
                    <div style="margin-top:4px">{fw_pills}</div>
                    """, unsafe_allow_html=True)
                with cb:
                    st.markdown(f"""
                    <div style="text-align:center;background:{sbg};border-radius:12px;
                                padding:18px;border:1px solid {sc}33">
                      <div style="font-size:0.65em;color:#94a3b8;font-weight:700;
                                  text-transform:uppercase;letter-spacing:.07em;
                                  margin-bottom:8px">Severity</div>
                      <div style="font-size:1.7em;font-weight:800;color:{sc}">{sev}</div>
                      <div style="font-size:0.72em;color:#94a3b8;margin-top:6px">
                        SLA: {rule['sla_hours']} hours
                      </div>
                    </div>
                    """, unsafe_allow_html=True)

    # ── Framework Coverage ────────────────────────────────────────────────────
    with t_fw:
        fws = ctrl.get("frameworks", [])
        n_cols = min(len(fws), 4)
        if n_cols:
            cols = st.columns(n_cols)
            for i, fw in enumerate(fws):
                with cols[i % n_cols]:
                    st.markdown(f"""
                    <div style="background:white;border-radius:12px;
                                padding:18px 20px;margin-bottom:14px;
                                box-shadow:0 1px 3px rgba(0,0,0,0.05);
                                border-top:3px solid {BLUE}">
                      <div style="font-weight:700;color:#1e293b;font-size:0.9em;
                                  margin-bottom:6px">{fw['ref']}</div>
                      <div style="font-size:0.78em;color:#64748b;line-height:1.65">
                        {fw['description']}
                      </div>
                    </div>
                    """, unsafe_allow_html=True)

        # Scoring weights
        st.markdown("<br>", unsafe_allow_html=True)
        sec_hdr("Risk Scoring Weights")
        sc1, sc2, sc3 = st.columns(3)
        with sc1:
            wt = scoring.get("severity_base", {})
            st.markdown("**Severity → Base Score**")
            st.dataframe(
                pd.DataFrame(list(wt.items()), columns=["Severity", "Base Score"]),
                hide_index=True, width="stretch",
            )
        with sc2:
            wt2 = scoring.get("system_criticality_multiplier", {})
            st.markdown("**Criticality Multiplier**")
            st.dataframe(
                pd.DataFrame(list(wt2.items()), columns=["Criticality", "Multiplier"]),
                hide_index=True, width="stretch",
            )
        with sc3:
            wt3 = scoring.get("access_level_multiplier", {})
            st.markdown("**Access Level Multiplier**")
            st.dataframe(
                pd.DataFrame(list(wt3.items()), columns=["Access Level", "Multiplier"]),
                hide_index=True, width="stretch",
            )

    # ── Raw YAML ──────────────────────────────────────────────────────────────
    with t_yaml:
        st.code(raw_yaml, language="yaml")


# ── Page: Evidence Packages ───────────────────────────────────────────────────

def page_evidence(
    findings: pd.DataFrame,
    employees: pd.DataFrame,
    access: pd.DataFrame,
    summary: dict,
) -> None:
    page_title(
        "Evidence Packages",
        "One-click audit-ready exports for SOC 2, PCI DSS and ISO 27001 auditors",
    )

    st.markdown("""
    <div style="background:#eff6ff;border-left:4px solid #3b82f6;border-radius:10px;
                padding:14px 18px;margin-bottom:24px;
                font-size:0.88em;color:#1d4ed8;font-weight:500">
      ℹ️  Each package is timestamped and contains findings, access snapshot, employee data,
      and an HTML manifest — suitable for direct submission to compliance auditors.
    </div>
    """, unsafe_allow_html=True)

    c1, c2 = st.columns(2)

    with c1:
        st.markdown("""
        <div class="card" style="min-height:240px">
          <div style="font-size:1.05em;font-weight:700;color:#1e293b;margin-bottom:8px">
            📦  Evidence Package
          </div>
          <div style="font-size:0.82em;color:#64748b;line-height:1.9;margin-bottom:20px">
            Timestamped directory containing:<br>
            <code>findings.json</code> &nbsp;/&nbsp; <code>findings.csv</code><br>
            <code>access_snapshot.csv</code><br>
            <code>employee_snapshot.csv</code><br>
            <code>summary.json</code> &nbsp;/&nbsp; <code>manifest.html</code>
          </div>
        """, unsafe_allow_html=True)
        if st.button("⚡  Generate Evidence Package", type="primary",
                     use_container_width=True, key="gen_pkg"):
            with st.spinner("Generating evidence package…"):
                pkg = generate_evidence_package(
                    findings, employees, access, summary,
                    output_dir=ROOT / "outputs" / "evidence",
                )
            st.success(f"✅  Saved to `{pkg.name}`")
            manifest = (pkg / "manifest.html").read_text(encoding="utf-8")
            st.download_button(
                "📋  Download Manifest (HTML)",
                data=manifest.encode(),
                file_name="evidence_manifest.html",
                mime="text/html",
                use_container_width=True,
            )
        st.markdown("</div>", unsafe_allow_html=True)

    with c2:
        st.markdown("""
        <div class="card" style="min-height:240px">
          <div style="font-size:1.05em;font-weight:700;color:#1e293b;margin-bottom:8px">
            📄  Executive Report
          </div>
          <div style="font-size:0.82em;color:#64748b;line-height:1.9;margin-bottom:20px">
            Printable HTML report containing:<br>
            Executive KPI summary with risk scoring<br>
            Findings by type, severity and department<br>
            Full findings table with SLA status<br>
            Suitable for board / management review
          </div>
        """, unsafe_allow_html=True)
        if st.button("⚡  Generate Executive Report", type="primary",
                     use_container_width=True, key="gen_rpt"):
            with st.spinner("Building report…"):
                ts  = time.strftime("%Y%m%d_%H%M%S")
                rpt = ROOT / "outputs" / "reports" / f"par_report_{ts}.html"
                build_html_report(findings, summary, rpt)
            st.success(f"✅  Saved to `{rpt.name}`")
            html = rpt.read_text(encoding="utf-8")
            st.download_button(
                "📋  Download Report (HTML)",
                data=html.encode(),
                file_name="par_executive_report.html",
                mime="text/html",
                use_container_width=True,
            )
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<hr>", unsafe_allow_html=True)
    sec_hdr("Quick Exports")

    e1, e2, e3 = st.columns(3)
    with e1:
        st.download_button(
            "📊  All Findings (CSV)",
            data=findings.to_csv(index=False).encode(),
            file_name="all_findings.csv", mime="text/csv",
            use_container_width=True,
        )
    with e2:
        st.download_button(
            "👥  Employee Snapshot (CSV)",
            data=employees.to_csv(index=False).encode(),
            file_name="employees.csv", mime="text/csv",
            use_container_width=True,
        )
    with e3:
        st.download_button(
            "🔐  Active Access (CSV)",
            data=access[access["is_active"]].to_csv(index=False).encode(),
            file_name="active_access.csv", mime="text/csv",
            use_container_width=True,
        )


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    with st.spinner("Loading GRC data…"):
        employees, access, systems, findings, summary = load_data()

    filters = render_sidebar(findings)

    # Primary navigation via native st.tabs (100% reliable, no CSS hackery)
    t_exec, t_find, t_acc, t_cfg, t_evi = st.tabs([
        "📊  Executive Dashboard",
        "🔍  Findings Explorer",
        "🗝️  Access Inventory",
        "⚙️  Control Configuration",
        "📦  Evidence Packages",
    ])

    with t_exec: page_executive(findings, summary, employees, access)
    with t_find: page_findings(findings, filters)
    with t_acc:  page_access(access, employees, systems)
    with t_cfg:  page_config()
    with t_evi:  page_evidence(findings, employees, access, summary)


if __name__ == "__main__":
    main()
