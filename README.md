# GRC Control Automation — Privileged Access Review
### DataStream Technologies · SOC 2 | PCI DSS | ISO 27001

A production-grade, end-to-end automation of the **Privileged Access Review (PAR)** control — transforming a manual, error-prone quarterly process into a continuous, evidence-generating compliance engine with an interactive dashboard.

---

## Problem Statement

**Before automation**, DataStream Technologies ran Privileged Access Review manually:

| Pain Point | Impact |
|---|---|
| 11+ hours of quarterly data exports from 6+ systems | Stale data by the time review completes |
| Email-based manager approvals with ~40% response rate | Reviews never formally closed |
| Terminated users retained access for weeks | Direct SOC 2 / PCI DSS violation risk |
| Evidence compiled days after review period ends | Auditors flag it as non-contemporaneous |
| Zero visibility into dormant or excessive privilege | Attack surface unknown |

**Quarterly reviews only meet the compliance minimum — they do not achieve the actual security objective: continuous appropriateness of access.**

---

## Solution Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    GRC Automation Platform                       │
│                                                                  │
│  Data Sources          Detection Engine        Outputs           │
│  ┌──────────┐         ┌──────────────────┐   ┌──────────────┐  │
│  │ HRIS /   │──────▶  │  7 Detection     │──▶│  Findings    │  │
│  │ Workday  │         │  Rules (YAML)    │   │  Dashboard   │  │
│  └──────────┘         │                  │   └──────────────┘  │
│  ┌──────────┐         │  • Terminated    │   ┌──────────────┐  │
│  │ IAM /    │──────▶  │    Access        │──▶│  Evidence    │  │
│  │ Okta     │         │  • Dormant 90d   │   │  Packages    │  │
│  └──────────┘         │  • Excessive     │   └──────────────┘  │
│  ┌──────────┐         │    Privilege     │   ┌──────────────┐  │
│  │ System   │──────▶  │  • SoD Conflict  │──▶│  Executive   │  │
│  │ Access   │         │  • MFA Missing   │   │  Reports     │  │
│  │ Logs     │         │  • Orphaned Acc  │   └──────────────┘  │
│  └──────────┘         │  • Unjustified   │                      │
│                        │    Critical Acc  │   Risk Scoring       │
│                        └──────────────────┘   0–100 composite    │
└─────────────────────────────────────────────────────────────────┘
```

### Seven-Phase Automation Framework

Following the methodology from `control-automation-design.md`:

| Phase | What We Did |
|---|---|
| **1. Intent Analysis** | Defined goal as *continuous access appropriateness*, not quarterly checkbox |
| **2. Failure Mapping** | Documented 5 manual workflow breakpoints (stale data, email reviews, delayed revocation) |
| **3. Architecture Design** | Automated data aggregation from HRIS + IAM + access logs |
| **4. Detection Rules** | 7 YAML-configured rules with severity, SLA, and framework mapping |
| **5. Evidence Generation** | Audit-ready packages (JSON + CSV + HTML) generated automatically |
| **6. Manual/Auto Separation** | Engine detects; humans approve remediation (no auto-revocation) |
| **7. Residual Risk Assessment** | False positives documented; compensating controls identified |

---

## Project Structure

```
04-grc-control-automation/
├── config/
│   ├── controls.yaml          # Detection rules, scoring, SLAs, frameworks
│   └── settings.yaml          # App settings & simulation parameters
├── src/
│   ├── data_generator.py      # Realistic synthetic data (210 employees, 20 systems)
│   ├── control_engine.py      # 7 detection rules → findings DataFrame
│   ├── risk_scorer.py         # 0–100 composite risk scoring algorithm
│   ├── evidence_generator.py  # Audit-ready evidence packages
│   └── report_builder.py      # Printable HTML executive report
├── dashboard/
│   └── app.py                 # Streamlit interactive dashboard (5 pages)
├── outputs/
│   ├── evidence/              # Generated evidence packages
│   └── reports/               # Generated HTML reports
├── tests/
│   └── test_control_engine.py # 35+ unit tests (pytest)
├── run_automation.py          # CLI runner with rich terminal output
└── requirements.txt
```

---

## Quick Start

### 1. Install dependencies

```bash
cd "04-grc-control-automation"
pip install -r requirements.txt
```

### 2. Run the CLI engine

```bash
# Print findings summary to terminal
python run_automation.py

# Save evidence package + HTML report
python run_automation.py --all
```

### 3. Launch the dashboard

```bash
streamlit run dashboard/app.py
```

Open [http://localhost:8501](http://localhost:8501) in your browser.

### 4. Run unit tests

```bash
pytest tests/ -v
```

---

## Detection Rules

| Rule | Type | Severity | SLA |
|---|---|---|---|
| RULE-001 | Terminated User Active Access | **CRITICAL** | 24 hours |
| RULE-002 | Dormant Access — 90 Days | **HIGH** | 7 days |
| RULE-003 | Excessive Privilege — Role Mismatch | **HIGH** | 72 hours |
| RULE-004 | Separation of Duties Conflict | **CRITICAL** | 48 hours |
| RULE-005 | MFA Not Enabled on Privileged Account | **HIGH** | 24 hours |
| RULE-006 | Orphaned Account — No Active Owner | **HIGH** | 72 hours |
| RULE-007 | Critical System Access Without Justification | **MEDIUM** | 5 days |

All rules are declaratively configured in `config/controls.yaml` — adding a new rule requires no code changes.

---

## Risk Scoring

Each finding receives a **composite risk score (0–100)**:

```
risk_score = base_severity × system_criticality_mult × access_level_mult
```

| Component | Values |
|---|---|
| Base severity | CRITICAL=100, HIGH=70, MEDIUM=40, LOW=15 |
| System criticality | critical=1.0, high=0.8, medium=0.55, low=0.3 |
| Access level | admin=1.0, elevated=0.75, standard=0.45 |

Risk bands: **CRITICAL** (≥80) · **HIGH** (≥55) · **MEDIUM** (≥30) · **LOW** (<30)

---

## Dashboard Pages

| Page | Contents |
|---|---|
| **Executive Dashboard** | KPI cards, severity chart, finding-type donut, department heatmap, risk distribution |
| **Findings Explorer** | Filterable findings table, search, per-finding detail card with SLA |
| **Access Inventory** | Full access rights view with filters, access-level breakdown charts |
| **Control Configuration** | All detection rules, framework coverage, raw YAML viewer |
| **Evidence Packages** | One-click evidence package and report generation with download |

---

## Compliance Framework Coverage

| Control Ref | Framework | Requirement |
|---|---|---|
| CC6.2 | SOC 2 | Logical access removed timely on termination |
| CC6.3 | SOC 2 | Access based on principle of least privilege |
| 7.2.1 | PCI DSS v4.0 | Access is based on need to know |
| 8.1.4 | PCI DSS v4.0 | Inactive accounts removed within 90 days |
| 8.4.2 | PCI DSS v4.0 | MFA for all access into the CDE |
| A.9.2.6 | ISO 27001 | Access rights removed/adjusted on employment change |
| A.9.2.5 | ISO 27001 | Regular review of access rights |

---

## Key Design Decisions

**Why not auto-revoke access?**
The engine detects; humans remediate. Automated revocation carries risk of business disruption (e.g., revoking a contractor mid-project). The control design is intentional: instant detection + human-approved revocation within SLA.

**Why synthetic data?**
The 210-employee dataset is generated deterministically (fixed seed=42) so every demo run produces identical findings. Violations are deliberately injected at realistic ratios from the `settings.yaml` simulation block.

**Why YAML-configured rules?**
Security teams should be able to adjust thresholds (e.g., change dormancy from 90→60 days) without touching Python. YAML rules separate policy from implementation.

**Evidence retention**
All packages include timestamps and are structured for 7-year retention per financial services requirements.

---

## Automation Impact

| Metric | Before | After |
|---|---|---|
| Time to complete review | 11+ hours/quarter | **< 5 minutes** (continuous) |
| Detection lag (terminated user) | 30–90 days | **< 1 hour** |
| Evidence generation | 2–3 days post-review | **Instant, automated** |
| Manager response rate | ~40% | **N/A — automated detection** |
| Review frequency | Quarterly | **Continuous** |
| False-positive handling | Manual | **Rule-based, documented** |

---

*DataStream Technologies · GRC Control Automation Platform v1.0*
*Control CTRL-IAM-001 · SOC 2 Type II · PCI DSS v4.0 · ISO 27001:2022*
