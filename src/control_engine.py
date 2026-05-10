"""
Core detection engine.
Runs all configured detection rules against the dataset and produces a
findings DataFrame with full metadata for evidence and reporting.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pandas as pd
import yaml

from src.risk_scorer import compute_score, score_to_band

# ── Load rule definitions ────────────────────────────────────────────────────

def _load_rules() -> list[dict]:
    path = Path(__file__).parent.parent / "config" / "controls.yaml"
    with open(path) as f:
        return yaml.safe_load(f)["detection_rules"]


RULES = _load_rules()
_RULE_MAP = {r["id"]: r for r in RULES}

NOW = datetime.now()


def _finding(
    rule_id: str,
    employee_id: str,
    employee_name: str,
    department: str,
    system_id: str,
    system_name: str,
    system_criticality: str,
    access_level: str,
    access_id: str,
    detail: str,
    extra: dict | None = None,
) -> dict[str, Any]:
    rule = _RULE_MAP[rule_id]
    severity = rule["severity"]
    risk_score = compute_score(severity, system_criticality, access_level)
    risk_band = score_to_band(risk_score)
    sla_hours = rule["sla_hours"]

    return {
        "finding_id":         f"FND-{uuid.uuid4().hex[:8].upper()}",
        "rule_id":            rule_id,
        "rule_name":          rule["name"],
        "finding_type":       rule["type"],
        "severity":           severity,
        "risk_score":         risk_score,
        "risk_band":          risk_band,
        "employee_id":        employee_id,
        "employee_name":      employee_name,
        "department":         department,
        "system_id":          system_id,
        "system_name":        system_name,
        "system_criticality": system_criticality,
        "access_level":       access_level,
        "access_id":          access_id,
        "detail":             detail,
        "status":             "OPEN",
        "detected_at":        NOW.strftime("%Y-%m-%d %H:%M:%S"),
        "sla_deadline":       (NOW + timedelta(hours=sla_hours)).strftime("%Y-%m-%d %H:%M:%S"),
        "frameworks":         ", ".join(rule.get("frameworks", [])),
        **(extra or {}),
    }


# ── Individual rule detectors ─────────────────────────────────────────────────

def detect_terminated_access(employees: pd.DataFrame, access: pd.DataFrame) -> list[dict]:
    """RULE-001: Active access belonging to terminated employees."""
    term = employees[employees["status"] == "terminated"][["employee_id", "full_name", "department", "termination_date"]]
    active_access = access[access["is_active"]]
    hits = active_access.merge(term, on="employee_id")
    findings = []
    for _, row in hits.iterrows():
        days_overdue = (NOW - datetime.strptime(row["termination_date"], "%Y-%m-%d")).days if row["termination_date"] else "?"
        findings.append(_finding(
            rule_id="RULE-001",
            employee_id=row["employee_id"],
            employee_name=row["full_name"],
            department=row["department"],
            system_id=row["system_id"],
            system_name=row["system_name"],
            system_criticality=row["system_criticality"],
            access_level=row["access_level"],
            access_id=row["access_id"],
            detail=f"Employee terminated {days_overdue} day(s) ago; access to '{row['system_name']}' was never revoked.",
        ))
    return findings


def detect_dormant_access(employees: pd.DataFrame, access: pd.DataFrame, threshold_days: int = 90) -> list[dict]:
    """RULE-002: Access not used in 90+ days."""
    active_emps = employees[employees["status"] == "active"][["employee_id", "full_name", "department"]]
    active_access = access[access["is_active"]]
    merged = active_access.merge(active_emps, on="employee_id")
    findings = []
    for _, row in merged.iterrows():
        last_used = datetime.strptime(row["last_used_date"], "%Y-%m-%d")
        days_dormant = (NOW - last_used).days
        if days_dormant >= threshold_days:
            findings.append(_finding(
                rule_id="RULE-002",
                employee_id=row["employee_id"],
                employee_name=row["full_name"],
                department=row["department"],
                system_id=row["system_id"],
                system_name=row["system_name"],
                system_criticality=row["system_criticality"],
                access_level=row["access_level"],
                access_id=row["access_id"],
                detail=f"Access to '{row['system_name']}' has not been used in {days_dormant} days (last used {row['last_used_date']}).",
            ))
    return findings


def detect_excessive_privilege(employees: pd.DataFrame, access: pd.DataFrame) -> list[dict]:
    """RULE-003: Admin/elevated access for roles that don't require it."""
    standard_depts = {"Sales", "Marketing", "Legal"}
    standard_role_emps = employees[
        employees["department"].isin(standard_depts) & (employees["status"] == "active")
    ][["employee_id", "full_name", "department"]]

    priv_access = access[access["access_level"].isin(["admin", "elevated"]) & access["is_active"]]
    merged = priv_access.merge(standard_role_emps, on="employee_id")
    findings = []
    for _, row in merged.iterrows():
        findings.append(_finding(
            rule_id="RULE-003",
            employee_id=row["employee_id"],
            employee_name=row["full_name"],
            department=row["department"],
            system_id=row["system_id"],
            system_name=row["system_name"],
            system_criticality=row["system_criticality"],
            access_level=row["access_level"],
            access_id=row["access_id"],
            detail=(
                f"'{row['full_name']}' ({row['department']}) holds {row['access_level'].upper()} "
                f"access on '{row['system_name']}'. Role does not require elevated privilege."
            ),
        ))
    return findings


def detect_sod_conflicts(employees: pd.DataFrame, access: pd.DataFrame) -> list[dict]:
    """RULE-004: Same employee holds both sides of a conflicting role pair."""
    CONFLICT_PAIRS = [
        ("financial_initiator", "financial_approver"),
        ("code_developer",      "code_deployer"),
        ("user_admin",          "user_auditor"),
        ("data_entry",          "data_approver"),
    ]
    active_emps = employees[employees["status"] == "active"][["employee_id", "full_name", "department"]]
    sod_access = access[access["sod_role"].notna() & access["is_active"]]
    merged = sod_access.merge(active_emps, on="employee_id")

    findings = []
    for emp_id, grp in merged.groupby("employee_id"):
        roles = set(grp["sod_role"])
        emp_row = grp.iloc[0]
        for role_a, role_b in CONFLICT_PAIRS:
            if role_a in roles and role_b in roles:
                system_name = emp_row["system_name"]
                findings.append(_finding(
                    rule_id="RULE-004",
                    employee_id=emp_id,
                    employee_name=emp_row["full_name"],
                    department=emp_row["department"],
                    system_id=emp_row["system_id"],
                    system_name=system_name,
                    system_criticality=emp_row["system_criticality"],
                    access_level=emp_row["access_level"],
                    access_id=emp_row["access_id"],
                    detail=(
                        f"SoD violation: '{emp_row['full_name']}' holds both '{role_a}' and '{role_b}' "
                        f"roles on '{system_name}'. Compensating control or role split required."
                    ),
                ))
    return findings


def detect_mfa_missing(employees: pd.DataFrame, access: pd.DataFrame) -> list[dict]:
    """RULE-005: Privileged accounts without MFA enabled."""
    no_mfa = employees[~employees["mfa_enabled"] & (employees["status"] == "active")][
        ["employee_id", "full_name", "department"]
    ]
    priv_access = access[access["access_level"].isin(["admin", "elevated"]) & access["is_active"]]
    merged = priv_access.merge(no_mfa, on="employee_id")
    findings = []
    seen: set[str] = set()
    for _, row in merged.iterrows():
        if row["employee_id"] in seen:
            continue
        seen.add(row["employee_id"])
        findings.append(_finding(
            rule_id="RULE-005",
            employee_id=row["employee_id"],
            employee_name=row["full_name"],
            department=row["department"],
            system_id=row["system_id"],
            system_name=row["system_name"],
            system_criticality=row["system_criticality"],
            access_level=row["access_level"],
            access_id=row["access_id"],
            detail=(
                f"'{row['full_name']}' has {row['access_level'].upper()} privileges but "
                f"MFA is not enabled on their account. Mandatory for all privileged access."
            ),
        ))
    return findings


def detect_orphaned_accounts(employees: pd.DataFrame, access: pd.DataFrame) -> list[dict]:
    """RULE-006: Active access records whose employee owner is terminated."""
    term = employees[employees["status"] == "terminated"][["employee_id", "full_name", "department"]]
    orphaned = access[access["is_active"]].merge(term, on="employee_id")
    # Differentiate from RULE-001 — mark as orphaned if also flagged as active but no business justification
    orphaned = orphaned[orphaned["business_justification"].isna()]
    findings = []
    for _, row in orphaned.iterrows():
        findings.append(_finding(
            rule_id="RULE-006",
            employee_id=row["employee_id"],
            employee_name=row["full_name"],
            department=row["department"],
            system_id=row["system_id"],
            system_name=row["system_name"],
            system_criticality=row["system_criticality"],
            access_level=row["access_level"],
            access_id=row["access_id"],
            detail=(
                f"Account ACC:{row['access_id']} on '{row['system_name']}' is active but owner "
                f"'{row['full_name']}' is terminated with no recorded business justification."
            ),
        ))
    return findings


def detect_unjustified_critical_access(employees: pd.DataFrame, access: pd.DataFrame) -> list[dict]:
    """RULE-007: Critical system access with no business justification on file."""
    active_emps = employees[employees["status"] == "active"][["employee_id", "full_name", "department"]]
    crit_access = access[
        (access["system_criticality"] == "critical") &
        access["is_active"] &
        access["business_justification"].isna()
    ]
    merged = crit_access.merge(active_emps, on="employee_id")
    findings = []
    for _, row in merged.iterrows():
        findings.append(_finding(
            rule_id="RULE-007",
            employee_id=row["employee_id"],
            employee_name=row["full_name"],
            department=row["department"],
            system_id=row["system_id"],
            system_name=row["system_name"],
            system_criticality=row["system_criticality"],
            access_level=row["access_level"],
            access_id=row["access_id"],
            detail=(
                f"'{row['full_name']}' has access to '{row['system_name']}' (CRITICAL tier) "
                f"with no recorded business justification. Approval documentation is required."
            ),
        ))
    return findings


# ── Master runner ────────────────────────────────────────────────────────────

def run_all_rules(employees: pd.DataFrame, access: pd.DataFrame) -> pd.DataFrame:
    """Execute every detection rule and return a unified findings DataFrame."""
    all_findings: list[dict] = []
    all_findings.extend(detect_terminated_access(employees, access))
    all_findings.extend(detect_dormant_access(employees, access))
    all_findings.extend(detect_excessive_privilege(employees, access))
    all_findings.extend(detect_sod_conflicts(employees, access))
    all_findings.extend(detect_mfa_missing(employees, access))
    all_findings.extend(detect_orphaned_accounts(employees, access))
    all_findings.extend(detect_unjustified_critical_access(employees, access))

    if not all_findings:
        return pd.DataFrame()

    df = pd.DataFrame(all_findings)
    df = df.sort_values(["risk_score", "severity"], ascending=[False, True]).reset_index(drop=True)
    return df


# ── Summary statistics ────────────────────────────────────────────────────────

def compute_summary(findings: pd.DataFrame, employees: pd.DataFrame, access: pd.DataFrame) -> dict:
    if findings.empty:
        return {}

    total = len(findings)
    by_severity = findings["severity"].value_counts().to_dict()
    by_type = findings["finding_type"].value_counts().to_dict()
    by_dept = findings["department"].value_counts().to_dict()
    by_system = findings["system_name"].value_counts().head(10).to_dict()
    avg_risk = round(findings["risk_score"].mean(), 1)
    max_risk = findings["risk_score"].max()

    active_employees = len(employees[employees["status"] == "active"])
    total_access = len(access[access["is_active"]])
    affected_employees = findings["employee_id"].nunique()
    affected_systems = findings["system_name"].nunique()

    return {
        "total_findings":      total,
        "critical_findings":   by_severity.get("CRITICAL", 0),
        "high_findings":       by_severity.get("HIGH", 0),
        "medium_findings":     by_severity.get("MEDIUM", 0),
        "low_findings":        by_severity.get("LOW", 0),
        "by_severity":         by_severity,
        "by_type":             by_type,
        "by_department":       by_dept,
        "by_system":           by_system,
        "avg_risk_score":      avg_risk,
        "max_risk_score":      max_risk,
        "active_employees":    active_employees,
        "total_access_records": total_access,
        "affected_employees":  affected_employees,
        "affected_systems":    affected_systems,
        "compliance_rate":     round((1 - total / max(total_access, 1)) * 100, 1),
    }
