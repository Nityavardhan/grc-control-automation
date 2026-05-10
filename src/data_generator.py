"""
Generates realistic, reproducible sample data for DataStream Technologies.
Injects deliberate compliance violations so the control engine has findings to surface.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
import yaml
from faker import Faker

fake = Faker("en_US")

# ── Company taxonomy ─────────────────────────────────────────────────────────

DEPARTMENTS: dict[str, dict] = {
    "Engineering":   {"headcount": 55, "typical_access": ["elevated", "standard"], "systems": ["github", "aws_prod", "aws_dev", "kubernetes", "jira", "confluence", "cicd", "monitoring"]},
    "Security":      {"headcount": 14, "typical_access": ["admin", "elevated"],    "systems": ["okta", "monitoring", "secrets_mgmt", "aws_prod", "github", "siem"]},
    "Finance":       {"headcount": 24, "typical_access": ["elevated", "standard"], "systems": ["financial_reporting", "payment_processing", "snowflake", "hr_system"]},
    "HR":            {"headcount": 18, "typical_access": ["elevated", "standard"], "systems": ["hr_system", "okta", "confluence", "jira"]},
    "Sales":         {"headcount": 42, "typical_access": ["standard"],             "systems": ["salesforce", "confluence", "jira"]},
    "Marketing":     {"headcount": 20, "typical_access": ["standard"],             "systems": ["salesforce", "confluence", "jira"]},
    "Legal":         {"headcount": 10, "typical_access": ["standard"],             "systems": ["confluence", "hr_system", "legal_vault"]},
    "Operations":    {"headcount": 22, "typical_access": ["elevated", "standard"], "systems": ["jira", "monitoring", "snowflake", "cicd"]},
    "Executive":     {"headcount": 5,  "typical_access": ["elevated", "standard"], "systems": ["salesforce", "financial_reporting", "snowflake", "hr_system", "confluence"]},
}

SYSTEMS: list[dict] = [
    {"system_id": "aws_prod",            "name": "AWS Production",             "type": "Cloud Infrastructure", "criticality": "critical", "data_classification": "Confidential",    "owner_dept": "Engineering"},
    {"system_id": "aws_dev",             "name": "AWS Development",            "type": "Cloud Infrastructure", "criticality": "high",     "data_classification": "Internal",        "owner_dept": "Engineering"},
    {"system_id": "okta",                "name": "Okta Identity Platform",     "type": "Identity Provider",    "criticality": "critical", "data_classification": "Confidential",    "owner_dept": "Security"},
    {"system_id": "github",              "name": "GitHub Enterprise",          "type": "Source Control",       "criticality": "high",     "data_classification": "Confidential",    "owner_dept": "Engineering"},
    {"system_id": "salesforce",          "name": "Salesforce CRM",             "type": "CRM",                  "criticality": "high",     "data_classification": "Confidential",    "owner_dept": "Sales"},
    {"system_id": "snowflake",           "name": "Snowflake Data Warehouse",   "type": "Data Platform",        "criticality": "critical", "data_classification": "Restricted",      "owner_dept": "Operations"},
    {"system_id": "payment_processing",  "name": "PCI Payment Processor",      "type": "Payment System",       "criticality": "critical", "data_classification": "Restricted",      "owner_dept": "Finance"},
    {"system_id": "hr_system",           "name": "Workday HRIS",               "type": "HR System",            "criticality": "critical", "data_classification": "Restricted",      "owner_dept": "HR"},
    {"system_id": "financial_reporting", "name": "Financial Reporting System", "type": "Finance",              "criticality": "critical", "data_classification": "Restricted",      "owner_dept": "Finance"},
    {"system_id": "customer_db",         "name": "Customer Database",          "type": "Database",             "criticality": "critical", "data_classification": "Restricted",      "owner_dept": "Engineering"},
    {"system_id": "kubernetes",          "name": "Kubernetes Cluster",         "type": "Container Orchestration", "criticality": "critical", "data_classification": "Confidential", "owner_dept": "Engineering"},
    {"system_id": "secrets_mgmt",        "name": "HashiCorp Vault",            "type": "Secrets Management",   "criticality": "critical", "data_classification": "Restricted",      "owner_dept": "Security"},
    {"system_id": "siem",                "name": "Splunk SIEM",                "type": "Security Monitoring",  "criticality": "high",     "data_classification": "Confidential",    "owner_dept": "Security"},
    {"system_id": "monitoring",          "name": "Datadog Monitoring",         "type": "Observability",        "criticality": "high",     "data_classification": "Internal",        "owner_dept": "Operations"},
    {"system_id": "jira",                "name": "Jira Project Management",    "type": "Project Management",   "criticality": "medium",   "data_classification": "Internal",        "owner_dept": "Operations"},
    {"system_id": "confluence",          "name": "Confluence Wiki",            "type": "Knowledge Base",       "criticality": "medium",   "data_classification": "Internal",        "owner_dept": "Operations"},
    {"system_id": "cicd",                "name": "GitHub Actions / CI-CD",     "type": "DevOps",               "criticality": "high",     "data_classification": "Confidential",    "owner_dept": "Engineering"},
    {"system_id": "vpn",                 "name": "Corporate VPN",              "type": "Network Access",       "criticality": "high",     "data_classification": "Confidential",    "owner_dept": "Security"},
    {"system_id": "legal_vault",         "name": "Legal Document Vault",       "type": "Document Management",  "criticality": "medium",   "data_classification": "Confidential",    "owner_dept": "Legal"},
    {"system_id": "code_signing",        "name": "Code Signing Server",        "type": "Security",             "criticality": "critical", "data_classification": "Restricted",      "owner_dept": "Security"},
]

TITLES_BY_DEPT: dict[str, list[str]] = {
    "Engineering":   ["Software Engineer I", "Software Engineer II", "Senior Software Engineer", "Staff Engineer", "Principal Engineer", "Engineering Manager", "VP Engineering"],
    "Security":      ["Security Analyst", "Senior Security Analyst", "Security Engineer", "Senior Security Engineer", "Security Manager", "CISO"],
    "Finance":       ["Financial Analyst", "Senior Financial Analyst", "Finance Manager", "Controller", "VP Finance", "CFO"],
    "HR":            ["HR Coordinator", "HR Business Partner", "HR Manager", "Director of HR", "Chief People Officer"],
    "Sales":         ["SDR", "Account Executive", "Senior AE", "Sales Manager", "VP Sales", "Chief Revenue Officer"],
    "Marketing":     ["Marketing Coordinator", "Marketing Manager", "Senior Marketing Manager", "VP Marketing", "CMO"],
    "Legal":         ["Legal Analyst", "Counsel", "Senior Counsel", "General Counsel"],
    "Operations":    ["Operations Analyst", "Operations Manager", "Director of Operations", "VP Operations", "COO"],
    "Executive":     ["CEO", "President", "Chief of Staff", "Executive Assistant", "Board Advisor"],
}

SOD_CONFLICT_PAIRS: list[tuple[str, str]] = [
    ("financial_initiator", "financial_approver"),
    ("code_developer", "code_deployer"),
    ("user_admin", "user_auditor"),
    ("data_entry", "data_approver"),
]


# ── Helper utilities ─────────────────────────────────────────────────────────

def _random_date(start: datetime, end: datetime) -> datetime:
    delta = end - start
    return start + timedelta(seconds=random.randint(0, int(delta.total_seconds())))


def _load_settings() -> dict:
    settings_path = Path(__file__).parent.parent / "config" / "settings.yaml"
    with open(settings_path) as f:
        return yaml.safe_load(f)


# ── Employee generator ───────────────────────────────────────────────────────

def generate_employees(seed: int = 42) -> pd.DataFrame:
    random.seed(seed)
    fake.seed_instance(seed)
    np.random.seed(seed)

    settings = _load_settings()
    terminated_ratio = settings["data"]["terminated_ratio"]
    on_leave_ratio = settings["data"]["on_leave_ratio"]

    now = datetime.now()
    records: list[dict[str, Any]] = []
    emp_id = 1000

    dept_managers: dict[str, str] = {}

    for dept, cfg in DEPARTMENTS.items():
        for i in range(cfg["headcount"]):
            emp_id += 1
            eid = f"EMP{emp_id}"
            hire_date = _random_date(now - timedelta(days=365 * 8), now - timedelta(days=30))

            r = random.random()
            if r < terminated_ratio:
                status = "terminated"
                term_date = _random_date(now - timedelta(days=180), now - timedelta(days=1))
            elif r < terminated_ratio + on_leave_ratio:
                status = "on_leave"
                term_date = None
            else:
                status = "active"
                term_date = None

            title = random.choice(TITLES_BY_DEPT[dept])
            is_manager = "Manager" in title or "Director" in title or any(x in title for x in ["VP", "CISO", "CFO", "CMO", "COO", "CRO", "CEO"])

            record = {
                "employee_id": eid,
                "full_name": fake.name(),
                "email": f"{fake.user_name()}@datastream.io",
                "department": dept,
                "title": title,
                "status": status,
                "hire_date": hire_date.strftime("%Y-%m-%d"),
                "termination_date": term_date.strftime("%Y-%m-%d") if term_date else None,
                "manager_id": None,
                "is_manager": is_manager,
                "mfa_enabled": random.random() > 0.08,
            }
            records.append(record)

            if is_manager and dept not in dept_managers:
                dept_managers[dept] = eid

    df = pd.DataFrame(records)

    # Assign managers
    def _get_manager(row: pd.Series) -> str | None:
        mgr_id = dept_managers.get(row["department"])
        if mgr_id and mgr_id != row["employee_id"]:
            return mgr_id
        return None

    df["manager_id"] = df.apply(_get_manager, axis=1)
    return df.reset_index(drop=True)


# ── Access rights generator ──────────────────────────────────────────────────

def generate_access_rights(employees: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    random.seed(seed + 1)
    np.random.seed(seed + 1)

    settings = _load_settings()
    now = datetime.now()
    records: list[dict[str, Any]] = []
    access_id = 5000

    systems_lookup = {s["system_id"]: s for s in SYSTEMS}

    for _, emp in employees.iterrows():
        dept_cfg = DEPARTMENTS.get(emp["department"], {})
        dept_systems: list[str] = dept_cfg.get("systems", [])
        typical_access: list[str] = dept_cfg.get("typical_access", ["standard"])

        # Each employee gets 2-5 system accesses
        num_accesses = random.randint(2, min(5, len(dept_systems)))
        assigned_systems = random.sample(dept_systems, min(num_accesses, len(dept_systems)))

        for sys_id in assigned_systems:
            access_id += 1
            sys_info = systems_lookup.get(sys_id, {})

            access_level = random.choice(typical_access)
            grant_date = _random_date(
                datetime.strptime(emp["hire_date"], "%Y-%m-%d"),
                now - timedelta(days=7),
            )
            last_used = _random_date(grant_date, now)
            is_active = emp["status"] != "terminated"

            records.append({
                "access_id": f"ACC{access_id}",
                "employee_id": emp["employee_id"],
                "system_id": sys_id,
                "system_name": sys_info.get("name", sys_id),
                "system_criticality": sys_info.get("criticality", "medium"),
                "access_level": access_level,
                "granted_date": grant_date.strftime("%Y-%m-%d"),
                "last_used_date": last_used.strftime("%Y-%m-%d"),
                "granted_by": random.choice(employees[employees["is_manager"]]["employee_id"].tolist() or [emp["employee_id"]]),
                "business_justification": fake.sentence(nb_words=8) if random.random() > 0.12 else None,
                "is_active": is_active,
                "sod_role": None,
                "review_status": "pending",
            })

    df = pd.DataFrame(records)
    return df.reset_index(drop=True)


# ── Inject violations ────────────────────────────────────────────────────────

def inject_violations(
    employees: pd.DataFrame,
    access: pd.DataFrame,
    seed: int = 42,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Deliberately introduce compliance violations for demo realism."""
    random.seed(seed + 99)
    np.random.seed(seed + 99)

    settings = _load_settings()
    sim = settings["simulation"]
    now = datetime.now()

    access = access.copy()
    employees = employees.copy()
    systems_lookup = {s["system_id"]: s for s in SYSTEMS}
    active_ids = employees[employees["status"] == "active"]["employee_id"].tolist()
    terminated_ids = employees[employees["status"] == "terminated"]["employee_id"].tolist()

    # 1. Terminated users with active access still on (missed revocation)
    term_with_access = access[access["employee_id"].isin(terminated_ids)].index
    reactivate = random.sample(list(term_with_access), min(sim["inject_terminated_access"], len(term_with_access)))
    access.loc[reactivate, "is_active"] = True

    # 2. Dormant access — last used 90-400 days ago
    active_access_idx = access[access["is_active"] & access["employee_id"].isin(active_ids)].index
    dormant_idx = random.sample(list(active_access_idx), min(sim["inject_dormant_access"], len(active_access_idx)))
    for idx in dormant_idx:
        days_ago = random.randint(91, 400)
        access.at[idx, "last_used_date"] = (now - timedelta(days=days_ago)).strftime("%Y-%m-%d")

    # 3. Excessive privilege — standard-role users with admin access
    standard_role_emps = employees[employees["department"].isin(["Sales", "Marketing", "Legal"])]["employee_id"].tolist()
    standard_access_idx = access[
        access["employee_id"].isin(standard_role_emps) & access["is_active"]
    ].index
    excess_idx = random.sample(list(standard_access_idx), min(sim["inject_excessive_privilege"], len(standard_access_idx)))
    access.loc[excess_idx, "access_level"] = random.choices(["admin", "elevated"], k=len(excess_idx))

    # 4. SoD conflicts — same employee with conflicting roles
    conflict_targets = random.sample(active_ids, min(sim["inject_sod_conflicts"], len(active_ids)))
    sod_access_id = 9000
    for emp_id in conflict_targets:
        sod_access_id += 1
        pair = random.choice(SOD_CONFLICT_PAIRS)
        sys_choice = random.choice(["financial_reporting", "payment_processing", "okta", "cicd"])
        sys_info = systems_lookup.get(sys_choice, {})
        for role in pair:
            sod_access_id += 1
            grant_date = _random_date(now - timedelta(days=365), now - timedelta(days=30))
            last_used = _random_date(grant_date, now)
            new_row = {
                "access_id": f"ACC{sod_access_id}",
                "employee_id": emp_id,
                "system_id": sys_choice,
                "system_name": sys_info.get("name", sys_choice),
                "system_criticality": sys_info.get("criticality", "critical"),
                "access_level": "elevated",
                "granted_date": grant_date.strftime("%Y-%m-%d"),
                "last_used_date": last_used.strftime("%Y-%m-%d"),
                "granted_by": random.choice(active_ids),
                "business_justification": fake.sentence(nb_words=6),
                "is_active": True,
                "sod_role": role,
                "review_status": "pending",
            }
            access = pd.concat([access, pd.DataFrame([new_row])], ignore_index=True)

    # 5. MFA missing on privileged accounts
    privileged_idx = access[
        access["access_level"].isin(["admin", "elevated"]) & access["is_active"]
    ].index
    mfa_missing_idx = random.sample(list(privileged_idx), min(sim["inject_mfa_missing"], len(privileged_idx)))
    for idx in mfa_missing_idx:
        emp_id = access.at[idx, "employee_id"]
        employees.loc[employees["employee_id"] == emp_id, "mfa_enabled"] = False

    # 6. Orphaned accounts — terminated owner, access still active
    term_emp = employees[employees["status"] == "terminated"]["employee_id"].tolist()
    orphan_idx = access[access["employee_id"].isin(term_emp) & ~access["is_active"]].index
    orphan_select = random.sample(list(orphan_idx), min(sim["inject_orphaned_accounts"], len(orphan_idx)))
    access.loc[orphan_select, "is_active"] = True

    # 7. Critical system access without justification
    critical_idx = access[
        (access["system_criticality"] == "critical") & access["is_active"]
    ].index
    no_just_idx = random.sample(list(critical_idx), min(sim["inject_unjustified_critical"], len(critical_idx)))
    access.loc[no_just_idx, "business_justification"] = None

    return employees, access


# ── Systems table ────────────────────────────────────────────────────────────

def generate_systems() -> pd.DataFrame:
    return pd.DataFrame(SYSTEMS)


# ── Master generation function ───────────────────────────────────────────────

def generate_all(output_dir: str | Path | None = None, seed: int = 42) -> dict[str, pd.DataFrame]:
    """Generate all datasets and optionally save to CSV files."""
    employees = generate_employees(seed)
    access = generate_access_rights(employees, seed)
    employees, access = inject_violations(employees, access, seed)
    systems = generate_systems()

    datasets = {
        "employees": employees,
        "access_rights": access,
        "systems": systems,
    }

    if output_dir:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        for name, df in datasets.items():
            df.to_csv(out / f"{name}.csv", index=False)

    return datasets
