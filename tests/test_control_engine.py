"""
Unit tests for the GRC Control Automation engine.
Tests cover data generation, individual detection rules, risk scoring, and summary computation.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

# Allow imports from project root
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from src.control_engine import (
    compute_summary,
    detect_dormant_access,
    detect_excessive_privilege,
    detect_mfa_missing,
    detect_orphaned_accounts,
    detect_sod_conflicts,
    detect_terminated_access,
    detect_unjustified_critical_access,
    run_all_rules,
)
from src.data_generator import generate_all, generate_employees, generate_systems
from src.risk_scorer import compute_score, score_to_band


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def datasets():
    return generate_all(seed=42)


@pytest.fixture(scope="module")
def employees(datasets):
    return datasets["employees"]


@pytest.fixture(scope="module")
def access(datasets):
    return datasets["access_rights"]


@pytest.fixture(scope="module")
def findings(employees, access):
    return run_all_rules(employees, access)


@pytest.fixture(scope="module")
def summary(findings, employees, access):
    return compute_summary(findings, employees, access)


# ── Data generation tests ─────────────────────────────────────────────────────

class TestDataGeneration:

    def test_employee_count_reasonable(self, employees):
        assert 150 <= len(employees) <= 250, "Expected ~200 employees"

    def test_employee_columns_present(self, employees):
        required = {"employee_id", "full_name", "email", "department", "status",
                    "hire_date", "mfa_enabled", "is_manager"}
        assert required.issubset(employees.columns)

    def test_employee_statuses_valid(self, employees):
        valid_statuses = {"active", "terminated", "on_leave"}
        assert set(employees["status"].unique()).issubset(valid_statuses)

    def test_terminated_employees_exist(self, employees):
        assert len(employees[employees["status"] == "terminated"]) > 0

    def test_active_employees_majority(self, employees):
        active_ratio = (employees["status"] == "active").mean()
        assert active_ratio > 0.8, "Active employees should be >80%"

    def test_access_records_exist(self, access):
        assert len(access) > 300, "Expected >300 access records"

    def test_access_columns_present(self, access):
        required = {"access_id", "employee_id", "system_id", "system_name",
                    "access_level", "is_active", "last_used_date", "granted_date"}
        assert required.issubset(access.columns)

    def test_access_levels_valid(self, access):
        valid = {"admin", "elevated", "standard"}
        assert set(access["access_level"].unique()).issubset(valid)

    def test_systems_table(self):
        systems = generate_systems()
        assert len(systems) == 20
        assert "criticality" in systems.columns

    def test_reproducibility(self):
        d1 = generate_all(seed=42)
        d2 = generate_all(seed=42)
        assert list(d1["employees"]["employee_id"]) == list(d2["employees"]["employee_id"])

    def test_different_seeds_differ(self):
        d1 = generate_all(seed=42)
        d2 = generate_all(seed=99)
        assert list(d1["employees"]["email"]) != list(d2["employees"]["email"])


# ── Risk scorer tests ─────────────────────────────────────────────────────────

class TestRiskScorer:

    def test_critical_admin_on_critical_system(self):
        score = compute_score("CRITICAL", "critical", "admin")
        assert score == 100.0

    def test_low_standard_on_low_system(self):
        score = compute_score("LOW", "low", "standard")
        assert score < 10

    def test_score_bounded_0_to_100(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            for crit in ["critical", "high", "medium", "low"]:
                for acc in ["admin", "elevated", "standard"]:
                    s = compute_score(sev, crit, acc)
                    assert 0 <= s <= 100

    def test_band_critical(self):
        assert score_to_band(85) == "CRITICAL"
        assert score_to_band(80) == "CRITICAL"

    def test_band_high(self):
        assert score_to_band(60) == "HIGH"

    def test_band_medium(self):
        assert score_to_band(40) == "MEDIUM"

    def test_band_low(self):
        assert score_to_band(10) == "LOW"

    def test_severity_ordering(self):
        s_crit = compute_score("CRITICAL", "critical", "admin")
        s_high = compute_score("HIGH",     "critical", "admin")
        s_med  = compute_score("MEDIUM",   "critical", "admin")
        s_low  = compute_score("LOW",      "critical", "admin")
        assert s_crit > s_high > s_med > s_low


# ── Detection rule tests ──────────────────────────────────────────────────────

class TestDetectionRules:

    def test_terminated_access_detects_violations(self, employees, access):
        findings = detect_terminated_access(employees, access)
        assert len(findings) > 0, "Should find terminated users with active access"

    def test_terminated_access_only_terminated(self, employees, access):
        findings = detect_terminated_access(employees, access)
        term_ids = set(employees[employees["status"] == "terminated"]["employee_id"])
        for f in findings:
            assert f["employee_id"] in term_ids

    def test_dormant_access_uses_90_day_threshold(self, employees, access):
        findings_90  = detect_dormant_access(employees, access, threshold_days=90)
        findings_180 = detect_dormant_access(employees, access, threshold_days=180)
        assert len(findings_90) >= len(findings_180)

    def test_dormant_access_detects_violations(self, employees, access):
        findings = detect_dormant_access(employees, access)
        assert len(findings) > 0

    def test_excessive_privilege_only_wrong_depts(self, employees, access):
        findings = detect_excessive_privilege(employees, access)
        allowed_depts = {"Sales", "Marketing", "Legal"}
        for f in findings:
            assert f["department"] in allowed_depts

    def test_excessive_privilege_access_level(self, employees, access):
        findings = detect_excessive_privilege(employees, access)
        for f in findings:
            assert f["access_level"] in ("admin", "elevated")

    def test_sod_conflicts_detected(self, employees, access):
        findings = detect_sod_conflicts(employees, access)
        assert len(findings) > 0

    def test_mfa_missing_only_privileged(self, employees, access):
        findings = detect_mfa_missing(employees, access)
        for f in findings:
            assert f["access_level"] in ("admin", "elevated")

    def test_orphaned_accounts_no_active_employees(self, employees, access):
        findings = detect_orphaned_accounts(employees, access)
        active_ids = set(employees[employees["status"] == "active"]["employee_id"])
        for f in findings:
            assert f["employee_id"] not in active_ids

    def test_unjustified_critical_on_critical_systems(self, employees, access):
        findings = detect_unjustified_critical_access(employees, access)
        for f in findings:
            assert f["system_criticality"] == "critical"

    def test_finding_ids_unique(self, findings):
        ids = findings["finding_id"].tolist()
        assert len(ids) == len(set(ids)), "All finding IDs must be unique (UUID-based)"


# ── Master runner tests ───────────────────────────────────────────────────────

class TestRunAllRules:

    def test_run_all_rules_returns_dataframe(self, findings):
        assert isinstance(findings, pd.DataFrame)

    def test_run_all_rules_has_findings(self, findings):
        assert len(findings) > 0

    def test_required_columns_present(self, findings):
        required = {
            "finding_id", "rule_id", "severity", "risk_score", "risk_band",
            "employee_id", "employee_name", "department", "system_name",
            "finding_type", "detail", "sla_deadline", "detected_at", "frameworks",
        }
        assert required.issubset(findings.columns)

    def test_sorted_by_risk_score_descending(self, findings):
        scores = findings["risk_score"].tolist()
        assert scores == sorted(scores, reverse=True)

    def test_risk_scores_in_range(self, findings):
        assert (findings["risk_score"] >= 0).all()
        assert (findings["risk_score"] <= 100).all()

    def test_severity_values_valid(self, findings):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert set(findings["severity"].unique()).issubset(valid)


# ── Summary tests ─────────────────────────────────────────────────────────────

class TestComputeSummary:

    def test_summary_keys_present(self, summary):
        required = {
            "total_findings", "critical_findings", "high_findings",
            "by_severity", "by_type", "by_department",
            "avg_risk_score", "compliance_rate",
        }
        assert required.issubset(summary.keys())

    def test_total_equals_sum_of_severities(self, summary):
        total = summary["total_findings"]
        by_sev_sum = sum(summary["by_severity"].values())
        assert total == by_sev_sum

    def test_compliance_rate_between_0_and_100(self, summary):
        assert 0 <= summary["compliance_rate"] <= 100

    def test_avg_risk_score_positive(self, summary):
        assert summary["avg_risk_score"] > 0
