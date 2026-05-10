"""
Risk scoring engine.
Computes a 0-100 composite risk score for each finding based on
finding severity, system criticality, and access level.
"""

from __future__ import annotations

import yaml
from pathlib import Path


def _load_scoring_config() -> dict:
    path = Path(__file__).parent.parent / "config" / "controls.yaml"
    with open(path) as f:
        return yaml.safe_load(f)["scoring"]


_SCORING = _load_scoring_config()


def compute_score(
    severity: str,
    system_criticality: str,
    access_level: str,
) -> float:
    """Return a 0-100 risk score for a finding."""
    base = _SCORING["severity_base"].get(severity, 40)
    crit_mult = _SCORING["system_criticality_multiplier"].get(system_criticality, 0.55)
    access_mult = _SCORING["access_level_multiplier"].get(access_level, 0.45)
    raw = base * crit_mult * access_mult
    return round(min(raw, 100.0), 1)


def score_to_band(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 55:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


BAND_COLORS = {
    "CRITICAL": "#d32f2f",
    "HIGH":     "#f57c00",
    "MEDIUM":   "#f9a825",
    "LOW":      "#388e3c",
}

BAND_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
