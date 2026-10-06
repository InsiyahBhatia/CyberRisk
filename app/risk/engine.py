"""Deterministic risk engine. No LLM involvement; same input -> same output.

Formulas (documented in README):
  inherent  = likelihood x impact                      (1-25)
  residual  = inherent x (1 - control_effectiveness)   (effectiveness 0-1)
  level     = LOW <5, MEDIUM <10, HIGH <17, else CRITICAL  (== 1-4 / 5-9 / 10-16 / 17-25 on integers)
  vuln risk = 100 x weighted mean of normalised components (weights in risk_config)
  enterprise= 0.7 x mean(residual/25 x 100) + 0.3 x (% open risks that are HIGH/CRITICAL)
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

DEFAULT_CONFIG: dict[str, float] = {
    "vuln.w_cvss": 0.40,
    "vuln.w_asset_criticality": 0.25,
    "vuln.w_exploitability": 0.10,
    "vuln.w_internet_exposure": 0.10,
    "vuln.w_known_exploited": 0.15,
    "enterprise.w_mean": 0.70,
    "enterprise.w_high_share": 0.30,
}

CONFIG_DESCRIPTIONS = {
    "vuln.w_cvss": "Weight of CVSS base score in vulnerability risk",
    "vuln.w_asset_criticality": "Weight of asset criticality",
    "vuln.w_exploitability": "Weight of exploitability rating",
    "vuln.w_internet_exposure": "Weight of internet exposure",
    "vuln.w_known_exploited": "Weight of CISA KEV membership",
    "enterprise.w_mean": "Weight of mean normalised residual risk in enterprise score",
    "enterprise.w_high_share": "Weight of share of HIGH/CRITICAL open risks in enterprise score",
}

CRITICALITY_FACTOR = {"LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "CRITICAL": 1.0}
EXPLOITABILITY_FACTOR = {"NONE": 0.0, "LOW": 0.25, "MEDIUM": 0.5, "HIGH": 0.75, "FUNCTIONAL": 0.75, "ACTIVE": 1.0}
SEVERITY_FROM_CVSS = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.0, "LOW"))


def risk_level(score: float) -> str:
    if score < 5:
        return "LOW"
    if score < 10:
        return "MEDIUM"
    if score < 17:
        return "HIGH"
    return "CRITICAL"


def cvss_severity(cvss: float) -> str:
    for threshold, name in SEVERITY_FROM_CVSS:
        if cvss >= threshold:
            return name
    return "LOW"


def inherent_score(likelihood: int, impact: int) -> int:
    if not (1 <= likelihood <= 5 and 1 <= impact <= 5):
        raise ValueError("likelihood and impact must be 1-5")
    return likelihood * impact


def residual_score(inherent: float, control_effectiveness: float) -> float:
    if not 0 <= control_effectiveness <= 1:
        raise ValueError("control_effectiveness must be 0-1")
    return inherent * (1 - control_effectiveness)


def vulnerability_risk(
    cvss: float,
    asset_criticality: str,
    exploitability: str | None,
    internet_exposed: bool,
    known_exploited: bool,
    config: Mapping[str, float] | None = None,
) -> float:
    """Normalised 0-100 score. CVSS is severity only; it is one input among several."""
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    components = {
        "vuln.w_cvss": max(0.0, min(cvss, 10.0)) / 10.0,
        "vuln.w_asset_criticality": CRITICALITY_FACTOR.get((asset_criticality or "").upper(), 0.5),
        "vuln.w_exploitability": EXPLOITABILITY_FACTOR.get((exploitability or "").upper(), 0.25),
        "vuln.w_internet_exposure": 1.0 if internet_exposed else 0.0,
        "vuln.w_known_exploited": 1.0 if known_exploited else 0.0,
    }
    total_w = sum(cfg[k] for k in components)
    return 100.0 * sum(cfg[k] * v for k, v in components.items()) / total_w


@dataclass(frozen=True)
class RiskInput:
    residual: float
    open: bool = True


def enterprise_score(risks: Iterable[RiskInput], config: Mapping[str, float] | None = None) -> float:
    cfg = {**DEFAULT_CONFIG, **(config or {})}
    open_risks = [r for r in risks if r.open]
    if not open_risks:
        return 0.0
    mean_norm = sum(r.residual / 25 * 100 for r in open_risks) / len(open_risks)
    high_share = 100 * sum(1 for r in open_risks if risk_level(r.residual) in ("HIGH", "CRITICAL")) / len(open_risks)
    w_mean, w_high = cfg["enterprise.w_mean"], cfg["enterprise.w_high_share"]
    return (w_mean * mean_norm + w_high * high_share) / (w_mean + w_high)


def projected_effectiveness(current: float, gains: Iterable[float]) -> float:
    """Each action closes a fraction of the remaining control gap (diminishing returns)."""
    gap = 1 - current
    for g in gains:
        gap *= 1 - g
    return 1 - gap


def simulate(inherent: float, current_effectiveness: float, gains: Iterable[float]) -> dict:
    gains = list(gains)
    current = residual_score(inherent, current_effectiveness)
    new_eff = projected_effectiveness(current_effectiveness, gains)
    projected = residual_score(inherent, new_eff)
    return {
        "current_residual": current,
        "projected_residual": projected,
        "delta": projected - current,
        "current_level": risk_level(current),
        "projected_level": risk_level(projected),
        "projected_effectiveness": new_eff,
        "is_projection": True,
    }
