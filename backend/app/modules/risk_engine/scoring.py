"""Documented, deterministic risk scoring model.

The model is intentionally transparent: every factor has a fixed weight, the
result is clamped to 0-100, and no AI component may alter the final score.
AI triage can explain the result but never compute authoritative risk.

Weights
-------
base severity (CVSS band)   critical 45, high 32, medium 18, low 8, info 2
internet exposure           +15 (public) / +7 (partner)
asset criticality           +12 (critical) / +7 (high) / +3 (medium)
known exploited (KEV)       +12
verified exploit available  +6
sensitive data involved     +6
authentication missing      +5
finding age                 +1 per 7 days since first seen (max +8)
fix available               -4 (deployment friction is already counted)

Score bands: >=85 critical, >=65 high, >=40 medium, >=15 low, otherwise info.
"""

from datetime import UTC, datetime

SEVERITY_WEIGHTS = {"critical": 45, "high": 32, "medium": 18, "low": 8, "info": 2, "unknown": 2}

EXPOSURE_WEIGHTS = {"public": 15, "partner": 7, "internal": 0, "restricted": 0}
CRITICALITY_WEIGHTS = {"critical": 12, "high": 7, "medium": 3, "low": 0}


def band(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def _age_days(first_seen: datetime | None) -> int:
    if first_seen is None:
        return 0
    reference = first_seen if first_seen.tzinfo else first_seen.replace(tzinfo=UTC)
    return max(0, (datetime.now(UTC) - reference).days)


def compute_finding_risk(
    *,
    severity: str,
    exposure: str = "internal",
    criticality: str = "medium",
    known_exploited: bool = False,
    exploit_available: bool = False,
    sensitive_data: bool = False,
    auth_missing: bool = False,
    first_seen: datetime | None = None,
    remediation_available: bool = False,
    cvss_score: float | None = None,
) -> tuple[float, str, dict]:
    factors: dict[str, float] = {"severity_base": SEVERITY_WEIGHTS.get(severity.lower(), 2)}
    if cvss_score is not None:
        factors["cvss_adjustment"] = round(max(0.0, (cvss_score - 5.0)) * 1.5, 2)

    factors["internet_exposure"] = EXPOSURE_WEIGHTS.get(exposure.lower(), 0)
    factors["asset_criticality"] = CRITICALITY_WEIGHTS.get(criticality.lower(), 3)
    if known_exploited:
        factors["known_exploited"] = 12
    if exploit_available:
        factors["exploit_available"] = 6
    if sensitive_data:
        factors["sensitive_data"] = 6
    if auth_missing:
        factors["missing_auth"] = 5
    age_factor = min(8, (_age_days(first_seen) // 7))
    if age_factor:
        factors["age"] = age_factor
    if remediation_available:
        factors["fix_available"] = -4

    score = round(max(0.0, min(100.0, sum(factors.values()))), 1)
    return score, band(score), factors


def posture_from_findings(findings: list) -> float:
    open_findings = [f for f in findings if f.status not in {"resolved", "closed", "false_positive", "risk_accepted"}]
    if not open_findings:
        return 100.0
    average = sum(float(f.risk_score or 0) for f in open_findings) / len(open_findings)
    return round(max(0.0, min(100.0, 100.0 - average)), 1)


SLA_DAYS = {"critical": 7, "high": 30, "medium": 90, "low": 180, "info": 365}


def sla_due(severity: str, first_seen: datetime | None) -> datetime:
    base = first_seen or datetime.now(UTC)
    if base.tzinfo is None:
        base = base.replace(tzinfo=UTC)
    from datetime import timedelta

    return base + timedelta(days=SLA_DAYS.get(severity.lower(), 90))
