from datetime import UTC, datetime

from app.modules.sbom.matching import compare_versions, is_affected


def test_compare_versions_basic():
    assert compare_versions("4.17.20", "4.17.21") == -1
    assert compare_versions("4.17.21", "4.17.20") == 1
    assert compare_versions("1.0.0", "1.0.0") == 0
    assert compare_versions("2.0.0", "10.0.0") == -1
    assert compare_versions("1.0.0-rc1", "1.0.0") == -1


def test_affected_range_with_fixed_version():
    affected = [{"package": {"name": "lodash"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}]
    assert is_affected("4.17.20", affected) is True
    assert is_affected("4.17.21", affected) is False
    assert is_affected("4.17.19", affected) is True


def test_affected_explicit_versions():
    affected = [{"package": {"name": "requests"}, "versions": ["2.25.0", "2.25.1"]}]
    assert is_affected("2.25.0", affected) is True
    assert is_affected("2.31.0", affected) is False
    assert is_affected(None, affected) is False


def test_risk_scoring_is_deterministic_and_bounded():
    from app.modules.risk_engine.scoring import band, compute_finding_risk

    first = compute_finding_risk(
        severity="critical",
        exposure="public",
        criticality="critical",
        known_exploited=True,
        exploit_available=True,
        first_seen=datetime.now(UTC),
        remediation_available=True,
    )
    second = compute_finding_risk(
        severity="critical",
        exposure="public",
        criticality="critical",
        known_exploited=True,
        exploit_available=True,
        first_seen=datetime.now(UTC),
        remediation_available=True,
    )
    assert first[0] == second[0]
    assert 0 <= first[0] <= 100
    assert first[1] in {"critical", "high", "medium", "low", "info"}
    assert band(90) == "critical"
    assert band(70) == "high"
    assert band(45) == "medium"
    assert band(20) == "low"
