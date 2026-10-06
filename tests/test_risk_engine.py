import pytest

from app.risk import engine as e


@pytest.mark.parametrize("score,level", [(1, "LOW"), (4, "LOW"), (5, "MEDIUM"), (9, "MEDIUM"), (10, "HIGH"), (16, "HIGH"), (17, "CRITICAL"), (25, "CRITICAL")])
def test_risk_level_boundaries(score, level):
    assert e.risk_level(score) == level


def test_every_integer_inherent_score_maps_to_spec_bands():
    for l in range(1, 6):
        for i in range(1, 6):
            s = e.inherent_score(l, i)
            expected = "LOW" if s <= 4 else "MEDIUM" if s <= 9 else "HIGH" if s <= 16 else "CRITICAL"
            assert e.risk_level(s) == expected


def test_inherent_validates_range():
    assert e.inherent_score(3, 4) == 12
    with pytest.raises(ValueError):
        e.inherent_score(0, 3)
    with pytest.raises(ValueError):
        e.inherent_score(3, 6)


def test_residual():
    assert e.residual_score(20, 0.25) == pytest.approx(15)
    assert e.residual_score(20, 0) == 20
    assert e.residual_score(20, 1) == 0
    with pytest.raises(ValueError):
        e.residual_score(20, 1.2)


def test_vulnerability_risk_is_deterministic_and_monotonic():
    args = dict(cvss=7.5, asset_criticality="HIGH", exploitability="MEDIUM", internet_exposed=True, known_exploited=False)
    assert e.vulnerability_risk(**args) == e.vulnerability_risk(**args)
    base = e.vulnerability_risk(**args)
    assert e.vulnerability_risk(**{**args, "known_exploited": True}) > base
    assert e.vulnerability_risk(**{**args, "internet_exposed": False}) < base
    assert e.vulnerability_risk(**{**args, "cvss": 9.8}) > base
    assert 0 <= e.vulnerability_risk(0, "LOW", "NONE", False, False) <= e.vulnerability_risk(10, "CRITICAL", "ACTIVE", True, True) <= 100
    assert e.vulnerability_risk(10, "CRITICAL", "ACTIVE", True, True) == pytest.approx(100)


def test_vulnerability_weights_are_configurable():
    only_kev = {"vuln.w_cvss": 0, "vuln.w_asset_criticality": 0, "vuln.w_exploitability": 0, "vuln.w_internet_exposure": 0, "vuln.w_known_exploited": 1}
    assert e.vulnerability_risk(1, "LOW", "NONE", False, True, only_kev) == pytest.approx(100)
    assert e.vulnerability_risk(10, "CRITICAL", "ACTIVE", True, False, only_kev) == pytest.approx(0)


def test_enterprise_score_ignores_closed_and_empty():
    assert e.enterprise_score([]) == 0
    assert e.enterprise_score([e.RiskInput(25, open=False)]) == 0
    assert e.enterprise_score([e.RiskInput(25)]) == pytest.approx(100)
    a = e.enterprise_score([e.RiskInput(5), e.RiskInput(20)])
    assert a == e.enterprise_score([e.RiskInput(5), e.RiskInput(20)])


def test_simulation_is_deterministic_and_diminishing():
    s1 = e.simulate(20, 0.5, [0.2])
    assert s1 == e.simulate(20, 0.5, [0.2])
    assert s1["current_residual"] == 10
    assert s1["projected_residual"] == pytest.approx(20 * 0.5 * 0.8)
    assert s1["delta"] < 0 and s1["is_projection"] is True
    s2 = e.simulate(20, 0.5, [0.2, 0.2])
    assert s2["projected_residual"] < s1["projected_residual"]
    assert s2["projected_effectiveness"] < 1
    assert e.simulate(20, 0.5, [])["delta"] == 0
