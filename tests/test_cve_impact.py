"""Tests für CVE-Impact-Berechnung (ohne DB, Unit-Level)."""

import pytest
from src.rag.cve_impact import _calc_risk_score, _risk_level


def test_risk_score_extern_with_internet_port():
    score = _calc_risk_score(
        cvss=7.5,
        exposure_level="EXTERN",
        open_ports=[{"port": 443, "proto": "tcp", "reachable_from": ["internet"]}],
        criticality=4,
    )
    # 7.5 * 1.5 (EXTERN) * 1.1 (internet port) * 0.9 (criticality 4)
    assert score > 7.5
    assert score > _calc_risk_score(7.5, "INTERN", None, 4)


def test_risk_score_intern_no_ports():
    score = _calc_risk_score(
        cvss=5.0,
        exposure_level="INTERN",
        open_ports=None,
        criticality=3,
    )
    # 5.0 * 1.0 * 1.0 * 0.8
    assert score == pytest.approx(4.0, abs=0.1)


def test_risk_level_high():
    assert _risk_level(8.0) == "HIGH"
    assert _risk_level(7.0) == "HIGH"


def test_risk_level_medium():
    assert _risk_level(6.9) == "MEDIUM"
    assert _risk_level(4.0) == "MEDIUM"


def test_risk_level_low():
    assert _risk_level(3.9) == "LOW"
    assert _risk_level(0.0) == "LOW"


def test_exposure_hierarchy():
    """EXTERN > DMZ > INTERN bei gleichem CVSS."""
    cvss = 6.0
    score_extern = _calc_risk_score(cvss, "EXTERN", None, 3)
    score_dmz = _calc_risk_score(cvss, "DMZ", None, 3)
    score_intern = _calc_risk_score(cvss, "INTERN", None, 3)

    assert score_extern > score_dmz > score_intern


def test_criticality_effect():
    """Kritikalität 5 produziert höheren Score als 1."""
    score_high = _calc_risk_score(5.0, "INTERN", None, criticality=5)
    score_low = _calc_risk_score(5.0, "INTERN", None, criticality=1)
    assert score_high > score_low


def test_port_factor_caps():
    """Port-Faktor steigt, aber nicht über 1.5."""
    many_ports = [{"port": i, "reachable_from": ["internet"]} for i in range(80, 100)]
    score = _calc_risk_score(5.0, "INTERN", many_ports, 3)
    # Faktor maximal 1.5
    max_possible = _calc_risk_score(5.0, "INTERN", None, 3) * 1.5
    assert score <= max_possible + 0.01
