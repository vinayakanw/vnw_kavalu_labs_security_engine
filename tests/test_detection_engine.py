"""Risk scoring: weights, diminishing returns, grade bands."""

import pytest

from core.detection_engine import GRADE_BANDS, SEVERITY_WEIGHT, _grade_for_score, score_findings


def finding(severity, title="x"):
    return {"severity": severity, "title": title}


def test_no_findings_is_grade_a_zero():
    result = score_findings([])
    assert result["score"] == 0.0
    assert result["grade"] == "A"
    assert result["top_contributors"] == []


def test_info_findings_never_add_risk():
    result = score_findings([finding("info")] * 20)
    assert result["score"] == 0.0
    assert result["severity_counts"]["info"] == 20


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low"])
def test_single_finding_scores_its_base_weight(severity):
    assert score_findings([finding(severity)])["score"] == SEVERITY_WEIGHT[severity]


def test_diminishing_returns_decay_by_sixty_percent():
    # 22 + 22*0.6 + 22*0.36 = 22 + 13.2 + 7.92 = 43.12 -> rounded to 43.1
    result = score_findings([finding("high")] * 3)
    assert result["score"] == pytest.approx(43.1, abs=0.05)


def test_score_is_capped_at_100():
    # 3 critical (78.4) + 3 high (43.1) = 121.5 before the cap.
    result = score_findings([finding("critical")] * 3 + [finding("high")] * 3)
    assert result["score"] == 100.0
    assert result["grade"] == "F"


def test_a_single_severity_can_never_reach_its_asymptote():
    """The decay series converges: sum(w * 0.6**n) -> w / 0.4, so criticals
    alone approach but never exceed 100, highs approach 55, mediums 25, lows 10."""
    assert score_findings([finding("critical")] * 50)["score"] <= 100.0
    assert score_findings([finding("high")] * 50)["score"] == pytest.approx(55.0, abs=0.1)
    assert score_findings([finding("medium")] * 50)["score"] == pytest.approx(25.0, abs=0.1)
    assert score_findings([finding("low")] * 50)["score"] == pytest.approx(10.0, abs=0.1)


def test_unknown_severity_is_treated_as_info():
    result = score_findings([finding("catastrophic")])
    assert result["score"] == 0.0
    assert result["severity_counts"]["info"] == 1


def test_missing_severity_key_is_treated_as_info():
    assert score_findings([{"title": "no severity"}])["score"] == 0.0


def test_top_contributors_sorted_descending_and_exclude_zero():
    result = score_findings([finding("low", "a"), finding("critical", "b"), finding("info", "c")])
    titles = [c["title"] for c in result["top_contributors"]]
    assert titles == ["b", "a"]


def test_top_contributors_capped_at_ten():
    result = score_findings([finding("low", str(i)) for i in range(25)])
    assert len(result["top_contributors"]) == 10


def test_scoring_is_deterministic():
    findings = [finding("high"), finding("medium"), finding("low"), finding("high")]
    assert score_findings(findings) == score_findings(list(findings))


@pytest.mark.parametrize(
    ("score", "grade"),
    [
        (0, "A"),
        (19.9, "A"),
        (20, "B"),
        (39.9, "B"),
        (40, "C"),
        (59.9, "C"),
        (60, "D"),
        (79.9, "D"),
        (80, "F"),
        (100, "F"),
    ],
)
def test_grade_band_boundaries(score, grade):
    assert _grade_for_score(score)["grade"] == grade


def test_grade_bands_are_sorted_high_to_low():
    thresholds = [band[0] for band in GRADE_BANDS]
    assert thresholds == sorted(thresholds, reverse=True)
