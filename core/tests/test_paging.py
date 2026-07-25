from f0_sectools_core.paging import (
    MAX_LIMIT,
    clamp_limit,
    more_available_finding,
    truncation_finding,
)


def test_clamp_limit_normal():
    assert clamp_limit(25) == 25
    assert clamp_limit(1) == 1


def test_clamp_limit_over_max_is_capped():
    assert clamp_limit(10000) == MAX_LIMIT


def test_clamp_limit_below_one_floors_to_one():
    assert clamp_limit(0) == 1
    assert clamp_limit(-5) == 1


def test_clamp_limit_invalid_returns_default():
    assert clamp_limit("abc") == 25
    assert clamp_limit(None) == 25


def test_more_available_with_total():
    f = more_available_finding("tenable", shown=25, total=210)
    assert f.finding_type.value == "posture"
    assert f.severity.value == "info"
    assert "25 of 210" in f.title


def test_more_available_without_total():
    f = more_available_finding("defender", shown=25)
    assert "more results available" in f.title


def test_truncation_finding_reports_a_known_total():
    f = truncation_finding("intune", shown=25, fetched=25, total=1000)
    assert f is not None
    assert "Showing 25 of 1000" in f.title


def test_truncation_finding_is_silent_when_the_total_fits():
    assert truncation_finding("intune", shown=9, fetched=9, total=9) is None


def test_a_known_total_overrides_a_stale_has_more_signal():
    # Graph can send @odata.nextLink on a page that is nonetheless complete;
    # an authoritative count settles it.
    assert truncation_finding("intune", shown=9, fetched=9, total=9, has_more=True) is None


def test_truncation_finding_falls_back_to_has_more():
    f = truncation_finding("limacharlie", shown=25, fetched=25, has_more=True)
    assert f is not None
    assert "more results available" in f.title


def test_truncation_finding_is_silent_without_any_signal():
    assert truncation_finding("tenable", shown=5, fetched=5) is None


def test_client_side_refinement_is_not_truncation():
    # 40 records fetched, 3 survived a client-side refinement, and the platform
    # holds exactly 40. Nothing was cut — telling the caller to raise `limit`
    # would send them after rows that do not exist.
    assert truncation_finding("defender", shown=3, fetched=40, total=40) is None
