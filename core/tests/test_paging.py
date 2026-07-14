from f0_sectools_core.paging import (
    MAX_LIMIT,
    clamp_limit,
    more_available_finding,
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
