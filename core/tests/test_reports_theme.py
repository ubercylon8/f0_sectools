import pytest
from f0_sectools_core.reports.theme import TIERS, inline_css


def test_inline_css_returns_nonempty_with_page_rule():
    css = inline_css("executive")
    assert "@page" in css
    assert "report--executive" in css or "--tier" in css
    assert len(css) > 200


def test_both_tiers_produce_css():
    for tier in TIERS:
        assert "@page" in inline_css(tier)


def test_unknown_tier_rejected():
    with pytest.raises(ValueError):
        inline_css("bogus")
