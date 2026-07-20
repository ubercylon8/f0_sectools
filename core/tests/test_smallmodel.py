"""Tests for the shared small-model input-validation predicates."""
from __future__ import annotations

from f0_sectools_core.smallmodel import scope_ok, search_ok


class TestScopeOk:
    def test_accepts_bounded_charset(self):
        assert scope_ok("web-01")
        assert scope_ok("windows")
        assert scope_ok("test_uuid@tag:x:3")   # target-string chars
        assert scope_ok("a" * 128)

    def test_rejects_empty(self):
        assert not scope_ok("")

    def test_rejects_over_128(self):
        assert not scope_ok("a" * 129)

    def test_rejects_out_of_charset(self):
        assert not scope_ok("bad\nvalue")       # newline
        assert not scope_ok("has(parens)")       # parentheses not in strict set
        assert not scope_ok("quote'd")


class TestSearchOk:
    def test_accepts_normal_multiword_and_ids(self):
        assert search_ok("pass the hash (T1550.002)")
        assert search_ok("web-01")
        assert search_ok("Zerologon (CVE-2020-1472)")
        assert search_ok("")                     # empty ok (callers guard non-empty)
        assert search_ok("a" * 128)

    def test_rejects_over_128(self):
        assert not search_ok("a" * 129)

    def test_rejects_control_chars(self):
        assert not search_ok("bad\nsearch")      # C0 control
        assert not search_ok("tab\there")
