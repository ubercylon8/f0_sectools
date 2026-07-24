from f0_sectools_core.reports.narrative import Narrative, parse_narrative


def test_parses_all_three_sections():
    text = (
        "## Executive Summary\n"
        "Our posture is moderate and stable.\n\n"
        "## Risk Framing\n"
        "Device compliance is the biggest surface.\n\n"
        "## Open Questions\n"
        "- Is 61% device compliance acceptable?\n"
        "- Do we treat the overlap as one workstream?\n"
    )
    n = parse_narrative(text)
    assert "moderate and stable" in n.executive_summary
    assert "biggest surface" in n.risk_framing
    assert n.open_questions == [
        "Is 61% device compliance acceptable?",
        "Do we treat the overlap as one workstream?",
    ]


def test_missing_sections_degrade_gracefully():
    n = parse_narrative("## Executive Summary\nJust a summary.\n")
    assert n.executive_summary == "Just a summary."
    assert n.risk_framing == ""
    assert n.open_questions == []


def test_open_questions_without_list_markers_split_by_line():
    n = parse_narrative("## Open Questions\nFirst question?\nSecond question?\n")
    assert n.open_questions == ["First question?", "Second question?"]


def test_empty_input_yields_empty_narrative():
    n = parse_narrative("")
    assert n == Narrative(executive_summary="", risk_framing="", open_questions=[])
