"""Drift guard: every sample finding in examples/findings/ must parse with the
real pydantic Finding model — the examples cannot drift from the schema."""
import json
from pathlib import Path

import pytest
from f0_sectools_core.schema.findings import Finding

FINDINGS_DIR = Path(__file__).resolve().parents[2] / "examples" / "findings"
SAMPLES = sorted(FINDINGS_DIR.glob("*.json"))


def test_samples_exist():
    assert len(SAMPLES) >= 8, "expected one sample finding per server"


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.name)
def test_sample_is_schema_valid(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    finding = Finding.model_validate(data)
    assert finding.schema_version == "1.0"
    assert finding.title
