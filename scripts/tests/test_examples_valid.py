"""Drift guard: every sample finding in examples/findings/ must parse with the
real pydantic Finding model — the examples cannot drift from the schema."""
import json
from pathlib import Path

import pytest
from f0_sectools_core.schema.findings import Finding

REPO_ROOT = Path(__file__).resolve().parents[2]
FINDINGS_DIR = REPO_ROOT / "examples" / "findings"
SAMPLES = sorted(FINDINGS_DIR.glob("*.json"))
SERVER_COUNT = len(
    [p for p in (REPO_ROOT / "servers").iterdir() if p.is_dir() and p.name.endswith("-mcp")]
)


def test_samples_exist():
    # Equality, not >=, so a tenth server can't silently ship without a
    # sample: >= would have kept passing forever even if a new server never
    # got one.
    assert len(SAMPLES) == SERVER_COUNT, "expected exactly one sample finding per server"


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.name)
def test_sample_is_schema_valid(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    finding = Finding.model_validate(data)
    assert finding.schema_version == "1.0"
    assert finding.title
