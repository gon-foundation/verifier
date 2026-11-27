"""Canonical JSON (RFC 8785) with non-ASCII member names: shared vectors in
tests/golden/jcs_vectors.json, checked here and by rust/tests/jcs.rs."""
import hashlib
import json
from pathlib import Path

import pytest

from gravit_verifier.kernel import canonical_json

VECTORS = json.loads((Path(__file__).parent / "golden" / "jcs_vectors.json").read_text(encoding="utf-8"))["vectors"]


@pytest.mark.parametrize("v", VECTORS, ids=[v["name"] for v in VECTORS])
def test_canonical_json_non_ascii_names(v):
    got = canonical_json(json.loads(v["input"]))
    assert got == v["expected"]
    assert hashlib.sha3_256(got.encode("utf-8")).hexdigest() == v["expected_sha3_256"]
