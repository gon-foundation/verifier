"""A malformed Record is excluded with reason "malformed" and never counts;
the request itself is still decided (found by tools/difftest_ext.py)."""
import json

from gravit_verifier.kernel import EvidenceRecord, VerificationRequest, canonical_json
from tests.test_full_cycle import kernel_with_all_bindings  # noqa: F401

GOOD = {"record_id": "r1", "theta": 0.61, "result": True, "verifier_id": "v-01",
        "timestamp": "2026-09-03T12:00:00Z", "provenance": "agent-A", "integrity_hash": "hash1"}
BAD = [
    dict(GOOD, record_id=7),
    dict(GOOD, theta="0.61"),
    dict(GOOD, theta=True),
    dict(GOOD, result=1),
    dict(GOOD, result="true"),
    dict(GOOD, timestamp=None),
    dict(GOOD, signature=5),
    {k: v for k, v in GOOD.items() if k != "provenance"},
    "not an object",
]


def _decide(kernel, records):
    req = VerificationRequest("a", None, [EvidenceRecord.from_json(r) for r in records], {})
    return kernel.verify(req).to_dict()


def test_each_malformed_record_is_excluded(kernel_with_all_bindings):  # noqa: F811
    for bad in BAD:
        d = _decide(kernel_with_all_bindings, [GOOD, bad])
        assert d["excluded_evidence"][-1]["reason"] == "malformed", bad
        rid = bad.get("record_id") if isinstance(bad, dict) else None
        assert d["excluded_evidence"][-1]["record_id"] == (rid if isinstance(rid, str) else None)
        canonical_json(d)  # the DecisionRecord stays valid JSON


def test_malformed_record_does_not_change_the_decision(kernel_with_all_bindings):  # noqa: F811
    base = _decide(kernel_with_all_bindings, [GOOD])
    for bad in BAD:
        d = _decide(kernel_with_all_bindings, [GOOD, bad])
        assert (d["final_epistemic_state"], d["status"]) == (base["final_epistemic_state"], base["status"]), bad


def test_unknown_members_are_ignored(kernel_with_all_bindings):  # noqa: F811
    a = _decide(kernel_with_all_bindings, [GOOD])
    b = _decide(kernel_with_all_bindings, [dict(GOOD, weight=3)])
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
