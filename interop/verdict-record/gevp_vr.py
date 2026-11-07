"""GEVP decisions as verdict records (draft-wright-verdict-record-02).

Each golden vector of the Gravit verifier becomes:
  item 0  the verification request (artifact, claimed state, signed evidence
          records, context), as RFC 8785 bytes;
  item 1  the verifier registry, exact file bytes (when the vector uses one);
  record  kind check-run, rule = the GEVP decision of the kernel at a pinned
          commit, every rule input bound to an evidence item (no copy in body),
          result = decision_id, final state and status.
The records are then checked with gvrcheck.py under several readings, and with
tampered or withheld inputs.

Usage: python3 gevp_vr.py ../.. records   (from this directory)
"""
import base64, hashlib, json, sys
from pathlib import Path

import gvrcheck as vr

REPO = Path(sys.argv[1]).resolve()
OUT = Path(sys.argv[2])
sys.path.insert(0, str(REPO))
from gravit_verifier.kernel import (VerifierKernel, VerificationRequest, EvidenceRecord,
                                    EpistemicState, canonical_json)
from gravit_verifier.loader import load_bindings_from_dir
from gravit_verifier import registry as reg

# The rule is the kernel and bindings at this commit (unchanged since c37c989).
COMMIT = "7f19df130dee73efa951d0acb72a8706ecc63885"
BASE = "https://github.com/gravit-open-network-foundation/verifier/tree/" + COMMIT
RULE = BASE + "#gevp-decision"
F_REQ = BASE + "#verification-request"
F_REG = BASE + "#verifier-registry"
UB = "2026-11-07T12:00:00.000000Z"  # upper time bound: given by the container, not by the record

G = REPO / "tests/golden"
TRUST_BYTES = (G / "trust_root.json").read_bytes()
ROOT = reg.TrustRoot.from_bytes(TRUST_BYTES)  # the checker's trust anchor
REG_BYTES = (G / "registry.json").read_bytes()
REG_SIG = (G / "registry.json.sig").read_text(encoding="utf-8")
BINDINGS = load_bindings_from_dir(REPO / "bindings")


def kernel(registry):
    k = VerifierKernel(registry)
    for b in BINDINGS:
        k.load_binding(b)
    return k


def registry_from_doc(doc, digest):
    """The registry the kernel uses, built from the parsed item (step 3 gets
    values, not bytes) and the digest of the item bytes."""
    keys = {}
    for i, (kid, pk, v) in enumerate(reg._public_key_entries(doc.get("verifiers"), "verifiers")):
        keys[kid] = reg.RegisteredKey(kid, pk, v["operator"], v.get("revoked", False),
                                      reg._independence_evidence(v.get("independence_evidence"), i))
    return reg.VerifierRegistry(keys, digest, ROOT.digest, [])


def gevp_rule(inp):
    """The GEVP decision. Inputs: request; optionally registry and registry_digest."""
    if "request" not in inp or set(inp) - {"request", "registry", "registry_digest"}:
        return None
    q = inp["request"]
    if not isinstance(q, dict) or set(q) != {"artifact_id", "claimed_state", "context", "evidence"}:
        return None
    registry = None
    if "registry" in inp:
        if not isinstance(inp.get("registry_digest"), str):
            return None
        registry = registry_from_doc(inp["registry"], inp["registry_digest"])
    req = VerificationRequest(q["artifact_id"], EpistemicState(q["claimed_state"]) if q["claimed_state"] else None,
                              [EvidenceRecord(**e) for e in q["evidence"]], q["context"])
    d = kernel(registry).verify(req).to_dict()
    return {"decision_id": d["decision_id"], "final_epistemic_state": d["final_epistemic_state"], "status": d["status"]}


def verify_request(item, items):
    try:
        q = vr.strict_parse(item["bytes"], fractions=True)
    except vr.Refuse:
        return False
    # Signatures of the evidence records are checked by the rule itself: a bad
    # one is excluded and the exclusion is part of the recorded decision.
    return isinstance(q, dict) and set(q) == {"artifact_id", "claimed_state", "context", "evidence"}


def verify_registry(item, items):
    try:
        reg.VerifierRegistry.from_bytes(item["bytes"], item.get("detached_signatures", ""), ROOT)
        return True
    except Exception:
        return False


vr.VERIFIES[F_REQ] = verify_request
vr.VERIFIES[F_REG] = verify_registry
RULES = dict(vr.RULES, **{RULE: gevp_rule})
POLICY = {"judgement_kinds": [], "formats": [F_REQ, F_REG], "max_depth": 0}


def build(v):
    q = {"artifact_id": v["name"], "claimed_state": v["claimed_state"], "context": v["context"], "evidence": v["evidence"]}
    qb = canonical_json(q).encode("utf-8")
    ev = [{"format": F_REQ, "sha256": vr.sha(qb)}]
    items = {vr.sha(qb): {"bytes": qb}}
    inputs = {"request": {"evidence": 0, "pointer": ""}}
    if v["use_registry"]:
        ev.append({"format": F_REG, "sha256": vr.sha(REG_BYTES)})
        items[vr.sha(REG_BYTES)] = {"bytes": REG_BYTES, "detached_signatures": REG_SIG}
        inputs["registry"] = {"evidence": 1, "pointer": ""}
        inputs["registry_digest"] = {"evidence": 1}
    exp = v["expected"]
    rec = {
        "act_time": "2026-11-07T10:00:00.000000Z",
        "actor": {"id": "gravit-verifier-python", "model": "none", "model_version": "0", "type": "system"},
        "body": {"claim": {"ref": ev[0]}},
        "check": {"inputs": inputs, "rule": RULE,
                  "result": {"decision_id": exp["decision_id"], "final_epistemic_state": exp["final_epistemic_state"],
                             "status": exp["status"]}},
        "evidence": ev, "key": "gevp/golden/" + v["name"], "kind": "check-run",
        "supersedes": None, "v": vr.V, "version": 1, "writer": "gravitopennetwork.org",
    }
    return vr.cbytes(rec), items


def run(rb, items, policy=POLICY):
    return vr.check(rb, items, UB, policy, 0, RULES)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    vectors = json.loads((G / "vectors.json").read_text(encoding="utf-8"))
    rows, tally = [], {}

    def count(label, res, want):
        ok = res["state"] == want
        tally.setdefault(label, [0, 0, want])
        tally[label][0] += ok
        tally[label][1] += 1
        if not ok:
            print("UNEXPECTED", label, res)
        return res

    for v in vectors:
        rb, items = build(v)
        # A: fractions allowed in evidence items read by pointer
        vr.ITEM_FRACTIONS = True
        a = count("A  bound inputs, fractions read from items", run(rb, items), "released")
        count("A' same, policy reads inputs from evidence only", run(rb, items, dict(POLICY, inputs_from_evidence_only=True)), "released")
        # B: Section 2.1 integer rule applied to items too
        vr.ITEM_FRACTIONS = False
        has_frac = any(isinstance(e.get("theta"), float) and not float(e["theta"]).is_integer() for e in v["evidence"])
        b = run(rb, items)
        count("B  integers only in items (vectors with a fractional theta)" if has_frac else
              "B  integers only in items (vectors without one)", b, "refused" if has_frac else "released")
        vr.ITEM_FRACTIONS = True
        # Tampering and withholding
        r = json.loads(rb)
        r["check"]["result"]["final_epistemic_state"] = "Verified Fact" if r["check"]["result"]["final_epistemic_state"] != "Verified Fact" else "Probabilistic Assessment"
        count("T1 stated state changed", run(vr.cbytes(r), items), "refused")
        if v["evidence"]:
            q = json.loads(items[r["evidence"][0]["sha256"]]["bytes"])
            q["evidence"][0]["result"] = not q["evidence"][0]["result"]
            qb = canonical_json(q).encode("utf-8")
            count("T2 one evidence record changed after the fact", run(rb, {vr.sha(qb): {"bytes": qb}, **{k: x for k, x in items.items() if k != r["evidence"][0]["sha256"]}}), "held")
        if v["use_registry"]:
            count("T3 registry withheld", run(rb, {k: x for k, x in items.items() if k != vr.sha(REG_BYTES)}), "held")
            bad = dict(items)
            bad[vr.sha(REG_BYTES)] = {"bytes": REG_BYTES, "detached_signatures": ""}
            count("T4 registry without root signatures", run(rb, bad), "held")
        (OUT / (v["name"] + ".json")).write_text(json.dumps({
            "name": v["name"], "record_b64": base64.b64encode(rb).decode(), "record_sha256": vr.sha(rb),
            "evidence_items": [dict({"b64": base64.b64encode(x["bytes"]).decode()},
                                    **({"detached_signatures": x["detached_signatures"]} if "detached_signatures" in x else {}))
                               for x in items.values()],
            "upper_time_bound": UB, "policy": POLICY, "policy_sha256": vr.sha(vr.cbytes(POLICY)),
            "trust_anchor_sha256": ROOT.digest,
            "expected_with_gevp_rule": {"state": a["state"], "steps": a["steps"]}}, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        rows.append((v["name"], vr.sha(rb)[:16], a["state"], b["state"]))

    print("rule:", RULE)
    print("policy sha256:", vr.sha(vr.cbytes(POLICY)), " trust anchor sha256:", ROOT.digest)
    for label, (ok, n, want) in tally.items():
        print("%-62s %3d/%-3d %s" % (label, ok, n, want))
