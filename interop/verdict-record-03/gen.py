"""Generate verdict records (draft-wright-verdict-record-03, kind check-run) over published Gravit golden vectors,
in the vector format of https://github.com/diggertydog/verdict-record-test-vectors.

    python3 interop/verdict-record-03/gen.py            # writes vectors/*.json and the held module's pin

Each positive record cites, by SHA-256, four files of this repository exactly as published: tests/golden/
vectors.json, registry.json, registry.json.sig and trust_root.json. Its rule runs the Gravit kernel whose sources
it names by digest; its result is the kernel's decision. The negative records break the record (non-ASCII and
non-BMP member names, Section 2.1) or state a result the re-run does not give.
"""
import base64
import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
GOLDEN = ROOT / "tests" / "golden"
UPPER = "2026-11-27T12:00:00.000000Z"
ACT = "2026-11-27T10:00:00.000000Z"
JSONDOC, SIGFMT = "urn:gravit:format:json-document", "urn:gravit:format:registry-signatures"


def sha(b):
    return hashlib.sha256(b).hexdigest()


def kernel_digest():
    files = sorted(list((ROOT / "gravit_verifier").glob("*.py")) + list((ROOT / "bindings").glob("*.yaml")))
    lines = "".join(f"{sha(p.read_bytes())}  {p.relative_to(ROOT).as_posix()}\n" for p in files)
    return sha(lines.encode("utf-8"))


def canon(obj):
    """Section 2.1: sorted members, no whitespace, UTF-8, integers only (all records here are ASCII-named)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def main():
    kd = kernel_digest()
    held = HERE / "held" / "gravit_verifier_decide.py"
    held.write_text(re.sub(r'KERNEL_SHA256 = "[^"]*"', f'KERNEL_SHA256 = "{kd}"', held.read_text()), encoding="utf-8")
    rule = "urn:gravit:rule:gevp-decide:kernel-sha256:" + kd

    files = {n: (GOLDEN / n).read_bytes() for n in ("vectors.json", "registry.json", "registry.json.sig", "trust_root.json")}
    vectors = json.loads(files["vectors.json"])
    evidence = [{"format": JSONDOC, "sha256": sha(files["vectors.json"])},
                {"format": JSONDOC, "sha256": sha(files["registry.json"])},
                {"format": SIGFMT, "sha256": sha(files["registry.json.sig"])},
                {"format": JSONDOC, "sha256": sha(files["trust_root.json"])}]
    items = [{"b64": base64.b64encode(b).decode()} for b in files.values()]
    policy = {"citation_depth": 1, "formats": [JSONDOC, SIGFMT], "inputs_from_evidence_only": True, "judgement_kinds": []}

    def pick(state, status, registry=True):
        for i, v in enumerate(vectors):
            e = v["expected"]
            if e["final_epistemic_state"] == state and e["status"] == status and v["use_registry"] == registry:
                return i, v
        raise SystemExit(f"no golden vector with {state} / {status}")

    def record(i, v, result, key, body_extra=None):
        body = {"claim": {"text": f"Gravit golden vector {v['name']} (index {i}) decides "
                                  f"{result['final_epistemic_state'] or 'no state'}, {result['status']}"}}
        r = {"v": "verdict-record/1", "kind": "check-run", "key": key, "version": 1, "supersedes": None,
             "writer": "Gravit Open Network Foundation (test vectors)",
             "actor": {"type": "system", "id": "gravit-verifier", "model": "gravit-verifier-kernel",
                       "model_version": "kernel-sha256:" + kd},
             "act_time": ACT, "evidence": evidence,
             "check": {"rule": rule, "inputs": {"request": {"evidence": 0, "pointer": f"/{i}"},
                                                "registry": {"evidence": 1}, "signatures": {"evidence": 2},
                                                "trust_root": {"evidence": 3}},
                       "result": result},
             "body": body}
        return r

    out = []
    for n, (state, status) in enumerate([("Verified Fact", "SUCCESS"), (None, "REJECTED"),
                                         ("Probabilistic Assessment", "DEGRADED")], 1):
        i, v = pick(state, status)
        res = {k: v["expected"][k] for k in ("decision_id", "final_epistemic_state", "status")}
        out.append((f"gv{n:02d}-{(status).lower()}", f"released: the rule re-run gives the stated result for {v['name']}",
                    canon(record(i, v, res, f"gravit-golden-{v['name']}")),
                    {"state": "released", "named": "PASS"}))

    # n01: the stated result is not what the kernel gives (claims Verified Fact for a rejected request).
    i, v = pick(None, "REJECTED")
    bad = {"decision_id": v["expected"]["decision_id"], "final_epistemic_state": "Verified Fact", "status": "SUCCESS"}
    out.append(("gn01-result-not-reproduced", f"refused: the re-run of {v['name']} gives REJECTED, not the stated result",
                canon(record(i, v, bad, f"gravit-golden-{v['name']}-wrong")), {"state": "refused", "named": "FAIL at step 3"}))

    # n02, n03: a member name outside ASCII breaks Section 2.1 (written as UTF-8 bytes, and as an escape).
    i, v = pick("Verified Fact", "SUCCESS")
    good = canon(record(i, v, {k: v["expected"][k] for k in ("decision_id", "final_epistemic_state", "status")}, "gravit-nonascii"))
    raw = good.replace(b'"claim":', '"\U0001D11E":1,"claim":'.encode("utf-8"))      # U+1D11E as UTF-8, sorts first
    esc = good.replace(b'"claim":', b'"\\ud834\\udd1e":1,"claim":')                     # the same as an escape
    out.append(("gn02-non-bmp-name-utf8", "refused before any step: member name U+1D11E (UTF-8 bytes) breaks Section 2.1",
                raw, {"state": "refused", "named": "Section 2.1"}))
    out.append(("gn03-non-bmp-name-escaped", "refused before any step: member name U+1D11E (escaped surrogate pair) breaks Section 2.1",
                esc, {"state": "refused", "named": "Section 2.1"}))

    (HERE / "vectors").mkdir(exist_ok=True)
    for name, desc, rb, exp in out:
        doc = {"name": name, "section": "2.1, 4.3", "description": desc,
               "record_b64": base64.b64encode(rb).decode(), "record_sha256": sha(rb),
               "evidence_items": items, "upper_time_bound": UPPER, "policy": policy,
               "policy_sha256": sha(canon(policy)), "expected": exp}
        (HERE / "vectors" / f"{name}.json").write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"kernel sha256 {kd}; wrote {len(out)} vectors")


if __name__ == "__main__":
    main()
