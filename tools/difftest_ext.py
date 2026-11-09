"""Extended differential test: inputs outside the reach of tools/difftest.py.

difftest.py mutates the golden vectors and keeps field types, small record sets
and well-formed signatures. This tool adds the classes CONFORMANCE.md lists as
untested, each case drawn from one class (weights below):

  types   a field of a record gets another JSON type or an extreme value
          (theta as integer, string, null, negative, above 1, 1e308; result as
          number, string, null, list; string fields as numbers, null, very long
          or non-ASCII text)
  shape   a record loses a field or gains an unknown one
  large   50 to 400 records, built from the golden records with mutations
  sig     adversarial Ed25519 signatures on an otherwise valid record: S + L
          (non-canonical scalar), R or S all zero, R the identity point, a
          signature truncated or extended by one byte, base64 without padding,
          URL-safe alphabet or with whitespace
  base    the mutations of difftest.py, as a control

usage: python difftest_ext.py <repo> <n> <seed> <outdir>
Deterministic for a given seed. Output files and outcome kinds as in
difftest.py, plus "by_class" in report.json. A case where both sides reject the
input (Python exception and Rust panic) is counted as "both_reject"; it is an
agreement, but it is listed apart from identical DecisionRecords.
"""
import base64, copy, json, random, subprocess, sys, time
from pathlib import Path

REPO, N, SEED, OUT = Path(sys.argv[1]).resolve(), int(sys.argv[2]), int(sys.argv[3]), Path(sys.argv[4])
sys.path.insert(0, str(REPO))
from gravit_verifier.kernel import VerifierKernel, VerificationRequest, EvidenceRecord, EpistemicState
from gravit_verifier.loader import load_bindings_from_dir
from gravit_verifier.registry import TrustRoot, VerifierRegistry

G = REPO / "tests/golden"
root = TrustRoot.from_file(G / "trust_root.json")
registry = VerifierRegistry.from_file(G / "registry.json", root)
kernels = {True: VerifierKernel(registry), False: VerifierKernel()}
for k in kernels.values():
    for b in load_bindings_from_dir(REPO / "bindings"):
        k.load_binding(b)
golden = json.loads((G / "vectors.json").read_text(encoding="utf-8"))
signed = [v for v in golden if any(e.get("signature") for e in v["evidence"])]
STATES = sorted({v["claimed_state"] for v in golden if v["claimed_state"]}) + [None]
CONTEXTS = [json.loads(s) for s in sorted({json.dumps(v["context"], sort_keys=True) for v in golden})]
VIDS = sorted({e["verifier_id"] for v in golden for e in v["evidence"]}) + ["v_unknown"]
PROVS = sorted({e["provenance"] for v in golden for e in v["evidence"]}) + ["Z", ""]
TS = sorted({e["timestamp"] for v in golden for e in v["evidence"]})
ALL_RECORDS = [e for v in golden for e in v["evidence"]]
FIELDS = ["record_id", "theta", "result", "verifier_id", "timestamp", "provenance", "integrity_hash", "key_id", "signature"]
EDGE = [0.0, 1.0, 0.7, 0.3, 0.6999999999999999, 0.7000000000000001, 0.3000000000000001, 0.5, 1e-9, 1 - 1e-9, 0.1 + 0.2, 2/3]
L = 2**252 + 27742317777372353535851937790883648493  # order of the Ed25519 base point

CLASSES = [("types", 30), ("shape", 10), ("large", 10), ("sig", 25), ("base", 25)]
rng = random.Random(SEED)


def theta():
    r = rng.random()
    if r < 0.4: return rng.choice(EDGE)
    if r < 0.8: return round(rng.random(), rng.choice([1, 2, 3, 6, 15]))
    return rng.random()


def flip_b64(s):
    if not isinstance(s, str) or not s: return s
    i = rng.randrange(len(s) - 2) if len(s) > 2 else 0
    c = "A" if s[i] != "A" else "B"
    return s[:i] + c + s[i + 1:]


def base_mutate(v, ops=None):
    """The mutations of tools/difftest.py."""
    for _ in range(ops or rng.randint(1, 4)):
        ev = v["evidence"]
        op = rng.choice(["theta", "theta", "result", "vid", "prov", "ts", "sig", "hash", "dup", "drop", "claim", "ctx", "reg", "swap", "rid"])
        if op in ("theta", "result", "vid", "prov", "ts", "sig", "hash", "rid") and not ev:
            op = "claim"
        if op == "theta": rng.choice(ev)["theta"] = theta()
        elif op == "result": e = rng.choice(ev); e["result"] = not e.get("result", True)
        elif op == "vid": rng.choice(ev)["verifier_id"] = rng.choice(VIDS)
        elif op == "prov": rng.choice(ev)["provenance"] = rng.choice(PROVS)
        elif op == "ts": rng.choice(ev)["timestamp"] = rng.choice(TS + ["2026-09-06T12:00:00+00:00", "2026-02-30T12:00:00Z", "not-a-date", ""])
        elif op == "sig": e = rng.choice(ev); e["signature"] = flip_b64(e.get("signature"))
        elif op == "hash": rng.choice(ev)["integrity_hash"] = rng.choice(["h", "h2", "6f1ed002ab5595859014ebf0951522d9", ""])
        elif op == "rid": rng.choice(ev)["record_id"] = rng.choice(["r1", "r2", "r3", "r9"])
        elif op == "dup" and ev: ev.append(copy.deepcopy(rng.choice(ev)))
        elif op == "drop" and ev: ev.pop(rng.randrange(len(ev)))
        elif op == "swap" and len(ev) > 1: rng.shuffle(ev)
        elif op == "claim": v["claimed_state"] = rng.choice(STATES)
        elif op == "ctx": v["context"] = copy.deepcopy(rng.choice(CONTEXTS))
        elif op == "reg": v["use_registry"] = not v["use_registry"]
    return v


def other_value(field):
    if field == "theta":
        return rng.choice([0, 1, 2, -1, -0.5, 1.5, 1e308, -1e308, 5e-324, "0.7", "", None, True, False, [0.7], {"v": 0.7}])
    if field == "result":
        return rng.choice([0, 1, 2, -1, 0.5, "true", "false", "", None, [], [True], {}, {"ok": True}])
    long = "x" * rng.choice([1000, 10000])
    return rng.choice([0, 1, -1, 1.5, None, True, [], {}, "", long, "Zürich", "检查", "\u0000", "a‮b", "𝔤𝔯𝔞𝔳𝔦𝔱"])


def mutate_types(v):
    ev = v["evidence"]
    if not ev:
        ev.append(copy.deepcopy(rng.choice(ALL_RECORDS)))
    for _ in range(rng.randint(1, 2)):
        e = rng.choice(ev)
        e[rng.choice(FIELDS)] = other_value(rng.choice(FIELDS) if rng.random() < 0.2 else rng.choice(["theta", "result", "theta", "result"] + FIELDS))
    return v


def mutate_shape(v):
    ev = v["evidence"]
    if not ev:
        ev.append(copy.deepcopy(rng.choice(ALL_RECORDS)))
    e = rng.choice(ev)
    if rng.random() < 0.5:
        e.pop(rng.choice(FIELDS), None)
    else:
        e[rng.choice(["extra", "Theta", "theta ", "weight", "_id"])] = rng.choice([1, "x", None, 0.7])
    return v


def mutate_large(v):
    n = rng.randint(50, 400)
    pool = v["evidence"] or ALL_RECORDS
    v["evidence"] = [copy.deepcopy(rng.choice(pool if rng.random() < 0.7 else ALL_RECORDS)) for _ in range(n)]
    for e in rng.sample(v["evidence"], k=min(len(v["evidence"]), rng.randint(0, 20))):
        e["theta"] = theta()
    return base_mutate(v, rng.randint(0, 2))


def bad_sig(sig):
    """Adversarial variants of a valid base64 Ed25519 signature."""
    raw = base64.b64decode(sig)
    R, S = raw[:32], raw[32:]
    k = rng.choice(["s_plus_l", "s_zero", "r_zero", "r_identity", "all_zero", "short", "long",
                    "nopad", "urlsafe", "space", "newline", "s_plus_l"])
    if k == "s_plus_l":
        s = int.from_bytes(S, "little") + L
        if s >= 2**256: s -= L  # does not fit: keep the canonical one, still a valid case
        return base64.b64encode(R + s.to_bytes(32, "little")).decode()
    if k == "s_zero": return base64.b64encode(R + bytes(32)).decode()
    if k == "r_zero": return base64.b64encode(bytes(32) + S).decode()
    if k == "r_identity": return base64.b64encode((1).to_bytes(32, "little") + S).decode()
    if k == "all_zero": return base64.b64encode(bytes(64)).decode()
    if k == "short": return base64.b64encode(raw[:63]).decode()
    if k == "long": return base64.b64encode(raw + b"\x00").decode()
    if k == "nopad": return sig.rstrip("=")
    if k == "urlsafe": return base64.urlsafe_b64encode(raw).decode()
    if k == "space": return sig[:10] + " " + sig[10:]
    return sig[:20] + "\n" + sig[20:]


def mutate_sig(v):
    v = copy.deepcopy(rng.choice(signed))
    v.pop("expected", None)
    cands = [e for e in v["evidence"] if e.get("signature")]
    for e in rng.sample(cands, k=rng.randint(1, len(cands))):
        try:
            e["signature"] = bad_sig(e["signature"])
        except Exception:
            e["signature"] = flip_b64(e["signature"])
    return v


def make_case():
    cls = rng.choices([c for c, _ in CLASSES], weights=[w for _, w in CLASSES])[0]
    v = copy.deepcopy(rng.choice(golden))
    v.pop("expected", None)
    v = {"types": mutate_types, "shape": mutate_shape, "large": mutate_large, "sig": mutate_sig, "base": base_mutate}[cls](v)
    return cls, v


def py_run(v):
    req = VerificationRequest(v["name"], EpistemicState(v["claimed_state"]) if v["claimed_state"] else None,
                              [EvidenceRecord(**e) for e in v["evidence"]], v["context"])
    return kernels[v["use_registry"]].verify(req).to_dict()


OUT.mkdir(parents=True, exist_ok=True)
t0 = time.time()
cases, classes, py_out = [], [], []
while len(cases) < N:
    cls, v = make_case()
    try:
        json.dumps(v, allow_nan=False)
    except ValueError:
        continue
    try:
        d = py_run(v)
    except Exception as e:
        d = {"python_exception": type(e).__name__ + ": " + str(e)[:200]}
    cases.append(v); classes.append(cls); py_out.append(d)
t_py = time.time() - t0
(OUT / "cases.json").write_text(json.dumps(cases, ensure_ascii=False, allow_nan=False), encoding="utf-8")
t1 = time.time()
rust = subprocess.run([str(REPO / "rust/target/release/examples/replay"), str(OUT / "cases.json")], capture_output=True, text=True, check=True)
t_rs = time.time() - t1
(OUT / "rust.jsonl").write_text(rust.stdout, encoding="utf-8")
rs_out = [json.loads(l) for l in rust.stdout.splitlines()]
assert len(rs_out) == N


def norm(x):
    return json.loads(json.dumps(x, sort_keys=True))


mism, kinds, states, by_class = [], {}, {}, {}
for i, (cls, c, p, r) in enumerate(zip(classes, cases, py_out, rs_out)):
    if "python_exception" in p:
        k = "both_reject" if "panic" in r else "python_exception_only"
    elif "panic" in r:
        k = "rust_panic_only"
    elif norm(p) != norm(r["got"]):
        k = "different_decision_record"
    else:
        k = "identical"
        s = (p.get("final_epistemic_state"), p.get("status")); states[str(s)] = states.get(str(s), 0) + 1
    kinds[k] = kinds.get(k, 0) + 1
    by_class.setdefault(cls, {}); by_class[cls][k] = by_class[cls].get(k, 0) + 1
    if k not in ("identical", "both_reject"):
        mism.append({"i": i, "class": cls, "kind": k, "case": c, "python": p, "rust": r})
report = {"seed": SEED, "cases": N, "outcomes": kinds, "by_class": by_class, "identical_by_state_status": states,
          "python_seconds": round(t_py, 2), "rust_seconds": round(t_rs, 2)}
(OUT / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True), encoding="utf-8")
(OUT / "mismatches.json").write_text(json.dumps(mism[:500], indent=1, ensure_ascii=False, sort_keys=True), encoding="utf-8")
print(json.dumps(report, indent=1, sort_keys=True))
