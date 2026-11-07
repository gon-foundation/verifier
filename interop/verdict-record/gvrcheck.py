"""Checker for draft-wright-verdict-record-02, written by the Gravit team.

Written from the draft text (-02) and the vector file format in the README of
https://github.com/diggertydog/verdict-record-test-vectors. The reference
checker (vrcheck.py) and the blind checker of that repository were not read.
Where -02 leaves a point open, the reading taken here is marked READING.

Usage: python3 gvrcheck.py VECTOR.json [...]   (prints state and steps, and
compares them with the vector's expected answer when it has one)
"""
import base64, hashlib, json, re, sys

V = "verdict-record/1"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
MAX_INT = 2**53 - 1
MAX_NEST = 32

# Test-only formats and rules defined by the vector repository (README, proposals/README).
VERIFIES = {
    "urn:example:verdict-record:format:opaque": True,
    "urn:example:verdict-record:format:never-verifies": False,
    "urn:example:verdict-record:format:provider-attestation": True,
    "urn:example:verdict-record:format:inference-proof": True,
    "urn:example:verdict-record:format:salted-commitment": False,  # no checker holds the salt
}


class Refuse(Exception):
    pass


# ---------------------------------------------------------------- Section 2.1

def _no_float(s):
    raise Refuse("number is not an integer: " + s)


def _int(s):
    n = int(s)
    if abs(n) > MAX_INT:
        raise Refuse("integer out of range: " + s)
    return n


def _pairs(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise Refuse("duplicate member: " + k)
        d[k] = v
    return d


def _walk(x, level):
    """Nesting level: the outermost value is level 1; each object or array
    inside adds one. Also rejects lone surrogates left by escapes."""
    if isinstance(x, str):
        if any(0xD800 <= ord(c) <= 0xDFFF for c in x):
            raise Refuse("lone surrogate")
        return
    if isinstance(x, (dict, list)):
        if level > MAX_NEST:
            raise Refuse("nested deeper than 32 levels")
        for k, v in (x.items() if isinstance(x, dict) else enumerate(x)):
            if isinstance(k, str):
                _walk(k, level)
            _walk(v, level + 1)


# READING: -02 says an evidence item read by pointer is "parsed as strict JSON
# by the rules of Section 2.1". Whether that excludes fractions in items is
# not settled. Default False refuses them, as for the record itself.
ITEM_FRACTIONS = False


def strict_parse(b, fractions=False):
    """Strict JSON of Section 2.1 (canonical form not required)."""
    if b.startswith(b"\xef\xbb\xbf"):
        raise Refuse("byte-order mark")
    try:
        text = b.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise Refuse("not UTF-8")
    try:
        x = json.loads(text, object_pairs_hook=_pairs, parse_float=float if fractions else _no_float,
                       parse_int=_int, parse_constant=_no_float)
    except Refuse:
        raise
    except (ValueError, RecursionError) as e:
        raise Refuse("not JSON: %s" % e)
    _walk(x, 1)
    return x


def _str(s):
    out = ['"']
    for c in s:
        o = ord(c)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif o < 0x20:
            # READING (I-12): JCS forms, \b \t \n \f \r short, others \u00xx.
            out.append({8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}.get(o, "\\u%04x" % o))
        else:
            out.append(c)
    out.append('"')
    return "".join(out)


def canonical(x):
    if x is None:
        return "null"
    if x is True:
        return "true"
    if x is False:
        return "false"
    if isinstance(x, int):
        return str(x)
    if isinstance(x, str):
        return _str(x)
    if isinstance(x, list):
        return "[" + ",".join(canonical(v) for v in x) + "]"
    if isinstance(x, dict):  # Python orders str by code point, as Section 2.1 asks
        return "{" + ",".join(_str(k) + ":" + canonical(x[k]) for k in sorted(x)) + "}"
    raise Refuse("not a JSON value")


def cbytes(x):
    return canonical(x).encode("utf-8")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


# ---------------------------------------------------------------- Section 2.2, 2.3

MEMBERS = {"v", "kind", "key", "version", "supersedes", "writer", "actor",
           "act_time", "evidence", "check", "body"}
REQUIRED = {"v", "kind", "key", "version", "writer", "body"}


def check_members(r):
    """Section 2.2 except evidence and check, and 2.3: refused before any step."""
    if not isinstance(r, dict):
        raise Refuse("record is not an object")
    extra = set(r) - MEMBERS
    if extra:
        raise Refuse("unknown member: " + ",".join(sorted(extra)))
    missing = REQUIRED - set(r)
    if missing:
        raise Refuse("missing member: " + ",".join(sorted(missing)))
    if r["v"] != V:
        raise Refuse("v is not " + V)
    if not isinstance(r["kind"], str):
        raise Refuse("kind is not a string")
    for m in ("key", "writer"):
        if not isinstance(r[m], str) or not r[m]:
            raise Refuse(m + " is not a non-empty string")
    if not is_int(r["version"]) or r["version"] < 1:
        raise Refuse("version is not an integer of 1 or more")
    if "supersedes" in r:
        s = r["supersedes"]
        if r["version"] == 1 and s is not None:
            raise Refuse("supersedes is not null for version 1")
        if r["version"] > 1 and not (isinstance(s, str) and HEX64.match(s)):
            raise Refuse("supersedes is not a digest")
    if "actor" in r:
        a = r["actor"]
        keys = {"type", "id"} | ({"model", "model_version"} if isinstance(a, dict) and a.get("type") == "system" else set())
        if not isinstance(a, dict) or set(a) != keys or a["type"] not in ("person", "system") \
                or not all(isinstance(a[k], str) for k in keys):
            raise Refuse("actor is malformed")
    if "act_time" in r and not (isinstance(r["act_time"], str) and TIME.match(r["act_time"])):
        raise Refuse("act_time is not a time")
    body = r["body"]
    if not isinstance(body, dict):
        raise Refuse("body is not an object")
    claim = body.get("claim")
    if not isinstance(claim, dict) or len(claim) != 1 or not (
            isinstance(claim.get("text"), str) or isinstance(claim.get("ref"), dict)):
        raise Refuse("body.claim is not an object with exactly one of text or ref")
    if "ref" in claim:
        ev = r.get("evidence")
        # READING (I-2): a ref missing from evidence is a Section 2.3 break, refused before the steps.
        if not isinstance(ev, list) or claim["ref"] not in ev:
            raise Refuse("body.claim.ref does not appear in evidence")


# ---------------------------------------------------------------- Section 4.5

POLICY = {"judgement_kinds", "formats", "max_depth"}
EVIDENCE_ONLY = "inputs_from_evidence_only"  # READING: -02 names no member for this option


def policy_valid(p):
    if not isinstance(p, dict) or not POLICY <= set(p) or set(p) - POLICY - {EVIDENCE_ONLY}:
        return False
    if EVIDENCE_ONLY in p and not isinstance(p[EVIDENCE_ONLY], bool):
        return False
    return (isinstance(p["judgement_kinds"], list) and all(isinstance(k, str) for k in p["judgement_kinds"])
            and isinstance(p["formats"], list) and all(isinstance(k, str) for k in p["formats"])
            and is_int(p["max_depth"]) and p["max_depth"] >= 0)


# ---------------------------------------------------------------- rules

def rule_at_least(inp):
    """urn:example:verdict-record:rule:at-least (vector README)."""
    if set(inp) != {"value", "min"} or not all(is_int(v) for v in inp.values()):
        return None  # wrong type: FAIL of step 3
    return "pass" if inp["value"] >= inp["min"] else "fail"


RULES = {"urn:example:verdict-record:rule:at-least": rule_at_least}


def pointer(doc, p):
    """RFC 6901. Returns (ok, value)."""
    if p == "":
        return True, doc
    if not p.startswith("/"):
        return False, None
    for tok in p[1:].split("/"):
        tok = tok.replace("~1", "/").replace("~0", "~")
        if isinstance(doc, dict) and tok in doc:
            doc = doc[tok]
        elif isinstance(doc, list) and re.fullmatch(r"0|[1-9]\d*", tok) and int(tok) < len(doc):
            doc = doc[int(tok)]
        else:
            return False, None
    return True, doc


# ---------------------------------------------------------------- Section 4

PASS, FAIL, NOT_RUN = "PASS", "FAIL", "NOT RUN"


def check(record_bytes, items, ub, policy, depth=0, rules=RULES):
    """items: {digest: {"bytes": b, "upper_time_bound": str|None}}.
    Returns {"state", "steps", "notes"}."""
    if not policy_valid(policy):
        return {"state": "no verdict", "steps": None, "notes": ["policy is invalid"]}
    try:
        r = strict_parse(record_bytes)
        if cbytes(r) != record_bytes:
            raise Refuse("not in canonical form")
        check_members(r)
    except Refuse as e:
        return {"state": "refused", "steps": None, "notes": [str(e)]}
    notes = []
    if ub is None:
        # READING (I-15): Section 3, the container gives no upper time bound.
        return {"state": "held", "steps": None, "notes": ["no upper time bound"]}

    # Step 1
    c = r.get("check")
    s1 = PASS
    if not isinstance(c, dict) or not ({"rule", "result"} <= set(c) <= {"rule", "result", "inputs"}) \
            or not isinstance(c["rule"], str):
        s1 = FAIL
        notes.append("step 1: check is missing or malformed")
    elif c["rule"] == "judgement" and r["kind"] not in policy["judgement_kinds"]:
        s1 = FAIL
        notes.append("step 1: judgement not allowed for kind " + r["kind"])

    # Step 2
    ev = r.get("evidence")
    relied = set()
    if not isinstance(ev, list) or not all(
            isinstance(e, dict) and set(e) == {"sha256", "format"} and isinstance(e["sha256"], str)
            and HEX64.match(e["sha256"]) and isinstance(e["format"], str) for e in ev):
        s2 = FAIL
        notes.append("step 2: evidence is missing or malformed")
    else:
        s2 = PASS
        for i, e in enumerate(ev):
            why = None
            it = items.get(e["sha256"])
            if it is None:
                why = "item not held"
            elif e["format"] not in policy["formats"]:
                why = "format not in policy: " + e["format"]
            elif it.get("upper_time_bound") is not None and it["upper_time_bound"] > ub:
                why = "item upper time bound later than the record's"
            elif e["format"] == V:
                if depth + 1 > policy["max_depth"]:
                    why = "beyond citation depth"
                elif check(it["bytes"], items, it.get("upper_time_bound"), policy, depth + 1, rules)["state"] != "released":
                    why = "cited verdict record is not released"
            elif e["format"] not in VERIFIES:
                why = "no rules held for format " + e["format"]
            elif not (VERIFIES[e["format"]](it, items) if callable(VERIFIES[e["format"]]) else VERIFIES[e["format"]]):
                why = "item does not verify"
            if why:
                s2 = NOT_RUN
                notes.append("step 2: entry %d: %s" % (i, why))
            else:
                relied.add(i)

    # Step 3
    if not isinstance(c, dict) or not isinstance(c.get("rule"), str) or "result" not in c:
        s3 = NOT_RUN
        notes.append("step 3: no rule or result to re-run")
    elif c["rule"] == "judgement":
        s3 = PASS  # READING (I-4): nothing to re-run
    elif c["rule"] not in rules:
        s3 = NOT_RUN
        notes.append("step 3: rule not held: " + c["rule"])
    else:
        s3, msg, from_body = _step3(r, c, ev, relied, items, policy, rules[c["rule"]])
        if msg:
            notes.append("step 3: " + msg)
        if from_body:
            notes.append("step 3: inputs read from body (issuer's statement): " + ",".join(from_body))

    steps = {"1": s1, "2": s2, "3": s3}
    vals = steps.values()
    state = "refused" if FAIL in vals else "held" if NOT_RUN in vals else "released"
    return {"state": state, "steps": steps, "notes": notes}


def _step3(r, c, ev, relied, items, policy, rule):
    inputs = c.get("inputs", {})
    if not isinstance(inputs, dict):
        return FAIL, "inputs is not an object", []
    vals, fail, notrun, from_body = {}, [], [], []
    for name, src in inputs.items():
        if isinstance(src, str):
            from_body.append(name)
            if policy.get(EVIDENCE_ONLY):
                notrun.append(name + " read from body under evidence-only policy")
            elif src not in r["body"]:
                fail.append(name + ": no such member of body")
            else:
                vals[name] = r["body"][src]
        elif isinstance(src, dict) and "evidence" in src and set(src) <= {"evidence", "pointer"} \
                and is_int(src["evidence"]) and isinstance(src.get("pointer", ""), str):
            i = src["evidence"]
            if not isinstance(ev, list) or not 0 <= i < len(ev) or not isinstance(ev[i], dict):
                fail.append(name + ": no such evidence entry")
            elif i not in relied:
                notrun.append(name + ": evidence %d not relied on by step 2" % i)
            else:
                b = items[ev[i]["sha256"]]["bytes"]
                if "pointer" not in src:
                    vals[name] = sha(b)
                else:
                    try:
                        ok, v = pointer(strict_parse(b, ITEM_FRACTIONS), src["pointer"])
                    except Refuse:
                        ok = False
                    if ok:
                        vals[name] = v
                    else:
                        fail.append(name + ": pointer does not resolve")
        else:
            fail.append(name + ": malformed binding")
    if fail:
        return FAIL, "; ".join(fail), from_body
    if notrun:
        return NOT_RUN, "; ".join(notrun), from_body
    got = rule(vals)
    if got is None:
        return FAIL, "rule input of the wrong type", from_body
    if canonical(got) != canonical(c["result"]):
        return FAIL, "re-run gives %s, record states %s" % (canonical(got), canonical(c["result"])), from_body
    return PASS, None, from_body


# ---------------------------------------------------------------- vectors

def load_items(v):
    items = {}
    for it in v.get("evidence_items", []):
        b = base64.b64decode(it["b64"])
        items[sha(b)] = {"bytes": b, "upper_time_bound": it.get("upper_time_bound")}
    return items


def run_vector(v, rules=RULES):
    rb = base64.b64decode(v["record_b64"])
    res = check(rb, load_items(v), v.get("upper_time_bound"), v["policy"], 0, rules)
    res["record_sha256_ok"] = sha(rb) == v.get("record_sha256")
    if policy_valid(v["policy"]):
        res["policy_sha256_ok"] = sha(cbytes(v["policy"])) == v.get("policy_sha256")
    return res


if __name__ == "__main__":
    agree = 0
    for f in sys.argv[1:]:
        v = json.load(open(f, encoding="utf-8"))
        res = run_vector(v)
        exp = v.get("expected") or v.get("expected_under_02")
        if exp is None:
            print("        " + v["name"].ljust(36) + res["state"].ljust(11) + str(res["steps"]))
            for n in res["notes"]:
                print("          " + n)
            continue
        same_state = exp.get("state") == res["state"]
        same_steps = exp.get("steps") is None or exp.get("steps") == res["steps"]
        agree += same_state and same_steps
        mark = "AGREE   " if same_state and same_steps else "DIFFER  "
        print(mark + v["name"].ljust(36) + res["state"].ljust(11) + str(res["steps"]) +
              ("" if same_state and same_steps else "  expected %s %s" % (exp.get("state"), exp.get("steps"))))
        for n in res["notes"]:
            print("          " + n)
    print("\n%d agree with the expected answer given" % agree)
