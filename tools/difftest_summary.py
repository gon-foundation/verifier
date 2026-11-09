"""Recompute the totals of a differential run from its per-seed reports.

Usage: python tools/difftest_summary.py reports/difftest-2026-11-07/seeds.jsonl.gz
Each line is the report.json of one seed (tools/difftest.py) plus "mismatches",
the number of entries in that seed's mismatches.json.
"""
import collections, gzip, json, sys

seeds, cases, mism, py, rs = set(), 0, 0, 0.0, 0.0
outcomes, classes = collections.Counter(), collections.Counter()
with gzip.open(sys.argv[1], "rt", encoding="utf-8") as f:
    for line in f:
        r = json.loads(line)
        if r["seed"] in seeds:
            sys.exit("duplicate seed %d" % r["seed"])
        seeds.add(r["seed"])
        cases += r["cases"]
        mism += r["mismatches"]
        outcomes.update(r["outcomes"])
        classes.update(r["identical_by_state_status"])
        py += r["python_seconds"]
        rs += r["rust_seconds"]
print(json.dumps({
    "seeds": len(seeds), "first_seed": min(seeds), "last_seed": max(seeds),
    "cases": cases, "outcomes": dict(outcomes), "mismatches": mism,
    "identical_by_state_status": dict(classes.most_common()),
    "python_cpu_seconds": round(py), "rust_cpu_seconds": round(rs),
}, indent=1))
