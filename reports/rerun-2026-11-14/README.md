# Re-run on a second machine, 14 November 2026: 10,000,000 cases

Part of the extended differential run of 9 to 10 November
(`reports/difftest-ext-2026-11-10`) was repeated on a different machine, at a
different provider, with newer Python and Rust, from a fresh clone of this
repository. The question: do the published results depend on the machine they
were produced on?

| | |
|---|---|
| Seeds | every tenth seed from 20001 to 29991: 1,000 seeds of 10,000 cases, spread over the whole original run |
| Class weights | `types=30,shape=10,large=1,sig=25,base=25`, as in the original run |
| Code | this repository at `0f6df11`, unchanged |
| Machine | cloud instance in Geneva, 4 vCPU, 8 GB, Ubuntu 24.04.5; Python 3.12.3, rustc 1.100.0 (original: Debian 12, 2 vCPU, Python 3.11.2, rustc 1.99.1) |
| Time | 2026-11-14T16:07:32Z to 2026-11-14T20:27:59Z |
| CPU time | Python 21,488 s, Rust 8,160 s |

## Result

**1,000 of 1,000 seed reports are identical to the published ones** in every
compared field (`cases`, `by_class`, `identical_by_state_status`). 10,000,000
cases, all decided identically by the Python reference and the Rust port; no
mismatch entry in any seed.

| Final state | Status | Cases |
|---|---|---|
| Probabilistic Assessment | DEGRADED | 4,596,322 |
| (none) | REJECTED | 2,889,833 |
| Verified Fact | SUCCESS | 827,315 |
| Probabilistic Assessment | SUCCESS | 729,130 |
| Speculative Claim | DEGRADED | 640,369 |
| Speculative Claim | SUCCESS | 123,508 |
| VALIDATED | DEGRADED | 99,440 |
| VALIDATED | SUCCESS | 94,083 |

## What this shows and what it does not

It shows that the published results do not depend on the original machine,
operating system, Python or Rust version: another machine reaches the same
decisions from the same seeds. It is a re-run by the same team, not an
independent third-party review. Anyone can repeat any seed with the command in
`reports/difftest-ext-2026-11-10/README.md`.

The first attempt stopped at 293 seeds because the disk filled with
intermediate case files; it was resumed, with intermediate files removed after
each seed. Seeds already finished were kept; no result was affected.

## Check it yourself

`seeds.jsonl.gz` holds the `report.json` of every re-run seed, one line each,
plus `mismatches`, the number of entries in that seed's `mismatches.json`
(sha256 of the uncompressed file `3946c9cc...b9f2`, of the gzip file `b543b30b...f2bf`).

```bash
python tools/difftest_summary.py reports/rerun-2026-11-14/seeds.jsonl.gz
python - <<'EOF'
import gzip, json
pub = {json.loads(l)["seed"]: json.loads(l) for l in gzip.open("reports/difftest-ext-2026-11-10/seeds.jsonl.gz", "rt")}
new = [json.loads(l) for l in gzip.open("reports/rerun-2026-11-14/seeds.jsonl.gz", "rt")]
keys = ("cases", "by_class", "identical_by_state_status")
same = sum(all(pub[r["seed"]][k] == r[k] for k in keys) for r in new)
print(same, "of", len(new), "identical to the published reports")
EOF
```
