# Differential run of 6 to 7 Nov 2026: 100,000,000 cases

Python reference kernel against the Rust port, with `tools/difftest.py`.
Every case is one of the 60 golden vectors with 1 to 4 random mutations; both
kernels decide it, and the full DecisionRecords are compared as JSON,
`decision_id` included.

| | |
|---|---|
| Seeds | 2001 to 12000, 10,000 cases each, deterministic per seed |
| Code | `tools/difftest.py` sha256 `95d87f92...`, `rust/examples/replay.rs` sha256 `ebab06e5...`, golden vectors sha256 `f3445f8a...`: byte-identical to this repository at 9416823 (PR #6) |
| Machine | Debian 12 server, 2 vCPU, two workers; Python 3.11.2, rustc 1.99.1 |
| Time | 2026-11-06T16:36:04Z to 2026-11-07T12:48:34Z; no failed batch |
| CPU time | Python 82,511 s (0.825 ms per case), Rust 35,342 s (0.353 ms per case), process start per batch included |

## Result

100,000,000 of 100,000,000 DecisionRecords identical. No Python exception, no Rust panic.

| Final state | Status | Cases |
|---|---|---|
| Probabilistic Assessment | DEGRADED | 45,183,746 |
| (none) | REJECTED | 22,773,232 |
| Probabilistic Assessment | SUCCESS | 11,803,396 |
| Verified Fact | SUCCESS | 8,789,082 |
| Speculative Claim | DEGRADED | 8,033,239 |
| Speculative Claim | SUCCESS | 1,687,356 |
| VALIDATED | DEGRADED | 941,440 |
| VALIDATED | SUCCESS | 788,509 |

All 8 outcome classes occur; the rarest has 788,509 cases.

## Check it yourself

`seeds.jsonl.gz` holds the `report.json` of every seed, one line each, plus
`mismatches`, the number of entries in that seed's `mismatches.json`
(sha256 of the uncompressed file `bd0b7b38...22b9`, of the gzip file `434bf9da...c96b`).

```bash
python tools/difftest_summary.py reports/difftest-2026-11-07/seeds.jsonl.gz   # totals above
(cd rust && cargo build --release --example replay)
python tools/difftest.py . 10000 7777 /tmp/seed7777   # any seed from 2001 to 12000
```

The counts of a re-run seed must equal its line in `seeds.jsonl.gz`; the
timings will differ. Seed 7777 was re-run this way on macOS (Apple silicon,
Python 3.12) on 9 Nov 2026 and matched.

## What this shows and what it does not

With no difference in 10^8 cases, a difference rate above 3 × 10^-8 per case is
excluded at 95 % (rule of three), for this mutation distribution only.

- Agreement shows that the two implementations behave alike. It does not show
  that the behaviour is what the drafts intend.
- Inputs far from the golden vectors, large record sets, other Bindings and
  adversarial Ed25519 encodings are outside this test (see `CONFORMANCE.md` §2).
- Both implementations come from the same team. An implementation written by
  another party would be a stronger test.
