# Extended differential run of 9 to 10 Nov 2026: 100,000,000 cases

Python reference kernel against the Rust port, with `tools/difftest_ext.py`.
Unlike the run of 6 to 7 Nov (`reports/difftest-2026-11-07`), most cases here
lie outside the reach of the golden-vector mutations: other JSON types and
extreme values, missing or unknown fields, large Record sets and adversarial
Ed25519 signature encodings. Both kernels decide every case, and the full
DecisionRecords are compared as JSON, `decision_id` included.

| | |
|---|---|
| Seeds | 20001 to 30000, 10,000 cases each, deterministic per seed and weights |
| Class weights | `types=30,shape=10,large=1,sig=25,base=25` (written to every `report.json`) |
| Code | `tools/difftest_ext.py` sha256 `f22e7a29...55b6`, `rust/examples/replay.rs` sha256 `ebab06e5...1a61`: byte-identical to this repository at 1092d20 (PR #10) |
| Machine | Debian 12 server, 2 vCPU, two workers; Python 3.11.2, rustc 1.99.1 |
| Time | 2026-11-09T10:11:04Z to 2026-11-10T22:02:56Z; no failed batch |
| CPU time | Python 144,039 s (1.440 ms per case), Rust 66,954 s (0.670 ms per case), process start per batch included |

## Result

100,000,000 of 100,000,000 DecisionRecords identical. No Python exception, no
Rust panic, no case where only one side rejected the input, and no case where
both did ("both_reject" = 0).

| Class | What it changes | Cases |
|---|---|---|
| types | a field gets another JSON type or an extreme value | 32,964,194 |
| base | the mutations of `tools/difftest.py`, as a control | 27,478,701 |
| sig | adversarial Ed25519 signature encodings on an otherwise valid Record | 27,464,410 |
| shape | a Record loses a field or gains an unknown one | 10,991,360 |
| large | 50 to 400 Records per request | 1,101,335 |

| Final state | Status | Cases |
|---|---|---|
| Probabilistic Assessment | DEGRADED | 45,964,278 |
| (none) | REJECTED | 28,864,094 |
| Verified Fact | SUCCESS | 8,293,024 |
| Probabilistic Assessment | SUCCESS | 7,289,878 |
| Speculative Claim | DEGRADED | 6,412,634 |
| Speculative Claim | SUCCESS | 1,239,809 |
| VALIDATED | DEGRADED | 992,551 |
| VALIDATED | SUCCESS | 943,732 |

All 8 outcome classes occur; the rarest has 943,732 cases.

The weight of `large` is 1 because a large case costs far more time than the
others (profiling before the run, PR #10); at the default weights the run
would not have fit on this machine in two days. 1.1 million large cases is the
honest size of that part of the test.

## Check it yourself

`seeds.jsonl.gz` holds the `report.json` of every seed, one line each, plus
`mismatches`, the number of entries in that seed's `mismatches.json`
(sha256 of the uncompressed file `72688ff2...d8e4`, of the gzip file `7a7f3134...1013`).

```bash
python tools/difftest_summary.py reports/difftest-ext-2026-11-10/seeds.jsonl.gz   # totals above
(cd rust && cargo build --release --example replay)
python tools/difftest_ext.py . 10000 25555 /tmp/seed25555 types=30,shape=10,large=1,sig=25,base=25
```

Any seed from 20001 to 30000 works; its counts, `by_class` and `weights` must
equal its line in `seeds.jsonl.gz`; the timings will differ. Seed 25555 was
re-run this way on macOS (Apple silicon, Python 3.12) on 11 Nov 2026 and matched.

## What this shows and what it does not

With no difference in 10^8 cases, a difference rate above 3 × 10^-8 per case is
excluded at 95 % (rule of three), for this class mix only. For a single class
the bound follows from its own count, e.g. about 2.7 × 10^-6 for `large`.

- Agreement shows that the two implementations behave alike, also on malformed
  and adversarial input. It does not show that the behaviour is what the drafts intend.
- Small-order public keys and non-canonical points in public keys are not in
  the `sig` class; other Bindings and other registries are not tested.
- Both implementations come from the same team. An implementation written by
  another party would be a stronger test.
