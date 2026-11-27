# Gravit decisions as verdict records (draft-wright-verdict-record-03)

Six verdict records of kind `check-run` over published Gravit golden vectors, in the vector format of
[verdict-record-test-vectors](https://github.com/diggertydog/verdict-record-test-vectors), with a held module for its
reference checker. Written for the SCITT list thread "Reviewers wanted: draft-wright-verdict-record", 27 Nov 2026.

## What a record says

Claim: "Gravit golden vector *name* decides *state*, *status*". Evidence, each cited by the SHA-256 of the exact
bytes published in this repository:

| # | File | Format |
|---|---|---|
| 0 | `tests/golden/vectors.json` | `urn:gravit:format:json-document` |
| 1 | `tests/golden/registry.json` | `urn:gravit:format:json-document` |
| 2 | `tests/golden/registry.json.sig` | `urn:gravit:format:registry-signatures` |
| 3 | `tests/golden/trust_root.json` | `urn:gravit:format:json-document` |

Rule: `urn:gravit:rule:gevp-decide:kernel-sha256:1f1bade7743d0996ec11de66db94fdf64782a87a70de913e745b0e392689a24a`. The rule is software, so its name binds the implementation:
the SHA-256 over the kernel's source files (`gravit_verifier/*.py`, `bindings/*.yaml`, sorted, one line
"`<sha256>  <path>`" each). The held module refuses to load against other sources. Inputs: `request` is bound with
a pointer into item 0; `registry`, `signatures` and `trust_root` are bound without pointer, so the rule reads the
exact held bytes (the registry is signed over its exact bytes). Result: `decision_id`, `final_epistemic_state`,
`status` of the kernel's decision. All published keys are test keys.

## Vectors and results

| Vector | Record | Reference checker |
|---|---|---|
| gv01-success | Verified Fact, SUCCESS | released; steps PASS PASS PASS |
| gv02-rejected | no state, REJECTED | released; steps PASS PASS PASS |
| gv03-degraded | Probabilistic Assessment, DEGRADED | released; steps PASS PASS PASS |
| gn01-result-not-reproduced | states Verified Fact for a request the kernel rejects | refused; FAIL at step 3 |
| gn02-non-bmp-name-utf8 | a body member named U+1D11E, as UTF-8 bytes | refused before any step, Section 2.1 |
| gn03-non-bmp-name-escaped | the same name as an escaped surrogate pair | refused before any step, Section 2.1 |

Reference checker `vrcheck.py` at commit 7e08e71; full reports in `results.json`. 6 of 6 as expected.

## One finding for the draft

The first run refused gv01 and gv03 at step 3. The checker parses fractions in an item as exact decimals; the kernel
reads JSON as Python's `json` module does (fractions as binary floats) and does not coerce a non-float theta, so it
rejected every record. The held rule now converts the parsed values the way the kernel's own JSON reading does. A rule
that runs software over a JSON item needs to say how it reads numbers; otherwise two checkers that both follow
Section 4.3 can re-run the same rule on the same bytes and get different results.

## Run

    git clone https://github.com/diggertydog/verdict-record-test-vectors vrtv
    python3 interop/verdict-record-03/gen.py          # regenerate (pins the kernel digest)
    cd vrtv && GRAVIT_VERIFIER=.. python3 vrcheck.py --hold ../interop/verdict-record-03/held/gravit_verifier_decide.py ../interop/verdict-record-03/vectors/*.json

No container is included: as in the reference vectors, each vector supplies the record's upper time bound directly.
