# GEVP decisions as verdict records

An interoperability exercise with
[draft-wright-verdict-record-02](https://datatracker.ietf.org/doc/draft-wright-verdict-record/)
and its test vectors at
[diggertydog/verdict-record-test-vectors](https://github.com/diggertydog/verdict-record-test-vectors)
(commit 97b63b2). Prompted by the author on the IETF AUDIT list, 7 Nov 2026.

Two parts:

1. `gvrcheck.py`: a checker for -02, written by the Gravit team from the draft text and the vector
   file format in the vectors README. The reference checker and the blind checker of that repository
   were not read. Readings taken where -02 leaves a point open are marked `READING` in the code.
2. `gevp_vr.py`: writes each of the 60 golden vectors of this repository as a verdict record and
   checks the records with `gvrcheck.py`, unchanged and tampered.

## Running

    # the vectors repository cloned next to this one
    python3 gvrcheck.py ../../../verdict-record-test-vectors/[a-f][0-9][0-9]-*.json \
                        ../../../verdict-record-test-vectors/proposals/p0[1-7]*.json
    python3 gevp_vr.py ../.. records

## Part 1: the checker against the published vectors

| Set | Agree with expected state and steps |
|---|---|
| 37 vectors (a01 to f01) | 37/37 |
| 7 proposal cases (p01 to p07, `expected_under_02`) | 7/7 |
| Appendix A.2 of -02 | digest 62017940… reproduced; held when the hop format's signature rule is applied, released when unsigned hops are accepted, as the draft states |

p08 was not run: it needs the IronTrellis replay as a rule. The record digests and policy digests of
all vectors match. Readings: I-2 (refused before the steps), I-4 (judgement passes step 3),
I-12 (control characters escaped as RFC 8785 does), I-15 (no upper time bound: held, no step run).
-02 does not name the policy member that sets "inputs from evidence only"; this checker uses
`inputs_from_evidence_only`.

## Part 2: a GEVP decision as a verdict record

Mapping:

- `kind` `check-run`; `rule` the GEVP decision of the kernel and bindings at commit 7f19df1
  (named by that commit, as -02 asks for a versioned rule name).
- Evidence item 0: the verification request (artifact, claimed state, signed evidence records,
  context) as RFC 8785 bytes. `body.claim.ref` points to it.
- Evidence item 1, where the vector uses one: the verifier registry, its exact file bytes. It
  verifies only with root signatures over those bytes; the trust root is the checker's trust anchor.
- Every rule input is bound to an evidence item (`request`, `registry` by JSON Pointer `""`,
  `registry_digest` by digest). Body holds only the claim.
- `check.result`: `decision_id`, `final_epistemic_state` and `status`. The `decision_id` is the
  content address of the whole GEVP decision record, so equality of the result covers all of it.

Results over the 60 golden vectors:

| Case | Expected | Result |
|---|---|---|
| Records as written | released | 60/60 |
| Same, policy reads inputs from evidence only | released | 60/60 |
| Stated final state changed | refused (step 3) | 60/60 |
| One evidence record changed after the record was made | held (step 2, item not held) | 58/58 |
| Registry withheld | held | 51/51 |
| Registry without valid root signatures | held | 51/51 |
| Items read under the integer rule of Section 2.1 | refused (step 3) where a theta is fractional | 58/58, 2/2 released |

The reference checker of the vectors repository, which holds neither the GEVP formats nor the
rule, reports these records `held` with step 1 PASS: it parses them as canonical.

## Where the shapes differ

1. **Numbers in evidence.** GEVP evidence carries fractional confidence values (0.88, and the 0.7
   threshold with its nearest binary64 neighbours). -02 reads a bound item "as strict JSON by the
   rules of Section 2.1". If that includes the canonical form's integer rule, 58 of 60 GEVP records
   are refused at step 3; if it does not, all 60 are released. The draft does not settle which. If
   fractions are allowed in items, how a number text maps to a value (for example binary64 as in
   RFC 8785) needs to be stated, since a GEVP decision turns on the exact value at 0.7.
2. **Result.** A full GEVP decision record holds fractions, so it cannot be the result under
   Section 2.1. The result here is the decision's content address and two strings.
3. **Detached signatures.** The registry verifies only together with a separate signature file.
   -02 verifies an item "by the rules of the format its entry names" and says nothing about
   material the format needs besides the item bytes. Here it travels with the item.
4. **Independence.** Whether two evidence records are independent sources is decided inside the
   GEVP rule. A verdict record has no way to state it, and nothing in -02 checks it. The known
   limit stays as it is in GEVP: `relay_undeclared_known_limit` is released, as its decision is.
5. **Canonical form.** For these records the canonical form of -02 and RFC 8785 give the same
   bytes (all member names are in the Basic Multilingual Plane).

## Limits

Both parts were written by one team. The checker agrees with the published answers, which were
visible while it was written; the vectors README, including its open points, was read before
writing. The upper time bound of the GEVP records is a fixed value given to the checker, not one
established from a container.
