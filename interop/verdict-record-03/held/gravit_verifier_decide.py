"""Held by a checker of draft-wright-verdict-record-03: the rule "decide with the Gravit Verifier" and the
formats of the files it reads.

The rule is software, so its name binds the implementation: the SHA-256 over the kernel's source files
(gravit_verifier/*.py and bindings/*.yaml, sorted by path, each line "<sha256 of file>  <path>\\n").
This module refuses to load when the checkout given in GRAVIT_VERIFIER (default: this repository) has
other sources, so a re-run always runs the code the record names.

Source: https://github.com/gon-foundation/verifier, interop/verdict-record-03/README.md.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

KERNEL_SHA256 = "1f1bade7743d0996ec11de66db94fdf64782a87a70de913e745b0e392689a24a"
RULE_NAME = "urn:gravit:rule:gevp-decide:kernel-sha256:" + KERNEL_SHA256

SOURCE = {"url": "https://github.com/gon-foundation/verifier/tree/main/interop/verdict-record-03",
          "rule": RULE_NAME,
          "kernel_files": "gravit_verifier/*.py, bindings/*.yaml"}

ROOT = Path(os.environ.get("GRAVIT_VERIFIER", Path(__file__).resolve().parents[3]))


def kernel_digest(root: Path) -> str:
    files = sorted([p for p in (root / "gravit_verifier").glob("*.py")] + [p for p in (root / "bindings").glob("*.yaml")])
    lines = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}\n" for p in files)
    return hashlib.sha256(lines.encode("utf-8")).hexdigest()


if kernel_digest(ROOT) != KERNEL_SHA256:
    raise ImportError(f"{ROOT} does not hold the kernel this rule names ({KERNEL_SHA256}); refusing to load")

sys.path.insert(0, str(ROOT))
from gravit_verifier.kernel import EpistemicState, EvidenceRecord, VerificationRequest, VerifierKernel  # noqa: E402
from gravit_verifier.loader import load_bindings_from_dir  # noqa: E402
from gravit_verifier.registry import RegistryError, TrustRoot, VerifierRegistry  # noqa: E402

REQUEST_KEYS = {"name", "claimed_state", "evidence", "context", "use_registry", "expected"}


class GevpDecide:
    """Inputs, exactly: request (a golden vector object, read with a pointer into vectors.json); registry,
    signatures and trust_root, each bound to its evidence item without pointer, so the input is the item's digest
    and the rule reads the exact held bytes (the registry is signed over its exact bytes). The result is {"decision_id", "final_epistemic_state", "status"} of the kernel's
    decision on the request; final_epistemic_state is null when the kernel reaches no state. An input of the wrong type, a
    registry that the trust root does not accept, or a request the kernel cannot read is a FAIL of step 3."""
    NAME = RULE_NAME
    INPUTS = ["registry", "request", "signatures", "trust_root"]

    @staticmethod
    def input_problems(values, names):
        if names != GevpDecide.INPUTS:
            return ["the rule's inputs are exactly " + ", ".join(GevpDecide.INPUTS)]
        p = []
        if "request" in values and not (isinstance(values["request"], dict) and set(values["request"]) <= REQUEST_KEYS):
            p.append("input request is not a golden vector object")
        for n in ("registry", "signatures", "trust_root"):
            if n in values and not isinstance(values[n], str):
                p.append(f"input {n} is not the digest of a held item")
        return p

    @staticmethod
    def rerun(values, ctx):
        items = ctx["items"]
        root = TrustRoot.from_bytes(items[values["trust_root"]]["bytes"])
        registry = VerifierRegistry.from_bytes(items[values["registry"]]["bytes"],
                                               items[values["signatures"]]["bytes"].decode("utf-8"), root)
        # A checker may parse JSON numbers as exact decimals; the kernel reads JSON as Python's json module does
        # (fractions as float). Convert the same text the same way, so the re-run sees what the kernel sees.
        v = _as_json_module(values["request"])
        kernel = VerifierKernel(registry) if v["use_registry"] else VerifierKernel()
        for b in load_bindings_from_dir(ROOT / "bindings"):
            kernel.load_binding(b)
        req = VerificationRequest(v["name"], EpistemicState(v["claimed_state"]) if v["claimed_state"] else None,
                                  [EvidenceRecord.from_json(e) for e in v["evidence"]], v["context"])
        d = kernel.verify(req).to_dict()
        return {"decision_id": d["decision_id"], "final_epistemic_state": d["final_epistemic_state"], "status": d["status"]}


def _as_json_module(x):
    import decimal
    if isinstance(x, decimal.Decimal):
        return int(x) if x == x.to_integral_value() and "." not in str(x) and "e" not in str(x).lower() else float(str(x))
    if isinstance(x, list):
        return [_as_json_module(y) for y in x]
    if isinstance(x, dict):
        return {k: _as_json_module(y) for k, y in x.items()}
    return x


class JsonDocument:
    NAME = "urn:gravit:format:json-document"

    def check_item(self, b, ctx):
        try:
            json.loads(b.decode("utf-8"))
            return (True, None, None)
        except (UnicodeDecodeError, ValueError) as e:
            return (False, f"not a JSON document: {e}", None)


class RegistrySignatures:
    """One "<root key_id> <base64 signature>" per line; blank lines and lines starting with # are ignored."""
    NAME = "urn:gravit:format:registry-signatures"

    def check_item(self, b, ctx):
        try:
            lines = [l for l in b.decode("utf-8").splitlines() if l.strip() and not l.startswith("#")]
        except UnicodeDecodeError:
            return (False, "not UTF-8", None)
        ok = lines and all(len(l.split()) == 2 for l in lines)
        return (bool(ok), None if ok else "not a registry signature file", None)


RULES = (GevpDecide,)
FORMATS = (JsonDocument(), RegistrySignatures())
