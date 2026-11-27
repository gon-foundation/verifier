//! Canonical JSON (RFC 8785) with non-ASCII member names: the same vectors
//! as tests/test_jcs.py, from tests/golden/jcs_vectors.json.
use serde_json::Value;
use sha3::{Digest, Sha3_256};

#[test]
fn canonical_json_non_ascii_names() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/golden/jcs_vectors.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("vectors")).expect("json");
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty());
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let input: Value = serde_json::from_str(v["input"].as_str().unwrap()).expect("input json");
        let got = gravit_verifier_rs::canonical_json(&input);
        assert_eq!(got, v["expected"].as_str().unwrap(), "{}", name);
        let digest: String = Sha3_256::digest(got.as_bytes()).iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(digest, v["expected_sha3_256"].as_str().unwrap(), "{}", name);
    }
}
