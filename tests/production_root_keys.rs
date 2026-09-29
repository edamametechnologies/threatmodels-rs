//! The embedded production root keys: every entry must parse, and each one
//! must be the key recorded at the 2026-09-29 key ceremony. A malformed entry
//! would otherwise surface only as a panic at a client's first model update
//! (`ModelAuthenticator::production` expects every entry to parse).

use threatmodels_rs::authenticity::{key_id, TrustedKey, PRODUCTION_ROOT_KEYS};

fn raw(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len(), 64, "a root public key is 32 bytes of hex");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect()
}

#[test]
fn production_root_keys_parse_and_match_the_ceremony_record() {
    let expected_ids = ["93295ebcb9a6ec08", "39f35c44b16e9f62"];
    assert_eq!(PRODUCTION_ROOT_KEYS.len(), expected_ids.len());
    for (hex, expected_id) in PRODUCTION_ROOT_KEYS.iter().zip(expected_ids) {
        TrustedKey::from_hex(hex).expect("PRODUCTION_ROOT_KEYS entry parses");
        assert_eq!(key_id(&raw(hex)), expected_id);
    }
    assert_ne!(PRODUCTION_ROOT_KEYS[0], PRODUCTION_ROOT_KEYS[1]);
}
