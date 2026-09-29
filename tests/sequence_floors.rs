//! The embedded rollback floors (`EMBEDDED_SEQUENCE_FLOOR_*`) against the
//! manifests threatmodels `main` served when they were set.
//!
//! `fixtures/production/` holds those four public files, copied byte for
//! byte from threatmodels `signed/`. Raising a floor means replacing them
//! with the manifests of the release's embedded models (see the constants'
//! documentation): these tests then check that the production root keys
//! verify them, that their sequences are the floors, and that a fresh
//! process refuses anything older.

use ring::signature::{Ed25519KeyPair, KeyPair};
use threatmodels_rs::authenticity::{
    hex_encode, key_id, manifest_message, sha256_hex, ManifestScope, ModelAuthenticator, Signer,
    TrustedKey, EMBEDDED_SEQUENCE_FLOOR_DATA, EMBEDDED_SEQUENCE_FLOOR_EXEC, PRODUCTION_ROOT_KEYS,
};

const EXEC_MANIFEST: &[u8] = include_bytes!("fixtures/production/manifest-exec.json");
const EXEC_SIGNATURE: &[u8] = include_bytes!("fixtures/production/manifest-exec.sig.json");
const DATA_MANIFEST: &[u8] = include_bytes!("fixtures/production/manifest-data.json");
const DATA_SIGNATURE: &[u8] = include_bytes!("fixtures/production/manifest-data.sig.json");

/// Root A, which signed the exec manifest and certified the CI key.
const ROOT_A_KEY_ID: &str = "93295ebcb9a6ec08";

/// The data manifest is signed by the CI key, whose certificate expires on
/// 2026-12-28: verify at the time that manifest was issued (2026-09-29
/// 12:19:27Z), not by the wall clock.
fn data_manifest_issue_time() -> u64 {
    1_790_684_367
}

fn production_roots() -> Vec<TrustedKey> {
    PRODUCTION_ROOT_KEYS
        .iter()
        .map(|k| TrustedKey::from_hex(k).expect("production root key parses"))
        .collect()
}

/// A process that starts with the embedded floors and the production keys.
fn fresh_production_process() -> ModelAuthenticator {
    ModelAuthenticator::new(
        production_roots(),
        EMBEDDED_SEQUENCE_FLOOR_EXEC,
        EMBEDDED_SEQUENCE_FLOOR_DATA,
    )
    .with_clock(data_manifest_issue_time)
}

fn fixture_sequence(manifest: &[u8]) -> u64 {
    let value: serde_json::Value = serde_json::from_slice(manifest).expect("fixture manifest");
    value["sequence"]
        .as_u64()
        .expect("fixture manifest sequence")
}

#[test]
fn the_floors_are_the_sequences_of_the_fixture_manifests() {
    assert_eq!(
        EMBEDDED_SEQUENCE_FLOOR_EXEC,
        fixture_sequence(EXEC_MANIFEST)
    );
    assert_eq!(
        EMBEDDED_SEQUENCE_FLOOR_DATA,
        fixture_sequence(DATA_MANIFEST)
    );
    // Never back to "no floor".
    assert!(EMBEDDED_SEQUENCE_FLOOR_EXEC >= 1_790_681_588);
    assert!(EMBEDDED_SEQUENCE_FLOOR_DATA >= 1_790_684_367);
}

#[test]
fn a_fresh_process_accepts_the_published_manifests_at_the_floors() {
    let auth = fresh_production_process();

    let exec = auth
        .verify_manifest(ManifestScope::Exec, "main", EXEC_MANIFEST, EXEC_SIGNATURE)
        .expect("the production keys verify the published exec manifest");
    assert_eq!(exec.sequence, EMBEDDED_SEQUENCE_FLOOR_EXEC);
    assert_eq!(exec.signer, Signer::Root(ROOT_A_KEY_ID.to_string()));

    let data = auth
        .verify_manifest(ManifestScope::Data, "main", DATA_MANIFEST, DATA_SIGNATURE)
        .expect("the production keys verify the published data manifest");
    assert_eq!(data.sequence, EMBEDDED_SEQUENCE_FLOOR_DATA);
    match &data.signer {
        Signer::Delegated { root_key_id, .. } => assert_eq!(root_key_id, ROOT_A_KEY_ID),
        other => panic!("the data manifest is signed by the certified CI key, got {other:?}"),
    }

    // The published manifests cover the published files.
    for file in [
        "threatmodel-Android.json",
        "threatmodel-Linux.json",
        "threatmodel-Windows.json",
        "threatmodel-iOS.json",
        "threatmodel-macOS.json",
    ] {
        let err = exec.check_file(file, b"not the model").unwrap_err();
        assert!(err.to_string().contains("does not match"), "{file}: {err}");
    }
    let err = data
        .check_file("whitelists-db.json", b"not the list")
        .unwrap_err();
    assert!(err.to_string().contains("does not match"), "{err}");
}

// ---------------------------------------------------------------- older manifests

/// A TEST root key (fixed seed), never a production key: production root
/// keys cannot sign in a test, so the refusal of an older manifest is shown
/// with a process that trusts this key and starts at the production floors.
fn test_root() -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).expect("test seed")
}

fn signed_manifest(scope: &str, sequence: u64) -> (Vec<u8>, Vec<u8>) {
    let root = test_root();
    let manifest = serde_json::to_vec_pretty(&serde_json::json!({
        "format": 1,
        "scope": scope,
        "branch": "main",
        "sequence": sequence,
        "issued_at": "2026-09-29T00:00:00Z",
        "files": { "model.json": sha256_hex(b"model") },
    }))
    .unwrap();
    let envelope = serde_json::to_vec(&serde_json::json!({
        "format": 1,
        "signatures": [{
            "key_id": key_id(root.public_key().as_ref()),
            "signature": hex_encode(root.sign(&manifest_message(&manifest)).as_ref()),
        }],
    }))
    .unwrap();
    (manifest, envelope)
}

fn fresh_test_process() -> ModelAuthenticator {
    let root = TrustedKey::from_public_key(test_root().public_key().as_ref()).unwrap();
    ModelAuthenticator::new(
        vec![root],
        EMBEDDED_SEQUENCE_FLOOR_EXEC,
        EMBEDDED_SEQUENCE_FLOOR_DATA,
    )
}

#[test]
fn a_fresh_process_refuses_a_manifest_older_than_the_floor() {
    for (scope, name, floor) in [
        (ManifestScope::Exec, "exec", EMBEDDED_SEQUENCE_FLOOR_EXEC),
        (ManifestScope::Data, "data", EMBEDDED_SEQUENCE_FLOOR_DATA),
    ] {
        let auth = fresh_test_process();
        let (older, older_sig) = signed_manifest(name, floor - 1);
        let err = auth
            .verify_manifest(scope, "main", &older, &older_sig)
            .unwrap_err();
        assert!(
            err.to_string().contains("rollback refused"),
            "{name}: {err}"
        );

        let (at_floor, at_floor_sig) = signed_manifest(name, floor);
        auth.verify_manifest(scope, "main", &at_floor, &at_floor_sig)
            .unwrap_or_else(|e| panic!("{name}: a manifest at the floor is accepted: {e}"));
        assert_eq!(auth.highest_sequence(scope), floor);
    }
}

/// The authenticator every CloudModel uses starts at the embedded floors.
#[cfg(feature = "model-signatures")]
#[test]
fn the_production_authenticator_starts_at_the_floors() {
    let auth = ModelAuthenticator::production().expect("model-signatures is on");
    assert!(auth.highest_sequence(ManifestScope::Exec) >= EMBEDDED_SEQUENCE_FLOOR_EXEC);
    assert!(auth.highest_sequence(ManifestScope::Data) >= EMBEDDED_SEQUENCE_FLOOR_DATA);
}
