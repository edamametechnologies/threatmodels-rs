//! Signed-manifest authentication of CloudModel downloads.
//!
//! Every key here is a TEST key derived from a fixed seed; none of them is,
//! or may become, a production key.

use anyhow::{anyhow, Result};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use threatmodels_rs::authenticity::{
    certificate_message, hex_encode, key_id, manifest_message, sha256_hex, ManifestScope,
    ModelAuthenticator, Signer, TrustedKey,
};
use threatmodels_rs::{
    model_authenticity_states, CloudModel, CloudSignature, ModelProvenance, UpdateStatus,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use undeadlock::CustomRwLock;

// ---------------------------------------------------------------- keys

struct TestKey {
    pair: Ed25519KeyPair,
}

impl TestKey {
    fn from_seed(seed: u8) -> Self {
        Self {
            pair: Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("test seed"),
        }
    }
    fn public(&self) -> &[u8] {
        self.pair.public_key().as_ref()
    }
    fn public_hex(&self) -> String {
        hex_encode(self.public())
    }
    fn id(&self) -> String {
        key_id(self.public())
    }
    fn trusted(&self) -> TrustedKey {
        TrustedKey::from_public_key(self.public()).unwrap()
    }
    fn sign_hex(&self, message: &[u8]) -> String {
        hex_encode(self.pair.sign(message).as_ref())
    }
}

fn root_a() -> TestKey {
    TestKey::from_seed(1)
}
fn root_b() -> TestKey {
    TestKey::from_seed(2)
}
fn ci_key() -> TestKey {
    TestKey::from_seed(3)
}
fn attacker() -> TestKey {
    TestKey::from_seed(9)
}

const NOW: u64 = 1_790_000_000;
fn fixed_clock() -> u64 {
    NOW
}

fn authenticator(roots: &[&TestKey]) -> ModelAuthenticator {
    ModelAuthenticator::new(roots.iter().map(|k| k.trusted()).collect(), 0, 0)
        .with_clock(fixed_clock)
}

// ---------------------------------------------------------------- manifests

fn manifest(scope: &str, branch: &str, sequence: u64, files: &[(&str, &[u8])]) -> Vec<u8> {
    let files: serde_json::Map<String, serde_json::Value> = files
        .iter()
        .map(|(path, bytes)| {
            (
                path.to_string(),
                serde_json::Value::String(sha256_hex(bytes)),
            )
        })
        .collect();
    serde_json::to_vec_pretty(&serde_json::json!({
        "format": 1,
        "scope": scope,
        "branch": branch,
        "sequence": sequence,
        "issued_at": "2026-09-28T00:00:00Z",
        "files": files,
    }))
    .unwrap()
}

fn root_entry(key: &TestKey, manifest_bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "key_id": key.id(),
        "signature": key.sign_hex(&manifest_message(manifest_bytes)),
    })
}

fn delegated_entry(
    key: &TestKey,
    root: &TestKey,
    not_after: u64,
    manifest_bytes: &[u8],
) -> serde_json::Value {
    let cert_msg = certificate_message(&key.id(), &key.public_hex(), not_after);
    serde_json::json!({
        "key_id": key.id(),
        "signature": key.sign_hex(&manifest_message(manifest_bytes)),
        "certificate": {
            "key_id": key.id(),
            "public_key": key.public_hex(),
            "not_after": not_after,
            "root_key_id": root.id(),
            "root_signature": root.sign_hex(&cert_msg),
        }
    })
}

fn envelope(entries: Vec<serde_json::Value>) -> Vec<u8> {
    serde_json::to_vec_pretty(&serde_json::json!({"format": 1, "signatures": entries})).unwrap()
}

// ---------------------------------------------------------------- model

#[derive(Debug, Clone, Deserialize)]
struct TestModel {
    content: String,
    signature: String,
}

impl CloudSignature for TestModel {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

fn parse(data: &str) -> Result<TestModel> {
    serde_json::from_str(data).map_err(|e| anyhow!(e))
}

const BUILTIN: &str = r#"{"content":"builtin","signature":"builtin-sig"}"#;
const REMOTE: &[u8] = br#"{"content":"remote","signature":"remote-sig"}"#;
const DATA_FILE: &str = "test-data.json";
const EXEC_FILE: &str = "threatmodel-Test.json";

// ---------------------------------------------------------------- tiny HTTP origin

type Files = Arc<CustomRwLock<HashMap<String, Vec<u8>>>>;
type Requests = Arc<CustomRwLock<Vec<String>>>;

async fn serve(files: HashMap<String, Vec<u8>>) -> (String, Files, Requests) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let files: Files = Arc::new(CustomRwLock::new(files));
    let requests: Requests = Arc::new(CustomRwLock::new(Vec::new()));
    let (f, r) = (files.clone(), requests.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let (f, r) = (f.clone(), r.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("/").to_string();
                r.write().await.push(path.clone());
                let body = f.read().await.get(&path).cloned();
                let response = match body {
                    Some(body) => {
                        let mut out = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        out.extend_from_slice(&body);
                        out
                    }
                    None => {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    }
                };
                let _ = socket.write_all(&response).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (base, files, requests)
}

/// The published layout: `<name>.json` + `<name>.sig` (unchanged since
/// 2.0.1) and, optionally, the signed manifest of the file's scope.
fn layout(
    file: &str,
    served: &[u8],
    signed: Option<(Vec<u8>, Vec<u8>)>,
) -> HashMap<String, Vec<u8>> {
    let mut files = HashMap::new();
    files.insert(format!("/main/{file}"), served.to_vec());
    files.insert(
        format!("/main/{}.sig", file.trim_end_matches(".json")),
        sha256_hex(served).into_bytes(),
    );
    if let Some((manifest, signature)) = signed {
        let scope = ManifestScope::for_path(file);
        files.insert(format!("/main/{}", scope.manifest_path()), manifest);
        files.insert(format!("/main/{}", scope.signature_path()), signature);
    }
    files
}

fn model(file: &str, base: &str, auth: Option<ModelAuthenticator>) -> CloudModel<TestModel> {
    CloudModel::initialize(file.to_string(), BUILTIN, parse)
        .unwrap()
        .with_base_url(base)
        .with_authenticator(auth.map(Arc::new))
}

// ================================================================ end-to-end

#[tokio::test]
async fn valid_signature_updates_and_reports_verified() {
    let m = manifest("data", "main", 10, &[(DATA_FILE, REMOTE)]);
    let s = envelope(vec![root_entry(&root_a(), &m)]);
    let (base, _, requests) = serve(layout(DATA_FILE, REMOTE, Some((m, s)))).await;
    let model = model(DATA_FILE, &base, Some(authenticator(&[&root_a()])));

    assert_eq!(model.provenance(), ModelProvenance::Embedded);
    let status = model.update("main", false, parse).await.unwrap();
    assert_eq!(status, UpdateStatus::Updated);
    assert_eq!(model.data.read().await.content, "remote");
    assert_eq!(model.provenance(), ModelProvenance::DownloadedVerified);
    assert_eq!(model.last_authenticity_error().await, None);
    assert_eq!(
        *requests.read().await,
        vec![
            "/main/test-data.sig",
            "/main/test-data.json",
            "/main/signed/manifest-data.json",
            "/main/signed/manifest-data.sig.json"
        ]
    );
}

#[tokio::test]
async fn exec_model_verified_with_root_signature() {
    let m = manifest("exec", "main", 10, &[(EXEC_FILE, REMOTE)]);
    let s = envelope(vec![root_entry(&root_a(), &m)]);
    let (base, _, _) = serve(layout(EXEC_FILE, REMOTE, Some((m, s)))).await;
    let model = model(EXEC_FILE, &base, Some(authenticator(&[&root_a()])));
    assert_eq!(
        model.update("main", false, parse).await.unwrap(),
        UpdateStatus::Updated
    );
    assert_eq!(model.provenance(), ModelProvenance::DownloadedVerified);
}

#[tokio::test]
async fn tampered_model_is_refused_and_current_data_kept() {
    let m = manifest("data", "main", 10, &[(DATA_FILE, REMOTE)]);
    let s = envelope(vec![root_entry(&root_a(), &m)]);
    let tampered: &[u8] = br#"{"content":"evil","signature":"remote-sig"}"#;
    let (base, _, _) = serve(layout(DATA_FILE, tampered, Some((m, s)))).await;
    let model = model(DATA_FILE, &base, Some(authenticator(&[&root_a()])));

    let status = model.update("main", false, parse).await.unwrap();
    assert_eq!(status, UpdateStatus::NotUpdated);
    assert_eq!(model.data.read().await.content, "builtin");
    assert_eq!(model.get_signature().await, "builtin-sig");
    assert_eq!(model.provenance(), ModelProvenance::Embedded);
    let err = model.last_authenticity_error().await.unwrap();
    assert!(err.contains("does not match"), "{err}");
}

#[tokio::test]
async fn refused_download_keeps_previously_verified_data() {
    let m = manifest("data", "main", 10, &[(DATA_FILE, REMOTE)]);
    let s = envelope(vec![root_entry(&root_a(), &m)]);
    let (base, files, _) = serve(layout(DATA_FILE, REMOTE, Some((m, s)))).await;
    let model = model(DATA_FILE, &base, Some(authenticator(&[&root_a()])));
    assert_eq!(
        model.update("main", false, parse).await.unwrap(),
        UpdateStatus::Updated
    );

    // The origin now serves a new, unsigned model (manifest unchanged).
    let evil: &[u8] = br#"{"content":"evil","signature":"evil-sig"}"#;
    {
        let mut f = files.write().await;
        f.insert("/main/test-data.json".into(), evil.to_vec());
        f.insert("/main/test-data.sig".into(), sha256_hex(evil).into_bytes());
    }
    assert_eq!(
        model.update("main", false, parse).await.unwrap(),
        UpdateStatus::NotUpdated
    );
    assert_eq!(model.data.read().await.content, "remote");
    assert_eq!(model.provenance(), ModelProvenance::DownloadedVerified);
}

/// New client, OLD repository layout (no `signed/` directory yet): the
/// download is refused and the embedded model stays in place.
#[tokio::test]
async fn new_client_on_old_layout_keeps_embedded_model() {
    let (base, _, requests) = serve(layout(DATA_FILE, REMOTE, None)).await;
    let model = model(DATA_FILE, &base, Some(authenticator(&[&root_a()])));

    let status = model.update("main", false, parse).await.unwrap();
    assert_eq!(status, UpdateStatus::NotUpdated);
    assert_eq!(model.data.read().await.content, "builtin");
    assert_eq!(model.provenance(), ModelProvenance::Embedded);
    let err = model.last_authenticity_error().await.unwrap();
    assert!(err.contains("404"), "{err}");
    assert_eq!(
        *requests.read().await,
        vec![
            "/main/test-data.sig",
            "/main/test-data.json",
            "/main/signed/manifest-data.json"
        ]
    );
}

/// OLD client code path (no authenticator: exactly what 2.0.1 runs), NEW
/// repository layout: it requests only `<name>.sig` and `<name>.json`,
/// which the signing step leaves untouched, and updates as before.
#[tokio::test]
async fn old_client_path_on_new_layout_is_unchanged() {
    let m = manifest("data", "main", 10, &[(DATA_FILE, REMOTE)]);
    let s = envelope(vec![root_entry(&root_a(), &m)]);
    let (base, _, requests) = serve(layout(DATA_FILE, REMOTE, Some((m, s)))).await;
    let model = model(DATA_FILE, &base, None);

    assert!(!model.authenticity_enforced());
    let status = model.update("main", false, parse).await.unwrap();
    assert_eq!(status, UpdateStatus::Updated);
    assert_eq!(model.data.read().await.content, "remote");
    assert_eq!(model.get_signature().await, sha256_hex(REMOTE));
    assert_eq!(model.provenance(), ModelProvenance::Downloaded);
    assert_eq!(
        *requests.read().await,
        vec!["/main/test-data.sig", "/main/test-data.json"]
    );

    // Unchanged .sig => no download at all, as before.
    assert_eq!(
        model.update("main", false, parse).await.unwrap(),
        UpdateStatus::NotUpdated
    );
    assert_eq!(requests.read().await.len(), 3);
}

/// The status registry: every initialized model with where its data came
/// from and why its last download was refused.
#[tokio::test]
async fn registry_reports_provenance_and_refusals() {
    const VERIFIED: &str = "registry-verified-db.json";
    const REFUSED: &str = "registry-refused-db.json";
    const PLAIN: &str = "registry-plain-db.json";
    const EXEC: &str = "threatmodel-Registry.json";
    let m = manifest("data", "main", 10, &[(VERIFIED, REMOTE), (REFUSED, REMOTE)]);
    let s = envelope(vec![root_entry(&root_a(), &m)]);
    let evil: &[u8] = br#"{"content":"evil","signature":"evil-sig"}"#;
    let mut files = layout(VERIFIED, REMOTE, Some((m.clone(), s.clone())));
    files.extend(layout(REFUSED, evil, Some((m, s))));
    let (base, _, _) = serve(files).await;

    let verified = model(VERIFIED, &base, Some(authenticator(&[&root_a()])));
    let refused = model(REFUSED, &base, Some(authenticator(&[&root_a()])));
    let _plain = model(PLAIN, &base, None);
    let _exec = model(EXEC, &base, Some(authenticator(&[&root_a()])));
    assert_eq!(
        verified.update("main", false, parse).await.unwrap(),
        UpdateStatus::Updated
    );
    assert_eq!(
        refused.update("main", false, parse).await.unwrap(),
        UpdateStatus::NotUpdated
    );

    let states = model_authenticity_states().await;
    let state = |name: &str| {
        states
            .iter()
            .find(|s| s.file_name == name)
            .cloned()
            .unwrap_or_else(|| panic!("{name} is registered: {states:?}"))
    };
    let v = state(VERIFIED);
    assert_eq!(v.provenance, ModelProvenance::DownloadedVerified);
    assert_eq!(v.provenance.as_str(), "downloaded_verified");
    assert_eq!(v.scope, ManifestScope::Data);
    assert!(v.authenticity_enforced);
    assert_eq!(v.last_authenticity_error, None);

    let r = state(REFUSED);
    assert_eq!(r.provenance, ModelProvenance::Embedded);
    assert!(
        r.last_authenticity_error
            .as_deref()
            .is_some_and(|e| e.contains("does not match")),
        "{r:?}"
    );

    // `with_authenticator(None)` after `initialize` is what the registry says.
    assert!(!state(PLAIN).authenticity_enforced);
    assert_eq!(state(EXEC).scope, ManifestScope::Exec);
    assert!(states.windows(2).all(|w| w[0].file_name <= w[1].file_name));
}

// ================================================================ verifier

fn verify(auth: &ModelAuthenticator, scope: ManifestScope, m: &[u8], s: &[u8]) -> Result<Signer> {
    auth.verify_manifest(scope, "main", m, s).map(|v| v.signer)
}

#[test]
fn tampered_manifest_is_refused() {
    let m = manifest("data", "main", 10, &[(DATA_FILE, REMOTE)]);
    let s = envelope(vec![root_entry(&root_a(), &m)]);
    let evil: &[u8] = b"evil";
    let tampered = String::from_utf8(m)
        .unwrap()
        .replace(&sha256_hex(REMOTE), &sha256_hex(evil))
        .into_bytes();
    let err = verify(
        &authenticator(&[&root_a()]),
        ManifestScope::Data,
        &tampered,
        &s,
    )
    .unwrap_err();
    assert!(err.to_string().contains("bad signature"), "{err}");
}

#[test]
fn wrong_key_is_refused() {
    let auth = authenticator(&[&root_a()]);
    let m = manifest("data", "main", 10, &[(DATA_FILE, REMOTE)]);
    // Signed by an unknown key under its own id.
    let err = verify(
        &auth,
        ManifestScope::Data,
        &m,
        &envelope(vec![root_entry(&attacker(), &m)]),
    )
    .unwrap_err();
    assert!(err.to_string().contains("not a trusted root key"), "{err}");
    // Signed by an unknown key claiming the trusted key's id.
    let forged = serde_json::json!({"key_id": root_a().id(), "signature": attacker().sign_hex(&manifest_message(&m))});
    let err = verify(&auth, ManifestScope::Data, &m, &envelope(vec![forged])).unwrap_err();
    assert!(err.to_string().contains("bad signature"), "{err}");
    // Empty envelope.
    assert!(verify(&auth, ManifestScope::Data, &m, &envelope(vec![])).is_err());
}

#[test]
fn rotated_root_key() {
    let m = manifest("exec", "main", 10, &[(EXEC_FILE, REMOTE)]);
    let only_b = envelope(vec![root_entry(&root_b(), &m)]);
    let both = envelope(vec![root_entry(&root_a(), &m), root_entry(&root_b(), &m)]);

    // Clients embedding both slots accept a manifest signed by either.
    assert_eq!(
        verify(
            &authenticator(&[&root_a(), &root_b()]),
            ManifestScope::Exec,
            &m,
            &only_b
        )
        .unwrap(),
        Signer::Root(root_b().id())
    );
    // During the overlap, a dual-signed manifest satisfies old (A-only) and new (B-only) clients.
    assert!(verify(&authenticator(&[&root_a()]), ManifestScope::Exec, &m, &both).is_ok());
    assert!(verify(&authenticator(&[&root_b()]), ManifestScope::Exec, &m, &both).is_ok());
    // A client that dropped A refuses a manifest only A signed.
    let only_a = envelope(vec![root_entry(&root_a(), &m)]);
    assert!(verify(
        &authenticator(&[&root_b()]),
        ManifestScope::Exec,
        &m,
        &only_a
    )
    .is_err());
}

#[test]
fn rollback_to_older_manifest_is_refused() {
    let auth = authenticator(&[&root_a()]);
    let newer = manifest("data", "main", 200, &[(DATA_FILE, REMOTE)]);
    let older = manifest("data", "main", 100, &[(DATA_FILE, b"old")]);
    assert!(verify(
        &auth,
        ManifestScope::Data,
        &newer,
        &envelope(vec![root_entry(&root_a(), &newer)])
    )
    .is_ok());
    assert_eq!(auth.highest_sequence(ManifestScope::Data), 200);
    let err = verify(
        &auth,
        ManifestScope::Data,
        &older,
        &envelope(vec![root_entry(&root_a(), &older)]),
    )
    .unwrap_err();
    assert!(err.to_string().contains("rollback refused"), "{err}");
    // Re-serving the same manifest is fine.
    assert!(verify(
        &auth,
        ManifestScope::Data,
        &newer,
        &envelope(vec![root_entry(&root_a(), &newer)])
    )
    .is_ok());
    // Scopes are tracked separately.
    assert_eq!(auth.highest_sequence(ManifestScope::Exec), 0);

    // Embedded floor: a fresh process refuses anything older than its snapshot.
    let floored = ModelAuthenticator::new(vec![root_a().trusted()], 0, 500);
    let err = floored
        .verify_manifest(
            ManifestScope::Data,
            "main",
            &newer,
            &envelope(vec![root_entry(&root_a(), &newer)]),
        )
        .unwrap_err();
    assert!(err.to_string().contains("rollback refused"), "{err}");
}

#[test]
fn branch_and_scope_are_bound() {
    let auth = authenticator(&[&root_a()]);
    let dev = manifest("data", "dev", 10, &[(DATA_FILE, REMOTE)]);
    let err = verify(
        &auth,
        ManifestScope::Data,
        &dev,
        &envelope(vec![root_entry(&root_a(), &dev)]),
    )
    .unwrap_err();
    assert!(err.to_string().contains("branch dev"), "{err}");
    // A data manifest served as the exec manifest.
    let data = manifest("data", "main", 10, &[(EXEC_FILE, REMOTE)]);
    let err = verify(
        &auth,
        ManifestScope::Exec,
        &data,
        &envelope(vec![root_entry(&root_a(), &data)]),
    )
    .unwrap_err();
    assert!(err.to_string().contains("scope data"), "{err}");
}

#[test]
fn file_not_in_manifest_is_refused() {
    let auth = authenticator(&[&root_a()]);
    let m = manifest("data", "main", 10, &[("other.json", REMOTE)]);
    let v = auth
        .verify_manifest(
            ManifestScope::Data,
            "main",
            &m,
            &envelope(vec![root_entry(&root_a(), &m)]),
        )
        .unwrap();
    assert!(v
        .check_file(DATA_FILE, REMOTE)
        .unwrap_err()
        .to_string()
        .contains("not listed"));
    assert!(v.check_file("other.json", REMOTE).is_ok());
}

#[test]
fn delegated_ci_key() {
    let auth = authenticator(&[&root_a()]);
    let data = manifest("data", "main", 10, &[(DATA_FILE, REMOTE)]);
    let exec = manifest("exec", "main", 10, &[(EXEC_FILE, REMOTE)]);

    // Valid certificate: accepted for data...
    let signer = verify(
        &auth,
        ManifestScope::Data,
        &data,
        &envelope(vec![delegated_entry(&ci_key(), &root_a(), NOW + 60, &data)]),
    )
    .unwrap();
    assert_eq!(
        signer,
        Signer::Delegated {
            key_id: ci_key().id(),
            root_key_id: root_a().id()
        }
    );
    // ...never for executable models.
    let err = verify(
        &auth,
        ManifestScope::Exec,
        &exec,
        &envelope(vec![delegated_entry(&ci_key(), &root_a(), NOW + 60, &exec)]),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("require a root signature"),
        "{err}"
    );
    // Expired certificate.
    let err = verify(
        &auth,
        ManifestScope::Data,
        &data,
        &envelope(vec![delegated_entry(&ci_key(), &root_a(), NOW - 1, &data)]),
    )
    .unwrap_err();
    assert!(err.to_string().contains("expired"), "{err}");
    // Certificate issued by an untrusted root.
    let err = verify(
        &auth,
        ManifestScope::Data,
        &data,
        &envelope(vec![delegated_entry(
            &ci_key(),
            &attacker(),
            NOW + 60,
            &data,
        )]),
    )
    .unwrap_err();
    assert!(err.to_string().contains("not trusted"), "{err}");
    // Certificate whose not_after was raised after signing.
    let mut entry = delegated_entry(&ci_key(), &root_a(), NOW - 1, &data);
    entry["certificate"]["not_after"] = serde_json::json!(NOW + 3600);
    let err = verify(&auth, ManifestScope::Data, &data, &envelope(vec![entry])).unwrap_err();
    assert!(
        err.to_string().contains("bad certificate signature"),
        "{err}"
    );
    // Manifest signed by a different key than the one certified.
    let mut entry = delegated_entry(&ci_key(), &root_a(), NOW + 60, &data);
    entry["signature"] = serde_json::json!(attacker().sign_hex(&manifest_message(&data)));
    assert!(verify(&auth, ManifestScope::Data, &data, &envelope(vec![entry])).is_err());
}

#[test]
fn scope_of_published_paths() {
    assert_eq!(
        ManifestScope::for_path("threatmodel-macOS.json"),
        ManifestScope::Exec
    );
    assert_eq!(
        ManifestScope::for_path("threatmodel-Windows.json"),
        ManifestScope::Exec
    );
    assert_eq!(
        ManifestScope::for_path("threatmodel-macOS-EN.md"),
        ManifestScope::Data
    );
    assert_eq!(
        ManifestScope::for_path("whitelists-db.json"),
        ManifestScope::Data
    );
    assert_eq!(
        ManifestScope::for_path("consent/privacy-LLM-EN.md"),
        ManifestScope::Data
    );
}

/// Manifest and signatures produced by threatmodels'
/// `src/publish/sign-manifest.py` with TEST keys (root seed 0x01, CI seed
/// 0x03), verified here: the Python signer and the Rust verifier agree on
/// every byte that is signed.
#[test]
fn python_signer_interop() {
    let auth = authenticator(&[&root_a()]);
    let exec_m = include_bytes!("fixtures/signed/manifest-exec.json");
    let exec_s = include_bytes!("fixtures/signed/manifest-exec.sig.json");
    let data_m = include_bytes!("fixtures/signed/manifest-data.json");
    let data_s = include_bytes!("fixtures/signed/manifest-data.sig.json");
    let threat = include_bytes!("fixtures/threatmodel-Test.json");
    let list = include_bytes!("fixtures/test-db.json");
    let consent = include_bytes!("fixtures/consent/test-EN.md");

    let exec = auth
        .verify_manifest(ManifestScope::Exec, "main", exec_m, exec_s)
        .unwrap();
    assert_eq!(exec.signer, Signer::Root(root_a().id()));
    exec.check_file("threatmodel-Test.json", threat).unwrap();

    let data = auth
        .verify_manifest(ManifestScope::Data, "main", data_m, data_s)
        .unwrap();
    assert_eq!(
        data.signer,
        Signer::Delegated {
            key_id: ci_key().id(),
            root_key_id: root_a().id()
        }
    );
    data.check_file("test-db.json", list).unwrap();
    data.check_file("consent/test-EN.md", consent).unwrap();
    assert!(data.check_file("threatmodel-Test.json", threat).is_err());
}
