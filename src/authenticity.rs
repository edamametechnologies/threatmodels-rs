//! Authenticity of the files published in the threatmodels repository.
//!
//! The `<name>.sig` companion that [`crate::CloudModel`] fetches is an unkeyed
//! SHA-256 of the model, served from the same origin as the model, and the
//! client never recomputes it: it is a change-detection token, not a
//! signature. Anyone who can write the repository (or rewrite the HTTPS
//! response) can publish a model, including the `cli` targets the helper runs
//! as root/SYSTEM.
//!
//! This module adds an Ed25519-signed manifest next to the untouched `.sig`
//! layout, so released clients keep working unchanged:
//!
//! ```text
//! signed/manifest-<scope>.json      {"format":1,"scope","branch","sequence","issued_at","files":{path: sha256}}
//! signed/manifest-<scope>.sig.json  {"format":1,"signatures":[{"key_id","signature","certificate"?}]}
//! ```
//!
//! Two scopes:
//!
//! * `exec` covers `threatmodel-*.json` (their implementation / remediation /
//!   rollback `cli` targets are executed, elevated, by the helper). It MUST be
//!   signed directly by an embedded root key, which is kept offline.
//! * `data` covers every other model and the consent pages. It may also be
//!   signed by a CI signing key, provided the signature entry carries a
//!   certificate for that key signed by an embedded root key and not expired.
//!
//! The signature covers `MANIFEST_DOMAIN || manifest bytes` exactly as served.
//! A manifest is accepted only if its `scope` and `branch` match the request
//! and its `sequence` is not lower than the highest sequence this process has
//! accepted for the scope (nor than the embedded floor): an attacker who
//! replays an older, validly signed manifest cannot roll clients back.
//!
//! Failure policy (enforced by the caller): a file that is not covered by a
//! verified manifest is never loaded; the model keeps its current data, which
//! is either the embedded snapshot or an earlier verified download.

use anyhow::{anyhow, bail, Context, Result};
use ring::digest::{digest, SHA256};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Supported manifest and signature-envelope format.
pub const MANIFEST_FORMAT: u32 = 1;
/// Domain separation prefix of a manifest signature.
pub const MANIFEST_DOMAIN: &[u8] = b"edamame-models-manifest-v1\n";
/// Domain separation prefix of a signing-key certificate.
pub const CERT_DOMAIN: &[u8] = b"edamame-models-signing-cert-v1\n";

/// Production root public keys (hex-encoded raw Ed25519, 32 bytes each).
///
/// Enabling the `model-signatures` feature with this list empty is a compile
/// error (see below), so a build cannot claim verification without a key to
/// verify against. Two slots: the primary root and a backup root, which lets
/// a compromised or lost root be retired by a release that drops it.
pub const PRODUCTION_ROOT_KEYS: &[&str] = &[
    // Root A (primary), key id 93295ebcb9a6ec08, created 2026-09-29.
    "5b5d49de669207ebf90a8d4cb07a69c61f425515be8e69cef6aec83872fc59c4",
    // Root B (backup), key id 39f35c44b16e9f62, created 2026-09-29.
    "e1fcfd06a9baafc2f4c9cd5ba5d2b8721c1e7e4df5adbb027549f8ff740319cb",
];

/// Lowest manifest sequence accepted, per scope, before any download. Raise
/// it with each release to the sequence of the manifest that matches the
/// embedded snapshots, so a fresh process cannot be rolled back further than
/// what it ships with.
pub const EMBEDDED_SEQUENCE_FLOOR_EXEC: u64 = 0;
pub const EMBEDDED_SEQUENCE_FLOOR_DATA: u64 = 0;

#[cfg(feature = "model-signatures")]
const _: () = assert!(
    !PRODUCTION_ROOT_KEYS.is_empty(),
    "feature `model-signatures` requires PRODUCTION_ROOT_KEYS to hold the real root public keys"
);

/// The manifest a published file belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ManifestScope {
    /// Threat models: carry scripts the helper executes elevated.
    Exec,
    /// Everything else (lists, params, profiles, consent pages).
    Data,
}

impl ManifestScope {
    /// Scope of a published path (relative to the repository root).
    pub fn for_path(path: &str) -> Self {
        let name = path.rsplit('/').next().unwrap_or(path);
        if name.starts_with("threatmodel-") && name.ends_with(".json") {
            ManifestScope::Exec
        } else {
            ManifestScope::Data
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ManifestScope::Exec => "exec",
            ManifestScope::Data => "data",
        }
    }

    pub fn manifest_path(self) -> String {
        format!("signed/manifest-{}.json", self.as_str())
    }

    pub fn signature_path(self) -> String {
        format!("signed/manifest-{}.sig.json", self.as_str())
    }

    fn index(self) -> usize {
        match self {
            ManifestScope::Exec => 0,
            ManifestScope::Data => 1,
        }
    }
}

/// An embedded, trusted root public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedKey {
    pub key_id: String,
    pub public_key: Vec<u8>,
}

impl TrustedKey {
    pub fn from_public_key(public_key: &[u8]) -> Result<Self> {
        if public_key.len() != 32 {
            bail!(
                "Ed25519 public key must be 32 bytes, got {}",
                public_key.len()
            );
        }
        Ok(Self {
            key_id: key_id(public_key),
            public_key: public_key.to_vec(),
        })
    }

    pub fn from_hex(public_key_hex: &str) -> Result<Self> {
        Self::from_public_key(&hex_decode(public_key_hex)?)
    }
}

/// Key id: first 16 hex chars of SHA-256(raw public key).
pub fn key_id(public_key: &[u8]) -> String {
    hex_encode(digest(&SHA256, public_key).as_ref())[..16].to_string()
}

/// Lowercase hex SHA-256 of `bytes`, as listed in a manifest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(digest(&SHA256, bytes).as_ref())
}

#[derive(Debug, Deserialize)]
struct Manifest {
    format: u32,
    scope: String,
    branch: String,
    sequence: u64,
    issued_at: String,
    files: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct SignatureEnvelope {
    format: u32,
    signatures: Vec<SignatureEntry>,
}

#[derive(Debug, Deserialize)]
struct SignatureEntry {
    key_id: String,
    signature: String,
    certificate: Option<Certificate>,
}

#[derive(Debug, Deserialize)]
struct Certificate {
    key_id: String,
    public_key: String,
    not_after: u64,
    root_key_id: String,
    root_signature: String,
}

/// Bytes a root key signs to certify a signing key.
pub fn certificate_message(key_id: &str, public_key_hex: &str, not_after: u64) -> Vec<u8> {
    let mut msg = CERT_DOMAIN.to_vec();
    msg.extend_from_slice(format!("{key_id}\n{public_key_hex}\n{not_after}\n").as_bytes());
    msg
}

/// Bytes a manifest signature covers.
pub fn manifest_message(manifest_bytes: &[u8]) -> Vec<u8> {
    let mut msg = MANIFEST_DOMAIN.to_vec();
    msg.extend_from_slice(manifest_bytes);
    msg
}

/// Who signed an accepted manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signer {
    Root(String),
    Delegated { key_id: String, root_key_id: String },
}

/// A manifest whose signature, scope, branch and sequence were checked.
#[derive(Clone, Debug)]
pub struct VerifiedManifest {
    pub scope: ManifestScope,
    pub sequence: u64,
    pub issued_at: String,
    pub signer: Signer,
    files: BTreeMap<String, String>,
}

impl VerifiedManifest {
    /// Check `bytes` against the manifest entry for `path`.
    pub fn check_file(&self, path: &str, bytes: &[u8]) -> Result<()> {
        let expected = self.files.get(path).ok_or_else(|| {
            anyhow!(
                "{path} is not listed in the {} manifest",
                self.scope.as_str()
            )
        })?;
        let actual = sha256_hex(bytes);
        if !expected.eq_ignore_ascii_case(&actual) {
            bail!(
                "{path} does not match the {} manifest (sequence {}): expected sha256 {expected}, got {actual}",
                self.scope.as_str(),
                self.sequence
            );
        }
        Ok(())
    }
}

/// Verifies manifests against a set of trusted root keys and tracks the
/// highest accepted sequence per scope (rollback protection).
#[derive(Debug)]
pub struct ModelAuthenticator {
    roots: Vec<TrustedKey>,
    highest_sequence: [AtomicU64; 2],
    now: fn() -> u64,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl ModelAuthenticator {
    pub fn new(roots: Vec<TrustedKey>, floor_exec: u64, floor_data: u64) -> Self {
        Self {
            roots,
            highest_sequence: [AtomicU64::new(floor_exec), AtomicU64::new(floor_data)],
            now: unix_now,
        }
    }

    /// Override the clock (certificate expiry) -- tests only.
    #[doc(hidden)]
    pub fn with_clock(mut self, now: fn() -> u64) -> Self {
        self.now = now;
        self
    }

    /// The authenticator every [`crate::CloudModel`] uses by default: `Some`
    /// only when the `model-signatures` feature is enabled (which requires
    /// [`PRODUCTION_ROOT_KEYS`] to be non-empty). `None` means downloads are
    /// NOT authenticated; models report [`crate::ModelProvenance::Downloaded`],
    /// never `DownloadedVerified`.
    pub fn production() -> Option<Arc<ModelAuthenticator>> {
        #[cfg(feature = "model-signatures")]
        {
            use std::sync::OnceLock;
            static PRODUCTION: OnceLock<Arc<ModelAuthenticator>> = OnceLock::new();
            Some(
                PRODUCTION
                    .get_or_init(|| {
                        let roots = PRODUCTION_ROOT_KEYS
                            .iter()
                            .map(|k| {
                                TrustedKey::from_hex(k).expect("invalid PRODUCTION_ROOT_KEYS entry")
                            })
                            .collect();
                        Arc::new(ModelAuthenticator::new(
                            roots,
                            EMBEDDED_SEQUENCE_FLOOR_EXEC,
                            EMBEDDED_SEQUENCE_FLOOR_DATA,
                        ))
                    })
                    .clone(),
            )
        }
        #[cfg(not(feature = "model-signatures"))]
        {
            None
        }
    }

    /// Raise the scope's sequence floor, e.g. to the sequence of the manifest
    /// matching the snapshots a binary embeds. Never lowers it.
    pub fn raise_floor(&self, scope: ManifestScope, sequence: u64) {
        self.highest_sequence[scope.index()].fetch_max(sequence, Ordering::AcqRel);
    }

    pub fn highest_sequence(&self, scope: ManifestScope) -> u64 {
        self.highest_sequence[scope.index()].load(Ordering::Acquire)
    }

    fn root(&self, key_id: &str) -> Option<&TrustedKey> {
        self.roots.iter().find(|k| k.key_id == key_id)
    }

    fn signer_of(
        &self,
        scope: ManifestScope,
        message: &[u8],
        envelope: &SignatureEnvelope,
    ) -> Result<Signer> {
        let mut reasons = Vec::new();
        for entry in &envelope.signatures {
            let signature = match hex_decode(&entry.signature) {
                Ok(s) => s,
                Err(e) => {
                    reasons.push(format!("{}: {e}", entry.key_id));
                    continue;
                }
            };
            match &entry.certificate {
                None => {
                    let Some(root) = self.root(&entry.key_id) else {
                        reasons.push(format!("{}: not a trusted root key", entry.key_id));
                        continue;
                    };
                    if UnparsedPublicKey::new(&ED25519, &root.public_key)
                        .verify(message, &signature)
                        .is_ok()
                    {
                        return Ok(Signer::Root(root.key_id.clone()));
                    }
                    reasons.push(format!("{}: bad signature", entry.key_id));
                }
                Some(cert) => {
                    if scope == ManifestScope::Exec {
                        reasons.push(format!(
                            "{}: exec manifests require a root signature, delegated keys are refused",
                            entry.key_id
                        ));
                        continue;
                    }
                    match self.check_certificate(cert, &entry.key_id) {
                        Ok(public_key) => {
                            if UnparsedPublicKey::new(&ED25519, &public_key)
                                .verify(message, &signature)
                                .is_ok()
                            {
                                return Ok(Signer::Delegated {
                                    key_id: cert.key_id.clone(),
                                    root_key_id: cert.root_key_id.clone(),
                                });
                            }
                            reasons.push(format!("{}: bad signature", entry.key_id));
                        }
                        Err(e) => reasons.push(format!("{}: {e}", entry.key_id)),
                    }
                }
            }
        }
        if reasons.is_empty() {
            bail!("signature envelope holds no signature");
        }
        bail!(
            "no valid signature from a trusted key ({})",
            reasons.join("; ")
        )
    }

    fn check_certificate(&self, cert: &Certificate, entry_key_id: &str) -> Result<Vec<u8>> {
        let root = self
            .root(&cert.root_key_id)
            .ok_or_else(|| anyhow!("certificate root {} is not trusted", cert.root_key_id))?;
        let public_key = hex_decode(&cert.public_key)?;
        if public_key.len() != 32 {
            bail!("certified key is not a 32-byte Ed25519 key");
        }
        if key_id(&public_key) != cert.key_id || cert.key_id != entry_key_id {
            bail!("certificate key id does not match the certified key");
        }
        let root_signature = hex_decode(&cert.root_signature)?;
        UnparsedPublicKey::new(&ED25519, &root.public_key)
            .verify(
                &certificate_message(
                    &cert.key_id,
                    &cert.public_key.to_ascii_lowercase(),
                    cert.not_after,
                ),
                &root_signature,
            )
            .map_err(|_| anyhow!("bad certificate signature from root {}", root.key_id))?;
        let now = (self.now)();
        if now > cert.not_after {
            bail!("certificate expired at {} (now {now})", cert.not_after);
        }
        Ok(public_key)
    }

    /// Verify a manifest and its signature envelope for `scope` / `branch`.
    /// On success the scope's sequence floor is raised to the manifest's.
    pub fn verify_manifest(
        &self,
        scope: ManifestScope,
        branch: &str,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<VerifiedManifest> {
        let envelope: SignatureEnvelope =
            serde_json::from_slice(signature_bytes).context("unreadable signature envelope")?;
        if envelope.format != MANIFEST_FORMAT {
            bail!("unsupported signature envelope format {}", envelope.format);
        }
        // Authenticate before parsing anything else from the manifest.
        let signer = self.signer_of(scope, &manifest_message(manifest_bytes), &envelope)?;
        let manifest: Manifest =
            serde_json::from_slice(manifest_bytes).context("unreadable manifest")?;
        if manifest.format != MANIFEST_FORMAT {
            bail!("unsupported manifest format {}", manifest.format);
        }
        if manifest.scope != scope.as_str() {
            bail!(
                "manifest scope {} where {} was requested",
                manifest.scope,
                scope.as_str()
            );
        }
        if manifest.branch != branch {
            bail!(
                "manifest signed for branch {} where {branch} was requested",
                manifest.branch
            );
        }
        let floor = &self.highest_sequence[scope.index()];
        let current = floor.load(Ordering::Acquire);
        if manifest.sequence < current {
            bail!(
                "manifest sequence {} is older than the accepted {current} (rollback refused)",
                manifest.sequence
            );
        }
        floor.fetch_max(manifest.sequence, Ordering::AcqRel);
        Ok(VerifiedManifest {
            scope,
            sequence: manifest.sequence,
            issued_at: manifest.issued_at,
            signer,
            files: manifest.files,
        })
    }

    /// Fetch the manifest covering `path` from `base_url/branch/` and check
    /// `bytes` against it.
    pub async fn verify_published_file(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        branch: &str,
        path: &str,
        bytes: &[u8],
    ) -> Result<VerifiedManifest> {
        let scope = ManifestScope::for_path(path);
        let manifest = fetch_bytes(
            client,
            &format!("{base_url}/{branch}/{}", scope.manifest_path()),
        )
        .await?;
        let signature = fetch_bytes(
            client,
            &format!("{base_url}/{branch}/{}", scope.signature_path()),
        )
        .await?;
        let verified = self.verify_manifest(scope, branch, &manifest, &signature)?;
        verified.check_file(path, bytes)?;
        Ok(verified)
    }
}

async fn fetch_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let response = crate::fetch_with_retry(client, url)
        .await
        .with_context(|| format!("failed to fetch {url}"))?;
    Ok(response
        .bytes()
        .await
        .with_context(|| format!("failed to read {url}"))?
        .to_vec())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub fn hex_decode(text: &str) -> Result<Vec<u8>> {
    let text = text.trim();
    if !text.is_ascii() || !text.len().is_multiple_of(2) {
        bail!("odd-length hex string");
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| anyhow!("invalid hex")))
        .collect()
}
