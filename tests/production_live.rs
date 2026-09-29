//! Live: every model and a consent page that threatmodels `main` serves
//! verify with the production root keys, as a client built with
//! `model-signatures` downloads them. Network, so ignored by default:
//!
//! ```text
//! cargo test --features model-signatures --test production_live -- --ignored
//! ```
//!
//! Run it after a signing change (a new exec manifest, a renewed CI
//! certificate) to see what released clients will accept.

#![cfg(feature = "model-signatures")]

use anyhow::Result;
use threatmodels_rs::authenticity::ModelAuthenticator;
use threatmodels_rs::{CloudModel, CloudSignature, ModelProvenance, UpdateStatus};

/// Only the published signature matters here, not the content.
#[derive(Debug, Clone)]
struct Raw {
    signature: String,
}

impl CloudSignature for Raw {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

fn parse_raw(_data: &str) -> Result<Raw> {
    Ok(Raw {
        signature: String::new(),
    })
}

const PUBLISHED_MODELS: &[&str] = &[
    // exec: signed by a root key
    "threatmodel-Android.json",
    "threatmodel-Linux.json",
    "threatmodel-Windows.json",
    "threatmodel-iOS.json",
    "threatmodel-macOS.json",
    // data: signed by the certified CI key
    "agent-visibility-params-db.json",
    "blacklists-db.json",
    "cve-detection-params-db.json",
    "lanscan-port-vulns-db.json",
    "lanscan-profiles-db.json",
    "lanscan-vendor-vulns-db.json",
    "sensitive-paths-db.json",
    "whitelists-db.json",
];

#[tokio::test]
#[ignore = "network: downloads from threatmodels main"]
async fn main_serves_what_the_production_keys_verify() {
    for file in PUBLISHED_MODELS {
        let model = CloudModel::initialize(file.to_string(), "{}", parse_raw).unwrap();
        assert!(model.authenticity_enforced());
        let status = model.update("main", true, parse_raw).await.unwrap();
        assert_eq!(
            status,
            UpdateStatus::Updated,
            "{file}: {:?}",
            model.last_authenticity_error().await
        );
        assert_eq!(model.provenance(), ModelProvenance::DownloadedVerified);
    }

    // A consent page (fetched outside CloudModel, checked the same way).
    const RAW: &str = "https://raw.githubusercontent.com/edamametechnologies/threatmodels";
    let path = "consent/privacy-LLM-EN.md";
    let client = threatmodels_rs::tls::client_builder().build().unwrap();
    let page = client
        .get(format!("{RAW}/main/{path}"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let authenticator = ModelAuthenticator::production().unwrap();
    authenticator
        .verify_published_file(&client, RAW, "main", path, &page)
        .await
        .expect("the consent page verifies");
    let tampered = [page.as_ref(), b"\n"].concat();
    assert!(authenticator
        .verify_published_file(&client, RAW, "main", path, &tampered)
        .await
        .is_err());
}
