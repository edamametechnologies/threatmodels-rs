//! Shared HTTP client construction for the EDAMAME workspace.
//!
//! Every outbound `reqwest` client in the workspace is built through these
//! helpers so TLS trust is configured in exactly one place.
//!
//! With the default `platform_certs` feature enabled, clients trust the
//! operating system / platform certificate store (system CAs, including
//! enterprise TLS-inspection proxies such as Netskope or Zscaler that
//! re-sign traffic with a locally-trusted CA) via `rustls-platform-verifier`,
//! instead of only the bundled webpki (Mozilla) root set that reqwest's
//! `rustls-tls-webpki-roots` backend ships.
//!
//! When the feature is disabled the helpers return a plain builder that keeps
//! reqwest's default webpki roots, so the trust policy is a compile-time
//! toggle rather than a behavioural fork in each call site.
//!
//! ## Android
//!
//! Android is intentionally excluded from the platform-verifier path even when
//! `platform_certs` is on: Android's certificate verifier requires a
//! JNI-bound Kotlin component bundled in the host app and a one-time
//! `rustls_platform_verifier::android::init_*` call before any TLS handshake,
//! neither of which is wired at the library level here. On Android the helpers
//! therefore fall back to the bundled webpki roots. The `rustls-platform-verifier`
//! crate still compiles for Android; it is simply never invoked.

/// Returns `true` when the platform certificate verifier is actually active
/// for this build (i.e. the `platform_certs` feature is enabled and the target
/// is not Android). Useful for diagnostics / startup logging.
pub fn platform_verifier_active() -> bool {
    cfg!(all(feature = "platform_certs", not(target_os = "android")))
}

#[cfg(all(feature = "platform_certs", not(target_os = "android")))]
fn platform_client_config() -> rustls::ClientConfig {
    use rustls_platform_verifier::BuilderVerifierExt;
    use std::sync::{Arc, OnceLock};

    // Building the platform verifier (and, on Linux, loading the native root
    // store) is comparatively expensive, so cache the config and hand out
    // cheap clones (the config is internally reference-counted).
    static CONFIG: OnceLock<rustls::ClientConfig> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            // Pin the ring provider explicitly so we never depend on a
            // process-default provider being installed, and so the provider
            // matches reqwest's ring backend.
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("rustls safe default protocol versions are always available")
                .with_platform_verifier()
                .expect("platform certificate verifier is available on this target")
                .with_no_client_auth();
            // Mirror reqwest's own ALPN policy for its built-in rustls backend:
            // advertise `h2` ONLY when reqwest is compiled with its `http2`
            // feature. Because `use_preconfigured_tls` hands this config to
            // reqwest verbatim (it does NOT re-derive ALPN like the built-in
            // backend does), advertising `h2` unconditionally would make the
            // server negotiate HTTP/2 and then hyper panics with
            // "http2 feature is not enabled". The `http2` feature (default off)
            // enables `reqwest/http2` and this `h2` entry together.
            config.alpn_protocols = vec![
                #[cfg(feature = "http2")]
                b"h2".to_vec(),
                b"http/1.1".to_vec(),
            ];
            config
        })
        .clone()
}

/// Builds a [`reqwest::ClientBuilder`] with the workspace TLS trust policy
/// applied. Callers chain their own `.timeout(..)`, headers, `.gzip(..)`, etc.
/// and then `.build()` as usual.
pub fn client_builder() -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder();
    #[cfg(all(feature = "platform_certs", not(target_os = "android")))]
    {
        builder.use_preconfigured_tls(platform_client_config())
    }
    #[cfg(not(all(feature = "platform_certs", not(target_os = "android"))))]
    {
        builder
    }
}

/// Blocking variant of [`client_builder`]. Requires the `blocking` feature
/// (which enables reqwest's `blocking` feature).
#[cfg(feature = "blocking")]
pub fn blocking_client_builder() -> reqwest::blocking::ClientBuilder {
    let builder = reqwest::blocking::Client::builder();
    #[cfg(all(feature = "platform_certs", not(target_os = "android")))]
    {
        builder.use_preconfigured_tls(platform_client_config())
    }
    #[cfg(not(all(feature = "platform_certs", not(target_os = "android"))))]
    {
        builder
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn async_client_builds() {
        // Exercises the full TLS configuration path (platform verifier when
        // enabled, webpki fallback otherwise).
        client_builder()
            .build()
            .expect("workspace reqwest client should build");
    }

    #[cfg(feature = "blocking")]
    #[test]
    fn blocking_client_builds() {
        blocking_client_builder()
            .build()
            .expect("workspace blocking reqwest client should build");
    }

    #[test]
    fn platform_verifier_flag_matches_cfg() {
        assert_eq!(
            platform_verifier_active(),
            cfg!(all(feature = "platform_certs", not(target_os = "android")))
        );
    }
}
