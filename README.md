# threatmodels-rs

A Rust crate providing cloud-based data model management with signature-based updates, custom data support, and thread-safe access patterns. Used to dynamically pull updates from https://github.com/edamametechnologies/threatmodels.

## Overview

The `threatmodels-rs` crate provides a generic `CloudModel<T>` system for managing data that can be:
- Fetched from remote sources (GitHub repositories)
- Updated based on signature changes
- Overridden with custom data
- Reset to built-in defaults
- Accessed in a thread-safe manner

## Key Components

### CloudModel<T>

The main struct that wraps data of type `T` and provides cloud synchronization capabilities.

```rust
use threatmodels_rs::{CloudModel, CloudSignature, UpdateStatus};

// Your data type must implement CloudSignature
#[derive(Clone)]
struct MyData {
    content: String,
    signature: String,
}

impl CloudSignature for MyData {
    fn get_signature(&self) -> String {
        self.signature.clone()
    }
    
    fn set_signature(&mut self, signature: String) {
        self.signature = signature;
    }
}

// Initialize with built-in data
let model = CloudModel::initialize(
    "my-data.json".to_string(),
    builtin_data_string,
    |data| serde_json::from_str(data)
)?;
```

### CloudSignature Trait

Types managed by `CloudModel` must implement this trait for signature-based updates:

```rust
pub trait CloudSignature {
    fn get_signature(&self) -> String;
    fn set_signature(&mut self, signature: String);
}
```

### UpdateStatus Enum

Represents the outcome of update operations:

```rust
pub enum UpdateStatus {
    Updated,        // Data was successfully updated
    NotUpdated,     // Data was already current
    FormatError,    // Data format was invalid
    SkippedCustom,  // Update skipped due to custom data
}
```

## Core Features

### 1. Signature-Based Updates

Updates are performed only when remote signatures differ from local ones:

```rust
// Check if update is needed
let needs_update = model.needs_update("main").await?;

// Perform update if needed
let status = model.update("main", false, |data| {
    serde_json::from_str(data)
}).await?;
```

### 2. Custom Data Override

Replace default data with custom implementations:

```rust
// Set custom data (disables automatic updates)
model.set_custom_data(my_custom_data).await;

// Check if using custom data
if model.is_custom().await {
    println!("Using custom data");
}

// Reset to default data
model.reset_to_default().await;
```

### 3. Thread-Safe Access

Data is protected by `Arc<CustomRwLock<T>>` for concurrent access:

```rust
// Read access
let data = model.data.read().await;
println!("Current signature: {}", data.get_signature());

// The model handles locking internally for updates
```

### 4. Remote Data Sources

Data is fetched from GitHub repositories using predictable URL patterns:

- Data: `https://raw.githubusercontent.com/edamametechnologies/threatmodels/{branch}/{filename}`
- Signature: `https://raw.githubusercontent.com/edamametechnologies/threatmodels/{branch}/{filename_without_extension}.sig`

## Usage Examples

### Threat Metrics (from threat_factory.rs)

```rust
lazy_static! {
    pub static ref THREATS: CloudModel<ThreatMetrics> = {
        CloudModel::initialize(
            "threatmodel-macOS.json".to_string(),
            BUILTIN_THREAT_DATA,
            |data| {
                let json: ThreatMetricsJSON = serde_json::from_str(data)?;
                ThreatMetrics::new_from_json(&json, "macos")
            },
        ).expect("Failed to initialize CloudModel")
    };
}

// Update threat data
pub async fn update(branch: &str, force: bool) -> Result<UpdateStatus> {
    THREATS.update(branch, force, |data| {
        let json: ThreatMetricsJSON = serde_json::from_str(data)?;
        ThreatMetrics::new_from_json(&json, "macos")
    }).await
}
```

### IP Blacklists (from blacklists.rs)

```rust
lazy_static! {
    static ref LISTS: CloudModel<Blacklists> = {
        CloudModel::initialize(
            "blacklists-db.json".to_string(),
            BUILTIN_BLACKLISTS,
            |data| {
                let json: BlacklistsJSON = serde_json::from_str(data)?;
                Ok(Blacklists::new_from_json(json, true)) // Filter local ranges
            }
        ).expect("Failed to initialize CloudModel")
    };
}

// Set custom blacklists
pub async fn set_custom_blacklists(json: &str) -> Result<()> {
    if json.is_empty() {
        LISTS.reset_to_default().await;
    } else {
        let data: BlacklistsJSON = serde_json::from_str(json)?;
        LISTS.set_custom_data(Blacklists::new_from_json(data, false)).await;
    }
    Ok(())
}
```

### Whitelists (from whitelists.rs)

```rust
lazy_static! {
    static ref LISTS: CloudModel<Whitelists> = {
        CloudModel::initialize(
            "whitelists-db.json".to_string(),
            BUILTIN_WHITELISTS,
            |data| {
                let json: WhitelistsJSON = serde_json::from_str(data)?;
                Ok(Whitelists::new_from_json(json))
            }
        ).expect("Failed to initialize CloudModel")
    };
}
```

## Model signatures (`model-signatures` feature)

The `.sig` next to each model is an unkeyed SHA-256 served by the same origin:
it tells a client that a model changed, not who published it. With the
`model-signatures` feature, every download is also checked against an
Ed25519-signed manifest before it is parsed (`src/authenticity.rs`):

- `signed/manifest-exec.json` covers the `threatmodel-*.json` files, whose
  scripts the EDAMAME helper runs as root/SYSTEM. It must be signed by one of
  the two embedded root keys (`PRODUCTION_ROOT_KEYS`), kept offline.
- `signed/manifest-data.json` covers every other model and the consent pages.
  It may be signed by a root key, or by a CI key carrying a root-signed
  certificate that has not expired.

A download that does not verify is never parsed: the model keeps its current
data (the embedded snapshot or an earlier verified download) and
`last_authenticity_error()` says why. While the origin keeps publishing that
same version (same `.sig`), it is not downloaded again for 10 minutes: an
update fetches only the `.sig` (the EDAMAME helper updates on every metric
order whose model signature differs from its copy). `force`, or a new `.sig`,
downloads at once. `provenance()` reports where the current
data came from: `Embedded`, `Custom` (set locally), `Downloaded` (feature off:
only TLS vouches for it) or `DownloadedVerified`. Only `main` is signed: a
build that reads models from another branch keeps its embedded models.

EDAMAME enables the feature in every shipped build: through `edamame_core`'s
default features (app, posture, cli) and on the helper's `edamame_foundation`
dependency. Enabling it with `PRODUCTION_ROOT_KEYS` empty is a compile error.
`authenticity::SIGNATURES_ENFORCED` tells whether the build has it.

### Status

`model_authenticity_states()` lists every model the process initialized
(`CloudModel::initialize` registers it), by file name, with its scope
(`exec` / `data`), whether its downloads are authenticated, its provenance and
its last authenticity error. It reads shared handles only, never a model's data
lock. `ModelProvenance::as_str()` gives the stable names status reports use:
`embedded`, `custom`, `downloaded`, `downloaded_verified`.

### Rollback floors

A manifest is refused when its `sequence` is lower than the highest one the
process accepted for that scope, or than the embedded floor
(`EMBEDDED_SEQUENCE_FLOOR_EXEC` / `EMBEDDED_SEQUENCE_FLOOR_DATA`), so a replayed
old manifest cannot roll a client back. The in-process floor is not persisted:
every start begins again from the embedded floors.

At each release, set the floors to the sequences of `signed/manifest-exec.json`
and `signed/manifest-data.json` on threatmodels `main` at the commit whose
models the release embeds, and copy those four `signed/` files into
`tests/fixtures/production/`. `tests/sequence_floors.rs` checks that the
production keys verify them and that their sequences are the floors. A floor
must never exceed a sequence `main` serves, or every verifying client refuses
every download of that scope; sequences only grow (a manifest's sequence is
the Unix time it was built), so a floor taken from `main` stays safe. Current
floors (2026-09-29, the first signed manifests): exec 1790681588, data
1790684367.

## Configuration

The crate uses these default settings:

- **Base URL**: `https://raw.githubusercontent.com/edamametechnologies/threatmodels`
- **Timeout**: 120 seconds for HTTP requests
- **Compression**: gzip enabled for transfers

## Error Handling

The crate uses `anyhow::Result<T>` for error handling:

```rust
use anyhow::{anyhow, Context, Result};

// Errors are contextual and chainable
let result = model.update("main", false, parser)
    .await
    .with_context(|| "Failed to update model")?;
```

## Testing

The crate provides testing utilities:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_model() {
        // Use test data override
        let test_data = MyData { /* ... */ };
        model.overwrite_with_test_data(test_data).await;
        
        // Test functionality
        assert!(model.is_custom().await);
    }
}
```

## Thread Safety

- All operations are async and thread-safe
- Internal data is protected by `CustomRwLock` from the `undeadlock` crate
- Multiple readers can access data concurrently
- Updates acquire exclusive locks only during data modification

## Dependencies

- `reqwest`: HTTP client for fetching remote data
- `tokio`: Async runtime
- `serde`: Serialization framework
- `anyhow`: Error handling
- `tracing`: Logging and instrumentation
- `undeadlock`: Deadlock-free synchronization primitives