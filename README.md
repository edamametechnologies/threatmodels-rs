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