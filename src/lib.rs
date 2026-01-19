use anyhow::{anyhow, Context, Result};
use chrono::NaiveDate;
use reqwest::{Client, Response, StatusCode};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::Duration;
use tracing::{error, info, trace, warn};
use undeadlock::CustomRwLock;

const BASE_URL: &str = "https://raw.githubusercontent.com/edamametechnologies/threatmodels";
static TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum number of retry attempts for transient HTTP errors
const MAX_RETRIES: u32 = 3;
/// Initial delay between retries (doubles with each attempt)
const INITIAL_RETRY_DELAY_MS: u64 = 1000;

/// HTTP status codes that are considered retryable (transient errors)
fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS       // 429
            | StatusCode::INTERNAL_SERVER_ERROR // 500
            | StatusCode::BAD_GATEWAY           // 502
            | StatusCode::SERVICE_UNAVAILABLE   // 503
            | StatusCode::GATEWAY_TIMEOUT       // 504
    )
}

/// Fetches a URL with retry logic for transient failures.
/// Retries on connection errors, timeouts, and 5xx/429 status codes.
async fn fetch_with_retry(client: &Client, url: &str) -> Result<Response> {
    let mut last_error = None;
    let mut delay_ms = INITIAL_RETRY_DELAY_MS;

    for attempt in 1..=MAX_RETRIES {
        match client.get(url).send().await {
            Ok(response) => {
                if response.status().is_success() {
                    return Ok(response);
                }

                if is_retryable_status(response.status()) && attempt < MAX_RETRIES {
                    warn!(
                        "Retryable HTTP {} from {} (attempt {}/{}), retrying in {}ms...",
                        response.status(),
                        url,
                        attempt,
                        MAX_RETRIES,
                        delay_ms
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms *= 2; // Exponential backoff
                    continue;
                }

                // Non-retryable error or final attempt
                return Err(anyhow!(
                    "Failed to fetch data from: {}. HTTP Status: {}",
                    url,
                    response.status()
                ));
            }
            Err(e) => {
                // Connection errors and timeouts are retryable
                if attempt < MAX_RETRIES {
                    warn!(
                        "Network error fetching {} (attempt {}/{}): {}. Retrying in {}ms...",
                        url, attempt, MAX_RETRIES, e, delay_ms
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms *= 2;
                    last_error = Some(e);
                    continue;
                }
                last_error = Some(e);
            }
        }
    }

    Err(anyhow!(
        "Failed to fetch {} after {} attempts: {}",
        url,
        MAX_RETRIES,
        last_error.map(|e| e.to_string()).unwrap_or_default()
    ))
}

pub trait CloudSignature {
    fn get_signature(&self) -> String;
    fn set_signature(&mut self, signature: String);
}

/// Optional trait for models that have a date field for validation.
/// If implemented, CloudModel will automatically reject downloads that are older than the built-in data.
pub trait CloudDate {
    fn get_date(&self) -> Option<&str>;
}

/// Represents the status of an update operation.
#[derive(Debug, Clone, PartialEq)]
pub enum UpdateStatus {
    Updated,
    NotUpdated,
    FormatError,
    SkippedCustom,
}

/// Outcome of applying custom validation logic during an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateValidation {
    /// Accept the downloaded model and persist it.
    Accept,
    /// Reject the downloaded model and revert to the built-in data set.
    RejectUseBuiltin,
    /// Reject the downloaded model but keep the currently loaded data.
    RejectKeepCurrent,
}

/// A generic model for handling cloud-based data fetching and updating.
#[derive(Debug, Clone)]
pub struct CloudModel<T: CloudSignature + Send + Sync + 'static> {
    pub data: Arc<CustomRwLock<T>>,
    file_name: String,
    is_custom: Arc<AtomicBool>,
    builtin_data: Arc<T>,
    update_in_progress: Arc<AtomicBool>,
}

impl<T> CloudModel<T>
where
    T: CloudSignature + Send + Sync + Clone + 'static,
{
    /// Initializes the CloudModel with built-in data.
    pub fn initialize<F>(file_name: String, builtin: &'static str, parser: F) -> Result<Self>
    where
        F: Fn(&str) -> Result<T>,
    {
        let initial_data = parser(builtin)
            .with_context(|| format!("Failed to parse built-in data for file: {}", file_name))?;

        let builtin_data = Arc::new(initial_data.clone());

        Ok(Self {
            data: Arc::new(CustomRwLock::new(initial_data)),
            file_name,
            is_custom: Arc::new(AtomicBool::new(false)),
            builtin_data,
            update_in_progress: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Initializes an empty CloudModel for testing purposes.
    pub fn initialize_empty() -> Self
    where
        T: Default,
    {
        let initial_data = T::default();
        let builtin_data = Arc::new(initial_data.clone());

        Self {
            data: Arc::new(CustomRwLock::new(initial_data)),
            file_name: "test_empty.json".to_string(),
            is_custom: Arc::new(AtomicBool::new(false)),
            builtin_data,
            update_in_progress: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Sets custom data, replacing the current data.
    pub async fn set_custom_data(&self, data: T) {
        *self.data.write().await = data;
        self.is_custom.store(true, Ordering::Relaxed);
        info!(
            "Set custom data for file: '{}'. Updates will be skipped.",
            self.file_name
        );
    }

    /// Resets the data to the original built-in data.
    pub async fn reset_to_default(&self) {
        if self.is_custom.load(Ordering::Relaxed) {
            *self.data.write().await = (*self.builtin_data).clone();
            self.is_custom.store(false, Ordering::Relaxed);
            info!(
                "Reset data to default for file: '{}'. Updates are now enabled.",
                self.file_name
            );
        } else {
            info!(
                "Data for file '{}' is already default. No reset needed.",
                self.file_name
            );
        }
    }

    /// Checks if the model is currently using custom data.
    pub async fn is_custom(&self) -> bool {
        self.is_custom.load(Ordering::Relaxed)
    }

    /// Overwrites the current data with test data (useful for testing).
    /// This marks the data as custom.
    pub async fn overwrite_with_test_data(&self, data: T) {
        *self.data.write().await = data;
        self.is_custom.store(true, Ordering::Relaxed);
        info!(
            "Overwrote with test data for file: '{}'. Marked as custom.",
            self.file_name
        );
    }

    /// Constructs the URL to fetch the signature file.
    pub fn get_sig_url(branch: &str, file_name: &str) -> String {
        let file_name = file_name.replace(".json", "");
        format!("{}/{}/{}.sig", BASE_URL, branch, file_name)
    }

    /// Constructs the URL to fetch the data file.
    pub fn get_data_url(branch: &str, file_name: &str) -> String {
        format!("{}/{}/{}", BASE_URL, branch, file_name)
    }

    /// Retrieves the current signature from the data.
    pub async fn get_signature(&self) -> String {
        let data = self.data.read().await;
        data.get_signature()
    }

    /// Sets a new signature in the data.
    pub async fn set_signature(&self, signature: String) {
        let mut data = self.data.write().await;
        data.set_signature(signature);
    }

    /// Determines if an update is needed by comparing the current signature with the remote one.
    /// Returns `Ok(false)` if the model is using custom data.
    pub async fn needs_update(&self, branch: &str) -> Result<bool> {
        if self.is_custom.load(Ordering::Relaxed) {
            trace!(
                "Skipping needs_update check for '{}' because custom data is active.",
                self.file_name
            );
            return Ok(false);
        }

        let sig_url = Self::get_sig_url(branch, &self.file_name);

        let client = Client::builder()
            .gzip(true)
            .timeout(TIMEOUT)
            .build()
            .context("Failed to build reqwest client")?;

        let sig_response = fetch_with_retry(&client, &sig_url)
            .await
            .with_context(|| format!("Failed to fetch signature from: {}", sig_url))?;

        let new_signature = sig_response
            .text()
            .await
            .with_context(|| format!("Failed to read signature text from response: {}", sig_url))?;

        trace!("Fetched new signature: {}", new_signature);

        let current_signature = {
            let data = self.data.read().await;
            data.get_signature()
        };

        Ok(new_signature != current_signature)
    }

    /// Updates the data if a new version is available or if forced.
    /// Skips the update if the model is currently using custom data, unless `force` is true.
    pub async fn update<F>(&self, branch: &str, force: bool, parser: F) -> Result<UpdateStatus>
    where
        F: Fn(&str) -> Result<T>,
    {
        self.update_with_validation(branch, force, parser, |_, _| Ok(UpdateValidation::Accept))
            .await
    }

    /// Same as [`CloudModel::update`] but accepts an additional validator that can reject
    /// downloaded data based on arbitrary business rules (e.g. rejecting stale models).
    pub async fn update_with_validation<F, V>(
        &self,
        branch: &str,
        force: bool,
        parser: F,
        validator: V,
    ) -> Result<UpdateStatus>
    where
        F: Fn(&str) -> Result<T>,
        V: Fn(&T, &T) -> Result<UpdateValidation>,
    {
        if self.is_custom.load(Ordering::Relaxed) && !force {
            info!(
                "Skipping update for file: '{}' on branch: '{}' because custom data is active and force=false.",
                self.file_name, branch
            );
            return Ok(UpdateStatus::SkippedCustom);
        }

        if self
            .update_in_progress
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            info!(
                "Skipping update for file: '{}' because another update is already in progress.",
                self.file_name
            );
            return Ok(UpdateStatus::NotUpdated);
        }
        let result = self.perform_update(branch, force, parser, validator).await;

        self.update_in_progress.store(false, Ordering::Release);

        result
    }

    async fn perform_update<F, V>(
        &self,
        branch: &str,
        force: bool,
        parser: F,
        validator: V,
    ) -> Result<UpdateStatus>
    where
        F: Fn(&str) -> Result<T>,
        V: Fn(&T, &T) -> Result<UpdateValidation>,
    {
        if self.is_custom.load(Ordering::Relaxed) && force {
            info!(
                "Forcing update for file: '{}'. Resetting to default first.",
                self.file_name
            );
            self.reset_to_default().await;
        }

        info!(
            "Starting update check for file: '{}' on branch: '{}'",
            self.file_name, branch
        );

        let client = Client::builder()
            .gzip(true)
            .timeout(TIMEOUT)
            .build()
            .context("Failed to build reqwest client")?;

        let sig_url = Self::get_sig_url(branch, &self.file_name);

        let sig_response = fetch_with_retry(&client, &sig_url)
            .await
            .with_context(|| format!("Failed to fetch signature from: {}", sig_url))?;

        let new_signature = sig_response
            .text()
            .await
            .with_context(|| format!("Failed to read signature text from response: {}", sig_url))?;

        trace!("Fetched new signature: {}", new_signature);

        let current_signature = {
            let data = self.data.read().await;
            data.get_signature()
        };

        let needs_update = current_signature != new_signature;

        if !needs_update && !force {
            info!(
                "No update required for file: '{}'. Signatures match.",
                self.file_name
            );
            return Ok(UpdateStatus::NotUpdated);
        }

        let data_url = Self::get_data_url(branch, &self.file_name);
        trace!("Fetching data from URL: {}", data_url);

        let response = fetch_with_retry(&client, &data_url)
            .await
            .with_context(|| format!("Failed to fetch data from: {}", data_url))?;

        let json_text = response
            .text()
            .await
            .with_context(|| format!("Failed to read response text from: {}", data_url))?;

        trace!("Received JSON data: {}", json_text);

        match parser(&json_text) {
            Ok(mut new_data) => {
                // Run custom validator first
                let validation_result = validator(self.builtin_data.as_ref(), &new_data)?;

                match validation_result {
                    UpdateValidation::Accept => {
                        new_data.set_signature(new_signature);
                        {
                            let mut data = self.data.write().await;
                            *data = new_data;
                        }
                        info!("Successfully updated file: '{}'", self.file_name);
                        Ok(UpdateStatus::Updated)
                    }
                    UpdateValidation::RejectUseBuiltin => {
                        warn!(
                            "Validator rejected downloaded data for '{}'. Restoring built-in data.",
                            self.file_name
                        );
                        let mut data = self.data.write().await;
                        *data = (*self.builtin_data).clone();
                        Ok(UpdateStatus::NotUpdated)
                    }
                    UpdateValidation::RejectKeepCurrent => {
                        warn!(
                            "Validator rejected downloaded data for '{}'. Keeping current data.",
                            self.file_name
                        );
                        Ok(UpdateStatus::NotUpdated)
                    }
                }
            }
            Err(err) => {
                error!(
                    "Failed to decode JSON data for file: '{}'. Error: {:?}",
                    self.file_name, err
                );
                Ok(UpdateStatus::FormatError)
            }
        }
    }
}

// Specialized implementation for types that implement CloudDate
impl<T> CloudModel<T>
where
    T: CloudSignature + CloudDate + Send + Sync + Clone + 'static,
{
    /// Updates with automatic date validation for models implementing CloudDate.
    /// Rejects downloads older than the built-in data.
    pub async fn update_with_date_check<F>(
        &self,
        branch: &str,
        force: bool,
        parser: F,
    ) -> Result<UpdateStatus>
    where
        F: Fn(&str) -> Result<T>,
    {
        self.update_with_validation(branch, force, parser, |builtin, downloaded| {
            validate_model_dates(builtin, downloaded)
        })
        .await
    }
}

/// Validates dates for models implementing CloudDate
fn validate_model_dates<T>(builtin: &T, downloaded: &T) -> Result<UpdateValidation>
where
    T: CloudDate,
{
    let builtin_date_str = match builtin.get_date() {
        Some(date) => date,
        None => return Ok(UpdateValidation::Accept),
    };

    let downloaded_date_str = match downloaded.get_date() {
        Some(date) => date,
        None => return Ok(UpdateValidation::Accept),
    };

    let builtin_date = match parse_model_date(builtin_date_str) {
        Some(date) => date,
        None => {
            info!(
                "Could not parse built-in date '{}', accepting update",
                builtin_date_str
            );
            return Ok(UpdateValidation::Accept);
        }
    };

    let downloaded_date = match parse_model_date(downloaded_date_str) {
        Some(date) => date,
        None => {
            info!(
                "Could not parse downloaded date '{}', accepting update",
                downloaded_date_str
            );
            return Ok(UpdateValidation::Accept);
        }
    };

    if downloaded_date < builtin_date {
        warn!(
            "Downloaded model has date '{}' which is older than built-in date '{}'. Rejecting update.",
            downloaded_date_str, builtin_date_str
        );
        return Ok(UpdateValidation::RejectUseBuiltin);
    }

    info!(
        "Date validation passed (downloaded: '{}', built-in: '{}')",
        downloaded_date_str, builtin_date_str
    );
    Ok(UpdateValidation::Accept)
}

/// Parse a date string in the format "Month DDth YYYY" (e.g., "November 23th 2025")
fn parse_model_date(date: &str) -> Option<NaiveDate> {
    let parts: Vec<&str> = date.trim().split_whitespace().collect();
    if parts.len() != 3 {
        return None;
    }

    let month = match parts[0].to_lowercase().as_str() {
        "january" => 1,
        "february" => 2,
        "march" => 3,
        "april" => 4,
        "may" => 5,
        "june" => 6,
        "july" => 7,
        "august" => 8,
        "september" => 9,
        "october" => 10,
        "november" => 11,
        "december" => 12,
        _ => return None,
    };

    let day_str = parts[1].trim_end_matches(|c: char| c.is_alphabetic());
    let day: u32 = day_str.parse().ok()?;
    let year: i32 = parts[2].parse().ok()?;

    NaiveDate::from_ymd_opt(year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use serial_test::serial; // Using serial_test just in case network tests interfere

    // Helper struct for testing CloudModel
    #[derive(Debug, Clone, PartialEq)]
    struct TestData {
        content: String,
        signature: String,
    }

    impl CloudSignature for TestData {
        fn get_signature(&self) -> String {
            self.signature.clone()
        }
        fn set_signature(&mut self, signature: String) {
            self.signature = signature;
        }
    }

    // Simple parser for test data (format: "content,signature")
    fn test_parser(data: &str) -> Result<TestData> {
        let parts: Vec<&str> = data.split(',').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Invalid test data format"));
        }
        Ok(TestData {
            content: parts[0].to_string(),
            signature: parts[1].to_string(),
        })
    }

    const TEST_BUILTIN: &str = "builtin_content,builtin_sig";
    const TEST_FILE_NAME: &str = "test_model.json";

    #[tokio::test]
    #[serial]
    async fn test_initialize_and_defaults() {
        let model = CloudModel::initialize(TEST_FILE_NAME.to_string(), TEST_BUILTIN, test_parser)
            .expect("Failed to initialize model");

        let data = model.data.read().await;
        assert_eq!(data.content, "builtin_content");
        assert_eq!(data.signature, "builtin_sig");
        assert!(
            !model.is_custom().await,
            "Model should not be custom initially"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_set_custom_data() {
        let model = CloudModel::initialize(TEST_FILE_NAME.to_string(), TEST_BUILTIN, test_parser)
            .expect("Failed to initialize model");

        let custom_data = TestData {
            content: "custom_content".to_string(),
            signature: "custom_sig".to_string(),
        };

        model.set_custom_data(custom_data.clone()).await;

        let data = model.data.read().await;
        assert_eq!(data.content, "custom_content");
        assert_eq!(data.signature, "custom_sig");
        assert!(
            model.is_custom().await,
            "Model should be custom after setting custom data"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_reset_to_default() {
        let model = CloudModel::initialize(TEST_FILE_NAME.to_string(), TEST_BUILTIN, test_parser)
            .expect("Failed to initialize model");

        let custom_data = TestData {
            content: "custom_content".to_string(),
            signature: "custom_sig".to_string(),
        };

        // Set custom data first
        model.set_custom_data(custom_data).await;
        assert!(
            model.is_custom().await,
            "Model should be custom initially in this test"
        );

        // Reset to default
        model.reset_to_default().await;

        let data = model.data.read().await;
        assert_eq!(data.content, "builtin_content");
        assert_eq!(data.signature, "builtin_sig");
        assert!(
            !model.is_custom().await,
            "Model should not be custom after reset"
        );

        // Test resetting when already default
        let initial_sig = data.signature.clone();
        drop(data); // Release read lock
        model.reset_to_default().await; // Should do nothing
        let data_after_reset = model.data.read().await;
        assert_eq!(
            data_after_reset.signature, initial_sig,
            "Resetting default should not change data"
        );
        assert!(!model.is_custom().await, "Model should still not be custom");
    }

    #[tokio::test]
    #[serial]
    async fn test_update_skipped_custom() {
        let model = CloudModel::initialize(TEST_FILE_NAME.to_string(), TEST_BUILTIN, test_parser)
            .expect("Failed to initialize model");

        let custom_data = TestData {
            content: "custom_content".to_string(),
            signature: "custom_sig".to_string(),
        };
        model.set_custom_data(custom_data.clone()).await;

        // Attempt update without force
        let update_status = model.update("main", false, test_parser).await.unwrap();

        assert_eq!(
            update_status,
            UpdateStatus::SkippedCustom,
            "Update should be skipped for custom data without force"
        );

        // Verify data hasn't changed
        let data = model.data.read().await;
        assert_eq!(data.content, "custom_content"); // Should still be custom
    }

    // Note: Testing force update requires a mock HTTP server or careful setup.
    // This test checks the logic flow but doesn't verify the actual network update part.
    #[tokio::test]
    #[serial]
    async fn test_update_force_custom_flow() {
        let model = CloudModel::initialize(TEST_FILE_NAME.to_string(), TEST_BUILTIN, test_parser)
            .expect("Failed to initialize model");

        let custom_data = TestData {
            content: "custom_content".to_string(),
            signature: "custom_sig".to_string(),
        };
        model.set_custom_data(custom_data.clone()).await;

        // Attempt update *with* force. We expect it to fail because the URLs are invalid,
        // but the key is that it should *attempt* the update after resetting.
        let update_result = model.update("main", true, test_parser).await;

        assert!(
            update_result.is_err(),
            "Update should fail due to network error, but it attempted"
        );

        // Verify model was reset to default *before* the failed update attempt
        assert!(
            !model.is_custom().await,
            "Model should have been reset to default during forced update"
        );
        let data = model.data.read().await;
        assert_eq!(data.content, "builtin_content"); // Should be reset
    }

    #[tokio::test]
    #[serial]
    async fn test_needs_update_custom() {
        let model = CloudModel::initialize(TEST_FILE_NAME.to_string(), TEST_BUILTIN, test_parser)
            .expect("Failed to initialize model");

        let custom_data = TestData {
            content: "custom_content".to_string(),
            signature: "custom_sig".to_string(),
        };
        model.set_custom_data(custom_data).await;

        // needs_update should return Ok(false) when custom data is set
        let needs_update_result = model.needs_update("main").await;
        assert!(needs_update_result.is_ok(), "needs_update should succeed");
        assert_eq!(
            needs_update_result.unwrap(),
            false,
            "needs_update should return false for custom data"
        );
    }

    // Test helper struct with CloudDate implementation
    #[derive(Debug, Clone, PartialEq)]
    struct DatedTestData {
        content: String,
        signature: String,
        date: String,
    }

    impl CloudSignature for DatedTestData {
        fn get_signature(&self) -> String {
            self.signature.clone()
        }
        fn set_signature(&mut self, signature: String) {
            self.signature = signature;
        }
    }

    impl CloudDate for DatedTestData {
        fn get_date(&self) -> Option<&str> {
            if self.date.is_empty() {
                None
            } else {
                Some(&self.date)
            }
        }
    }

    // Parser for dated test data (format: "content,signature,date")
    fn dated_test_parser(data: &str) -> Result<DatedTestData> {
        let parts: Vec<&str> = data.split(',').collect();
        if parts.len() != 3 {
            return Err(anyhow!("Invalid dated test data format"));
        }
        Ok(DatedTestData {
            content: parts[0].to_string(),
            signature: parts[1].to_string(),
            date: parts[2].to_string(),
        })
    }

    #[test]
    fn test_parse_model_date_valid() {
        let date1 = parse_model_date("November 23th 2025");
        assert!(date1.is_some());
        assert_eq!(date1.unwrap().to_string(), "2025-11-23");

        let date2 = parse_model_date("January 1st 2024");
        assert!(date2.is_some());
        assert_eq!(date2.unwrap().to_string(), "2024-01-01");

        let date3 = parse_model_date("December 31st 2023");
        assert!(date3.is_some());
        assert_eq!(date3.unwrap().to_string(), "2023-12-31");
    }

    #[test]
    fn test_parse_model_date_invalid() {
        assert!(parse_model_date("Invalid Date").is_none());
        assert!(parse_model_date("November 2025").is_none());
        assert!(parse_model_date("Foo 23th 2025").is_none());
        assert!(parse_model_date("November 32nd 2025").is_none());
        assert!(parse_model_date("").is_none());
    }

    #[test]
    fn test_validate_model_dates_newer() {
        let builtin = DatedTestData {
            content: "old".to_string(),
            signature: "sig1".to_string(),
            date: "November 1st 2025".to_string(),
        };
        let downloaded = DatedTestData {
            content: "new".to_string(),
            signature: "sig2".to_string(),
            date: "November 23th 2025".to_string(),
        };

        let result = validate_model_dates(&builtin, &downloaded).unwrap();
        assert_eq!(result, UpdateValidation::Accept);
    }

    #[test]
    fn test_validate_model_dates_older_rejects() {
        let builtin = DatedTestData {
            content: "new".to_string(),
            signature: "sig1".to_string(),
            date: "November 23th 2025".to_string(),
        };
        let downloaded = DatedTestData {
            content: "old".to_string(),
            signature: "sig2".to_string(),
            date: "November 1st 2025".to_string(),
        };

        let result = validate_model_dates(&builtin, &downloaded).unwrap();
        assert_eq!(result, UpdateValidation::RejectUseBuiltin);
    }

    #[test]
    fn test_validate_model_dates_same() {
        let builtin = DatedTestData {
            content: "content1".to_string(),
            signature: "sig1".to_string(),
            date: "November 23th 2025".to_string(),
        };
        let downloaded = DatedTestData {
            content: "content2".to_string(),
            signature: "sig2".to_string(),
            date: "November 23th 2025".to_string(),
        };

        let result = validate_model_dates(&builtin, &downloaded).unwrap();
        assert_eq!(result, UpdateValidation::Accept);
    }

    #[test]
    fn test_validate_model_dates_no_date() {
        let builtin = DatedTestData {
            content: "content1".to_string(),
            signature: "sig1".to_string(),
            date: "".to_string(),
        };
        let downloaded = DatedTestData {
            content: "content2".to_string(),
            signature: "sig2".to_string(),
            date: "November 23th 2025".to_string(),
        };

        let result = validate_model_dates(&builtin, &downloaded).unwrap();
        assert_eq!(result, UpdateValidation::Accept);
    }

    #[test]
    fn test_validate_model_dates_invalid_format() {
        let builtin = DatedTestData {
            content: "content1".to_string(),
            signature: "sig1".to_string(),
            date: "Invalid Date".to_string(),
        };
        let downloaded = DatedTestData {
            content: "content2".to_string(),
            signature: "sig2".to_string(),
            date: "November 23th 2025".to_string(),
        };

        let result = validate_model_dates(&builtin, &downloaded).unwrap();
        assert_eq!(result, UpdateValidation::Accept);
    }

    #[tokio::test]
    #[serial]
    async fn test_update_with_date_check_initialization() {
        const DATED_BUILTIN: &str = "builtin_content,builtin_sig,November 1st 2025";

        let model = CloudModel::initialize(
            "test_dated_model.json".to_string(),
            DATED_BUILTIN,
            dated_test_parser,
        )
        .expect("Failed to initialize model");

        let data = model.data.read().await;
        assert_eq!(data.content, "builtin_content");
        assert_eq!(data.date, "November 1st 2025");
    }

    #[tokio::test]
    #[serial]
    async fn test_update_with_date_check_rejects_older() {
        const DATED_BUILTIN: &str = "builtin_content,builtin_sig,November 23th 2025";

        let model = CloudModel::initialize(
            "test_dated_model.json".to_string(),
            DATED_BUILTIN,
            dated_test_parser,
        )
        .expect("Failed to initialize model");

        // Simulate validator that would receive older data
        let builtin_data = model.builtin_data.clone();
        let older_data = DatedTestData {
            content: "downloaded".to_string(),
            signature: "new_sig".to_string(),
            date: "November 1st 2025".to_string(),
        };

        let validation_result = validate_model_dates(&*builtin_data, &older_data).unwrap();
        assert_eq!(
            validation_result,
            UpdateValidation::RejectUseBuiltin,
            "Should reject older downloaded model"
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_update_with_date_check_accepts_newer() {
        const DATED_BUILTIN: &str = "builtin_content,builtin_sig,November 1st 2025";

        let model = CloudModel::initialize(
            "test_dated_model.json".to_string(),
            DATED_BUILTIN,
            dated_test_parser,
        )
        .expect("Failed to initialize model");

        // Simulate validator that would receive newer data
        let builtin_data = model.builtin_data.clone();
        let newer_data = DatedTestData {
            content: "downloaded".to_string(),
            signature: "new_sig".to_string(),
            date: "December 1st 2025".to_string(),
        };

        let validation_result = validate_model_dates(&*builtin_data, &newer_data).unwrap();
        assert_eq!(
            validation_result,
            UpdateValidation::Accept,
            "Should accept newer downloaded model"
        );
    }
}
